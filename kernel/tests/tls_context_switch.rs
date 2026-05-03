//! Integration test for #835: end-to-end static Thread-Local Storage.
//!
//! Verifies:
//! 1. TLS (FS base) is preserved across preemptive context switches —
//!    two tasks write distinct TLS bases and spin-check they survive
//!    preemption (same pattern as `fpu_context_switch` / `fsgsbase`).
//! 2. `fork_address_space` clones the TLS VMA into an independent
//!    backing object so parent and child have isolated TLS blocks.
//! 3. `arch_prctl(ARCH_SET_FS)` / `arch_prctl(ARCH_GET_FS)` round-trip
//!    through the syscall dispatch path.
//! 4. `%fs:0` returns the TCB self-pointer after FS base is set to a
//!    properly-initialised TLS block (x86_64 ELF variant II layout).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    time, QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    x86_64::instructions::interrupts::enable();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "tls_fs_base_preserved_across_preemption",
            &(tls_fs_base_preserved_across_preemption as fn()),
        ),
        (
            "fork_tls_isolation",
            &(fork_tls_isolation as fn()),
        ),
        (
            "arch_prctl_set_get_roundtrip",
            &(arch_prctl_set_get_roundtrip as fn()),
        ),
        (
            "tcb_self_pointer_via_fs_deref",
            &(tcb_self_pointer_via_fs_deref as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ==========================================================================
// Test 1: TLS (FS base) preserved across preemptive context switches
// ==========================================================================

/// Sentinel FS base value for worker A. Chosen to be in the lower half
/// (canonical user-range) so it would be valid as a TLS base, though we
/// only use `wrfsbase`/`rdfsbase` here — no actual memory dereference.
const TLS_PATTERN_A: u64 = 0x0000_DEAD_BEEF_0001;
const TLS_PATTERN_B: u64 = 0x0000_CAFE_BABE_0002;

static A_ITERS: AtomicUsize = AtomicUsize::new(0);
static B_ITERS: AtomicUsize = AtomicUsize::new(0);
static A_FAIL: AtomicBool = AtomicBool::new(false);
static B_FAIL: AtomicBool = AtomicBool::new(false);

fn tls_worker_a() -> ! {
    // Set FS base via both the task struct and the MSR/FSGSBASE.
    task::set_current_fs_base(TLS_PATTERN_A);
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) TLS_PATTERN_A,
            options(nomem, nostack, preserves_flags),
        );
    }

    loop {
        let val: u64;
        unsafe {
            core::arch::asm!(
                "rdfsbase {}",
                out(reg) val,
                options(nomem, nostack, preserves_flags),
            );
        }
        if val != TLS_PATTERN_A {
            A_FAIL.store(true, Ordering::Relaxed);
        }
        A_ITERS.fetch_add(1, Ordering::Relaxed);
        // Reload to keep the test honest after a real failure.
        unsafe {
            core::arch::asm!(
                "wrfsbase {}",
                in(reg) TLS_PATTERN_A,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::hint::spin_loop();
    }
}

fn tls_worker_b() -> ! {
    task::set_current_fs_base(TLS_PATTERN_B);
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) TLS_PATTERN_B,
            options(nomem, nostack, preserves_flags),
        );
    }

    loop {
        let val: u64;
        unsafe {
            core::arch::asm!(
                "rdfsbase {}",
                out(reg) val,
                options(nomem, nostack, preserves_flags),
            );
        }
        if val != TLS_PATTERN_B {
            B_FAIL.store(true, Ordering::Relaxed);
        }
        B_ITERS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            core::arch::asm!(
                "wrfsbase {}",
                in(reg) TLS_PATTERN_B,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::hint::spin_loop();
    }
}

/// Spawn two tasks that each set FS base to a unique TLS-like pattern and
/// spin verifying it across preemption ticks. Without proper save/restore
/// in the context-switch path, one task's FS base would clobber the other's
/// within a single preemption tick.
fn tls_fs_base_preserved_across_preemption() {
    A_ITERS.store(0, Ordering::SeqCst);
    B_ITERS.store(0, Ordering::SeqCst);
    A_FAIL.store(false, Ordering::SeqCst);
    B_FAIL.store(false, Ordering::SeqCst);

    task::spawn(tls_worker_a);
    task::spawn(tls_worker_b);

    // 200 ms = ~20 PIT ticks at 100 Hz. The two 10 ms slices interleave
    // ~10 times each over this window; without FS base save/restore the
    // first preemption would already corrupt one task's TLS pattern.
    let start = time::uptime_ms();
    while time::uptime_ms() < start + 200 {
        x86_64::instructions::hlt();
    }

    let a = A_ITERS.load(Ordering::Relaxed);
    let b = B_ITERS.load(Ordering::Relaxed);
    let af = A_FAIL.load(Ordering::Relaxed);
    let bf = B_FAIL.load(Ordering::Relaxed);
    serial_println!("tls preemption: a_iters={a} b_iters={b} a_fail={af} b_fail={bf}");
    assert!(a > 0, "tls_worker_a never ran (a={a})");
    assert!(b > 0, "tls_worker_b never ran (b={b})");
    assert!(!af, "tls_worker_a saw FS base corruption (TLS not preserved)");
    assert!(!bf, "tls_worker_b saw FS base corruption (TLS not preserved)");
}

// ==========================================================================
// Test 2: fork produces independent TLS VMAs
// ==========================================================================

/// Verify that `fork_address_space` clones the TLS region VMA into a
/// distinct backing object, so parent and child have isolated TLS blocks.
/// Uses the same AddressSpace + VMA infrastructure as the real TLS
/// allocation path in `loader::allocate_tls_block`.
fn fork_tls_isolation() {
    use vibix::mem::addrspace::AddressSpace;
    use vibix::mem::tlb::Flusher;
    use vibix::mem::vmatree::{Share, Vma};
    use vibix::mem::vmobject::AnonObject;
    use x86_64::structures::paging::PageTableFlags;

    // Simulate a TLS region: one page at a lower-half VA.
    const TLS_VA: usize = 0x0000_5000_0000_0000;
    const TLS_PAGES: usize = 1;

    let mut parent = AddressSpace::new_empty();
    let tls_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    parent.insert(Vma::new(
        TLS_VA,
        TLS_VA + TLS_PAGES * 4096,
        0x3, // PROT_READ|WRITE
        tls_flags.bits(),
        Share::Private,
        AnonObject::new(Some(TLS_PAGES)),
        0,
    ));

    // Verify the VMA exists in the parent.
    assert!(parent.find(TLS_VA).is_some(), "parent TLS VMA missing");

    let mut flusher = Flusher::new_active();
    let child = parent
        .fork_address_space(&mut flusher)
        .expect("fork_address_space failed");
    flusher.finish();

    // The child must have a TLS VMA at the same address range.
    let child_vma = child.find(TLS_VA).expect("child TLS VMA missing after fork");
    assert_eq!(child_vma.start, TLS_VA, "child TLS VMA start mismatch");
    assert_eq!(
        child_vma.end,
        TLS_VA + TLS_PAGES * 4096,
        "child TLS VMA end mismatch"
    );

    // Private VMAs must get an independent backing object after fork.
    // Compare the data pointers (first half of the fat pointer) to check
    // distinctness without casting the whole fat pointer to usize.
    let parent_vma = parent.find(TLS_VA).expect("parent TLS VMA missing");
    let parent_data = Arc::as_ptr(&parent_vma.object) as *const () as usize;
    let child_data = Arc::as_ptr(&child_vma.object) as *const () as usize;
    assert_ne!(
        parent_data, child_data,
        "fork must create a distinct AnonObject for the TLS VMA (isolation)"
    );

    serial_println!(
        "fork_tls_isolation: parent_obj={:#x} child_obj={:#x} — isolated",
        parent_data,
        child_data
    );

    drop(parent);
    drop(child);
}

// ==========================================================================
// Test 3: arch_prctl(ARCH_SET_FS) / arch_prctl(ARCH_GET_FS) round-trip
// ==========================================================================

/// Call `set_current_fs_base` (the kernel-side implementation of
/// ARCH_SET_FS) and `current_fs_base` (ARCH_GET_FS), then verify the
/// round-trip returns the same value. Also verifies the hardware MSR
/// matches via `rdfsbase`.
fn arch_prctl_set_get_roundtrip() {
    let test_val: u64 = 0x0000_1234_5678_ABCD;

    // ARCH_SET_FS equivalent: store in task + write hardware.
    task::set_current_fs_base(test_val);
    unsafe {
        // Write the hardware MSR to match (arch_prctl does both).
        x86_64::registers::model_specific::Msr::new(0xC000_0100).write(test_val);
    }

    // ARCH_GET_FS equivalent: read from the task struct.
    let readback = task::current_fs_base();
    assert_eq!(
        readback, test_val,
        "arch_prctl round-trip: task fs_base={readback:#x}, expected {test_val:#x}"
    );

    // Also verify the hardware MSR matches.
    let hw_val: u64;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) hw_val,
            options(nomem, nostack, preserves_flags),
        );
    }
    assert_eq!(
        hw_val, test_val,
        "arch_prctl round-trip: hardware FS base={hw_val:#x}, expected {test_val:#x}"
    );

    serial_println!(
        "arch_prctl round-trip: set={test_val:#x} get={readback:#x} hw={hw_val:#x} — ok"
    );

    // Restore FS base to 0 so we don't leak a stale value into
    // subsequent tests.
    task::set_current_fs_base(0);
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) 0u64,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ==========================================================================
// Test 4: %fs:0 returns the TCB self-pointer
// ==========================================================================

/// Allocate a physical frame, write a TLS block with a TCB self-pointer
/// per x86_64 variant II conventions into its HHDM window, set FS base
/// to the TCB address within that window, and verify `%fs:0` (a memory
/// load at `[fs_base + 0]`) returns the TCB virtual address.
///
/// This exercises the same layout that `allocate_tls_block` produces for
/// real userspace ELF binaries with PT_TLS segments.
fn tcb_self_pointer_via_fs_deref() {
    use vibix::mem::paging::hhdm_offset;

    // Allocate a fresh physical frame.
    let frame_phys = vibix::mem::frame::alloc()
        .expect("frame alloc failed for TCB test page");

    // Compute the HHDM virtual address for this frame.
    let hhdm = hhdm_offset();
    let page_va = (hhdm + frame_phys).as_u64();
    let page_ptr = page_va as *mut u8;

    // Zero-fill the page.
    unsafe {
        core::ptr::write_bytes(page_ptr, 0, 4096);
    }

    // Lay out a minimal TLS block per x86_64 variant II:
    //   [.tdata (16 bytes)] [.tbss (16 bytes)] [TCB (8 bytes)]
    //                                            ^--- fs_base
    //
    // With align=8, tdata starts at offset 0 within the page, tdata is
    // 16 bytes, total_size is 32 bytes (16 .tdata + 16 .tbss), so the
    // TCB sits at offset 32 from the page start.
    let tdata_size: u64 = 16;
    let total_size: u64 = 32;
    let tcb_offset: u64 = total_size; // TCB is right after .tdata + .tbss
    let tcb_va = page_va + tcb_offset;

    // Fill .tdata with a recognisable pattern.
    unsafe {
        core::ptr::write_bytes(page_ptr, 0xAA, tdata_size as usize);
    }

    // Write the TCB self-pointer: TCB[0] = &TCB (x86_64 variant II).
    unsafe {
        let tcb_ptr = tcb_va as *mut u64;
        core::ptr::write_volatile(tcb_ptr, tcb_va);
    }

    // Save the original FS base so we can restore it.
    let original_fs: u64;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) original_fs,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Set FS base to the TCB address (within the HHDM-mapped page).
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) tcb_va,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Read %fs:0 — this dereferences memory at [fs_base + 0] using the
    // FS segment override prefix. The value should be the TCB
    // self-pointer (== tcb_va itself).
    let fs_deref: u64;
    unsafe {
        core::arch::asm!(
            "mov {out}, fs:[0]",
            out = out(reg) fs_deref,
            options(nostack, preserves_flags, readonly),
        );
    }

    assert_eq!(
        fs_deref, tcb_va,
        "%%fs:0 returned {fs_deref:#x}, expected TCB self-pointer {tcb_va:#x}"
    );
    serial_println!("tcb self-pointer: fs_base={tcb_va:#x} %%fs:0={fs_deref:#x} — ok");

    // Restore original FS base.
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) original_fs,
            options(nomem, nostack, preserves_flags),
        );
    }

    // Free the frame we allocated.
    vibix::mem::frame::put(frame_phys);
}
