//! Integration test for #836: CR4.FSGSBASE is enabled at boot and the
//! `rdfsbase`/`wrfsbase` instructions are usable from ring 0.
//!
//! Verifies:
//! 1. CR4 bit 16 (FSGSBASE) is set after `vibix::init()`.
//! 2. A `wrfsbase` / `rdfsbase` round-trip returns the written value.
//! 3. The context-switch helpers preserve FS base across a preemption
//!    window (same pattern as `fpu_context_switch`).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    time, QemuExitCode,
};
use x86_64::registers::control::{Cr4, Cr4Flags};

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
        ("cr4_fsgsbase_bit_set", &(cr4_fsgsbase_bit_set as fn())),
        (
            "wrfsbase_rdfsbase_roundtrip",
            &(wrfsbase_rdfsbase_roundtrip as fn()),
        ),
        (
            "fs_base_preserved_across_preemption",
            &(fs_base_preserved_across_preemption as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// CR4.FSGSBASE (bit 16) must be set after boot.
fn cr4_fsgsbase_bit_set() {
    let flags = Cr4::read();
    assert!(
        flags.contains(Cr4Flags::FSGSBASE),
        "CR4.FSGSBASE not set — enable_fsgsbase() did not run or CPU lacks support"
    );
}

/// Write a non-zero value via `wrfsbase`, read it back via `rdfsbase`,
/// then restore the original value. Without CR4.FSGSBASE these
/// instructions would #UD.
fn wrfsbase_rdfsbase_roundtrip() {
    // Save the current FS base so we can restore it.
    let original: u64;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) original,
            options(nomem, nostack, preserves_flags),
        );
    }

    let test_val: u64 = 0xDEAD_BEEF_CAFE_0836;
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) test_val,
            options(nomem, nostack, preserves_flags),
        );
    }

    let readback: u64;
    unsafe {
        core::arch::asm!(
            "rdfsbase {}",
            out(reg) readback,
            options(nomem, nostack, preserves_flags),
        );
    }

    assert_eq!(
        readback, test_val,
        "rdfsbase returned {readback:#x}, expected {test_val:#x}"
    );

    // Restore original FS base.
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) original,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// ----- preemption-survival test -----

const PATTERN_A: u64 = 0xAAAA_BBBB_CCCC_0001;
const PATTERN_B: u64 = 0x1111_2222_3333_0002;

static A_ITERS: AtomicUsize = AtomicUsize::new(0);
static B_ITERS: AtomicUsize = AtomicUsize::new(0);
static A_FAIL: AtomicBool = AtomicBool::new(false);
static B_FAIL: AtomicBool = AtomicBool::new(false);

fn worker_a() -> ! {
    // Set FS base to our pattern.
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) PATTERN_A,
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
        if val != PATTERN_A {
            A_FAIL.store(true, Ordering::Relaxed);
        }
        A_ITERS.fetch_add(1, Ordering::Relaxed);
        // Reload to keep the test honest after a real failure — we want
        // subsequent iterations to also flag corruption, not silently pass.
        unsafe {
            core::arch::asm!(
                "wrfsbase {}",
                in(reg) PATTERN_A,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::hint::spin_loop();
    }
}

fn worker_b() -> ! {
    unsafe {
        core::arch::asm!(
            "wrfsbase {}",
            in(reg) PATTERN_B,
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
        if val != PATTERN_B {
            B_FAIL.store(true, Ordering::Relaxed);
        }
        B_ITERS.fetch_add(1, Ordering::Relaxed);
        unsafe {
            core::arch::asm!(
                "wrfsbase {}",
                in(reg) PATTERN_B,
                options(nomem, nostack, preserves_flags),
            );
        }
        core::hint::spin_loop();
    }
}

/// Spawn two tasks that each set FS base to a unique pattern and spin
/// verifying it. Without proper save/restore in the context-switch
/// path, one task's pattern would clobber the other's within a single
/// preemption tick.
fn fs_base_preserved_across_preemption() {
    A_ITERS.store(0, Ordering::SeqCst);
    B_ITERS.store(0, Ordering::SeqCst);
    A_FAIL.store(false, Ordering::SeqCst);
    B_FAIL.store(false, Ordering::SeqCst);

    task::spawn(worker_a);
    task::spawn(worker_b);

    // 200 ms = 20 PIT ticks at 100 Hz. The two 10 ms slices interleave
    // ~10 times each over this window; without FS base save/restore the
    // first preemption would already corrupt one task's pattern.
    let start = time::uptime_ms();
    while time::uptime_ms() < start + 200 {
        x86_64::instructions::hlt();
    }

    let a = A_ITERS.load(Ordering::Relaxed);
    let b = B_ITERS.load(Ordering::Relaxed);
    let af = A_FAIL.load(Ordering::Relaxed);
    let bf = B_FAIL.load(Ordering::Relaxed);
    serial_println!("fsgsbase test: a_iters={a} b_iters={b} a_fail={af} b_fail={bf}");
    assert!(a > 0, "worker_a never ran (a={a})");
    assert!(b > 0, "worker_b never ran (b={b})");
    assert!(!af, "worker_a saw FS base corruption");
    assert!(!bf, "worker_b saw FS base corruption");
}
