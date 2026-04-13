//! Integration test: x87/SSE register state survives preemptive context
//! switches.
//!
//! Two worker tasks each load a unique 128-bit pattern into XMM0 (via
//! inline asm — the kernel target is soft-float, so the compiler never
//! touches XMM regs on its own). Each worker then spins reading XMM0
//! back into a `[u64; 2]` snapshot and asserting the bits still match
//! the pattern it loaded. Without per-task FPU save/restore on context
//! switch the two patterns would cross-contaminate within the first
//! preemption tick.

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
    let tests: &[(&str, &dyn Testable)] = &[(
        "fpu_state_preserved_across_preemption",
        &(fpu_state_preserved_across_preemption as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

const A_LO: u64 = 0xA1A1_A1A1_A1A1_A1A1;
const A_HI: u64 = 0xA2A2_A2A2_A2A2_A2A2;
const B_LO: u64 = 0xB1B1_B1B1_B1B1_B1B1;
const B_HI: u64 = 0xB2B2_B2B2_B2B2_B2B2;

static A_ITERS: AtomicUsize = AtomicUsize::new(0);
static B_ITERS: AtomicUsize = AtomicUsize::new(0);
static A_FAIL: AtomicBool = AtomicBool::new(false);
static B_FAIL: AtomicBool = AtomicBool::new(false);

#[inline(always)]
unsafe fn load_xmm0(lo: u64, hi: u64) {
    let pair = [lo, hi];
    // SAFETY: caller upholds that the FPU is enabled (CR4.OSFXSR set
    // by `arch::init` → `fpu::init`). The asm only writes XMM0.
    unsafe {
        core::arch::asm!(
            "movupd xmm0, [{p}]",
            p = in(reg) pair.as_ptr(),
            out("xmm0") _,
            options(nostack, preserves_flags),
        );
    }
}

#[inline(always)]
unsafe fn read_xmm0() -> [u64; 2] {
    let mut out = [0u64; 2];
    // SAFETY: same as load_xmm0 — XMM0 is observable as soon as the
    // FPU is enabled.
    unsafe {
        core::arch::asm!(
            "movupd [{p}], xmm0",
            p = in(reg) out.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    out
}

fn worker_a() -> ! {
    // SAFETY: FPU init ran in `vibix::init` → `arch::init`.
    unsafe { load_xmm0(A_LO, A_HI) };
    loop {
        let read = unsafe { read_xmm0() };
        if read != [A_LO, A_HI] {
            A_FAIL.store(true, Ordering::Relaxed);
        }
        A_ITERS.fetch_add(1, Ordering::Relaxed);
        // Reload to keep the test honest if a real failure already
        // corrupted the register — we want subsequent iterations to
        // also flag the issue, not silently pass.
        unsafe { load_xmm0(A_LO, A_HI) };
        core::hint::spin_loop();
    }
}

fn worker_b() -> ! {
    unsafe { load_xmm0(B_LO, B_HI) };
    loop {
        let read = unsafe { read_xmm0() };
        if read != [B_LO, B_HI] {
            B_FAIL.store(true, Ordering::Relaxed);
        }
        B_ITERS.fetch_add(1, Ordering::Relaxed);
        unsafe { load_xmm0(B_LO, B_HI) };
        core::hint::spin_loop();
    }
}

fn fpu_state_preserved_across_preemption() {
    A_ITERS.store(0, Ordering::SeqCst);
    B_ITERS.store(0, Ordering::SeqCst);
    A_FAIL.store(false, Ordering::SeqCst);
    B_FAIL.store(false, Ordering::SeqCst);

    task::spawn(worker_a);
    task::spawn(worker_b);

    // 200 ms = 20 PIT ticks at 100 Hz. The two 10 ms slices interleave
    // ~10 times each over this window; without FPU save/restore the
    // first preemption would already corrupt one task's XMM0.
    let start = time::uptime_ms();
    while time::uptime_ms() < start + 200 {
        x86_64::instructions::hlt();
    }

    let a = A_ITERS.load(Ordering::Relaxed);
    let b = B_ITERS.load(Ordering::Relaxed);
    let af = A_FAIL.load(Ordering::Relaxed);
    let bf = B_FAIL.load(Ordering::Relaxed);
    serial_println!("fpu test: a_iters={a} b_iters={b} a_fail={af} b_fail={bf}");
    assert!(a > 0, "worker_a never ran (a={a})");
    assert!(b > 0, "worker_b never ran (b={b})");
    assert!(!af, "worker_a saw XMM0 corruption");
    assert!(!bf, "worker_b saw XMM0 corruption");
}
