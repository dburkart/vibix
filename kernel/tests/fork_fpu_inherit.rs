//! Integration test: `fpu::save` captures *live* FPU register state, not
//! the stale snapshot left by the last context switch.
//!
//! `fork_current_task` snapshots the parent's saved `FpuArea` into the
//! child before any context switch happens on the parent — if the syscall
//! path doesn't `fxsave` the live CPU registers first, the child inherits
//! whatever was in the parent's area from its *previous* switch. This
//! test drives `fpu::save` directly against a fresh `FpuArea`, then uses
//! `fpu::restore` to prove the area captured the value that was actually
//! live in XMM0 at save time. Without the fix to `fork_current_task`,
//! `new_forked`'s `copy_nonoverlapping(parent_fpu, ...)` would run before
//! any `save`, and the captured state would not match the running regs.
//!
//! Uses XMM0 because the kernel target is soft-float — the compiler never
//! touches XMM regs on its own, so any clobber we observe is the test.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::{
    arch::x86_64::fpu,
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[(
        "fpu_save_captures_live_xmm_state",
        &(fpu_save_captures_live_xmm_state as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

const PAT_LO: u64 = 0xDEAD_BEEF_CAFE_BABE;
const PAT_HI: u64 = 0xFEED_FACE_0123_4567;
const DECOY_LO: u64 = 0x1111_1111_1111_1111;
const DECOY_HI: u64 = 0x2222_2222_2222_2222;

#[inline(always)]
unsafe fn load_xmm0(lo: u64, hi: u64) {
    let pair = [lo, hi];
    // SAFETY: FPU init ran in `vibix::init` → `arch::init`, so XMM regs
    // are accessible. Inline asm only writes XMM0.
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
    // SAFETY: same as load_xmm0.
    unsafe {
        core::arch::asm!(
            "movupd [{p}], xmm0",
            p = in(reg) out.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
    out
}

fn fpu_save_captures_live_xmm_state() {
    let mut area = fpu::FpuArea::new_initialized();

    // SAFETY: fpu::init ran at arch bringup; XMM0 is ours to clobber.
    // `save` requires a &mut FpuArea that is not aliased by another
    // in-flight save — we hold `area` locally.
    unsafe {
        load_xmm0(PAT_LO, PAT_HI);
        fpu::save(&mut area);

        // Overwrite the live XMM0 with a decoy so that a subsequent
        // restore has visible effect (and so we're definitely not just
        // reading a register that was never changed).
        load_xmm0(DECOY_LO, DECOY_HI);
        let decoy = read_xmm0();
        assert_eq!(
            decoy,
            [DECOY_LO, DECOY_HI],
            "XMM0 decoy load failed (got {:#x?})",
            decoy
        );

        // Restore from the saved area. If `save` actually captured the
        // live registers, XMM0 now reads back as the original pattern.
        // If it instead left the area untouched / stale, XMM0 would read
        // back as whatever was in the canonical init template (zeros).
        fpu::restore(&area);
    }

    let got = unsafe { read_xmm0() };
    assert_eq!(
        got,
        [PAT_LO, PAT_HI],
        "fpu::save did not capture live XMM0 (got {:#x?}, expected [{:#x}, {:#x}])",
        got,
        PAT_LO,
        PAT_HI,
    );
    serial_println!("fpu::save captured live XMM0: {:#x?}", got);
}
