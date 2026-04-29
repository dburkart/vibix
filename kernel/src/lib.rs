//! vibix kernel library.
//!
//! The crate is structured as a library + thin bin so that integration
//! tests under `kernel/tests/*` and host-side unit tests can share the
//! same code. The `#![no_std]` attribute is gated on `not(test)` so
//! host unit tests (`cargo test --lib`) compile against the standard
//! library and can run on the development machine.
//!
//! RFC 0006 (host-side DST simulator) adds a second host-build path:
//! `cargo build --target x86_64-unknown-linux-gnu --features sched-mock`.
//! That build also needs `std` because the host arm of `task::env::env()`
//! is implemented with `thread_local!` (issue #714). The exception is
//! kept narrow — only the host triple **plus** the explicit `sched-mock`
//! feature pulls `std` in; production bare-metal (`target_os = "none"`)
//! and feature-off host builds stay `#![no_std]`.

#![cfg_attr(
    all(not(test), not(all(not(target_os = "none"), feature = "sched-mock"))),
    no_std
)]
#![cfg_attr(target_os = "none", feature(abi_x86_interrupt))]

extern crate alloc;

#[cfg(any(test, target_os = "none"))]
pub mod abi;
#[cfg(any(test, target_os = "none"))]
pub mod block;
pub mod build_info;
pub mod cpu;
pub mod debug_lockdep;
#[cfg(any(test, target_os = "none"))]
pub mod fork_abi;
#[cfg(any(test, target_os = "none"))]
pub mod fs;
#[cfg(any(test, target_os = "none"))]
pub mod gdbstub;
pub mod input;
#[cfg(any(test, target_os = "none"))]
pub mod ipc;
pub mod klog;
pub mod mem;
#[cfg(any(test, target_os = "none"))]
pub mod pci;

#[cfg(target_os = "none")]
pub mod acpi;

#[cfg(target_os = "none")]
pub mod arch;
#[cfg(all(target_os = "none", feature = "bench"))]
pub mod bench;
#[cfg(target_os = "none")]
pub mod boot;
pub mod boot_cmdline;
pub mod fbview;
#[cfg(any(test, target_os = "none"))]
pub mod framebuffer;
#[cfg(any(test, target_os = "none"))]
pub mod hpet;
#[cfg(target_os = "none")]
pub mod init_process;
#[cfg(target_os = "none")]
pub mod ksymtab;
pub mod lntab;
#[cfg(any(test, target_os = "none"))]
pub mod poll;
#[cfg(target_os = "none")]
pub mod process;
#[cfg(target_os = "none")]
pub mod serial;
#[cfg(any(test, target_os = "none"))]
pub mod shell;
#[cfg(target_os = "none")]
pub mod signal;
#[cfg(target_os = "none")]
pub mod sync;
// `pub mod task` is normally bare-metal-only — the scheduler core
// touches `arch`, `sync`, and `x86_64` which are all `target_os =
// "none"`. The exception is the `task::env` submodule (RFC 0005
// scheduler / IRQ seam), whose trait definitions and `MockClock` /
// `MockTimerIrq` impls (gated behind `feature = "sched-mock"`) are
// host-buildable so the seam has CI-runnable host unit tests. RFC 0006
// (issue #714) extends the host-build arm to plain `cargo build`
// (not just `cargo test`) so the future `simulator/` crate can link
// the kernel with `--features sched-mock` without depending on the
// `cfg(test)` hack — hence the `feature = "sched-mock"` arm covers
// both. The body of `task/mod.rs` stays gated to `target_os = "none"`
// internally; only `task::env` is reachable from a host build.
#[cfg(any(target_os = "none", feature = "sched-mock"))]
pub mod task;
#[cfg(target_os = "none")]
pub mod test_harness;
#[cfg(target_os = "none")]
pub mod test_hook;
#[cfg(any(test, target_os = "none"))]
pub mod time;
#[cfg(any(test, target_os = "none"))]
pub mod tty;

#[cfg(target_os = "none")]
pub use test_harness::{exit_qemu, QemuExitCode, Testable};

/// Bring up core kernel subsystems in the right order. Callable from
/// both the main bin and from integration-test `_start`s. Interrupts
/// remain **disabled** on return — callers `sti` when they're ready.
#[cfg(target_os = "none")]
pub fn init() {
    serial::init();
    let hhdm = boot::HHDM_REQUEST
        .get_response()
        .expect("Limine HHDM response missing")
        .offset();
    let rsdp = boot::RSDP_REQUEST
        .get_response()
        .expect("Limine RSDP response missing")
        .address();
    arch::init();
    mem::init();
    fs::vfs::init::init();
    arch::init_apic(rsdp, hhdm);
    match hpet::init() {
        Ok(()) => {}
        Err(e) => serial_println!("hpet: unavailable ({:?}), falling back to PIT", e),
    }
    time::init();
    tty::ps2::init();
    tty::serial::init();
}

/// Halt forever. Handy in panic paths and as a terminal call in tests.
#[cfg(target_os = "none")]
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
