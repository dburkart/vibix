//! vibix kernel library.
//!
//! The crate is structured as a library + thin bin so that integration
//! tests under `kernel/tests/*` and host-side unit tests can share the
//! same code. The `#![no_std]` attribute is gated on `not(test)` so
//! host unit tests (`cargo test --lib`) compile against the standard
//! library and can run on the development machine.

#![cfg_attr(not(test), no_std)]
#![cfg_attr(target_os = "none", feature(abi_x86_interrupt))]

extern crate alloc;

pub mod mem;

#[cfg(target_os = "none")]
pub mod arch;
#[cfg(target_os = "none")]
pub mod boot;
#[cfg(target_os = "none")]
pub mod framebuffer;
#[cfg(target_os = "none")]
pub mod serial;
#[cfg(target_os = "none")]
pub mod test_harness;

#[cfg(target_os = "none")]
pub use test_harness::{exit_qemu, QemuExitCode, Testable};

/// Bring up core kernel subsystems in the right order. Callable from
/// both the main bin and from integration-test `_start`s.
#[cfg(target_os = "none")]
pub fn init() {
    serial::init();
    arch::init();
    mem::init();
}

/// Halt forever. Handy in panic paths and as a terminal call in tests.
#[cfg(target_os = "none")]
pub fn hlt_loop() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}
