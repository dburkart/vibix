//! Integration test: panicking is correctly reported as test failure.
//! Uses an inverted panic handler — a panic is *expected* here, so the
//! panic path exits QEMU with Success; reaching the end of `_start`
//! without panicking would exit with Failure.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use vibix::{exit_qemu, serial_println, QemuExitCode};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    should_fail();

    // If we get here, nothing panicked — that's a test failure.
    serial_println!("should_panic: no panic occurred");
    exit_qemu(QemuExitCode::Failure);
}

fn should_fail() {
    serial_println!("should_panic::should_fail ... ");
    assert_eq!(0, 1);
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial_println!("[ok]");
    exit_qemu(QemuExitCode::Success);
}
