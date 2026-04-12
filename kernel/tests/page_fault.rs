//! Integration test: deliberately trigger a `#PF` at a known unmapped
//! VA and verify the handler observes the expected fault address.
//!
//! Oracle: the IST guard page is the lowest 4 KiB of `DOUBLE_FAULT_STACK`,
//! unmapped during `mem::init`. Its VA is exported by `gdt`, so we can
//! arm the expectation, read from it once, and let the `#PF` handler
//! `exit_qemu(Success)` on match or `Failure` on mismatch.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::ptr;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, QemuExitCode},
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("page_fault: init ok");

    let guard = vibix::arch::x86_64::gdt::df_stack_guard_addr().as_u64();
    serial_println!("page_fault: arming expectation @ {:#x}", guard);

    vibix::test_hook::expect_page_fault(guard);

    // The handler exits QEMU directly on match/mismatch, so this read
    // should never return. Reach here only if the fault didn't fire —
    // treat that as a failure.
    unsafe {
        let _ = ptr::read_volatile(guard as *const u64);
    }

    serial_println!("page_fault: deref did NOT fault — test failed");
    exit_qemu(QemuExitCode::Failure);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}
