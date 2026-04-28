//! Integration test: PIT → IDT → tick counter.
//!
//! After full init and `sti`, `time::uptime_ms()` should advance
//! monotonically. The PIT ticks at 100 Hz (10 ms), so waiting for a
//! handful of ticks is cheap even under QEMU.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
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
        ("ticks_advance", &(ticks_advance as fn())),
        ("uptime_monotonic", &(uptime_monotonic as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn ticks_advance() {
    // Route through the scheduler/IRQ seam (RFC 0005); production
    // resolves to the same `crate::time::ticks()` source.
    let (clock, _irq) = vibix::task::env::env();
    let start = clock.now().raw();
    // Wait for at least ~50 ms worth of ticks (5 @ 100 Hz). Use hlt
    // so the CPU actually sleeps between interrupts — a busy loop
    // under QEMU can race the first tick.
    while clock.now().raw() < start + 5 {
        x86_64::instructions::hlt();
    }
    assert!(clock.now().raw() >= start + 5);
}

fn uptime_monotonic() {
    let a = vibix::time::uptime_ms();
    for _ in 0..3 {
        x86_64::instructions::hlt();
    }
    let b = vibix::time::uptime_ms();
    assert!(b >= a, "uptime went backwards: {a} -> {b}");
}
