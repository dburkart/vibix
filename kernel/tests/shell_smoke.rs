//! Integration test: spawning `shell::run` flips the `SHELL_ONLINE`
//! flag after a handful of yields, proving the shell task actually got
//! scheduled and entered its main loop.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use vibix::{
    exit_qemu, serial_println,
    shell::SHELL_ONLINE,
    task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    // Enable preemption: without IF=1 the PIT won't fire and the
    // spawned shell task will never get the CPU back from the driver.
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
        "shell_task_comes_online",
        &(shell_task_comes_online as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn shell_task_comes_online() {
    assert!(!SHELL_ONLINE.load(Ordering::SeqCst));
    task::spawn(vibix::shell::run);
    for _ in 0..100 {
        if SHELL_ONLINE.load(Ordering::SeqCst) {
            return;
        }
        // PIT preempt ticks rotate the spawned shell task in.
        x86_64::instructions::hlt();
    }
    panic!("SHELL_ONLINE never flipped — shell task didn't start");
}
