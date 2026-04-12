//! Integration test: the PIT preempts tasks that never yield.
//!
//! Spawns two workers that spin on a counter with no cooperative
//! cooperative yield, then the driver sleeps on `hlt` watching `uptime_ms()`
//! until the deadline passes. Both workers must have made progress —
//! if either counter is still zero, preemption didn't rotate through.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

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
        "preempts_never_yielding_tasks",
        &(preempts_never_yielding_tasks as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static A: AtomicUsize = AtomicUsize::new(0);
static B: AtomicUsize = AtomicUsize::new(0);

fn spin_a() -> ! {
    loop {
        A.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

fn spin_b() -> ! {
    loop {
        B.fetch_add(1, Ordering::Relaxed);
        core::hint::spin_loop();
    }
}

fn preempts_never_yielding_tasks() {
    A.store(0, Ordering::SeqCst);
    B.store(0, Ordering::SeqCst);

    task::spawn(spin_a);
    task::spawn(spin_b);

    // 100 ms window = 10 PIT ticks at 100 Hz. With a 10 ms slice each
    // worker should land at least one full slice; hlt parks the driver
    // between ticks so the workers get the CPU.
    let start = time::uptime_ms();
    while time::uptime_ms() < start + 100 {
        x86_64::instructions::hlt();
    }

    let a = A.load(Ordering::Relaxed);
    let b = B.load(Ordering::Relaxed);
    assert!(a > 0, "spin_a never ran under preemption (a={a})");
    assert!(b > 0, "spin_b never ran under preemption (b={b})");
}
