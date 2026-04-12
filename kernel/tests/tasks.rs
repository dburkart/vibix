//! Integration test: cooperative kernel tasks actually interleave, and
//! a spawned task can flip a flag the driver task polls.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("two_tasks_interleave", &(two_tasks_interleave as fn())),
        (
            "spawn_then_join_via_flag",
            &(spawn_then_join_via_flag as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static A: AtomicUsize = AtomicUsize::new(0);
static B: AtomicUsize = AtomicUsize::new(0);
const ROUNDS: usize = 50;

fn task_a() -> ! {
    for _ in 0..ROUNDS {
        A.fetch_add(1, Ordering::SeqCst);
        task::yield_now();
    }
    loop {
        task::yield_now();
    }
}

fn task_b() -> ! {
    for _ in 0..ROUNDS {
        B.fetch_add(1, Ordering::SeqCst);
        task::yield_now();
    }
    loop {
        task::yield_now();
    }
}

fn two_tasks_interleave() {
    A.store(0, Ordering::SeqCst);
    B.store(0, Ordering::SeqCst);

    task::spawn(task_a);
    task::spawn(task_b);

    // Drive the scheduler from the driver (bootstrap) task. ROUNDS*3
    // yields is comfortably enough for both workers to finish their
    // ROUNDS bumps under round-robin.
    for _ in 0..(ROUNDS * 3) {
        task::yield_now();
    }

    let a = A.load(Ordering::SeqCst);
    let b = B.load(Ordering::SeqCst);
    assert_eq!(a, ROUNDS, "task_a didn't run to completion (a={a})");
    assert_eq!(b, ROUNDS, "task_b didn't run to completion (b={b})");
}

static FLAG: AtomicBool = AtomicBool::new(false);

fn flag_setter() -> ! {
    FLAG.store(true, Ordering::SeqCst);
    loop {
        task::yield_now();
    }
}

fn spawn_then_join_via_flag() {
    FLAG.store(false, Ordering::SeqCst);
    task::spawn(flag_setter);

    // Poll + yield until the flag flips. Bound the loop so a
    // scheduler bug fails the test fast instead of hanging CI.
    for _ in 0..1_000 {
        if FLAG.load(Ordering::SeqCst) {
            return;
        }
        task::yield_now();
    }
    panic!("flag never flipped — scheduler didn't run the spawned task");
}
