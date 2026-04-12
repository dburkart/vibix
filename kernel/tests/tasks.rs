//! Integration test: kernel tasks actually interleave under
//! preemption, and a spawned task can flip a flag the driver polls.
//!
//! Post-#92 there's no cooperative yield — this test relies entirely
//! on the PIT preempt tick to rotate tasks. It's distinct from
//! `preempt.rs` (which exercises the never-yielding tight-loop case)
//! in that these workers block cleanly on `hlt` and `spin_loop`, the
//! same way real kernel tasks are expected to idle.

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
    // Enable preemption: without IF=1 the PIT won't fire and the
    // workers will never get the CPU back from the driver.
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
/// Enough `pause` iterations per round that each worker spans several
/// preempt ticks rather than collapsing into a single 10 ms slice.
/// ~100k `pause` instructions ≈ a millisecond of real work, so ROUNDS
/// rounds of it comfortably crosses the 10 ms boundary and forces
/// rotation.
const INNER_SPINS: usize = 100_000;

// Worker tasks that count up while doing enough busy work to span
// multiple preempt slices, then park on `hlt`. No explicit yield —
// preemption alone is what rotates them.
fn task_a() -> ! {
    for _ in 0..ROUNDS {
        A.fetch_add(1, Ordering::SeqCst);
        for _ in 0..INNER_SPINS {
            core::hint::spin_loop();
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn task_b() -> ! {
    for _ in 0..ROUNDS {
        B.fetch_add(1, Ordering::SeqCst);
        for _ in 0..INNER_SPINS {
            core::hint::spin_loop();
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn two_tasks_interleave() {
    A.store(0, Ordering::SeqCst);
    B.store(0, Ordering::SeqCst);

    task::spawn(task_a);
    task::spawn(task_b);

    // Park the driver on `hlt` until both counters are full or the
    // deadline passes. `hlt` wakes on the next PIT tick (~10 ms), so
    // this is a 100 Hz sampling loop. `saw_overlap` turns the weak
    // "both eventually finish" check into a real proof of preemptive
    // interleaving — if the scheduler ran them sequentially (A to
    // completion, then B), we'd never observe a moment where both
    // are partially done.
    let deadline_iters = 2_000;
    let mut saw_overlap = false;
    for _ in 0..deadline_iters {
        let a = A.load(Ordering::SeqCst);
        let b = B.load(Ordering::SeqCst);
        if a > 0 && b > 0 && a < ROUNDS && b < ROUNDS {
            saw_overlap = true;
        }
        if a == ROUNDS && b == ROUNDS {
            break;
        }
        x86_64::instructions::hlt();
    }

    let a = A.load(Ordering::SeqCst);
    let b = B.load(Ordering::SeqCst);
    assert_eq!(a, ROUNDS, "task_a didn't run to completion (a={a})");
    assert_eq!(b, ROUNDS, "task_b didn't run to completion (b={b})");
    assert!(
        saw_overlap,
        "workers never overlapped — preemption didn't rotate them"
    );
}

static FLAG: AtomicBool = AtomicBool::new(false);

fn flag_setter() -> ! {
    FLAG.store(true, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn spawn_then_join_via_flag() {
    FLAG.store(false, Ordering::SeqCst);
    task::spawn(flag_setter);

    // Poll + hlt until the flag flips. Bounded so a scheduler
    // regression fails the test in ~1 s of wall time instead of
    // hanging CI.
    for _ in 0..1_000 {
        if FLAG.load(Ordering::SeqCst) {
            return;
        }
        x86_64::instructions::hlt();
    }
    panic!("flag never flipped — scheduler didn't run the spawned task");
}
