//! Integration test: `task::exit()` removes the running task from the
//! scheduler and its stack pages, VMA-backed frames, and PML4 frame
//! are returned to the global allocator. Validated by running many
//! spawn→exit cycles in a single boot without exhausting free frames.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
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
    let tests: &[(&str, &dyn Testable)] = &[
        ("exit_removes_task", &(exit_removes_task as fn())),
        ("exit_loop_no_leak", &(exit_loop_no_leak as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static EXIT_REACHED: AtomicUsize = AtomicUsize::new(0);

fn exit_worker() -> ! {
    EXIT_REACHED.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn exit_removes_task() {
    // Baseline: only the bootstrap task is live.
    let mut baseline = 0usize;
    task::for_each_task(|_| baseline += 1);
    assert_eq!(baseline, 1, "unexpected tasks before spawn");

    EXIT_REACHED.store(0, Ordering::SeqCst);
    task::spawn(exit_worker);

    // Wait for the worker to run and then be reaped. One tick (10 ms)
    // is enough to reap; give it generous slack.
    for _ in 0..50 {
        if EXIT_REACHED.load(Ordering::SeqCst) == 1 {
            // Extra ticks so pending_exit drains through preempt_tick.
            for _ in 0..10 {
                x86_64::instructions::hlt();
            }
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        EXIT_REACHED.load(Ordering::SeqCst),
        1,
        "worker never reached exit()"
    );

    let mut after = 0usize;
    task::for_each_task(|_| after += 1);
    assert_eq!(
        after, baseline,
        "task count didn't return to baseline after exit (leak in scheduler)"
    );
}

fn exit_loop_no_leak() {
    // Spawn-and-exit many times. If the PML4 / stack frames were not
    // being returned to the global allocator, `new_task_pml4` or the
    // stack-page map calls would eventually fail — the kernel has a
    // small pool of usable frames and 64 unreaped PML4s + stacks would
    // comfortably exhaust it.
    //
    // The strong signal here is "kernel still boots tests through this
    // loop without panicking in the allocator path." A leak panics;
    // a clean reap survives.
    const ITERATIONS: usize = 64;

    for i in 0..ITERATIONS {
        EXIT_REACHED.store(0, Ordering::SeqCst);
        task::spawn(exit_worker);
        for _ in 0..50 {
            if EXIT_REACHED.load(Ordering::SeqCst) == 1 {
                for _ in 0..4 {
                    x86_64::instructions::hlt();
                }
                break;
            }
            x86_64::instructions::hlt();
        }
        assert_eq!(
            EXIT_REACHED.load(Ordering::SeqCst),
            1,
            "worker {i} didn't reach exit()"
        );
    }

    let mut live = 0usize;
    task::for_each_task(|_| live += 1);
    assert_eq!(live, 1, "tasks leaking across exit loop");
}
