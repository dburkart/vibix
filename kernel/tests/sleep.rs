//! Integration test: `task::sleep_ms` parks the calling task and
//! resumes it after at least the requested interval has elapsed.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

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
    let tests: &[(&str, &dyn Testable)] = &[
        ("sleep_ms_parks_for_interval", &(sleep_ms_parks as fn())),
        (
            "sleep_ms_multiple_tasks_independent",
            &(sleep_ms_multiple as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- sleep_ms_parks_for_interval ------------------------------------

static SLEEP_START_MS: AtomicU64 = AtomicU64::new(0);
static SLEEP_ELAPSED_MS: AtomicU64 = AtomicU64::new(0);
static SLEEP_DONE: AtomicUsize = AtomicUsize::new(0);

const SLEEP_MS_TARGET: u64 = 50;

fn sleep_worker() -> ! {
    let start = time::uptime_ms();
    SLEEP_START_MS.store(start, Ordering::SeqCst);
    task::sleep_ms(SLEEP_MS_TARGET);
    let elapsed = time::uptime_ms().saturating_sub(start);
    SLEEP_ELAPSED_MS.store(elapsed, Ordering::SeqCst);
    SLEEP_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn sleep_ms_parks() {
    SLEEP_START_MS.store(0, Ordering::SeqCst);
    SLEEP_ELAPSED_MS.store(0, Ordering::SeqCst);
    SLEEP_DONE.store(0, Ordering::SeqCst);

    task::spawn(sleep_worker);

    // Driver waits on hlt. Deadline is generous (~2 s) — a miss means
    // the wakeup queue never drained or `block_current` wedged.
    for _ in 0..200 {
        if SLEEP_DONE.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        SLEEP_DONE.load(Ordering::SeqCst),
        1,
        "sleep_worker didn't resume — wakeup queue not drained?"
    );
    let elapsed = SLEEP_ELAPSED_MS.load(Ordering::SeqCst);
    assert!(
        elapsed >= SLEEP_MS_TARGET,
        "sleep_ms returned early: elapsed={elapsed}ms, target={SLEEP_MS_TARGET}ms"
    );
    // Upper bound is loose — ten ticks of slop covers scheduling jitter
    // on a busy QEMU host but still catches obvious runaways.
    assert!(
        elapsed < SLEEP_MS_TARGET + 500,
        "sleep_ms overshot by > 500ms: elapsed={elapsed}ms"
    );
}

// --- sleep_ms_multiple_tasks_independent ----------------------------
//
// Two tasks sleep for different durations concurrently. Both must
// wake, and the shorter-sleep task must finish first.

static MULTI_SHORT_DONE_AT: AtomicU64 = AtomicU64::new(0);
static MULTI_LONG_DONE_AT: AtomicU64 = AtomicU64::new(0);
static MULTI_DONE: AtomicUsize = AtomicUsize::new(0);

fn multi_short_worker() -> ! {
    task::sleep_ms(30);
    MULTI_SHORT_DONE_AT.store(time::uptime_ms(), Ordering::SeqCst);
    MULTI_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn multi_long_worker() -> ! {
    task::sleep_ms(80);
    MULTI_LONG_DONE_AT.store(time::uptime_ms(), Ordering::SeqCst);
    MULTI_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn sleep_ms_multiple() {
    MULTI_SHORT_DONE_AT.store(0, Ordering::SeqCst);
    MULTI_LONG_DONE_AT.store(0, Ordering::SeqCst);
    MULTI_DONE.store(0, Ordering::SeqCst);

    let start = time::uptime_ms();
    task::spawn(multi_short_worker);
    task::spawn(multi_long_worker);

    for _ in 0..200 {
        if MULTI_DONE.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        MULTI_DONE.load(Ordering::SeqCst),
        2,
        "not all sleep workers finished"
    );
    let short = MULTI_SHORT_DONE_AT.load(Ordering::SeqCst);
    let long = MULTI_LONG_DONE_AT.load(Ordering::SeqCst);
    assert!(
        short >= start + 30,
        "short sleeper woke too early: start={start} short_done_at={short}"
    );
    assert!(
        long >= start + 80,
        "long sleeper woke too early: start={start} long_done_at={long}"
    );
    assert!(
        short < long,
        "short sleep finished after long sleep: short={short} long={long}"
    );
}
