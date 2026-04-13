//! Integration test: the scheduler honors task priorities.
//!
//! Test ordering matters — tasks in this kernel don't exit, so any
//! test that leaves a high-priority worker looping will starve tasks
//! at lower priority in later tests. The high-priority test runs last
//! for that reason, and the earlier tests exercise introspection and
//! metadata APIs rather than assuming a particular task gets CPU.

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
        (
            "nice_sets_visible_priority",
            &(nice_sets_visible_priority as fn()),
        ),
        (
            "set_affinity_round_trip",
            &(set_affinity_round_trip as fn()),
        ),
        (
            "set_priority_round_trip",
            &(set_priority_round_trip as fn()),
        ),
        (
            "high_priority_runs_before_low",
            &(high_priority_runs_before_low as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

static HI_FLAG: AtomicBool = AtomicBool::new(false);
static HI_HITS: AtomicUsize = AtomicUsize::new(0);
static LO_HITS: AtomicUsize = AtomicUsize::new(0);
static STOP_LO: AtomicBool = AtomicBool::new(false);

fn hi_worker() -> ! {
    HI_HITS.fetch_add(1, Ordering::SeqCst);
    HI_FLAG.store(true, Ordering::SeqCst);
    // Demote so the driver (priority 19) can resume and observe the
    // flag. Strict priority scheduling would otherwise starve it —
    // the one-shot body above already proved the scheduling property.
    task::set_priority(task::current_id(), 1);
    loop {
        x86_64::instructions::hlt();
    }
}

fn lo_spinner() -> ! {
    loop {
        LO_HITS.fetch_add(1, Ordering::SeqCst);
        if STOP_LO.load(Ordering::SeqCst) {
            break;
        }
        for _ in 0..10_000 {
            core::hint::spin_loop();
        }
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn high_priority_runs_before_low() {
    HI_FLAG.store(false, Ordering::SeqCst);
    HI_HITS.store(0, Ordering::SeqCst);
    LO_HITS.store(0, Ordering::SeqCst);
    STOP_LO.store(false, Ordering::SeqCst);

    // Spawn the low-priority spinner first so it's definitely queued
    // before the hot task. Without priorities, round-robin would let
    // the spinner keep hogging slices.
    task::spawn_with_priority(lo_spinner, task::DEFAULT_PRIORITY - 5);
    task::spawn_with_priority(hi_worker, task::DEFAULT_PRIORITY + 5);

    // The hi_worker is one tick away. Give it plenty of rope.
    for _ in 0..200 {
        if HI_FLAG.load(Ordering::SeqCst) {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert!(
        HI_FLAG.load(Ordering::SeqCst),
        "hi_worker never ran even though it outranked the spinner"
    );
    assert_eq!(
        HI_HITS.load(Ordering::SeqCst),
        1,
        "hi_worker's one-shot body ran the wrong number of times"
    );
    STOP_LO.store(true, Ordering::SeqCst);

    // Let the spinner wind down before the next test reuses statics.
    for _ in 0..50 {
        x86_64::instructions::hlt();
    }
}

fn idle_forever() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

fn nice_sets_visible_priority() {
    // With DEFAULT_PRIORITY=19, nice=10 maps to priority 9 and
    // nice=-5 maps to priority 24. The task list must reflect both
    // mappings. Doesn't depend on the spawned tasks running — a
    // lower-priority task would starve against the default-priority
    // driver and that's the point.
    task::spawn_with_nice(idle_forever, 10);
    task::spawn_with_nice(idle_forever, -5);

    let lo_prio = task::priority_from_nice(10);
    let hi_prio = task::priority_from_nice(-5);
    // Round-trip across the full legal nice range.
    for nice in task::NICE_MIN..=task::NICE_MAX {
        let p = task::priority_from_nice(nice);
        assert!(p <= task::MAX_PRIORITY);
        assert_eq!(task::nice_from_priority(p), nice);
    }
    // Edge cases: nice extremes must not saturate before mapping.
    assert_eq!(task::priority_from_nice(task::NICE_MIN), task::MAX_PRIORITY);
    assert_eq!(task::priority_from_nice(task::NICE_MAX), 0);

    let mut saw_low = false;
    let mut saw_high = false;
    task::for_each_task(|info| {
        assert!(info.priority <= task::MAX_PRIORITY);
        assert!(info.nice >= task::NICE_MIN && info.nice <= task::NICE_MAX);
        assert_eq!(task::nice_from_priority(info.priority), info.nice);
        if info.nice == 10 && info.priority == lo_prio {
            saw_low = true;
        }
        if info.nice == -5 && info.priority == hi_prio {
            saw_high = true;
        }
    });
    assert!(saw_low, "task list missing the nice=10 worker");
    assert!(saw_high, "task list missing the nice=-5 worker");

    // Demote every task we just spawned so the next test's driver
    // isn't starved. The kernel doesn't support task exit yet.
    demote_non_driver_tasks();
}

/// Drop every non-driver task's priority to 1 so the bootstrap task
/// (priority 20) gets CPU in the next test. Tasks in this test binary
/// spawn for their lifetime — there's no exit path — so we settle for
/// keeping them harmlessly below the driver instead.
fn demote_non_driver_tasks() {
    let driver_id = task::current_id();
    let mut ids = alloc::vec::Vec::new();
    task::for_each_task(|info| {
        if info.id != driver_id {
            ids.push(info.id);
        }
    });
    for id in ids {
        task::set_priority(id, 1);
    }
}

fn set_priority_round_trip() {
    // Spawn a task at nice=5 (priority 15), then promote via
    // set_priority and verify the introspection picks up the change.
    task::spawn_with_nice(idle_forever, 5);
    let mut target_id = 0usize;
    task::for_each_task(|info| {
        if info.nice == 5 && target_id == 0 {
            target_id = info.id;
        }
    });
    assert!(target_id != 0, "didn't find freshly-spawned nice=5 task");

    assert!(task::set_priority(target_id, 30));
    let mut new_prio = None;
    task::for_each_task(|info| {
        if info.id == target_id {
            new_prio = Some(info.priority);
        }
    });
    assert_eq!(new_prio, Some(30));

    assert!(!task::set_priority(usize::MAX, 10), "accepted unknown id");

    // adjust_nice on the target: priority 30 -> nice -11 (with
    // DEFAULT_PRIORITY=19). Bump by +3 → nice -8 → priority 27.
    let new_nice = task::adjust_nice(target_id, 3);
    assert_eq!(new_nice, Some(-8));
    let mut adjusted_prio = None;
    task::for_each_task(|info| {
        if info.id == target_id {
            adjusted_prio = Some(info.priority);
        }
    });
    assert_eq!(adjusted_prio, Some(27));

    demote_non_driver_tasks();
}

static AFF_RAN: AtomicBool = AtomicBool::new(false);
static AFF_ID: AtomicUsize = AtomicUsize::new(0);

fn aff_worker() -> ! {
    AFF_ID.store(task::current_id(), Ordering::SeqCst);
    AFF_RAN.store(true, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn set_affinity_round_trip() {
    AFF_RAN.store(false, Ordering::SeqCst);
    AFF_ID.store(0, Ordering::SeqCst);
    task::spawn(aff_worker);

    for _ in 0..500 {
        if AFF_RAN.load(Ordering::SeqCst) {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert!(AFF_RAN.load(Ordering::SeqCst), "aff_worker never ran");

    let id = AFF_ID.load(Ordering::SeqCst);
    assert!(id != 0);
    // Pin to CPU 0 only.
    assert!(
        task::set_affinity(id, 0b1),
        "set_affinity on live task failed"
    );
    // Zero mask is rejected (a task must be runnable somewhere).
    assert!(
        !task::set_affinity(id, 0),
        "set_affinity accepted zero mask"
    );
    // Unknown id is rejected.
    assert!(
        !task::set_affinity(usize::MAX, 0b1),
        "set_affinity accepted unknown id"
    );

    let mut saw_mask = None;
    task::for_each_task(|info| {
        if info.id == id {
            saw_mask = Some(info.affinity);
        }
    });
    assert_eq!(saw_mask, Some(0b1), "affinity mask didn't round-trip");

    demote_non_driver_tasks();
}
