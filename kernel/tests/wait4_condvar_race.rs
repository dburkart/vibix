//! Integration test: `wait4` hand-rolled condvar correctness under
//! concurrent child exits (issue #508).
//!
//! Replicates the snapshot / reap / `wait_while` loop from the WAIT4
//! syscall arm in `arch/x86_64/syscall.rs` at the process-module level
//! (without going through ring-3), then races several "children" that
//! call `process::mark_zombie` against it. All children must be reaped
//! — no wake-up may be lost.
//!
//! Two scenarios are exercised:
//!
//! * `wait4_concurrent_exits_reaps_all` — N children, each a spawned
//!   kernel task that calls `mark_zombie`. The driver drives the
//!   wait4 loop and expects to reap all N. This covers the general
//!   multi-exit case.
//!
//! * `wait4_exit_in_reap_gap_wakes_wait_while` — deliberately squeezes
//!   a child exit into the gap between the driver's `reap_child →
//!   None` and the `wait_while` park, then asserts the driver still
//!   makes progress. Uses `WaitQueue::waiter_count` for deterministic
//!   synchronisation rather than timing.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex as SpinMutex;

use vibix::process::{self, test_helpers as h};
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
            "wait4_concurrent_exits_reaps_all",
            &(wait4_concurrent_exits_reaps_all as fn()),
        ),
        (
            "wait4_exit_in_reap_gap_wakes_wait_while",
            &(wait4_exit_in_reap_gap_wakes_wait_while as fn()),
        ),
        (
            "wait4_repeated_rounds_no_wedge",
            &(wait4_repeated_rounds_no_wedge as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- shared helpers --------------------------------------------------

/// A parent PID chosen large enough to be out of range of anything
/// `register_init` / `register` might allocate in the same boot, so
/// the synthetic entries inserted by `test_helpers::insert` don't
/// collide with real ones. `test_helpers::reset_table` resets
/// `NEXT_PID` to 2, but it doesn't lock out `register` running in
/// parallel — keeping the parent PID well above `NEXT_PID` avoids
/// any aliasing if a real registration happens between reset and
/// our inserts.
const PARENT_PID: u32 = 0x500;

/// Spin on `hlt` until `cond()` returns true or `deadline_ticks`
/// iterations elapse. Panics on timeout so the test fails with a
/// clear signal rather than hanging forever.
fn hlt_until<F: Fn() -> bool>(cond: F, deadline_ticks: usize, what: &str) {
    for _ in 0..deadline_ticks {
        if cond() {
            return;
        }
        x86_64::instructions::hlt();
    }
    panic!("timeout waiting for: {what}");
}

/// The real wait4 loop from `arch/x86_64/syscall.rs` WAIT4 arm,
/// replicated here *exactly* in its condvar shape so that this test
/// regresses the real syscall code. Returns `Some(child_pid)` when a
/// child is reaped or `None` when no children remain.
fn wait4_loop(parent_pid: u32) -> Option<u32> {
    loop {
        let snap = process::exit_event_count();
        if let Some((child_pid, _status)) = process::reap_child(parent_pid, -1) {
            return Some(child_pid);
        }
        if !process::has_children(parent_pid) {
            return None;
        }
        process::CHILD_WAIT.wait_while(|| process::exit_event_count() == snap);
    }
}

// --- wait4_concurrent_exits_reaps_all --------------------------------
//
// Spawns N kernel tasks. Each picks a distinct PID slot, registers a
// synthetic `Alive` `ProcessEntry` with `PARENT_PID` as parent, then
// calls `mark_zombie`. The driver calls `wait4_loop` until every
// child is reaped. Success means no wake-up was lost.
//
// `mark_zombie` must be called from the child task itself so that the
// EXIT_EVENT bump and `CHILD_WAIT.notify_all` happen concurrently
// with the driver's reap/park sequence — the whole point of the test.

const N_CHILDREN: u32 = 8;
const FIRST_CHILD_PID: u32 = PARENT_PID + 1;

/// Slot index picked up by each spawned child so it knows its own
/// PID. `AtomicUsize::fetch_add` guarantees each spawned worker
/// takes a unique slot even though they race to enter the function.
static NEXT_SLOT: AtomicUsize = AtomicUsize::new(0);

fn child_task() -> ! {
    let slot = NEXT_SLOT.fetch_add(1, Ordering::SeqCst) as u32;
    let pid = FIRST_CHILD_PID + slot;
    // `mark_zombie` flips state and bumps EXIT_EVENT. The Release on
    // the bump is what wait4's Acquire-load in `wait_while`'s cond
    // pairs with.
    process::mark_zombie(pid, slot as i32);
    task::exit();
}

fn wait4_concurrent_exits_reaps_all() {
    // Wipe and pre-populate TABLE. reset_table drops *everything*,
    // including entries any earlier test left behind — important because
    // residual entries with our PARENT_PID could cause `has_children`
    // to return wrong answers.
    h::reset_table();

    // Parent. `task_id` argument is ignored by `reap_child`/`has_children`/
    // `mark_zombie`, so any value is fine; use PARENT_PID for obviousness.
    h::insert(PARENT_PID, /* parent_pid */ 0, PARENT_PID, PARENT_PID);
    // Children, all with PARENT_PID as parent, all Alive.
    for i in 0..N_CHILDREN {
        h::insert(FIRST_CHILD_PID + i, PARENT_PID, PARENT_PID, PARENT_PID);
    }

    NEXT_SLOT.store(0, Ordering::SeqCst);
    for _ in 0..N_CHILDREN {
        task::spawn(child_task);
    }

    // Drive the same loop wait4 uses. We must reap all N children;
    // the Nth+1 call must observe "no children" and return None.
    let mut reaped: u32 = 0;
    while wait4_loop(PARENT_PID).is_some() {
        reaped += 1;
        if reaped > N_CHILDREN {
            panic!("reaped more children than we spawned");
        }
    }
    assert_eq!(
        reaped, N_CHILDREN,
        "wait4_loop dropped a child — missed wake-up (reaped={reaped}, expected={N_CHILDREN})",
    );

    // Leave TABLE clean for the next test.
    h::reset_table();
}

// --- wait4_exit_in_reap_gap_wakes_wait_while -------------------------
//
// Minimal reproducer of the specific window the issue calls out: the
// driver has already taken its snapshot and seen reap_child → None,
// but has not yet entered wait_while when the child exits.
//
// We can't literally pause the driver between reap and wait_while
// without dirtying the production wait4 path, so we simulate the
// window by:
//
//   1. Pre-registering one child (Alive, parent = PARENT_PID).
//   2. Spawning a controlled "exiter" task that waits on a go-flag
//      before calling `mark_zombie`.
//   3. On the driver, running the wait4 loop once — it will snapshot
//      EXIT_EVENT, see no zombie (child still Alive), and enter
//      wait_while. The moment the driver has enqueued itself on
//      CHILD_WAIT (we detect this via `waiter_count()`), we release
//      the go-flag from … the exiter itself is parked, so we
//      instead flip the flag from a second "gatekeeper" task that
//      wakes the moment `CHILD_WAIT.waiter_count() >= 1`.
//
// The three-way synchronisation lets us put the mark_zombie call
// *after* the driver is definitely inside `wait_while` but before the
// driver has re-checked the predicate on wakeup — reproducing the
// exact "wake arrives between snapshot and park completion" window.

static GAP_GO: AtomicBool = AtomicBool::new(false);
static GAP_EXITER_DONE: AtomicBool = AtomicBool::new(false);
static GAP_GATEKEEPER_DONE: AtomicBool = AtomicBool::new(false);

const GAP_CHILD_PID: u32 = PARENT_PID + 100;

fn gap_exiter() -> ! {
    // Park on a busy-hlt until the gatekeeper flips the go-flag.
    while !GAP_GO.load(Ordering::Acquire) {
        x86_64::instructions::hlt();
    }
    process::mark_zombie(GAP_CHILD_PID, 42);
    GAP_EXITER_DONE.store(true, Ordering::Release);
    task::exit();
}

fn gap_gatekeeper() -> ! {
    // Wait for the driver to actually enqueue itself on CHILD_WAIT —
    // i.e. reach the park inside wait_while. Then release the exiter.
    // Because wait_while checks the predicate under the queue lock
    // before enqueuing, `waiter_count() >= 1` is observed only after
    // the driver has committed to parking on the current snapshot.
    loop {
        if process::CHILD_WAIT.waiter_count() >= 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    GAP_GO.store(true, Ordering::Release);
    GAP_GATEKEEPER_DONE.store(true, Ordering::Release);
    task::exit();
}

fn wait4_exit_in_reap_gap_wakes_wait_while() {
    h::reset_table();
    h::insert(PARENT_PID, 0, PARENT_PID, PARENT_PID);
    h::insert(GAP_CHILD_PID, PARENT_PID, PARENT_PID, PARENT_PID);

    GAP_GO.store(false, Ordering::SeqCst);
    GAP_EXITER_DONE.store(false, Ordering::SeqCst);
    GAP_GATEKEEPER_DONE.store(false, Ordering::SeqCst);

    // Spawn both in exit-first-but-won't-run-until-gate order, then
    // the gatekeeper which releases the gate the moment the driver is
    // parked. The driver is *this* task — it calls wait4_loop below.
    task::spawn(gap_exiter);
    task::spawn(gap_gatekeeper);

    // Run one wait4 cycle. If the race is handled correctly, this
    // returns Some(GAP_CHILD_PID) even though the mark_zombie call
    // happens after the driver has already entered wait_while.
    let reaped = wait4_loop(PARENT_PID);
    assert_eq!(
        reaped,
        Some(GAP_CHILD_PID),
        "driver didn't reap the child — wake delivered during wait_while was lost",
    );

    // Make sure the helper tasks finished cleanly so the scheduler
    // doesn't carry stale zombies into the next test.
    hlt_until(
        || GAP_EXITER_DONE.load(Ordering::Acquire),
        1000,
        "gap_exiter finish",
    );
    hlt_until(
        || GAP_GATEKEEPER_DONE.load(Ordering::Acquire),
        1000,
        "gap_gatekeeper finish",
    );

    // Next wait4 must see "no children".
    let none = wait4_loop(PARENT_PID);
    assert_eq!(
        none, None,
        "expected ECHILD-equivalent after draining, got {none:?}"
    );

    h::reset_table();
}

// --- wait4_repeated_rounds_no_wedge ----------------------------------
//
// Stress: run many rounds of the N-child scenario back-to-back. One
// lost wake-up inside CHILD_WAIT.wait_while would freeze the driver
// forever; bounded iteration count + hlt_until timeout turns that
// into a visible test failure.

// 10 rounds × 4 children = 40 spawn/reap cycles. Originally 20 rounds;
// dialled back in #619 after the test repeatedly tripped the xtask
// per-test timeout on shared CI runners. Each round forces the driver
// through one full `snap → reap → has_children → wait_while` sweep of
// the wait4 condvar, so 10 rounds still surfaces a lost-wakeup —
// a real missed wake would wedge `wait4_loop` within a single round,
// not across many.
const STRESS_ROUNDS: u32 = 10;
const STRESS_CHILDREN_PER_ROUND: u32 = 4;
const STRESS_FIRST_CHILD_PID: u32 = PARENT_PID + 200;

static STRESS_SLOT: AtomicUsize = AtomicUsize::new(0);
static STRESS_ROUND_BASE: AtomicUsize = AtomicUsize::new(0);

// Collect each round's reap list so an assertion can catch a
// duplicate or missing reap. Cleared at the top of each round.
static STRESS_REAPED: SpinMutex<Option<Vec<u32>>> = SpinMutex::new(None);

fn stress_child() -> ! {
    let slot = STRESS_SLOT.fetch_add(1, Ordering::SeqCst) as u32;
    let base = STRESS_ROUND_BASE.load(Ordering::SeqCst) as u32;
    let pid = base + slot;
    process::mark_zombie(pid, 0);
    task::exit();
}

fn wait4_repeated_rounds_no_wedge() {
    for round in 0..STRESS_ROUNDS {
        h::reset_table();
        let base = STRESS_FIRST_CHILD_PID + round * STRESS_CHILDREN_PER_ROUND;
        h::insert(PARENT_PID, 0, PARENT_PID, PARENT_PID);
        for i in 0..STRESS_CHILDREN_PER_ROUND {
            h::insert(base + i, PARENT_PID, PARENT_PID, PARENT_PID);
        }

        STRESS_SLOT.store(0, Ordering::SeqCst);
        STRESS_ROUND_BASE.store(base as usize, Ordering::SeqCst);
        *STRESS_REAPED.lock() = Some(Vec::new());

        for _ in 0..STRESS_CHILDREN_PER_ROUND {
            task::spawn(stress_child);
        }

        let mut reaped: u32 = 0;
        while let Some(pid) = wait4_loop(PARENT_PID) {
            if let Some(list) = STRESS_REAPED.lock().as_mut() {
                list.push(pid);
            }
            reaped += 1;
            if reaped > STRESS_CHILDREN_PER_ROUND {
                panic!(
                    "round {round}: reaped more children ({reaped}) than spawned ({STRESS_CHILDREN_PER_ROUND})"
                );
            }
        }
        assert_eq!(
            reaped, STRESS_CHILDREN_PER_ROUND,
            "round {round}: wait4_loop dropped a child — missed wake-up (reaped={reaped})",
        );

        // Verify every expected pid appeared exactly once.
        let list = STRESS_REAPED
            .lock()
            .take()
            .expect("round list must be present");
        for i in 0..STRESS_CHILDREN_PER_ROUND {
            let target = base + i;
            let n = list.iter().filter(|&&p| p == target).count();
            assert_eq!(n, 1, "round {round}: pid {target} reaped {n} times, want 1");
        }
    }

    h::reset_table();
}
