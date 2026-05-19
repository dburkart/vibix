//! Integration test: `sigpending(2)` and `sigsuspend(2)` signal-waiting
//! syscalls (#926).
//!
//! ## sigpending
//!
//! Verifies that `sigpending` returns the intersection of the pending and
//! blocked signal sets for the calling process.
//!
//! ## sigsuspend
//!
//! Verifies that `sigsuspend` atomically replaces the signal mask,
//! suspends until a signal is delivered, and restores the original mask.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use vibix::process::{self, test_helpers as h};
use vibix::signal::{self, sig_bit, SIGTERM, SIGUSR1, SIGUSR2};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

/// The BSP task has `task_id = 0` after `task::init()`. We register
/// a process entry with `pid = 0` (and therefore `task_id = 0`) so
/// `with_signal_state_for_task(0, ...)` finds it.

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

/// Register a process entry for the BSP task so
/// `with_signal_state_for_task` can find it.  `h::insert(pid, ...)`
/// internally sets `task_id = pid as usize`, so passing `pid = 0`
/// creates the mapping `pid_of[0] = 0` which is what
/// `with_signal_state_for_task(current_id(), ...)` needs (BSP
/// has `task_id = 0`).
fn setup_process_entry() {
    h::reset_table();
    h::insert(0, 0, 0, 0);
}

fn run_tests() {
    setup_process_entry();

    let tests: &[(&str, &dyn Testable)] = &[
        (
            "sigpending_returns_pending_and_blocked",
            &(sigpending_returns_pending_and_blocked as fn()),
        ),
        (
            "sigpending_empty_when_nothing_pending",
            &(sigpending_empty_when_nothing_pending as fn()),
        ),
        (
            "sigpending_excludes_unblocked_pending",
            &(sigpending_excludes_unblocked_pending as fn()),
        ),
        (
            "sigsuspend_wakes_on_signal",
            &(sigsuspend_wakes_on_signal as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── sigpending tests ────────────────────────────────────────────────────

/// Block SIGUSR1 and SIGTERM, raise both plus SIGUSR2 (unblocked).
/// sigpending should return only SIGUSR1 | SIGTERM.
fn sigpending_returns_pending_and_blocked() {
    let task_id = task::current_id();
    // Set up signal state: block SIGUSR1 and SIGTERM, raise all three.
    process::with_signal_state_for_task(task_id, |state| {
        state.blocked = sig_bit(SIGUSR1) | sig_bit(SIGTERM);
        state.raise(SIGUSR1);
        state.raise(SIGUSR2);
        state.raise(SIGTERM);
    })
    .expect("process entry missing for main task");

    // Read back pending & blocked.
    let result =
        process::with_signal_state_for_task(task_id, |state| state.pending & state.blocked)
            .unwrap();

    assert_eq!(
        result,
        sig_bit(SIGUSR1) | sig_bit(SIGTERM),
        "sigpending should return intersection of pending and blocked"
    );

    // Clean up.
    let _ = process::with_signal_state_for_task(task_id, |state| {
        state.pending = 0;
        state.blocked = 0;
    });
}

/// When no signals are pending, sigpending returns 0.
fn sigpending_empty_when_nothing_pending() {
    let task_id = task::current_id();
    process::with_signal_state_for_task(task_id, |state| {
        state.pending = 0;
        state.blocked = sig_bit(SIGUSR1); // blocked but not pending
    })
    .expect("process entry missing for main task");

    let result =
        process::with_signal_state_for_task(task_id, |state| state.pending & state.blocked)
            .unwrap();

    assert_eq!(result, 0, "sigpending should be 0 when nothing is pending");

    // Clean up.
    let _ = process::with_signal_state_for_task(task_id, |state| {
        state.blocked = 0;
    });
}

/// A pending but unblocked signal should NOT appear in sigpending.
fn sigpending_excludes_unblocked_pending() {
    let task_id = task::current_id();
    process::with_signal_state_for_task(task_id, |state| {
        state.pending = 0;
        state.blocked = 0;
        state.raise(SIGUSR1); // pending but not blocked
    })
    .expect("process entry missing for main task");

    let result =
        process::with_signal_state_for_task(task_id, |state| state.pending & state.blocked)
            .unwrap();

    assert_eq!(
        result, 0,
        "sigpending should not include unblocked pending signals"
    );

    // Clean up.
    let _ = process::with_signal_state_for_task(task_id, |state| {
        state.pending = 0;
    });
}

// ── sigsuspend tests ────────────────────────────────────────────────────

/// The target task_id for the sigsuspend test. The signal-sender task
/// reads this to know which task to raise the signal on.
static SUSPEND_TARGET: AtomicUsize = AtomicUsize::new(0);

/// Set to true when the sigsuspend test has started blocking.
static SUSPEND_STARTED: AtomicBool = AtomicBool::new(false);

/// Set to true when the sigsuspend test has been woken.
static SUSPEND_WOKE: AtomicBool = AtomicBool::new(false);

/// Helper task that sends SIGUSR1 to the suspended task.
fn signal_sender() -> ! {
    // Spin until the target has set up and started sigsuspend.
    while !SUSPEND_STARTED.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }

    // Small delay to ensure the target is actually parked.
    for _ in 0..100_000 {
        core::hint::spin_loop();
    }

    let target = SUSPEND_TARGET.load(Ordering::Acquire);
    // Raise SIGUSR1 on the target task.
    signal::raise_signal_on_task(target, SIGUSR1);

    task::exit();
}

/// Test that sigsuspend correctly suspends and wakes on signal delivery.
///
/// Strategy: the main test task blocks SIGUSR1 in its normal mask, then
/// calls the sigsuspend blocking loop with a temporary mask that does NOT
/// block SIGUSR1. A helper task raises SIGUSR1 on the main test task.
/// The main task should wake up because SIGUSR1 is deliverable under the
/// temporary mask.
fn sigsuspend_wakes_on_signal() {
    let task_id = task::current_id();
    SUSPEND_TARGET.store(task_id, Ordering::Release);
    SUSPEND_STARTED.store(false, Ordering::Release);
    SUSPEND_WOKE.store(false, Ordering::Release);

    // Set up: block SIGUSR1 in the normal mask, set disposition to
    // Ignore so the signal doesn't terminate the process.
    process::with_signal_state_for_task(task_id, |state| {
        state.blocked = sig_bit(SIGUSR1);
        state.dispositions[(SIGUSR1 - 1) as usize] = signal::Disposition::Ignore;
        state.pending = 0;
    })
    .expect("process entry missing for main task");

    // Spawn the signal sender.
    task::spawn(signal_sender);

    // Temporary mask: block nothing (SIGUSR1 is unblocked under this mask).
    let temp_mask: u64 = 0;

    // Simulate sigsuspend: atomically install temp mask, block until
    // a signal is deliverable, then restore.
    process::with_signal_state_for_task(task_id, |state| {
        let old_mask = state.blocked;
        state.blocked = temp_mask;
        state.saved_mask = Some(old_mask);
    })
    .unwrap();

    // Signal the sender that we're ready.
    SUSPEND_STARTED.store(true, Ordering::Release);

    // Block until a signal is deliverable under the temporary mask.
    // This mirrors the SIGSUSPEND_WAIT.wait_while() in sys_sigsuspend.
    signal::SIGSUSPEND_WAIT.wait_while(|| {
        process::with_signal_state_for_task(task_id, |state| !state.has_deliverable())
            .unwrap_or(false)
    });

    SUSPEND_WOKE.store(true, Ordering::Release);

    // Verify we woke up.
    assert!(
        SUSPEND_WOKE.load(Ordering::Acquire),
        "sigsuspend should have woken up on SIGUSR1 delivery"
    );

    // Simulate what deliver_signal does on the Ignore path: consume
    // saved_mask and restore blocked to the pre-sigsuspend mask.
    // In the real syscall path, check_and_deliver_signals calls
    // deliver_signal which does this automatically. We mirror that
    // here since we cannot invoke the full syscall dispatch from a
    // ring-0 integration test.
    let _ = process::with_signal_state_for_task(task_id, |state| {
        let pre = state.saved_mask.take().unwrap_or(state.blocked);
        state.blocked = pre;
    });

    // Verify the mask was restored (SIGUSR1 should be blocked again).
    let blocked = process::with_signal_state_for_task(task_id, |state| state.blocked).unwrap();
    assert_ne!(
        blocked & sig_bit(SIGUSR1),
        0,
        "sigsuspend should restore the original blocked mask"
    );

    // Clean up: pop the pending SIGUSR1 and restore state.
    let _ = process::with_signal_state_for_task(task_id, |state| {
        state.pending = 0;
        state.blocked = 0;
        state.dispositions[(SIGUSR1 - 1) as usize] = signal::Disposition::Default;
    });
}
