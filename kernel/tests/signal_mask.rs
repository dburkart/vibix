//! Integration test: signal mask (`sigprocmask`) — blocking, pending,
//! unblocking, and priority-ordered drain.
//!
//! Exercises:
//!   - `update_mask` with `SIG_BLOCK`, `SIG_UNBLOCK`, `SIG_SETMASK`.
//!   - Pending signals are deferred while blocked.
//!   - Unblocking drains the pending queue in ascending signal order.
//!   - SIGKILL and SIGSTOP cannot be blocked regardless of the mask.
//!   - Multiple mask operations compose correctly.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::{
    sig_bit, SignalState, SIGINT, SIGKILL, SIGSTOP, SIGTERM, SIGUSR1, SIGUSR2, SIG_BLOCK,
    SIG_SETMASK, SIG_UNBLOCK,
};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("signal_mask: init ok");
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("block_defers_delivery", &(block_defers_delivery as fn())),
        (
            "unblock_drains_in_priority_order",
            &(unblock_drains_in_priority_order as fn()),
        ),
        (
            "sigkill_bypasses_block_mask",
            &(sigkill_bypasses_block_mask as fn()),
        ),
        (
            "sigstop_bypasses_block_mask",
            &(sigstop_bypasses_block_mask as fn()),
        ),
        (
            "setmask_replaces_blocked_set",
            &(setmask_replaces_blocked_set as fn()),
        ),
        (
            "block_accumulates_signals",
            &(block_accumulates_signals as fn()),
        ),
        (
            "unblock_partial_leaves_others",
            &(unblock_partial_leaves_others as fn()),
        ),
        (
            "update_mask_returns_old_mask",
            &(update_mask_returns_old_mask as fn()),
        ),
        (
            "sigkill_sigstop_stripped_from_mask",
            &(sigkill_sigstop_stripped_from_mask as fn()),
        ),
        (
            "blocked_signals_queue_and_drain_on_unblock",
            &(blocked_signals_queue_and_drain_on_unblock as fn()),
        ),
        (
            "invalid_how_leaves_mask_unchanged",
            &(invalid_how_leaves_mask_unchanged as fn()),
        ),
        ("mask_via_process_entry", &(mask_via_process_entry as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Blocking a signal prevents pop_next_pending from returning it.
fn block_defers_delivery() {
    let mut s = SignalState::new();
    s.raise(SIGUSR1);
    s.blocked = sig_bit(SIGUSR1);
    assert_eq!(
        s.pop_next_pending(),
        None,
        "blocked signal should not be delivered"
    );
    // Signal is still pending.
    assert_ne!(
        s.pending & sig_bit(SIGUSR1),
        0,
        "signal should remain pending while blocked"
    );
}

/// After unblocking, previously blocked signals drain in ascending order.
fn unblock_drains_in_priority_order() {
    let mut s = SignalState::new();
    // Block everything except SIGKILL/SIGSTOP.
    s.blocked = !0u64 & !(sig_bit(SIGKILL) | sig_bit(SIGSTOP));

    // Raise several signals while blocked (in descending order to verify sorting).
    s.raise(SIGTERM); // 15
    s.raise(SIGUSR2); // 12
    s.raise(SIGUSR1); // 10
    s.raise(SIGINT); // 2

    // All should be blocked.
    assert_eq!(s.pop_next_pending(), None);

    // Unblock all.
    s.blocked = 0;

    // Should drain in ascending signal order: 2, 10, 12, 15.
    assert_eq!(s.pop_next_pending(), Some(SIGINT));
    assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
    assert_eq!(s.pop_next_pending(), Some(SIGUSR2));
    assert_eq!(s.pop_next_pending(), Some(SIGTERM));
    assert_eq!(s.pop_next_pending(), None);
}

/// SIGKILL bypasses the blocked mask and is always deliverable.
fn sigkill_bypasses_block_mask() {
    let mut s = SignalState::new();
    s.blocked = !0u64; // Block everything.
    s.raise(SIGKILL);
    assert_eq!(
        s.pop_next_pending(),
        Some(SIGKILL),
        "SIGKILL must bypass the blocked mask"
    );
}

/// SIGSTOP bypasses the blocked mask and is always deliverable.
fn sigstop_bypasses_block_mask() {
    let mut s = SignalState::new();
    s.blocked = !0u64; // Block everything.
    s.raise(SIGSTOP);
    assert_eq!(
        s.pop_next_pending(),
        Some(SIGSTOP),
        "SIGSTOP must bypass the blocked mask"
    );
}

/// SIG_SETMASK replaces the entire blocked set.
fn setmask_replaces_blocked_set() {
    let mut s = SignalState::new();
    s.update_mask(SIG_BLOCK, sig_bit(SIGUSR1) | sig_bit(SIGUSR2));
    assert_eq!(s.blocked, sig_bit(SIGUSR1) | sig_bit(SIGUSR2));

    s.update_mask(SIG_SETMASK, sig_bit(SIGINT));
    assert_eq!(s.blocked, sig_bit(SIGINT));
}

/// SIG_BLOCK accumulates — previously blocked signals remain blocked.
fn block_accumulates_signals() {
    let mut s = SignalState::new();
    s.update_mask(SIG_BLOCK, sig_bit(SIGUSR1));
    s.update_mask(SIG_BLOCK, sig_bit(SIGUSR2));
    assert_ne!(
        s.blocked & sig_bit(SIGUSR1),
        0,
        "SIGUSR1 should still be blocked"
    );
    assert_ne!(
        s.blocked & sig_bit(SIGUSR2),
        0,
        "SIGUSR2 should still be blocked"
    );
}

/// SIG_UNBLOCK removes only the specified signals; others stay blocked.
fn unblock_partial_leaves_others() {
    let mut s = SignalState::new();
    s.update_mask(
        SIG_BLOCK,
        sig_bit(SIGUSR1) | sig_bit(SIGUSR2) | sig_bit(SIGINT),
    );
    s.update_mask(SIG_UNBLOCK, sig_bit(SIGUSR1));
    assert_eq!(
        s.blocked & sig_bit(SIGUSR1),
        0,
        "SIGUSR1 should be unblocked"
    );
    assert_ne!(
        s.blocked & sig_bit(SIGUSR2),
        0,
        "SIGUSR2 should remain blocked"
    );
    assert_ne!(
        s.blocked & sig_bit(SIGINT),
        0,
        "SIGINT should remain blocked"
    );
}

/// update_mask returns the old mask value before the update.
fn update_mask_returns_old_mask() {
    let mut s = SignalState::new();
    s.blocked = sig_bit(SIGUSR1);
    let old = s.update_mask(SIG_SETMASK, sig_bit(SIGUSR2));
    assert_eq!(old, sig_bit(SIGUSR1), "should return old mask");
    assert_eq!(s.blocked, sig_bit(SIGUSR2), "should have new mask");
}

/// SIGKILL and SIGSTOP bits are always stripped from the blocked mask,
/// even if the caller tries to set them.
fn sigkill_sigstop_stripped_from_mask() {
    let mut s = SignalState::new();
    s.update_mask(SIG_SETMASK, !0u64);
    assert_eq!(
        s.blocked & sig_bit(SIGKILL),
        0,
        "SIGKILL must not appear in blocked mask"
    );
    assert_eq!(
        s.blocked & sig_bit(SIGSTOP),
        0,
        "SIGSTOP must not appear in blocked mask"
    );
}

/// Full round-trip: block signals, raise while blocked, verify they queue,
/// unblock, verify they drain in ascending order.
fn blocked_signals_queue_and_drain_on_unblock() {
    let mut s = SignalState::new();

    // Block SIGUSR1 and SIGTERM.
    s.update_mask(SIG_BLOCK, sig_bit(SIGUSR1) | sig_bit(SIGTERM));

    // Raise both while blocked.
    s.raise(SIGTERM); // 15
    s.raise(SIGUSR1); // 10

    // Verify they are pending but not deliverable.
    assert_ne!(s.pending & sig_bit(SIGUSR1), 0);
    assert_ne!(s.pending & sig_bit(SIGTERM), 0);
    assert_eq!(s.pop_next_pending(), None);

    // Unblock SIGUSR1 only — it should become deliverable, SIGTERM should not.
    s.update_mask(SIG_UNBLOCK, sig_bit(SIGUSR1));
    assert_eq!(s.pop_next_pending(), Some(SIGUSR1));
    assert_eq!(s.pop_next_pending(), None); // SIGTERM still blocked.

    // Unblock SIGTERM — now it should drain.
    s.update_mask(SIG_UNBLOCK, sig_bit(SIGTERM));
    assert_eq!(s.pop_next_pending(), Some(SIGTERM));
    assert_eq!(s.pop_next_pending(), None);
}

/// An invalid `how` value leaves the mask unchanged.
fn invalid_how_leaves_mask_unchanged() {
    let mut s = SignalState::new();
    s.blocked = sig_bit(SIGUSR1);
    let old = s.update_mask(999, sig_bit(SIGTERM));
    assert_eq!(old, sig_bit(SIGUSR1));
    assert_eq!(
        s.blocked,
        sig_bit(SIGUSR1),
        "invalid how should leave mask unchanged"
    );
}

/// Blocking and unblocking via process-table entry round-trips correctly.
fn mask_via_process_entry() {
    h::reset_table();
    h::insert(200, 0, 200, 200);

    // Block SIGUSR1 via process entry.
    process::with_signal_state_for_task(200, |s| {
        s.update_mask(SIG_BLOCK, sig_bit(SIGUSR1));
    });

    // Raise SIGUSR1.
    process::with_signal_state_for_task(200, |s| {
        s.raise(SIGUSR1);
    });

    // Should not be deliverable.
    let popped = process::with_signal_state_for_task(200, |s| s.pop_next_pending()).flatten();
    assert_eq!(
        popped, None,
        "SIGUSR1 blocked via process entry should not pop"
    );

    // Unblock.
    process::with_signal_state_for_task(200, |s| {
        s.update_mask(SIG_UNBLOCK, sig_bit(SIGUSR1));
    });

    // Now it should pop.
    let popped = process::with_signal_state_for_task(200, |s| s.pop_next_pending()).flatten();
    assert_eq!(popped, Some(SIGUSR1));

    h::reset_table();
}
