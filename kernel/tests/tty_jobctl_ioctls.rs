//! Integration test: controlling-terminal job-control ioctls (#432).
//!
//! Exercises `tty::tiocsctty_for` / `tiocspgrp_for` / `tiocgpgrp_for` /
//! `tiocgsid_for` / `tiocnotty_for` / `acquire_ctty_on_open` against the
//! process-table test helpers. End-to-end ring-3 ioctl dispatch is
//! covered once userspace has `tcsetpgrp` helpers.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::tty::{
    acquire_ctty_on_open, tiocgpgrp_for, tiocgsid_for, tiocnotty_for, tiocsctty_for, tiocspgrp_for,
    Tty,
};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("tty_jobctl_ioctls: init ok");
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
            "tiocsctty_requires_session_leader",
            &(tiocsctty_requires_session_leader as fn()),
        ),
        (
            "tiocsctty_leader_attaches_and_sets_pgrp",
            &(tiocsctty_leader_attaches_and_sets_pgrp as fn()),
        ),
        (
            "tiocsctty_without_force_fails_when_tty_has_other_session",
            &(tiocsctty_without_force_fails_when_tty_has_other_session as fn()),
        ),
        (
            "tiocsctty_force_without_root_fails",
            &(tiocsctty_force_without_root_fails as fn()),
        ),
        (
            "tiocsctty_force_with_root_steals_and_clears_old_session",
            &(tiocsctty_force_with_root_steals_and_clears_old_session as fn()),
        ),
        (
            "tiocsctty_idempotent_within_same_session",
            &(tiocsctty_idempotent_within_same_session as fn()),
        ),
        (
            "tiocsctty_rejects_when_leader_already_owns_other_tty",
            &(tiocsctty_rejects_when_leader_already_owns_other_tty as fn()),
        ),
        (
            "tiocspgrp_rejects_cross_session",
            &(tiocspgrp_rejects_cross_session as fn()),
        ),
        (
            "tiocspgrp_rejects_unknown_pgid",
            &(tiocspgrp_rejects_unknown_pgid as fn()),
        ),
        (
            "tiocspgrp_updates_pgrp_and_snapshot",
            &(tiocspgrp_updates_pgrp_and_snapshot as fn()),
        ),
        (
            "tiocspgrp_returns_enotty_when_no_session_attached",
            &(tiocspgrp_returns_enotty_when_no_session_attached as fn()),
        ),
        (
            "tiocgpgrp_and_tiocgsid_return_enotty_without_attachment",
            &(tiocgpgrp_and_tiocgsid_return_enotty_without_attachment as fn()),
        ),
        (
            "tiocgpgrp_and_tiocgsid_return_ids_after_attach",
            &(tiocgpgrp_and_tiocgsid_return_ids_after_attach as fn()),
        ),
        (
            "tiocnotty_nonleader_detaches_only_caller",
            &(tiocnotty_nonleader_detaches_only_caller as fn()),
        ),
        (
            "tiocnotty_leader_clears_session_members",
            &(tiocnotty_leader_clears_session_members as fn()),
        ),
        (
            "tiocnotty_returns_enotty_without_ctty",
            &(tiocnotty_returns_enotty_without_ctty as fn()),
        ),
        (
            "acquire_ctty_on_open_succeeds_for_leader_with_none",
            &(acquire_ctty_on_open_succeeds_for_leader_with_none as fn()),
        ),
        (
            "acquire_ctty_on_open_noop_for_nonleader",
            &(acquire_ctty_on_open_noop_for_nonleader as fn()),
        ),
        (
            "acquire_ctty_on_open_noop_when_leader_already_has_ctty",
            &(acquire_ctty_on_open_noop_when_leader_already_has_ctty as fn()),
        ),
        (
            "acquire_ctty_on_open_noop_when_tty_already_attached",
            &(acquire_ctty_on_open_noop_when_tty_already_attached as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn fresh_tty() -> Arc<Tty> {
    Arc::new(Tty::new())
}

fn tiocsctty_requires_session_leader() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(10, &tty, false, false), h::EPERM_I64);
}

fn tiocsctty_leader_attaches_and_sets_pgrp() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
    let ctrl = tty.ctrl.lock();
    assert_eq!(ctrl.session, Some(7));
    assert_eq!(ctrl.pgrp, Some(7));
    assert_eq!(ctrl.pgrp_snapshot.load(), 7);
}

fn tiocsctty_without_force_fails_when_tty_has_other_session() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
    h::insert(9, 0, 9, 9);
    assert_eq!(tiocsctty_for(9, &tty, false, false), h::EPERM_I64);
}

fn tiocsctty_force_without_root_fails() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
    h::insert(9, 0, 9, 9);
    assert_eq!(tiocsctty_for(9, &tty, true, false), h::EPERM_I64);
}

fn tiocsctty_force_with_root_steals_and_clears_old_session() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    h::insert(8, 7, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
    h::patch(8, |e| e.controlling_tty = Some(Arc::clone(&tty)));
    h::insert(9, 0, 9, 9);
    assert_eq!(tiocsctty_for(9, &tty, true, true), 0);
    assert!(process::ctty_of(7).is_none());
    assert!(process::ctty_of(8).is_none());
    assert!(process::ctty_of(9).is_some());
    let ctrl = tty.ctrl.lock();
    assert_eq!(ctrl.session, Some(9));
    assert_eq!(ctrl.pgrp, Some(9));
}

fn tiocsctty_idempotent_within_same_session() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
    assert_eq!(tiocsctty_for(7, &tty, false, false), 0);
}

fn tiocsctty_rejects_when_leader_already_owns_other_tty() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty_a = fresh_tty();
    let tty_b = fresh_tty();
    assert_eq!(tiocsctty_for(7, &tty_a, false, false), 0);
    // Attempting to switch to a different tty must fail, leaving tty_a untouched.
    assert_eq!(tiocsctty_for(7, &tty_b, false, false), h::EPERM_I64);
    assert_eq!(tiocsctty_for(7, &tty_b, true, true), h::EPERM_I64);
    assert!(tty_b.ctrl.lock().session.is_none());
    let ctrl_a = tty_a.ctrl.lock();
    assert_eq!(ctrl_a.session, Some(7));
    assert_eq!(ctrl_a.pgrp, Some(7));
}

fn tiocspgrp_rejects_cross_session() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    h::insert(20, 0, 20, 20);
    assert_eq!(tiocspgrp_for(20, &tty, 20), h::EPERM_I64);
}

fn tiocspgrp_rejects_unknown_pgid() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    assert_eq!(tiocspgrp_for(7, &tty, 999), h::EPERM_I64);
}

fn tiocspgrp_updates_pgrp_and_snapshot() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    h::insert(8, 7, 7, 8);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    assert_eq!(tiocspgrp_for(7, &tty, 8), 0);
    let ctrl = tty.ctrl.lock();
    assert_eq!(ctrl.pgrp, Some(8));
    assert_eq!(ctrl.pgrp_snapshot.load(), 8);
}

fn tiocspgrp_returns_enotty_when_no_session_attached() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert_eq!(tiocspgrp_for(7, &tty, 7), h::ENOTTY_I64);
}

fn tiocgpgrp_and_tiocgsid_return_enotty_without_attachment() {
    let tty = fresh_tty();
    assert_eq!(tiocgpgrp_for(&tty), h::ENOTTY_I64);
    assert_eq!(tiocgsid_for(&tty), h::ENOTTY_I64);
}

fn tiocgpgrp_and_tiocgsid_return_ids_after_attach() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    assert_eq!(tiocgpgrp_for(&tty), 7);
    assert_eq!(tiocgsid_for(&tty), 7);
}

fn tiocnotty_nonleader_detaches_only_caller() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    h::insert(8, 7, 7, 7);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    h::patch(8, |e| e.controlling_tty = Some(Arc::clone(&tty)));
    assert_eq!(tiocnotty_for(8), 0);
    assert!(process::ctty_of(8).is_none());
    assert!(process::ctty_of(7).is_some());
    assert_eq!(tty.ctrl.lock().session, Some(7));
}

fn tiocnotty_leader_clears_session_members() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    h::insert(8, 7, 7, 7);
    let tty = fresh_tty();
    tiocsctty_for(7, &tty, false, false);
    h::patch(8, |e| e.controlling_tty = Some(Arc::clone(&tty)));
    assert_eq!(tiocnotty_for(7), 0);
    assert!(process::ctty_of(7).is_none());
    assert!(process::ctty_of(8).is_none());
    let ctrl = tty.ctrl.lock();
    assert!(ctrl.session.is_none());
    assert!(ctrl.pgrp.is_none());
    assert_eq!(ctrl.pgrp_snapshot.load(), 0);
}

fn tiocnotty_returns_enotty_without_ctty() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    assert_eq!(tiocnotty_for(7), h::ENOTTY_I64);
}

fn acquire_ctty_on_open_succeeds_for_leader_with_none() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty = fresh_tty();
    assert!(acquire_ctty_on_open(7, &tty));
    assert!(process::ctty_of(7).is_some());
    assert_eq!(tty.ctrl.lock().session, Some(7));
}

fn acquire_ctty_on_open_noop_for_nonleader() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    let tty = fresh_tty();
    assert!(!acquire_ctty_on_open(10, &tty));
    assert!(tty.ctrl.lock().session.is_none());
}

fn acquire_ctty_on_open_noop_when_leader_already_has_ctty() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    let tty_a = fresh_tty();
    let tty_b = fresh_tty();
    assert!(acquire_ctty_on_open(7, &tty_a));
    assert!(!acquire_ctty_on_open(7, &tty_b));
    assert!(tty_b.ctrl.lock().session.is_none());
}

fn acquire_ctty_on_open_noop_when_tty_already_attached() {
    h::reset_table();
    h::insert(7, 0, 7, 7);
    h::insert(9, 0, 9, 9);
    let tty = fresh_tty();
    assert!(acquire_ctty_on_open(7, &tty));
    assert!(!acquire_ctty_on_open(9, &tty));
    assert_eq!(tty.ctrl.lock().session, Some(7));
}
