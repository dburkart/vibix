//! Integration test: session / process-group PCB fields and the
//! `setsid` / `setpgid` / `getsid` / `getpgid` syscall helpers (#372).
//!
//! Drives `process::test_helpers` to set up synthetic `ProcessEntry`
//! rows and exercise the pure branches of `setsid_for` / `setpgid_for`.
//! End-to-end ring-3 syscall dispatch is covered by userspace work in
//! #376.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use vibix::process::{self, test_helpers as h};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("session_syscalls: init ok");
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
            "register_inherits_session_and_pgrp_from_parent",
            &(register_inherits_session_and_pgrp_from_parent as fn()),
        ),
        (
            "register_without_parent_opens_own_session",
            &(register_without_parent_opens_own_session as fn()),
        ),
        (
            "getsid_and_getpgid_lookup",
            &(getsid_and_getpgid_lookup as fn()),
        ),
        (
            "setsid_rejects_process_group_leader",
            &(setsid_rejects_process_group_leader as fn()),
        ),
        (
            "setsid_rejects_unknown_caller",
            &(setsid_rejects_unknown_caller as fn()),
        ),
        (
            "setsid_creates_new_session_and_clears_ctty",
            &(setsid_creates_new_session_and_clears_ctty as fn()),
        ),
        (
            "setpgid_rejects_cross_session_target",
            &(setpgid_rejects_cross_session_target as fn()),
        ),
        (
            "setpgid_rejects_non_child_target",
            &(setpgid_rejects_non_child_target as fn()),
        ),
        (
            "setpgid_rejects_session_leader_target",
            &(setpgid_rejects_session_leader_target as fn()),
        ),
        (
            "setpgid_moves_child_into_existing_pgrp",
            &(setpgid_moves_child_into_existing_pgrp as fn()),
        ),
        (
            "setpgid_creates_new_pgrp_when_pgid_equals_target",
            &(setpgid_creates_new_pgrp_when_pgid_equals_target as fn()),
        ),
        (
            "setpgid_rejects_nonexistent_pgid_in_session",
            &(setpgid_rejects_nonexistent_pgid_in_session as fn()),
        ),
        (
            "setpgid_pgid_zero_means_target",
            &(setpgid_pgid_zero_means_target as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn register_inherits_session_and_pgrp_from_parent() {
    h::reset_table();
    h::insert(100, 0, 42, 77);
    let child = process::register(200, 100);
    let (session, pgrp, has_tty) = h::snapshot(child).unwrap();
    assert_eq!(session, 42);
    assert_eq!(pgrp, 77);
    assert!(!has_tty);
}

fn register_without_parent_opens_own_session() {
    h::reset_table();
    let child = process::register(300, 999);
    let (session, pgrp, _) = h::snapshot(child).unwrap();
    assert_eq!(session, child);
    assert_eq!(pgrp, child);
}

fn getsid_and_getpgid_lookup() {
    h::reset_table();
    h::insert(10, 0, 5, 7);
    assert_eq!(process::sys_getsid(10), 5);
    assert_eq!(process::sys_getpgid(10), 7);
    assert_eq!(process::sys_getsid(9999), h::ESRCH_I64);
    assert_eq!(process::sys_getpgid(9999), h::ESRCH_I64);
}

fn setsid_rejects_process_group_leader() {
    h::reset_table();
    h::insert(10, 0, 10, 10);
    assert_eq!(process::setsid_for(10), h::EPERM_I64);
}

fn setsid_rejects_unknown_caller() {
    h::reset_table();
    assert_eq!(process::setsid_for(0), h::EPERM_I64);
    assert_eq!(process::setsid_for(9999), h::EPERM_I64);
}

fn setsid_creates_new_session_and_clears_ctty() {
    h::reset_table();
    h::insert(50, 0, 5, 7);
    h::attach_ctty(50);
    assert_eq!(process::setsid_for(50), 50);
    let (session, pgrp, has_tty) = h::snapshot(50).unwrap();
    assert_eq!(session, 50);
    assert_eq!(pgrp, 50);
    assert!(!has_tty);
}

fn setpgid_rejects_cross_session_target() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(30, 10, 9, 30);
    assert_eq!(process::setpgid_for(10, 30, 30), h::EPERM_I64);
}

fn setpgid_rejects_non_child_target() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(20, 99, 5, 20);
    assert_eq!(process::setpgid_for(10, 20, 20), h::ESRCH_I64);
}

fn setpgid_rejects_session_leader_target() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    // pid=5 is a session leader (session_id == pid). Re-parent under 10
    // so the caller-authority check passes and the leader guard fires.
    h::insert(5, 10, 5, 5);
    assert_eq!(process::setpgid_for(10, 5, 5), h::EPERM_I64);
}

fn setpgid_moves_child_into_existing_pgrp() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(20, 10, 5, 20); // pgrp leader of pgrp 20
    h::insert(21, 10, 5, 21); // own pgrp, will join 20
    assert_eq!(process::setpgid_for(10, 21, 20), 0);
    let (_, pgrp, _) = h::snapshot(21).unwrap();
    assert_eq!(pgrp, 20);
}

fn setpgid_creates_new_pgrp_when_pgid_equals_target() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(20, 10, 5, 10); // child inherited parent's pgrp
    assert_eq!(process::setpgid_for(10, 20, 20), 0);
    let (_, pgrp, _) = h::snapshot(20).unwrap();
    assert_eq!(pgrp, 20);
}

fn setpgid_rejects_nonexistent_pgid_in_session() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(20, 10, 5, 10);
    assert_eq!(process::setpgid_for(10, 20, 99), h::EINVAL_I64);
}

fn setpgid_pgid_zero_means_target() {
    h::reset_table();
    h::insert(10, 0, 5, 10);
    h::insert(20, 10, 5, 10);
    // pgid == 0 should resolve to target_pid (20), creating a new pgrp.
    assert_eq!(process::setpgid_for(10, 20, 0), 0);
    let (_, pgrp, _) = h::snapshot(20).unwrap();
    assert_eq!(pgrp, 20);
}
