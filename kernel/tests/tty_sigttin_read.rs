//! Integration test: SIGTTIN on background-pgrp tty read (#433).
//!
//! Exercises `tty::tty_check_sigttin` against the process-table test helpers.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::{sig_bit, Disposition, SIGTTIN};
use vibix::tty::{tty_check_sigttin, Tty, EIO, KERN_ERESTARTSYS};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("tty_sigttin_read: init ok");
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
            "foreground_pgrp_reads_succeed",
            &(foreground_pgrp_reads_succeed as fn()),
        ),
        (
            "background_pgrp_raises_sigttin",
            &(background_pgrp_raises_sigttin as fn()),
        ),
        (
            "no_fg_pgrp_allows_read",
            &(no_fg_pgrp_allows_read as fn()),
        ),
        (
            "caller_pid_zero_allows_read",
            &(caller_pid_zero_allows_read as fn()),
        ),
        (
            "sigttin_blocked_returns_eio",
            &(sigttin_blocked_returns_eio as fn()),
        ),
        (
            "sigttin_ignored_returns_eio",
            &(sigttin_ignored_returns_eio as fn()),
        ),
        (
            "sigttin_delivered_to_every_pgrp_member",
            &(sigttin_delivered_to_every_pgrp_member as fn()),
        ),
        (
            "unattached_caller_allows_read",
            &(unattached_caller_allows_read as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn fresh_tty_with_fg(sid: u32, pgrp: u32) -> Arc<Tty> {
    let tty = Arc::new(Tty::new());
    {
        let mut ctrl = tty.ctrl.lock();
        ctrl.session = Some(sid);
        ctrl.set_pgrp(Some(pgrp));
    }
    tty
}

fn pending_bits_for_pid(pid: u32) -> u64 {
    process::with_signal_state_for_task(pid as usize, |s| s.pending).unwrap_or(0)
}

fn foreground_pgrp_reads_succeed() {
    h::reset_table();
    h::insert(10, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9);
    assert!(tty_check_sigttin(&tty, 10).is_none());
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTIN), 0);
}

fn background_pgrp_raises_sigttin() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(20, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9);
    let rc = tty_check_sigttin(&tty, 10);
    assert_eq!(rc, Some(KERN_ERESTARTSYS));
    assert_ne!(pending_bits_for_pid(10) & sig_bit(SIGTTIN), 0);
    assert_eq!(pending_bits_for_pid(20) & sig_bit(SIGTTIN), 0);
}

fn no_fg_pgrp_allows_read() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    let tty = Arc::new(Tty::new());
    assert!(tty_check_sigttin(&tty, 10).is_none());
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTIN), 0);
}

fn caller_pid_zero_allows_read() {
    h::reset_table();
    let tty = fresh_tty_with_fg(5, 9);
    assert!(tty_check_sigttin(&tty, 0).is_none());
}

fn sigttin_blocked_returns_eio() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(20, 0, 5, 9);
    h::patch(10, |e| {
        e.signals.lock().blocked |= sig_bit(SIGTTIN);
    });
    let tty = fresh_tty_with_fg(5, 9);
    let rc = tty_check_sigttin(&tty, 10);
    assert_eq!(rc, Some(EIO));
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTIN), 0);
}

fn sigttin_ignored_returns_eio() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(20, 0, 5, 9);
    h::patch(10, |e| {
        e.signals.lock().dispositions[(SIGTTIN - 1) as usize] = Disposition::Ignore;
    });
    let tty = fresh_tty_with_fg(5, 9);
    let rc = tty_check_sigttin(&tty, 10);
    assert_eq!(rc, Some(EIO));
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTIN), 0);
}

fn sigttin_delivered_to_every_pgrp_member() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(11, 0, 5, 5);
    h::insert(12, 0, 5, 5);
    h::insert(30, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9);
    let rc = tty_check_sigttin(&tty, 10);
    assert_eq!(rc, Some(KERN_ERESTARTSYS));
    for &pid in &[10u32, 11, 12] {
        assert_ne!(
            pending_bits_for_pid(pid) & sig_bit(SIGTTIN),
            0,
            "pid {pid} missing SIGTTIN"
        );
    }
    assert_eq!(pending_bits_for_pid(30) & sig_bit(SIGTTIN), 0);
}

fn unattached_caller_allows_read() {
    h::reset_table();
    let tty = fresh_tty_with_fg(5, 9);
    assert!(tty_check_sigttin(&tty, 99).is_none());
}
