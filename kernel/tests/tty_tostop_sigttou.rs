//! Integration test: SIGTTOU + TOSTOP on background-pgrp tty write (#434).
//!
//! Exercises `tty::tty_check_tostop` against the process-table test helpers.
//! End-to-end user-visible EINTR delivery on `write(2)` is covered once the
//! shell exercises job control from ring 3.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::{
    restart_decision, sig_bit, Disposition, RestartDecision, SA_RESTART, SIGTERM, SIGTTOU,
};
use vibix::tty::{termios, tty_check_tostop, Tty, KERN_ERESTARTSYS};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("tty_tostop_sigttou: init ok");
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
            "tostop_clear_allows_write",
            &(tostop_clear_allows_write as fn()),
        ),
        (
            "caller_matches_fg_pgrp_allows_write",
            &(caller_matches_fg_pgrp_allows_write as fn()),
        ),
        (
            "no_foreground_pgrp_allows_write",
            &(no_foreground_pgrp_allows_write as fn()),
        ),
        (
            "unattached_caller_allows_write",
            &(unattached_caller_allows_write as fn()),
        ),
        (
            "background_pgrp_with_tostop_raises_sigttou",
            &(background_pgrp_with_tostop_raises_sigttou as fn()),
        ),
        (
            "sigttou_delivered_to_every_pgrp_member",
            &(sigttou_delivered_to_every_pgrp_member as fn()),
        ),
        (
            "erestartsys_sa_restart_rewinds_syscall",
            &(erestartsys_sa_restart_rewinds_syscall as fn()),
        ),
        (
            "erestartsys_without_sa_restart_yields_eintr",
            &(erestartsys_without_sa_restart_yields_eintr as fn()),
        ),
        (
            "erestartsys_default_stop_rewinds",
            &(erestartsys_default_stop_rewinds as fn()),
        ),
        (
            "erestartsys_no_pending_signal_unconditionally_rewinds",
            &(erestartsys_no_pending_signal_unconditionally_rewinds as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn fresh_tty_with_fg(sid: u32, pgrp: u32, tostop: bool) -> Arc<Tty> {
    let tty = Arc::new(Tty::new());
    {
        let mut ctrl = tty.ctrl.lock();
        ctrl.session = Some(sid);
        ctrl.set_pgrp(Some(pgrp));
    }
    if tostop {
        let mut t = tty.termios.lock();
        t.c_lflag |= termios::TOSTOP;
    } else {
        let mut t = tty.termios.lock();
        t.c_lflag &= !termios::TOSTOP;
    }
    tty
}

fn pending_bits_for_pid(pid: u32) -> u64 {
    process::with_signal_state_for_task(pid as usize, |s| s.pending).unwrap_or(0)
}

fn tostop_clear_allows_write() {
    h::reset_table();
    h::insert(10, 0, 5, 5); // caller in pgrp 5
    h::insert(20, 0, 5, 9); // fg pgrp 9 owner in same session
    let tty = fresh_tty_with_fg(5, 9, false);
    // Caller pgrp (5) != fg (9), but TOSTOP is clear → no gate, no signal.
    assert!(tty_check_tostop(&tty, 10).is_none());
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTOU), 0);
}

fn caller_matches_fg_pgrp_allows_write() {
    h::reset_table();
    h::insert(10, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9, true);
    // Caller IS in the foreground pgrp → no gate, no signal, even with TOSTOP.
    assert!(tty_check_tostop(&tty, 10).is_none());
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTOU), 0);
}

fn no_foreground_pgrp_allows_write() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    let tty = Arc::new(Tty::new());
    {
        let mut t = tty.termios.lock();
        t.c_lflag |= termios::TOSTOP;
    }
    // No fg pgrp (snapshot == 0) → no gate regardless of TOSTOP.
    assert!(tty_check_tostop(&tty, 10).is_none());
    assert_eq!(pending_bits_for_pid(10) & sig_bit(SIGTTOU), 0);
}

fn unattached_caller_allows_write() {
    h::reset_table();
    let tty = fresh_tty_with_fg(5, 9, true);
    // pid 0 (no process context) short-circuits — kernel writes proceed.
    assert!(tty_check_tostop(&tty, 0).is_none());
}

fn background_pgrp_with_tostop_raises_sigttou() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(20, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9, true);
    let rc = tty_check_tostop(&tty, 10);
    assert_eq!(rc, Some(KERN_ERESTARTSYS));
    assert_ne!(pending_bits_for_pid(10) & sig_bit(SIGTTOU), 0);
    // Foreground pgrp member must NOT receive the signal.
    assert_eq!(pending_bits_for_pid(20) & sig_bit(SIGTTOU), 0);
}

fn sigttou_delivered_to_every_pgrp_member() {
    h::reset_table();
    h::insert(10, 0, 5, 5);
    h::insert(11, 0, 5, 5);
    h::insert(12, 0, 5, 5);
    h::insert(30, 0, 5, 9);
    let tty = fresh_tty_with_fg(5, 9, true);
    let rc = tty_check_tostop(&tty, 10);
    assert_eq!(rc, Some(KERN_ERESTARTSYS));
    // Every member of caller's pgrp (5) must have SIGTTOU pending.
    for &pid in &[10u32, 11, 12] {
        assert_ne!(
            pending_bits_for_pid(pid) & sig_bit(SIGTTOU),
            0,
            "pid {pid} missing SIGTTOU"
        );
    }
    assert_eq!(pending_bits_for_pid(30) & sig_bit(SIGTTOU), 0);
}

// ── ERESTARTSYS / SA_RESTART trampoline classifier ──────────────────────
//
// The syscall trampoline (`check_and_deliver_signals`) reacts to
// `tty_check_tostop`'s KERN_ERESTARTSYS by consulting `restart_decision`.
// These cases drive the classifier directly — the trampoline path itself
// needs a live kernel-stack-backed `SyscallReturnContext` and signal
// frame push, which is covered by the shell-level end-to-end tests.

fn erestartsys_sa_restart_rewinds_syscall() {
    // Handler installed with SA_RESTART: rv=-ERESTARTSYS must restart
    // the syscall *and* deliver the handler on top of the restart.
    assert_eq!(
        restart_decision(
            KERN_ERESTARTSYS,
            Some(SIGTTOU),
            Disposition::Handler(0x0000_4000_0000_0000),
            SA_RESTART,
        ),
        RestartDecision::Restart {
            deliver_handler: true
        }
    );
}

fn erestartsys_without_sa_restart_yields_eintr() {
    // Handler installed without SA_RESTART: convert to -EINTR.
    assert_eq!(
        restart_decision(
            KERN_ERESTARTSYS,
            Some(SIGTTOU),
            Disposition::Handler(0x0000_4000_0000_0000),
            0,
        ),
        RestartDecision::Eintr
    );
    // Non-ERESTARTSYS rv is passed through untouched.
    assert_eq!(
        restart_decision(
            -4, // EINTR
            Some(SIGTTOU),
            Disposition::Handler(0x0000_4000_0000_0000),
            0,
        ),
        RestartDecision::NoChange
    );
}

fn erestartsys_default_stop_rewinds() {
    // Default SIGTTOU action is Stop (job-control). Restart so that when
    // the task is resumed it re-evaluates the tostop gate and either
    // proceeds or re-enters the wait.
    assert_eq!(
        restart_decision(
            KERN_ERESTARTSYS,
            Some(SIGTTOU),
            Disposition::Default,
            0, // flags irrelevant for default disposition
        ),
        RestartDecision::Restart {
            deliver_handler: false
        }
    );
    // Default-Terminate (e.g. SIGTERM) also rewinds; the task is about
    // to die via deliver_signal but -512 must not leak into userspace.
    assert_eq!(
        restart_decision(
            KERN_ERESTARTSYS,
            Some(SIGTERM),
            Disposition::Default,
            0,
        ),
        RestartDecision::Restart {
            deliver_handler: false
        }
    );
}

fn erestartsys_no_pending_signal_unconditionally_rewinds() {
    // A caller that returned ERESTARTSYS but no pending signal was
    // actually consumed (e.g. spurious wake) restarts unconditionally.
    assert_eq!(
        restart_decision(KERN_ERESTARTSYS, None, Disposition::Default, 0),
        RestartDecision::Restart {
            deliver_handler: false
        }
    );
}
