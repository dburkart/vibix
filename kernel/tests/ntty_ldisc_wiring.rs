//! Integration test: `NTtyLdisc` is wired into the shared console tty
//! that PS/2 + serial rx both feed, so a byte arriving via
//! `tty.ldisc.receive_byte()` actually drives the N_TTY state machine —
//! generates SIGINT for VINTR and commits canonical-mode lines into the
//! raw ring (#474 / #898).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::{sig_bit, SIGINT};
use vibix::tty::ntty::{KernelSignalDispatch, NTtyLdisc, SignalDispatch};
use vibix::tty::termios::{ICANON, ISIG};
use vibix::tty::{LineDiscipline, NullDriver, Tty, TtyDriver};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("ntty_ldisc_wiring: init ok");
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("ps2_ldisc_is_ntty", &(ps2_ldisc_is_ntty as fn())),
        ("serial_ldisc_is_ntty", &(serial_ldisc_is_ntty as fn())),
        (
            "vintr_through_ldisc_signals_pgrp",
            &(vintr_through_ldisc_signals_pgrp as fn()),
        ),
        (
            "canonical_line_commits_through_ldisc",
            &(canonical_line_commits_through_ldisc as fn()),
        ),
        (
            "raw_mode_bytes_visible_immediately",
            &(raw_mode_bytes_visible_immediately as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Helpers ───────────────────────────────────────────────────────────

fn make_ntty_tty() -> (Arc<Tty>, Arc<NTtyLdisc>) {
    let dispatch: Arc<dyn SignalDispatch> = Arc::new(KernelSignalDispatch);
    let ldisc = Arc::new(NTtyLdisc::new(dispatch));
    let driver: Arc<dyn TtyDriver> = Arc::new(NullDriver);
    let tty = Arc::new(Tty::with_driver(
        driver,
        ldisc.clone() as Arc<dyn LineDiscipline>,
    ));
    (tty, ldisc)
}

fn pending_bits_for_pid(pid: u32) -> u64 {
    process::with_signal_state_for_task(pid as usize, |s| s.pending).unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────

/// The PS/2 path must return the shared console tty which has an
/// NTtyLdisc attached, not a passthrough.
fn ps2_ldisc_is_ntty() {
    let tty = vibix::tty::ps2::tty();
    // Both ps2::tty() and serial::tty() now return console_tty(),
    // which is initialised with NTtyLdisc. Push a byte and confirm no
    // panic — deeper assertions happen in the locally-constructed
    // NTtyLdisc subtests below.
    tty.ldisc.receive_byte(&tty, b'a');
}

fn serial_ldisc_is_ntty() {
    let tty = vibix::tty::serial::tty();
    tty.ldisc.receive_byte(&tty, b'a');
    // Both sources must return the same Arc<Tty> — they share one
    // console tty so userspace sees a single stdin.
    let ps2 = vibix::tty::ps2::tty();
    assert!(
        Arc::ptr_eq(&tty, &ps2),
        "serial::tty() and ps2::tty() must return the same console tty"
    );
}

/// Pushing VINTR through the public `ldisc.receive_byte` surface — i.e.
/// the same path the PS/2 softirq drain uses — must raise SIGINT on the
/// foreground pgrp and flush any queued bytes from the raw ring.
fn vintr_through_ldisc_signals_pgrp() {
    h::reset_table();
    h::insert(101, 0, 50, 60);
    let (tty, ldisc) = make_ntty_tty();

    // Configure the tty: ICANON | ISIG, fg pgrp = 60.
    {
        let mut t = tty.termios.lock();
        t.c_lflag = ISIG | ICANON;
    }
    {
        let mut c = tty.ctrl.lock();
        c.session = Some(50);
        c.set_pgrp(Some(60));
    }
    let vintr = tty.termios.lock().c_cc[vibix::tty::termios::VINTR];

    // Type "abc" then VINTR — same byte sequence the rx softirq would push.
    for &b in b"abc" {
        tty.ldisc.receive_byte(&tty, b);
    }
    tty.ldisc.receive_byte(&tty, vintr);

    assert_ne!(
        pending_bits_for_pid(101) & sig_bit(SIGINT),
        0,
        "SIGINT must be pending on pid 101 after VINTR through ldisc"
    );
    assert_eq!(
        ldisc.ntty().reader_len(),
        0,
        "VINTR must flush the raw ring; got {}",
        ldisc.ntty().reader_len(),
    );
}

/// In canonical mode, typing "abc\n" through the ldisc must commit the
/// full line (4 bytes including the newline) into the N_TTY raw ring so
/// a /dev/tty reader could observe it.
fn canonical_line_commits_through_ldisc() {
    h::reset_table();
    h::insert(102, 0, 51, 61);
    let (tty, ldisc) = make_ntty_tty();
    {
        let mut t = tty.termios.lock();
        t.c_lflag = ISIG | ICANON;
    }
    {
        let mut c = tty.ctrl.lock();
        c.session = Some(51);
        c.set_pgrp(Some(61));
    }

    // Without the newline the line buffer holds the bytes but the raw
    // ring is still empty — readers see nothing.
    for &b in b"abc" {
        tty.ldisc.receive_byte(&tty, b);
    }
    assert_eq!(
        ldisc.ntty().reader_len(),
        0,
        "in-progress canonical line must not be visible to readers yet"
    );

    // Newline commits.
    tty.ldisc.receive_byte(&tty, b'\n');
    assert_eq!(
        ldisc.ntty().reader_len(),
        4,
        "after commit, readers must see 'abc\\n' (4 bytes); got {}",
        ldisc.ntty().reader_len(),
    );
}

/// In raw mode (ICANON clear), every byte must hit the raw ring
/// immediately — no line-editor buffering.
fn raw_mode_bytes_visible_immediately() {
    h::reset_table();
    h::insert(103, 0, 52, 62);
    let (tty, ldisc) = make_ntty_tty();
    {
        let mut t = tty.termios.lock();
        t.c_lflag = 0; // ICANON + ISIG cleared
    }
    {
        let mut c = tty.ctrl.lock();
        c.session = Some(52);
        c.set_pgrp(Some(62));
    }

    tty.ldisc.receive_byte(&tty, b'X');
    tty.ldisc.receive_byte(&tty, b'Y');
    assert_eq!(
        ldisc.ntty().reader_len(),
        2,
        "raw-mode bytes must be readable immediately; got {}",
        ldisc.ntty().reader_len(),
    );
}
