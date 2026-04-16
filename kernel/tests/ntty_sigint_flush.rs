//! Integration test: N_TTY canonical-mode VINTR delivers SIGINT to the
//! foreground pgrp AND flushes the pending line/raw buffers (#463).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::{sig_bit, SIGINT};
use vibix::tty::ntty::{KernelSignalDispatch, NTty, NullWake};
use vibix::tty::termios::{Termios, ICANON, ISIG, VINTR};
use vibix::tty::JobControl;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("ntty_sigint_flush: init ok");
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
            "vintr_delivers_sigint_and_flushes",
            &(vintr_delivers_sigint_and_flushes as fn()),
        ),
        (
            "vintr_with_empty_line_still_signals",
            &(vintr_with_empty_line_still_signals as fn()),
        ),
        (
            "vintr_flushes_committed_line_too",
            &(vintr_flushes_committed_line_too as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn termios_canon_isig() -> Termios {
    let mut t = Termios::sane();
    t.c_lflag = ISIG | ICANON;
    t
}

fn ctrl_with(sid: u32, pgrp: u32) -> JobControl {
    let mut jc = JobControl::new();
    jc.session = Some(sid);
    jc.set_pgrp(Some(pgrp));
    jc
}

fn pending_bits_for_pid(pid: u32) -> u64 {
    process::with_signal_state_for_task(pid as usize, |s| s.pending).unwrap_or(0)
}

fn feed_byte(n: &NTty, termios: &Termios, ctrl: &JobControl, b: u8) {
    if let Some(out) = n.receive_signal_or_byte(termios, ctrl, &KernelSignalDispatch, b) {
        n.canon_input(termios, out, &NullWake);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

fn vintr_delivers_sigint_and_flushes() {
    h::reset_table();
    h::insert(10, 0, 5, 9);
    let n = NTty::new();
    let t = termios_canon_isig();
    let ctrl = ctrl_with(5, 9);

    // Type "abc" without committing — lives in the line buffer.
    for b in b"abc" {
        feed_byte(&n, &t, &ctrl, *b);
    }
    // VINTR (0x03 by default): must signal + flush.
    feed_byte(&n, &t, &ctrl, t.c_cc[VINTR]);

    assert_ne!(
        pending_bits_for_pid(10) & sig_bit(SIGINT),
        0,
        "SIGINT must be pending on pid 10 after VINTR"
    );
    assert_eq!(
        n.reader_len(),
        0,
        "reader must observe 0 bytes after VINTR flush, got {}",
        n.reader_len()
    );
}

fn vintr_with_empty_line_still_signals() {
    h::reset_table();
    h::insert(20, 0, 7, 11);
    let n = NTty::new();
    let t = termios_canon_isig();
    let ctrl = ctrl_with(7, 11);

    feed_byte(&n, &t, &ctrl, t.c_cc[VINTR]);

    assert_ne!(
        pending_bits_for_pid(20) & sig_bit(SIGINT),
        0,
        "SIGINT must be pending on pid 20"
    );
    assert_eq!(n.reader_len(), 0);
}

fn vintr_flushes_committed_line_too() {
    h::reset_table();
    h::insert(30, 0, 3, 4);
    let n = NTty::new();
    let t = termios_canon_isig();
    let ctrl = ctrl_with(3, 4);

    // Commit a full line (goes into the raw ring).
    for b in b"hello\n" {
        feed_byte(&n, &t, &ctrl, *b);
    }
    assert_eq!(
        n.reader_len(),
        6,
        "committed line should populate raw ring"
    );

    // Start a new in-progress line, then VINTR.
    for b in b"xyz" {
        feed_byte(&n, &t, &ctrl, *b);
    }
    feed_byte(&n, &t, &ctrl, t.c_cc[VINTR]);

    assert_ne!(pending_bits_for_pid(30) & sig_bit(SIGINT), 0);
    assert_eq!(
        n.reader_len(),
        0,
        "VINTR must flush both in-progress line and already-committed raw bytes"
    );
}
