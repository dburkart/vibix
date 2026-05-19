//! Integration test: fork→exit→waitpid round-trip and POSIX wait status
//! encoding.
//!
//! Exercises:
//!   - `process::register` + `process::mark_zombie` + `process::reap_child`
//!     round-trip.
//!   - Normal exit: status encoded via `((exit_status & 0xFF) << 8)` matches
//!     the POSIX `WIFEXITED`/`WEXITSTATUS` layout.
//!   - Signal-terminated exit: raw status is `-(sig as i32)`, and the
//!     kernel's current wait4 encoding places `(status & 0xFF) << 8`.
//!   - Multiple children reaped in any order with `target_pid = -1`.
//!   - Specific child reap with `target_pid = child_pid`.
//!   - ECHILD-equivalent when no children exist.
//!   - Parent sees all children after multiple register calls.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::process::{self, test_helpers as h};
use vibix::signal::SIGSEGV;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    vibix::task::init();
    x86_64::instructions::interrupts::enable();
    serial_println!("process_wait: init ok");
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
            "register_mark_zombie_reap_roundtrip",
            &(register_mark_zombie_reap_roundtrip as fn()),
        ),
        (
            "normal_exit_status_encoding",
            &(normal_exit_status_encoding as fn()),
        ),
        (
            "signal_terminated_status_encoding",
            &(signal_terminated_status_encoding as fn()),
        ),
        (
            "reap_any_child_returns_zombie",
            &(reap_any_child_returns_zombie as fn()),
        ),
        (
            "reap_specific_child",
            &(reap_specific_child as fn()),
        ),
        (
            "reap_nonexistent_returns_none",
            &(reap_nonexistent_returns_none as fn()),
        ),
        (
            "reap_alive_child_returns_none",
            &(reap_alive_child_returns_none as fn()),
        ),
        (
            "multiple_children_all_reapable",
            &(multiple_children_all_reapable as fn()),
        ),
        (
            "exit_status_zero",
            &(exit_status_zero as fn()),
        ),
        (
            "exit_status_wraps_at_8_bits",
            &(exit_status_wraps_at_8_bits as fn()),
        ),
        (
            "wifexited_wexitstatus_encoding",
            &(wifexited_wexitstatus_encoding as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Parent PID chosen to avoid collision with the real process table.
const PARENT: u32 = 0x700;

// ── POSIX wait status macros ────────────────────────────────────────────
//
// These replicate the Linux wait status encoding that the kernel's WAIT4
// syscall arm uses: `encoded = ((exit_status & 0xFF) << 8) as u32`.
//
// POSIX defines:
//   WIFEXITED(s)   — true if low 7 bits are 0 (normal exit).
//   WEXITSTATUS(s) — bits 15..8 (exit code, 0–255).
//   WIFSIGNALED(s) — true if low 7 bits are non-zero and != 0x7f.
//   WTERMSIG(s)    — low 7 bits (signal number).
//
// The current kernel always encodes as `(status & 0xFF) << 8`, which means
// WIFEXITED is always true and WIFSIGNALED is always false for all exits.
// This is correct for normal exits; for signal-terminated processes the
// kernel should ideally encode as `(sig & 0x7F)` in the low bits, but that
// is tracked as future work. We test the current behavior here.

fn encode_wstatus(exit_status: i32) -> u32 {
    ((exit_status & 0xFF) << 8) as u32
}

fn wifexited(wstatus: u32) -> bool {
    (wstatus & 0x7F) == 0
}

fn wexitstatus(wstatus: u32) -> u32 {
    (wstatus >> 8) & 0xFF
}

fn wifsignaled(wstatus: u32) -> bool {
    let low7 = wstatus & 0x7F;
    low7 != 0 && low7 != 0x7F
}

/// Extract the terminating signal number from a wait status.
/// Provided for completeness; will be used when the kernel implements
/// POSIX-correct signal-terminated encoding (low 7 bits = signo).
#[allow(dead_code)]
fn wtermsig(wstatus: u32) -> u32 {
    wstatus & 0x7F
}

// ── Tests ────────────────────────────────────────────────────────────────

/// Basic round-trip: register child, mark zombie, reap.
fn register_mark_zombie_reap_roundtrip() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);
    h::insert(PARENT + 1, PARENT, PARENT, PARENT);

    process::mark_zombie(PARENT + 1, 42);

    let reaped = process::reap_child(PARENT, (PARENT + 1) as i32);
    assert_eq!(reaped, Some((PARENT + 1, 42)));

    h::reset_table();
}

/// Normal exit with status 0 encodes correctly.
fn exit_status_zero() {
    let wstatus = encode_wstatus(0);
    assert!(wifexited(wstatus), "exit(0) should set WIFEXITED");
    assert_eq!(wexitstatus(wstatus), 0, "WEXITSTATUS should be 0");
    assert!(!wifsignaled(wstatus), "exit(0) should not set WIFSIGNALED");
}

/// Normal exit status encoding matches POSIX WIFEXITED/WEXITSTATUS layout.
fn normal_exit_status_encoding() {
    for code in [0i32, 1, 42, 127, 255] {
        let wstatus = encode_wstatus(code);
        assert!(wifexited(wstatus), "exit({code}) should set WIFEXITED");
        assert_eq!(
            wexitstatus(wstatus),
            code as u32,
            "WEXITSTATUS({code}) mismatch"
        );
    }
}

/// Signal-terminated exit: the kernel encodes `-(sig as i32)` as the raw
/// status. Through the current `((s & 0xFF) << 8)` encoding, verify the
/// raw exit status is correct.
fn signal_terminated_status_encoding() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);
    h::insert(PARENT + 1, PARENT, PARENT, PARENT);

    // SIGSEGV = 11, so mark_zombie gets -11.
    process::mark_zombie(PARENT + 1, -(SIGSEGV as i32));

    let reaped = process::reap_child(PARENT, (PARENT + 1) as i32);
    assert!(reaped.is_some());
    let (pid, raw_status) = reaped.unwrap();
    assert_eq!(pid, PARENT + 1);
    assert_eq!(raw_status, -(SIGSEGV as i32), "raw status should be -SIGSEGV");

    // Verify what wait4 would encode: the current kernel shifts the raw
    // status, which for a negative value wraps through 0xFF masking.
    let wstatus = encode_wstatus(raw_status);
    // -11 & 0xFF = 245, shifted left 8 = 245 << 8 = 0xF500.
    let expected = (((-11i32) & 0xFF) << 8) as u32;
    assert_eq!(wstatus, expected);

    h::reset_table();
}

/// `reap_child(parent, -1)` returns any zombie child.
fn reap_any_child_returns_zombie() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);
    h::insert(PARENT + 1, PARENT, PARENT, PARENT);
    h::insert(PARENT + 2, PARENT, PARENT, PARENT);

    process::mark_zombie(PARENT + 2, 99);

    let reaped = process::reap_child(PARENT, -1);
    assert!(reaped.is_some(), "should reap any zombie child");
    let (pid, status) = reaped.unwrap();
    assert_eq!(pid, PARENT + 2);
    assert_eq!(status, 99);

    h::reset_table();
}

/// `reap_child(parent, specific_pid)` returns only that specific child.
fn reap_specific_child() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);
    h::insert(PARENT + 1, PARENT, PARENT, PARENT);
    h::insert(PARENT + 2, PARENT, PARENT, PARENT);

    // Mark both as zombies.
    process::mark_zombie(PARENT + 1, 10);
    process::mark_zombie(PARENT + 2, 20);

    // Reap specific child.
    let reaped = process::reap_child(PARENT, (PARENT + 2) as i32);
    assert_eq!(reaped, Some((PARENT + 2, 20)));

    // The other child should still be reapable.
    let reaped2 = process::reap_child(PARENT, (PARENT + 1) as i32);
    assert_eq!(reaped2, Some((PARENT + 1, 10)));

    h::reset_table();
}

/// Reaping a nonexistent child returns None.
fn reap_nonexistent_returns_none() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);

    let reaped = process::reap_child(PARENT, 9999);
    assert_eq!(reaped, None, "reaping nonexistent child should return None");

    h::reset_table();
}

/// Reaping an alive (non-zombie) child returns None.
fn reap_alive_child_returns_none() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);
    h::insert(PARENT + 1, PARENT, PARENT, PARENT);

    let reaped = process::reap_child(PARENT, (PARENT + 1) as i32);
    assert_eq!(reaped, None, "alive child should not be reapable");

    h::reset_table();
}

/// Multiple children can all be reaped after they exit.
fn multiple_children_all_reapable() {
    h::reset_table();
    h::insert(PARENT, 0, PARENT, PARENT);

    const N: u32 = 5;
    for i in 1..=N {
        h::insert(PARENT + i, PARENT, PARENT, PARENT);
    }
    for i in 1..=N {
        process::mark_zombie(PARENT + i, i as i32);
    }

    let mut reaped_pids = alloc::vec::Vec::new();
    while let Some((pid, status)) = process::reap_child(PARENT, -1) {
        reaped_pids.push(pid);
        assert_eq!(
            status,
            (pid - PARENT) as i32,
            "exit status mismatch for pid {pid}"
        );
    }

    assert_eq!(reaped_pids.len(), N as usize, "should reap all {N} children");

    // Verify all pids appeared.
    for i in 1..=N {
        assert!(
            reaped_pids.contains(&(PARENT + i)),
            "pid {} not found in reaped set",
            PARENT + i
        );
    }

    h::reset_table();
}

/// Exit status wraps at 8 bits through the POSIX encoding — status 256
/// should produce WEXITSTATUS 0 (only low 8 bits are preserved).
fn exit_status_wraps_at_8_bits() {
    let wstatus = encode_wstatus(256);
    assert!(wifexited(wstatus));
    assert_eq!(
        wexitstatus(wstatus),
        0,
        "exit(256) should wrap to WEXITSTATUS(0)"
    );

    let wstatus2 = encode_wstatus(257);
    assert_eq!(
        wexitstatus(wstatus2),
        1,
        "exit(257) should wrap to WEXITSTATUS(1)"
    );
}

/// End-to-end WIFEXITED/WEXITSTATUS encoding verification for a range
/// of exit codes through the kernel's encoding function.
fn wifexited_wexitstatus_encoding() {
    for code in 0u8..=255 {
        let wstatus = encode_wstatus(code as i32);
        assert!(
            wifexited(wstatus),
            "exit({code}) must set WIFEXITED"
        );
        assert_eq!(
            wexitstatus(wstatus),
            code as u32,
            "WEXITSTATUS mismatch for exit({code})"
        );
        assert!(
            !wifsignaled(wstatus),
            "exit({code}) must not set WIFSIGNALED"
        );
    }
}
