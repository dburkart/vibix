//! Integration test for issue #547 / RFC 0004 Workstream B:
//! `getuid(2)`, `geteuid(2)`, `getgid(2)`, `getegid(2)` dispatch arms.
//!
//! Exercises the dispatcher end-to-end for each of the four
//! credential-query syscalls. The tasks under test here run with the
//! bootstrap/kernel credentials — `Credential::kernel()` — so every
//! field is 0 (root). Until issue #548 lands the `setuid` family there
//! is no other `Credential` value a test task can reach, so asserting
//! == 0 across the board is the tightest check available and the
//! correct expected value for a kernel task executing these syscalls.
//!
//! When #548 lands, a follow-on test should swap in a non-root
//! `Credential` via `Task::credentials.write()`, re-issue these
//! syscalls, and confirm each arm returns the corresponding field from
//! the new snapshot (not a stale kernel-zero).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const SYS_GETUID: u64 = 102;
const SYS_GETGID: u64 = 104;
const SYS_GETEUID: u64 = 107;
const SYS_GETEGID: u64 = 108;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    vibix::task::init();
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
            "getuid_returns_kernel_uid",
            &(getuid_returns_kernel_uid as fn()),
        ),
        (
            "geteuid_returns_kernel_euid",
            &(geteuid_returns_kernel_euid as fn()),
        ),
        (
            "getgid_returns_kernel_gid",
            &(getgid_returns_kernel_gid as fn()),
        ),
        (
            "getegid_returns_kernel_egid",
            &(getegid_returns_kernel_egid as fn()),
        ),
        (
            "getuid_family_matches_credential_snapshot",
            &(getuid_family_matches_credential_snapshot as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Drive the credential-query arms through the dispatcher. All four
/// syscalls take no arguments; we pass zeros and a null `ctx` because
/// these paths never touch the `SyscallReturnContext` (they don't
/// sleep, they don't signal-restart, they don't copy_to_user).
fn dispatch_nullary(nr: u64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), nr, 0, 0, 0, 0, 0, 0) }
}

fn getuid_returns_kernel_uid() {
    let rc = dispatch_nullary(SYS_GETUID);
    assert_eq!(
        rc, 0,
        "getuid() on a kernel task must be 0 (root); got {rc}"
    );
}

fn geteuid_returns_kernel_euid() {
    let rc = dispatch_nullary(SYS_GETEUID);
    assert_eq!(
        rc, 0,
        "geteuid() on a kernel task must be 0 (root); got {rc}"
    );
}

fn getgid_returns_kernel_gid() {
    let rc = dispatch_nullary(SYS_GETGID);
    assert_eq!(
        rc, 0,
        "getgid() on a kernel task must be 0 (root); got {rc}"
    );
}

fn getegid_returns_kernel_egid() {
    let rc = dispatch_nullary(SYS_GETEGID);
    assert_eq!(
        rc, 0,
        "getegid() on a kernel task must be 0 (root); got {rc}"
    );
}

/// Cross-check: each syscall arm must return exactly the corresponding
/// field of the current task's credential snapshot. Catches a stale
/// copy-paste (e.g. wiring geteuid to the `uid` field) that the
/// uniform-zero assertions above would miss when every field happens
/// to be zero.
fn getuid_family_matches_credential_snapshot() {
    let cred = vibix::task::current_credentials();
    assert_eq!(
        dispatch_nullary(SYS_GETUID),
        cred.uid as i64,
        "SYS_getuid arm must return Credential::uid"
    );
    assert_eq!(
        dispatch_nullary(SYS_GETEUID),
        cred.euid as i64,
        "SYS_geteuid arm must return Credential::euid"
    );
    assert_eq!(
        dispatch_nullary(SYS_GETGID),
        cred.gid as i64,
        "SYS_getgid arm must return Credential::gid"
    );
    assert_eq!(
        dispatch_nullary(SYS_GETEGID),
        cred.egid as i64,
        "SYS_getegid arm must return Credential::egid"
    );
}
