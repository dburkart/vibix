//! Integration test for issue #548 / RFC 0004 Workstream B:
//! `setuid(2)` / `setgid(2)` / `setreuid(2)` / `setregid(2)` /
//! `setresuid(2)` / `setresgid(2)` dispatch arms.
//!
//! Each test builds a fresh `Credential` snapshot, installs it on the
//! currently-running task via
//! [`vibix::task::replace_current_credentials`], dispatches the
//! relevant syscall through the real dispatcher, then asserts both the
//! numeric return code (0 on success, negative errno on failure) and
//! the post-swap `{ruid, euid, suid}` / `{rgid, egid, sgid}` triple as
//! observed through `current_credentials()`.
//!
//! Cross-checking after each write validates the Arc-swap is visible
//! to the read path — the "atomic update via Arc swap" contract from
//! RFC 0004 §Credential model that pairs these write arms with the
//! `getuid`-family read arms merged in #547.
//!
//! The test matrix covers (per the issue body):
//! - root setuid drops all three to non-zero and cannot regain
//! - setuid-binary drop-and-restore via setreuid(ruid, suid)
//! - setresuid with -1 preserves fields
//! - setregid(-1, new_egid) transitions egid only
//! Plus the POSIX edge cases: `setuid(-1)` rejected with EINVAL,
//! `setreuid(-1, -1)` no-op, same-value self-set always succeeds,
//! non-root transitions outside `{ruid, euid, suid}` rejected with
//! EPERM.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::vfs::Credential;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

// Syscall numbers (Linux x86_64 ABI; parity-checked in the unit test
// at `kernel/src/arch/x86_64/syscall.rs::tests`).
const SYS_SETUID: u64 = 105;
const SYS_SETGID: u64 = 106;
const SYS_SETREUID: u64 = 113;
const SYS_SETREGID: u64 = 114;
const SYS_SETRESUID: u64 = 117;
const SYS_SETRESGID: u64 = 119;

// C errno contract (negated to match syscall return convention).
const EPERM: i64 = -1;
const EINVAL: i64 = -22;

// The C `(uid_t)-1` / `(gid_t)-1` sentinel — u32 wire transport, so
// `-1` is `u32::MAX` when zero-extended into the syscall register.
const MINUS_ONE: u64 = u32::MAX as u64;

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
        ("setuid_minus_one_einval", &(setuid_minus_one_einval as fn())),
        ("setgid_minus_one_einval", &(setgid_minus_one_einval as fn())),
        (
            "root_setuid_drops_all_three",
            &(root_setuid_drops_all_three as fn()),
        ),
        (
            "dropped_uid_cannot_regain",
            &(dropped_uid_cannot_regain as fn()),
        ),
        (
            "setreuid_minus_one_minus_one_is_noop",
            &(setreuid_minus_one_minus_one_is_noop as fn()),
        ),
        (
            "setuid_binary_drop_and_restore",
            &(setuid_binary_drop_and_restore as fn()),
        ),
        (
            "setresuid_minus_one_preserves",
            &(setresuid_minus_one_preserves as fn()),
        ),
        (
            "setregid_minus_one_new_egid_transitions_egid_only",
            &(setregid_minus_one_new_egid_transitions_egid_only as fn()),
        ),
        (
            "nonroot_setuid_to_outside_set_eperm",
            &(nonroot_setuid_to_outside_set_eperm as fn()),
        ),
        (
            "nonroot_same_value_is_success",
            &(nonroot_same_value_is_success as fn()),
        ),
        (
            "setresuid_nonroot_outside_set_eperm",
            &(setresuid_nonroot_outside_set_eperm as fn()),
        ),
        (
            "setresuid_root_sets_all_three",
            &(setresuid_root_sets_all_three as fn()),
        ),
        (
            "setreuid_ruid_change_bumps_suid",
            &(setreuid_ruid_change_bumps_suid as fn()),
        ),
        (
            "setgid_family_mirrors_uid_family",
            &(setgid_family_mirrors_uid_family as fn()),
        ),
        (
            "uid_transition_preserves_supplementary_groups",
            &(uid_transition_preserves_supplementary_groups as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---- Test helpers ---------------------------------------------------

/// Install a fresh six-ID + groups snapshot on the currently-running
/// task. All tests call this on entry so the matrix is
/// state-independent (each case sets exactly the initial credential it
/// wants, then drives the syscall).
fn install_cred(uid: u32, euid: u32, suid: u32, gid: u32, egid: u32, sgid: u32) {
    let cred = Credential::from_task_ids(uid, euid, suid, gid, egid, sgid, Vec::new());
    vibix::task::replace_current_credentials(cred);
}

fn install_cred_with_groups(
    uid: u32,
    euid: u32,
    suid: u32,
    gid: u32,
    egid: u32,
    sgid: u32,
    groups: Vec<u32>,
) {
    let cred = Credential::from_task_ids(uid, euid, suid, gid, egid, sgid, groups);
    vibix::task::replace_current_credentials(cred);
}

/// Dispatch a syscall through the real entry point.
fn dispatch(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    // `ctx` is never dereferenced by any credential syscall arm (they
    // do not sleep, signal-restart, or copy_to_user), so a null pointer
    // is fine — matches the pattern used by `syscall_getuid_family`.
    unsafe { syscall_dispatch(core::ptr::null_mut(), nr, a0, a1, a2, 0, 0, 0) }
}

fn cur() -> alloc::sync::Arc<Credential> {
    vibix::task::current_credentials()
}

// ---- Tests: single-arg EINVAL on -1 ---------------------------------

fn setuid_minus_one_einval() {
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETUID, MINUS_ONE, 0, 0);
    assert_eq!(
        rc, EINVAL,
        "setuid((uid_t)-1) must return EINVAL (single-arg form has no unchanged sentinel); got {rc}"
    );
    // Snapshot unchanged.
    let c = cur();
    assert_eq!((c.uid, c.euid, c.suid), (0, 0, 0));
}

fn setgid_minus_one_einval() {
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETGID, MINUS_ONE, 0, 0);
    assert_eq!(rc, EINVAL, "setgid((gid_t)-1) must return EINVAL; got {rc}");
    let c = cur();
    assert_eq!((c.gid, c.egid, c.sgid), (0, 0, 0));
}

// ---- Tests: root drops ----------------------------------------------

fn root_setuid_drops_all_three() {
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETUID, 1000, 0, 0);
    assert_eq!(rc, 0, "root setuid(1000) must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (1000, 1000, 1000),
        "root setuid(u) sets ruid=euid=suid=u per POSIX.1 §setuid"
    );
}

fn dropped_uid_cannot_regain() {
    // After an irrevocable drop, reclaiming root is EPERM — there is
    // no 0 anywhere in {ruid, euid, suid} to authorise the setuid.
    install_cred(1000, 1000, 1000, 1000, 1000, 1000);
    let rc = dispatch(SYS_SETUID, 0, 0, 0);
    assert_eq!(
        rc, EPERM,
        "non-root setuid(0) with 0 ∉ {{ruid, euid, suid}} must be EPERM; got {rc}"
    );
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (1000, 1000, 1000),
        "failed setuid must not mutate any field"
    );
}

// ---- Tests: setreuid -------------------------------------------------

fn setreuid_minus_one_minus_one_is_noop() {
    install_cred(500, 600, 700, 0, 0, 0);
    let rc = dispatch(SYS_SETREUID, MINUS_ONE, MINUS_ONE, 0);
    assert_eq!(rc, 0, "setreuid(-1, -1) must be a no-op success; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (500, 600, 700),
        "setreuid(-1, -1) must not touch any field"
    );
}

fn setuid_binary_drop_and_restore() {
    // Classic "setuid-root binary" pattern: we exec'd as uid=1000 with
    // the setuid bit flipping euid to 0, giving us {ruid=1000, euid=0,
    // suid=0}. Drop euid to the real uid to run the non-privileged
    // section, then reclaim root via euid=suid later.
    install_cred(1000, 0, 0, 0, 0, 0);

    // Drop: setreuid(-1, 1000) → euid=1000. The suid-bump rule fires
    // only when euid changes to a value != old ruid; here new euid
    // (1000) == old ruid (1000), so suid stays at 0. That preserved
    // suid=0 is what authorises reclaiming root below.
    let rc = dispatch(SYS_SETREUID, MINUS_ONE, 1000, 0);
    assert_eq!(rc, 0, "setreuid(-1, 1000) from root must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (1000, 1000, 0),
        "drop phase: ruid preserved, euid=1000, suid still 0 (new euid == old ruid, no bump)"
    );

    // Restore: setreuid(-1, 0). suid=0 is in {ruid, euid, suid} so
    // euid=0 is authorised. The bump rule fires because new euid (0)
    // != old ruid (1000), so suid is updated to the new euid. suid
    // stays at 0, which is what we want.
    let rc = dispatch(SYS_SETREUID, MINUS_ONE, 0, 0);
    assert_eq!(rc, 0, "restore phase: setreuid(-1, 0) must succeed when suid=0; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (1000, 0, 0),
        "restore phase: ruid preserved, euid reclaimed to 0, suid still 0"
    );
}

fn setreuid_ruid_change_bumps_suid() {
    // When ruid is set (argument is not -1), suid := new euid per the
    // POSIX.1 §setreuid fourth paragraph bump rule. Here we run as
    // root so the membership check is bypassed.
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETREUID, 1000, 2000, 0);
    assert_eq!(rc, 0, "root setreuid(1000, 2000) must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (1000, 2000, 2000),
        "ruid was set, so suid := new euid (POSIX bump rule)"
    );
}

// ---- Tests: setresuid -----------------------------------------------

fn setresuid_minus_one_preserves() {
    install_cred(100, 200, 300, 0, 0, 0);
    // Non-root caller (euid=200 != 0). Change only euid; target 100
    // is a member of {ruid=100, euid=200, suid=300} so the
    // membership check passes. -1 preserves ruid and suid verbatim.
    let rc = dispatch(SYS_SETRESUID, MINUS_ONE, 100, MINUS_ONE);
    assert_eq!(
        rc, 0,
        "setresuid(-1, 100, -1) with 100=ruid must succeed; got {rc}"
    );
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (100, 100, 300),
        "setresuid(-1, X, -1) changes only euid — ruid and suid preserved"
    );
}

fn setresuid_nonroot_outside_set_eperm() {
    install_cred(100, 200, 300, 0, 0, 0);
    // 999 is not in {100, 200, 300} — reject with EPERM.
    let rc = dispatch(SYS_SETRESUID, 999, MINUS_ONE, MINUS_ONE);
    assert_eq!(
        rc, EPERM,
        "non-root setresuid with target ∉ {{ruid, euid, suid}} must be EPERM; got {rc}"
    );
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (100, 200, 300),
        "failed setresuid must not mutate any field"
    );
}

fn setresuid_root_sets_all_three() {
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETRESUID, 111, 222, 333);
    assert_eq!(rc, 0, "root setresuid(111, 222, 333) must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (111, 222, 333),
        "root setresuid writes all three fields literally — no implicit suid bump"
    );
}

// ---- Tests: setregid -------------------------------------------------

fn setregid_minus_one_new_egid_transitions_egid_only() {
    // euid=0 so we're root — pass the membership check trivially, and
    // confirm the field-selection logic: setregid(-1, new_egid)
    // touches only egid. The sgid-bump rule fires because egid
    // changes to a value != old rgid, so sgid := new egid.
    install_cred(0, 0, 0, 10, 20, 30);
    let rc = dispatch(SYS_SETREGID, MINUS_ONE, 999, 0);
    assert_eq!(
        rc, 0,
        "root setregid(-1, 999) must succeed; got {rc}"
    );
    let c = cur();
    assert_eq!(
        (c.gid, c.egid, c.sgid),
        (10, 999, 999),
        "setregid(-1, e) with e != old rgid: rgid preserved, egid=e, sgid bumped to e"
    );
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (0, 0, 0),
        "setregid must not touch any uid field"
    );
}

// ---- Tests: non-root edge cases -------------------------------------

fn nonroot_setuid_to_outside_set_eperm() {
    install_cred(100, 100, 100, 0, 0, 0);
    let rc = dispatch(SYS_SETUID, 42, 0, 0);
    assert_eq!(
        rc, EPERM,
        "non-root setuid(u) with u ∉ {{ruid, suid}} must be EPERM; got {rc}"
    );
    let c = cur();
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (100, 100, 100),
        "failed setuid must not mutate any field"
    );
}

fn nonroot_same_value_is_success() {
    // POSIX: "Setting the same field to its current value is a success,
    // not EPERM." For non-root `setuid(u)` this works because u == ruid
    // (and ruid is a valid target).
    install_cred(100, 100, 100, 0, 0, 0);
    let rc = dispatch(SYS_SETUID, 100, 0, 0);
    assert_eq!(
        rc, 0,
        "non-root setuid(current ruid) must succeed (same-value case); got {rc}"
    );
    let c = cur();
    assert_eq!((c.uid, c.euid, c.suid), (100, 100, 100));
}

// ---- Tests: gid mirrors uid -----------------------------------------

fn setgid_family_mirrors_uid_family() {
    // Root (euid == 0) can set all three gid fields via setgid(g).
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETGID, 1000, 0, 0);
    assert_eq!(rc, 0, "root setgid(1000) must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        (c.gid, c.egid, c.sgid),
        (1000, 1000, 1000),
        "root setgid(g) sets rgid=egid=sgid=g"
    );
    assert_eq!(
        (c.uid, c.euid, c.suid),
        (0, 0, 0),
        "setgid must not touch any uid field"
    );

    // After the transition to non-root effective *user* id, setgid is
    // no longer privileged (POSIX: only euid confers privilege). So
    // install {euid=500} and check non-root rejection of an
    // out-of-set target.
    install_cred(500, 500, 500, 1000, 1000, 1000);
    let rc = dispatch(SYS_SETGID, 42, 0, 0);
    assert_eq!(
        rc, EPERM,
        "non-root setgid(g) with g ∉ {{rgid, sgid}} must be EPERM; got {rc}"
    );

    // setresgid root path.
    install_cred(0, 0, 0, 0, 0, 0);
    let rc = dispatch(SYS_SETRESGID, 111, 222, 333);
    assert_eq!(rc, 0, "root setresgid(111,222,333) must succeed; got {rc}");
    let c = cur();
    assert_eq!((c.gid, c.egid, c.sgid), (111, 222, 333));
}

// ---- Tests: supplementary groups preserved --------------------------

fn uid_transition_preserves_supplementary_groups() {
    // RFC 0004 §945-957: supplementary groups are NOT cleared on any
    // setuid/setgid transition (Linux rule, not BSD). setgroups
    // remains the explicit-mutation path.
    let groups: Vec<u32> = [10u32, 20, 30].iter().copied().collect();
    install_cred_with_groups(0, 0, 0, 0, 0, 0, groups.clone());

    let rc = dispatch(SYS_SETUID, 1000, 0, 0);
    assert_eq!(rc, 0, "root setuid(1000) must succeed");
    let c = cur();
    assert_eq!(
        c.groups.as_slice(),
        [10, 20, 30],
        "supplementary groups must survive a uid transition (Linux rule per RFC 0004)"
    );

    // A successful gid transition must also preserve the list. The
    // task is now non-root (uid=euid=suid=1000 after the setuid above)
    // so pass a same-value target (0 == current rgid) to land on the
    // unprivileged success path.
    let rc = dispatch(SYS_SETGID, 0, 0, 0);
    assert_eq!(rc, 0, "non-root setgid(current rgid) must succeed; got {rc}");
    let c = cur();
    assert_eq!(
        c.groups.as_slice(),
        [10, 20, 30],
        "supplementary groups must survive a gid transition too"
    );
}
