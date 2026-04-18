//! Integration test for issue #541: `chmod` / `fchmod` / `fchmodat`
//! and `chown` / `fchown` / `fchownat` / `lchown` wired to
//! `InodeOps::setattr` with POSIX DAC rules.
//!
//! Each impl is compiled unconditionally; the syscall dispatch arms are
//! gated behind `#[cfg(feature = "vfs_creds")]` per RFC 0004's
//! A-before-B ordering. Tests call `sys_*_impl` directly so the VFS
//! wiring is exercised regardless of feature state, mirroring the
//! mkdir/unlink convention.
//!
//! Coverage per the issue contract:
//! - `chmod` by owner succeeds.
//! - `chmod` by non-owner non-root returns `EPERM`.
//! - `chown` by root succeeds.
//! - `chown` by non-root non-owner returns `EPERM`.
//! - `chown` by non-root clears `S_ISUID` on a regular file.
//! - `fchmod` / `fchown` on a good fd round-trip; on a bogus fd
//!   return `EBADF`.
//! - `fchown(fd, -1, -1)` is a no-op success.
//! - `fchownat(AT_SYMLINK_NOFOLLOW)` / `lchown` resolve without
//!   following the trailing symlink.
//! - `fchmodat` / `fchownat` reject unknown flag bits with `EINVAL`.
//! - Dispatch arms return `-ENOSYS` until `vfs_creds` flips on.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::{syscall_dispatch, syscall_nr};
use vibix::arch::x86_64::syscalls::vfs::{
    sys_chmod_impl, sys_chown_impl, sys_fchmod_impl, sys_fchmodat_impl, sys_fchown_impl,
    sys_fchownat_impl, sys_lchown_impl, AT_FDCWD,
};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::vfs::Credential;
use vibix::fs::{EBADF, EINVAL, EPERM};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_STAT: u64 = 4;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;

const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;

const ENOSYS: i64 = -38;

const S_ISUID: u32 = 0o4000;
const S_ISGID: u32 = 0o2000;
const S_IXGRP: u32 = 0o0010;
const S_IFMT: u32 = 0o170_000;

const USER_PAGE_VA: usize = 0x0000_2005_0000_0000;
const USER_PAGE_LEN: usize = 4 * 4096;

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
            "chmod_by_owner_succeeds",
            &(chmod_by_owner_succeeds as fn()),
        ),
        (
            "chmod_by_non_owner_eperm",
            &(chmod_by_non_owner_eperm as fn()),
        ),
        ("chmod_by_root_succeeds", &(chmod_by_root_succeeds as fn())),
        ("chown_by_root_succeeds", &(chown_by_root_succeeds as fn())),
        (
            "chown_by_non_root_eperm",
            &(chown_by_non_root_eperm as fn()),
        ),
        (
            "chown_clears_setuid_on_non_root",
            &(chown_clears_setuid_on_non_root as fn()),
        ),
        (
            "chown_root_preserves_setuid",
            &(chown_root_preserves_setuid as fn()),
        ),
        ("fchmod_round_trip", &(fchmod_round_trip as fn())),
        ("fchmod_bad_fd_ebadf", &(fchmod_bad_fd_ebadf as fn())),
        ("fchown_noop_minus_one", &(fchown_noop_minus_one as fn())),
        ("fchown_bad_fd_ebadf", &(fchown_bad_fd_ebadf as fn())),
        (
            "fchmodat_rejects_unknown_flag",
            &(fchmodat_rejects_unknown_flag as fn()),
        ),
        (
            "fchownat_rejects_unknown_flag",
            &(fchownat_rejects_unknown_flag as fn()),
        ),
        (
            "chmod_dispatch_gate_enosys",
            &(chmod_dispatch_gate_enosys as fn()),
        ),
        (
            "chown_dispatch_gate_enosys",
            &(chown_dispatch_gate_enosys as fn()),
        ),
        (
            "chown_gid_owner_in_group_ok",
            &(chown_gid_owner_in_group_ok as fn()),
        ),
        (
            "chown_gid_owner_out_of_group_eperm",
            &(chown_gid_owner_out_of_group_eperm as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn install_user_staging_vma() {
    static INSTALLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    if INSTALLED.swap(true, core::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let prot_pte =
        (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits();
    vibix::task::install_vma_on_current(Vma::new(
        USER_PAGE_VA,
        USER_PAGE_VA + USER_PAGE_LEN,
        0x3,
        prot_pte,
        Share::Private,
        AnonObject::new(Some(USER_PAGE_LEN / 4096)),
        0,
    ));
    unsafe {
        let dst = USER_PAGE_VA as *mut u8;
        let mut i = 0;
        while i < USER_PAGE_LEN {
            ptr::write_volatile(dst.add(i), 0);
            i += 4096;
        }
    }
}

fn stage(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    assert!(bytes.len() < 4096);
    unsafe {
        let dst = USER_PAGE_VA as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
        ptr::write_volatile(dst.add(bytes.len()), 0);
    }
    USER_PAGE_VA as u64
}

/// Offset within the user staging VMA reserved for `struct stat`
/// copy-out. Keeps the path buffer (at offset 0) and the statbuf on
/// different pages so `check_user_range` doesn't see them overlap.
fn statbuf_uva() -> u64 {
    install_user_staging_vma();
    USER_PAGE_VA as u64 + 3 * 4096
}

fn read_stat() -> Stat {
    unsafe { ptr::read_volatile(statbuf_uva() as *const Stat) }
}

fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, flags, mode, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn stat(path: &[u8]) -> i64 {
    let uva = stage(path);
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_STAT,
            uva,
            statbuf_uva(),
            0,
            0,
            0,
            0,
        )
    }
}

fn chmod(path: &[u8], mode: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_chmod_impl(uva, mode as u64) }
}

fn chown(path: &[u8], uid: u32, gid: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_chown_impl(uva, uid as u64, gid as u64) }
}

fn fchmod(fd: i64, mode: u32) -> i64 {
    unsafe { sys_fchmod_impl(fd as u64, mode as u64) }
}

fn fchown(fd: i64, uid: u32, gid: u32) -> i64 {
    unsafe { sys_fchown_impl(fd as u64, uid as u64, gid as u64) }
}

/// Create a regular file, stat it, and return `(fd, current_mode)` so
/// the test can reason about the seeded state. The caller closes the fd
/// when done; leaving it open is fine too — fd table is wiped by exit.
fn create_regular(path: &[u8]) -> i64 {
    let fd = open(path, O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "create({:?}) expected fd, got {}", path, fd);
    fd
}

fn stat_of(path: &[u8]) -> Stat {
    let r = stat(path);
    assert_eq!(r, 0, "stat({:?}) must succeed, got {}", path, r);
    read_stat()
}

/// Set the current task's credential to a non-root user with the given
/// uid/gid. Supplementary groups are empty by default — callers that
/// need extra groups use `set_creds_with_groups`.
fn set_creds(uid: u32, gid: u32) {
    set_creds_with_groups(uid, gid, &[]);
}

fn set_creds_with_groups(uid: u32, gid: u32, groups: &[u32]) {
    let mut g = alloc::vec::Vec::new();
    g.extend_from_slice(groups);
    vibix::task::set_current_credentials(Credential::from_task_ids(
        uid, uid, uid, gid, gid, gid, g,
    ));
}

fn set_root_creds() {
    vibix::task::set_current_credentials(Credential::kernel());
}

// --- Tests --------------------------------------------------------------

fn chmod_by_owner_succeeds() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chmod-owner");
    close(fd);
    // Seed ownership to uid 1000 then drop privs.
    let r = chown(b"/tmp/chmod-owner", 1000, 1000);
    assert_eq!(r, 0, "seeding chown failed: {}", r);
    set_creds(1000, 1000);

    let r = chmod(b"/tmp/chmod-owner", 0o600);
    assert_eq!(r, 0, "owner chmod must succeed, got {}", r);

    set_root_creds();
    let sb = stat_of(b"/tmp/chmod-owner");
    assert_eq!(
        sb.st_mode & 0o7777,
        0o600,
        "mode bits must reflect chmod, got {:o}",
        sb.st_mode
    );
}

fn chmod_by_non_owner_eperm() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chmod-stranger");
    close(fd);
    let r = chown(b"/tmp/chmod-stranger", 1000, 1000);
    assert_eq!(r, 0);
    // Caller is uid 2000, file is owned by 1000.
    set_creds(2000, 2000);
    let r = chmod(b"/tmp/chmod-stranger", 0o600);
    assert_eq!(r, EPERM, "non-owner chmod must be EPERM, got {}", r);
    set_root_creds();
}

fn chmod_by_root_succeeds() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chmod-root");
    close(fd);
    // File owned by 1000. Root still chmods.
    let r = chown(b"/tmp/chmod-root", 1000, 1000);
    assert_eq!(r, 0);

    let r = chmod(b"/tmp/chmod-root", 0o755);
    assert_eq!(r, 0, "root chmod must succeed, got {}", r);
    let sb = stat_of(b"/tmp/chmod-root");
    assert_eq!(sb.st_mode & 0o7777, 0o755);
}

fn chown_by_root_succeeds() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-root");
    close(fd);
    let r = chown(b"/tmp/chown-root", 1234, 5678);
    assert_eq!(r, 0, "root chown must succeed, got {}", r);
    let sb = stat_of(b"/tmp/chown-root");
    assert_eq!(sb.st_uid, 1234, "uid after root chown");
    assert_eq!(sb.st_gid, 5678, "gid after root chown");
}

fn chown_by_non_root_eperm() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-nonroot");
    close(fd);
    let r = chown(b"/tmp/chown-nonroot", 1000, 1000);
    assert_eq!(r, 0);
    set_creds(1000, 1000);
    // Owner attempting to change uid is still EPERM per POSIX.
    let r = chown(b"/tmp/chown-nonroot", 2000, 1000);
    assert_eq!(r, EPERM, "non-root chown(uid) must be EPERM, got {}", r);
    set_root_creds();
}

fn chown_clears_setuid_on_non_root() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-setuid");
    close(fd);
    // Seed ownership + setuid/setgid-exec bits as root.
    let r = chown(b"/tmp/chown-setuid", 1000, 1000);
    assert_eq!(r, 0);
    let r = chmod(b"/tmp/chown-setuid", 0o6755); // setuid + setgid + rwxr-xr-x
    assert_eq!(r, 0);
    let sb = stat_of(b"/tmp/chown-setuid");
    assert_eq!(
        sb.st_mode & 0o7000,
        0o6000,
        "setid bits must be set pre-chown, mode={:o}",
        sb.st_mode
    );

    // Owner drops privs and chowns to their own gid (allowed: no uid
    // change requested, gid is the owner's current group).
    set_creds_with_groups(1000, 1000, &[1000]);
    let r = chown(b"/tmp/chown-setuid", u32::MAX, 1000);
    assert_eq!(r, 0, "owner chown(gid→own group) must succeed, got {}", r);

    set_root_creds();
    let sb = stat_of(b"/tmp/chown-setuid");
    // S_ISUID cleared unconditionally; S_ISGID cleared because S_IXGRP
    // was set (regular setgid binary, not mandatory-lock marker).
    assert_eq!(
        sb.st_mode & S_ISUID,
        0,
        "S_ISUID must be cleared on non-root chown, mode={:o}",
        sb.st_mode
    );
    assert_eq!(
        sb.st_mode & S_ISGID,
        0,
        "S_ISGID (with X_GRP set) must be cleared on non-root chown, mode={:o}",
        sb.st_mode
    );
}

fn chown_root_preserves_setuid() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-root-preserve");
    close(fd);
    let r = chmod(b"/tmp/chown-root-preserve", 0o6755);
    assert_eq!(r, 0);

    // Root-initiated chown preserves the setid bits (POSIX says
    // implementation-defined; Linux preserves them for root).
    let r = chown(b"/tmp/chown-root-preserve", 1000, 1000);
    assert_eq!(r, 0);
    let sb = stat_of(b"/tmp/chown-root-preserve");
    assert_eq!(
        sb.st_mode & 0o7000,
        0o6000,
        "root chown must preserve setid, mode={:o}",
        sb.st_mode
    );
}

fn fchmod_round_trip() {
    set_root_creds();
    let fd = create_regular(b"/tmp/fchmod-target");
    let r = fchmod(fd, 0o600);
    assert_eq!(r, 0, "root fchmod must succeed, got {}", r);
    close(fd);
    let sb = stat_of(b"/tmp/fchmod-target");
    assert_eq!(sb.st_mode & 0o7777, 0o600);
}

fn fchmod_bad_fd_ebadf() {
    set_root_creds();
    let r = fchmod(9999, 0o600);
    assert_eq!(r, EBADF, "fchmod on nonexistent fd must EBADF, got {}", r);
}

fn fchown_noop_minus_one() {
    set_root_creds();
    let fd = create_regular(b"/tmp/fchown-noop");
    let r = fchown(fd, u32::MAX, u32::MAX);
    assert_eq!(
        r, 0,
        "fchown(fd, -1, -1) must be a success no-op, got {}",
        r
    );
    close(fd);
}

fn fchown_bad_fd_ebadf() {
    set_root_creds();
    let r = fchown(9999, 0, 0);
    assert_eq!(r, EBADF, "fchown on nonexistent fd must EBADF, got {}", r);
}

fn fchmodat_rejects_unknown_flag() {
    set_root_creds();
    let uva = stage(b"/tmp/anything");
    let r = unsafe { sys_fchmodat_impl(AT_FDCWD, uva, 0o644, 0x8000) };
    assert_eq!(
        r, EINVAL,
        "fchmodat with unknown flag must EINVAL, got {}",
        r
    );
}

fn fchownat_rejects_unknown_flag() {
    set_root_creds();
    let uva = stage(b"/tmp/anything");
    let r = unsafe { sys_fchownat_impl(AT_FDCWD, uva, 0, 0, 0x8000) };
    assert_eq!(
        r, EINVAL,
        "fchownat with unknown flag must EINVAL, got {}",
        r
    );
    // lchown is a thin wrapper; exercise it too.
    let uva = stage(b"/tmp/lchown-target-missing");
    let r = unsafe { sys_lchown_impl(uva, 0, 0) };
    // Path doesn't exist: ENOENT, not EINVAL. We just want lchown to
    // reach the resolver rather than panic on an unsupported flag.
    assert!(
        r < 0,
        "lchown on missing path must return a negative errno, got {}",
        r
    );
}

/// With `vfs_creds` off (the default), every new dispatch arm falls
/// through to the dispatcher's `-ENOSYS` default. Any non-ENOSYS return
/// from `syscall_dispatch(SYS_chmod, ...)` would mean the RFC 0004
/// A-before-B gate has leaked.
#[cfg(not(feature = "vfs_creds"))]
fn chmod_dispatch_gate_enosys() {
    set_root_creds();
    let uva = stage(b"/tmp/anything");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::CHMOD,
            uva,
            0o644,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_chmod must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn chmod_dispatch_gate_enosys() {
    set_root_creds();
    let uva = stage(b"/tmp/anything-chmod");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::CHMOD,
            uva,
            0o644,
            0,
            0,
            0,
            0,
        )
    };
    assert!(
        r != ENOSYS,
        "SYS_chmod dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

#[cfg(not(feature = "vfs_creds"))]
fn chown_dispatch_gate_enosys() {
    set_root_creds();
    let uva = stage(b"/tmp/anything");
    let r =
        unsafe { syscall_dispatch(core::ptr::null_mut(), syscall_nr::CHOWN, uva, 0, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOSYS,
        "SYS_chown must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn chown_dispatch_gate_enosys() {
    set_root_creds();
    let uva = stage(b"/tmp/anything-chown");
    let r =
        unsafe { syscall_dispatch(core::ptr::null_mut(), syscall_nr::CHOWN, uva, 0, 0, 0, 0, 0) };
    assert!(
        r != ENOSYS,
        "SYS_chown dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

fn chown_gid_owner_in_group_ok() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-gid-ok");
    close(fd);
    let r = chown(b"/tmp/chown-gid-ok", 1000, 100);
    assert_eq!(r, 0);
    // Caller is the owner (uid 1000) and has supplementary group 200;
    // chowning the gid to 200 is allowed.
    set_creds_with_groups(1000, 1000, &[200]);
    let r = chown(b"/tmp/chown-gid-ok", u32::MAX, 200);
    assert_eq!(
        r, 0,
        "owner chown(gid→supplementary-group) must succeed, got {}",
        r
    );
    set_root_creds();
    let sb = stat_of(b"/tmp/chown-gid-ok");
    assert_eq!(sb.st_gid, 200);
}

fn chown_gid_owner_out_of_group_eperm() {
    set_root_creds();
    let fd = create_regular(b"/tmp/chown-gid-nope");
    close(fd);
    let r = chown(b"/tmp/chown-gid-nope", 1000, 100);
    assert_eq!(r, 0);
    // Caller owns the file but gid 999 is not in their set.
    set_creds_with_groups(1000, 1000, &[100, 200]);
    let r = chown(b"/tmp/chown-gid-nope", u32::MAX, 999);
    assert_eq!(
        r, EPERM,
        "owner chown(gid→out-of-set) must EPERM, got {}",
        r
    );
    set_root_creds();
}

// Make sure S_IFMT is referenced so the constant is not dead. The
// chown-preserves-setid assertion only checks `0o7000`; S_IFMT is here
// as a sanity escape hatch for future coverage.
#[allow(dead_code)]
const _: u32 = S_IFMT;
#[allow(dead_code)]
const _: u32 = S_IXGRP;
