//! Integration test for issue #544: `utimensat` / `futimens` wired to
//! `InodeOps::setattr` with UTIME_NOW / UTIME_OMIT / AT_SYMLINK_NOFOLLOW
//! and the POSIX permission matrix.
//!
//! `sys_utimensat_impl` is compiled unconditionally; the dispatch arm
//! is gated on `vfs_creds`. Tests call the `impl` entry point directly
//! so the VFS wiring is exercised regardless of feature state —
//! mirrors the mkdir/unlink/chmod convention.
//!
//! Coverage per the issue:
//! - `times == NULL`       → atime + mtime bumped to "now".
//! - `UTIME_OMIT`          → matching field left unchanged.
//! - `UTIME_NOW`           → matching field bumped to "now".
//! - Explicit ns out of range → `EINVAL`.
//! - Unknown flag bit       → `EINVAL`.
//! - Explicit time as non-owner → `EPERM`.
//! - `UTIME_NOW` as non-owner without write perm → `EACCES`.
//! - `UTIME_NOW` as non-owner *with* write perm → `0`.
//! - `futimens` (= `utimensat(fd, NULL, times, 0)`) round-trips.
//! - `futimens` on a bogus fd → `EBADF`.
//! - Dispatcher gate: `-ENOSYS` without `vfs_creds`; reaches impl with.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::{syscall_dispatch, syscall_nr};
use vibix::arch::x86_64::syscalls::vfs::{
    sys_chmod_impl, sys_chown_impl, sys_futimens_impl, sys_utimensat_impl, AT_FDCWD,
    AT_SYMLINK_NOFOLLOW, UTIME_NOW, UTIME_OMIT,
};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::vfs::Credential;
use vibix::fs::{EACCES, EBADF, EINVAL, EPERM};
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

const USER_PAGE_VA: usize = 0x0000_2006_0000_0000;
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
        ("null_times_bumps_both", &(null_times_bumps_both as fn())),
        (
            "utime_omit_leaves_atime",
            &(utime_omit_leaves_atime as fn()),
        ),
        ("utime_now_bumps_mtime", &(utime_now_bumps_mtime as fn())),
        (
            "explicit_time_owner_sets_value",
            &(explicit_time_owner_sets_value as fn()),
        ),
        (
            "explicit_time_non_owner_eperm",
            &(explicit_time_non_owner_eperm as fn()),
        ),
        (
            "utime_now_non_owner_no_write_eaccess",
            &(utime_now_non_owner_no_write_eaccess as fn()),
        ),
        (
            "utime_now_non_owner_with_write_ok",
            &(utime_now_non_owner_with_write_ok as fn()),
        ),
        ("bad_nsec_einval", &(bad_nsec_einval as fn())),
        ("unknown_flag_einval", &(unknown_flag_einval as fn())),
        ("double_omit_is_noop", &(double_omit_is_noop as fn())),
        ("futimens_round_trip", &(futimens_round_trip as fn())),
        ("futimens_bad_fd_ebadf", &(futimens_bad_fd_ebadf as fn())),
        (
            "at_symlink_nofollow_accepted",
            &(at_symlink_nofollow_accepted as fn()),
        ),
        (
            "utimensat_dispatch_gate",
            &(utimensat_dispatch_gate as fn()),
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

fn statbuf_uva() -> u64 {
    install_user_staging_vma();
    USER_PAGE_VA as u64 + 3 * 4096
}

/// Stage a `[timespec; 2]` blob in user memory, returning its user VA.
/// Placed on a different page from the path buffer so `check_user_range`
/// sees no overlap.
fn stage_times(atime_sec: i64, atime_nsec: i64, mtime_sec: i64, mtime_nsec: i64) -> u64 {
    install_user_staging_vma();
    let off = 2 * 4096;
    unsafe {
        let dst = (USER_PAGE_VA + off) as *mut u8;
        let words: [i64; 4] = [atime_sec, atime_nsec, mtime_sec, mtime_nsec];
        for (i, w) in words.iter().enumerate() {
            ptr::write_volatile(dst.add(i * 8) as *mut i64, *w);
        }
    }
    (USER_PAGE_VA + off) as u64
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

/// Seed file `path` with owner (1000, 1000) and mode `mode`. File is
/// created as root, closed, then root chmod/chown it into the target
/// state. Returns nothing — tests re-stat to get fresh timestamps.
fn seed_owned(path: &[u8], mode: u32) {
    set_root_creds();
    let fd = create_regular(path);
    close(fd);
    let uva = stage(path);
    let r = unsafe { sys_chown_impl(uva, 1000, 1000) };
    assert_eq!(r, 0, "seed chown failed: {}", r);
    let uva = stage(path);
    let r = unsafe { sys_chmod_impl(uva, mode as u64) };
    assert_eq!(r, 0, "seed chmod failed: {}", r);
}

// --- Tests --------------------------------------------------------------

fn null_times_bumps_both() {
    set_root_creds();
    seed_owned(b"/tmp/utime-null", 0o644);
    let pre = stat_of(b"/tmp/utime-null");

    let uva = stage(b"/tmp/utime-null");
    // times_uva = 0 means "both NOW" per POSIX.
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, 0, 0) };
    assert_eq!(r, 0, "utimensat(NULL) must succeed, got {}", r);

    let post = stat_of(b"/tmp/utime-null");
    assert!(
        post.st_atime >= pre.st_atime && post.st_mtime >= pre.st_mtime,
        "both atime and mtime must move forward (pre a={} m={} post a={} m={})",
        pre.st_atime,
        pre.st_mtime,
        post.st_atime,
        post.st_mtime
    );
    // At least one of the two should have *strictly* advanced given
    // Timespec::now() uses monotonic uptime and we just called open+stat
    // in between seed and utimensat.
    assert!(
        post.st_mtime > pre.st_mtime || post.st_mtime_nsec != pre.st_mtime_nsec,
        "mtime must strictly advance"
    );
}

fn utime_omit_leaves_atime() {
    set_root_creds();
    seed_owned(b"/tmp/utime-omit", 0o644);
    let pre = stat_of(b"/tmp/utime-omit");
    let pre_atime = pre.st_atime;
    let pre_atime_ns = pre.st_atime_nsec;

    // atime = OMIT (leave), mtime = NOW (bump).
    let uva = stage(b"/tmp/utime-omit");
    let times = stage_times(0, UTIME_OMIT as i64, 0, UTIME_NOW as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(r, 0, "utimensat(OMIT,NOW) must succeed, got {}", r);

    let post = stat_of(b"/tmp/utime-omit");
    assert_eq!(
        post.st_atime, pre_atime,
        "atime.sec must be unchanged by UTIME_OMIT"
    );
    assert_eq!(
        post.st_atime_nsec, pre_atime_ns,
        "atime.nsec must be unchanged by UTIME_OMIT"
    );
    assert!(
        post.st_mtime >= pre.st_mtime,
        "mtime must not regress under UTIME_NOW"
    );
}

fn utime_now_bumps_mtime() {
    set_root_creds();
    seed_owned(b"/tmp/utime-now", 0o644);
    let pre = stat_of(b"/tmp/utime-now");

    // atime = NOW, mtime = OMIT.
    let uva = stage(b"/tmp/utime-now");
    let times = stage_times(0, UTIME_NOW as i64, 0, UTIME_OMIT as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(r, 0, "utimensat(NOW,OMIT) must succeed, got {}", r);

    let post = stat_of(b"/tmp/utime-now");
    assert_eq!(
        post.st_mtime, pre.st_mtime,
        "mtime.sec must be unchanged by UTIME_OMIT"
    );
    assert_eq!(
        post.st_mtime_nsec, pre.st_mtime_nsec,
        "mtime.nsec must be unchanged by UTIME_OMIT"
    );
    assert!(
        post.st_atime >= pre.st_atime,
        "atime must advance under UTIME_NOW"
    );
}

fn explicit_time_owner_sets_value() {
    set_root_creds();
    seed_owned(b"/tmp/utime-explicit", 0o644);
    set_creds(1000, 1000); // owner

    // Explicit atime = 1_000_000 s, mtime = 2_000_000 s.
    let uva = stage(b"/tmp/utime-explicit");
    let times = stage_times(1_000_000, 123, 2_000_000, 456);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(
        r, 0,
        "owner explicit-time utimensat must succeed, got {}",
        r
    );

    set_root_creds();
    let post = stat_of(b"/tmp/utime-explicit");
    assert_eq!(post.st_atime, 1_000_000, "atime.sec");
    assert_eq!(post.st_atime_nsec, 123, "atime.nsec");
    assert_eq!(post.st_mtime, 2_000_000, "mtime.sec");
    assert_eq!(post.st_mtime_nsec, 456, "mtime.nsec");
}

fn explicit_time_non_owner_eperm() {
    set_root_creds();
    seed_owned(b"/tmp/utime-explicit-stranger", 0o666); // world-writable
                                                        // Caller is uid 2000; file is owned by 1000. Even with world-write,
                                                        // explicit timestamps require ownership — anti-forensics rule.
    set_creds(2000, 2000);

    let uva = stage(b"/tmp/utime-explicit-stranger");
    let times = stage_times(1_000_000, 0, 2_000_000, 0);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(
        r, EPERM,
        "explicit-time non-owner (even with write) must EPERM, got {}",
        r
    );
    set_root_creds();
}

fn utime_now_non_owner_no_write_eaccess() {
    set_root_creds();
    seed_owned(b"/tmp/utime-now-noperm", 0o600); // owner-only
    set_creds(2000, 2000); // not owner, no write bit

    let uva = stage(b"/tmp/utime-now-noperm");
    let times = stage_times(0, UTIME_NOW as i64, 0, UTIME_NOW as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(
        r, EACCES,
        "UTIME_NOW non-owner without write perm must EACCES, got {}",
        r
    );
    set_root_creds();
}

fn utime_now_non_owner_with_write_ok() {
    set_root_creds();
    seed_owned(b"/tmp/utime-now-writeok", 0o666); // world-writable
    set_creds(2000, 2000); // non-owner, but world-write grants W.

    let uva = stage(b"/tmp/utime-now-writeok");
    let times = stage_times(0, UTIME_NOW as i64, 0, UTIME_NOW as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(
        r, 0,
        "UTIME_NOW non-owner with write perm must succeed, got {}",
        r
    );
    set_root_creds();
}

fn bad_nsec_einval() {
    set_root_creds();
    seed_owned(b"/tmp/utime-bad-ns", 0o644);

    let uva = stage(b"/tmp/utime-bad-ns");
    // tv_nsec = 1e9 is out of [0, 1e9) and is not a sentinel.
    let times = stage_times(0, 1_000_000_000, 0, 0);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(r, EINVAL, "out-of-range tv_nsec must EINVAL, got {}", r);

    let uva = stage(b"/tmp/utime-bad-ns");
    let times = stage_times(0, -1, 0, 0);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(r, EINVAL, "negative tv_nsec must EINVAL, got {}", r);
}

fn unknown_flag_einval() {
    set_root_creds();
    let uva = stage(b"/tmp/utime-whatever");
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, 0, 0x8000) };
    assert_eq!(r, EINVAL, "unknown flag must EINVAL, got {}", r);
}

fn double_omit_is_noop() {
    set_root_creds();
    seed_owned(b"/tmp/utime-double-omit", 0o600);
    // Even a caller with zero claim to the file gets success on
    // (OMIT, OMIT): POSIX permits the no-op.
    set_creds(2000, 2000);
    let uva = stage(b"/tmp/utime-double-omit");
    let times = stage_times(0, UTIME_OMIT as i64, 0, UTIME_OMIT as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, 0) };
    assert_eq!(
        r, 0,
        "(OMIT, OMIT) must be a permit-and-skip no-op, got {}",
        r
    );
    set_root_creds();
}

fn futimens_round_trip() {
    set_root_creds();
    let fd = create_regular(b"/tmp/futimens-target");
    let times = stage_times(1_000, 0, 2_000, 0);
    let r = unsafe { sys_futimens_impl(fd as u64, times) };
    assert_eq!(r, 0, "futimens must succeed, got {}", r);
    close(fd);
    let sb = stat_of(b"/tmp/futimens-target");
    assert_eq!(sb.st_atime, 1_000);
    assert_eq!(sb.st_mtime, 2_000);
}

fn futimens_bad_fd_ebadf() {
    set_root_creds();
    let times = stage_times(0, UTIME_NOW as i64, 0, UTIME_NOW as i64);
    let r = unsafe { sys_futimens_impl(9999, times) };
    assert_eq!(r, EBADF, "futimens on bogus fd must EBADF, got {}", r);
}

fn at_symlink_nofollow_accepted() {
    // No symlink creation syscall exists yet, so we can't verify the
    // resolver stops on a link. What we CAN verify is that the flag is
    // accepted (no EINVAL) when applied to a regular file — the
    // resolver produces the same inode either way, so the success path
    // must not regress.
    set_root_creds();
    seed_owned(b"/tmp/utime-nofollow", 0o644);
    let uva = stage(b"/tmp/utime-nofollow");
    let times = stage_times(0, UTIME_NOW as i64, 0, UTIME_NOW as i64);
    let r = unsafe { sys_utimensat_impl(AT_FDCWD, uva, times, AT_SYMLINK_NOFOLLOW) };
    assert_eq!(
        r, 0,
        "AT_SYMLINK_NOFOLLOW on a regular file must be a success pass-through, got {}",
        r
    );
}

/// With `vfs_creds` off (the default), SYS_utimensat falls through to
/// the dispatcher's `-ENOSYS` default. With it on, the arm must reach
/// the impl — which, in the test harness, returns some non-ENOSYS value
/// (success or a path errno) because the path we pass is a stub.
#[cfg(not(feature = "vfs_creds"))]
fn utimensat_dispatch_gate() {
    set_root_creds();
    let uva = stage(b"/tmp/utime-gate");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::UTIMENSAT,
            AT_FDCWD as u64,
            uva,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_utimensat must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn utimensat_dispatch_gate() {
    set_root_creds();
    seed_owned(b"/tmp/utime-gate-on", 0o644);
    let uva = stage(b"/tmp/utime-gate-on");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::UTIMENSAT,
            AT_FDCWD as u64,
            uva,
            0,
            0,
            0,
            0,
        )
    };
    assert!(
        r != ENOSYS,
        "SYS_utimensat dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}
