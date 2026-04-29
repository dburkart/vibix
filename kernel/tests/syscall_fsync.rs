//! Integration test for issue #748: `fsync(2)` / `fdatasync(2)`
//! syscalls.
//!
//! Exercises the `SYS_FSYNC` (74) and `SYS_FDATASYNC` (75) dispatch
//! arms end-to-end:
//!
//! - `fsync` / `fdatasync` on a valid VFS fd succeeds (default
//!   `FileOps::fsync` is `Ok(())`, default `SuperOps::sync_fs` is
//!   `Ok(())`, no inode mapping is wired so `wb_err` is zero).
//! - `fsync` / `fdatasync` on a closed/invalid fd returns `EBADF`.
//! - The `OpenFile`'s per-file errseq snapshot starts at zero (no
//!   inode mapping yet — issue #745) and never spuriously surfaces
//!   `EIO`. This pins the seam in place so when #745 lands the
//!   errseq logic has a regression test.
//! - `fsync` and `fdatasync` are *separate* dispatch arms; the
//!   distinction is preserved at the ABI even though the underlying
//!   sb-side flush is currently a superset (split tracked as a
//!   follow-up; see issue auto-engineer files).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::EBADF;
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_FSYNC: u64 = 74;
const SYS_FDATASYNC: u64 = 75;

const O_RDONLY: u32 = 0o0;
const O_RDWR: u32 = 0o2;

const HOSTNAME_PATH: &[u8] = b"/etc/hostname\0";

const USER_PAGE_VA: usize = 0x0000_2001_0000_0000;
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
            "fsync_on_valid_fd_returns_zero",
            &(fsync_on_valid_fd_returns_zero as fn()),
        ),
        (
            "fdatasync_on_valid_fd_returns_zero",
            &(fdatasync_on_valid_fd_returns_zero as fn()),
        ),
        (
            "fsync_repeated_calls_stay_clean",
            &(fsync_repeated_calls_stay_clean as fn()),
        ),
        ("fsync_bad_fd_ebadf", &(fsync_bad_fd_ebadf as fn())),
        ("fdatasync_bad_fd_ebadf", &(fdatasync_bad_fd_ebadf as fn())),
        (
            "fsync_after_close_ebadf",
            &(fsync_after_close_ebadf as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_fsync: {}", name);
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
        ptr::write_volatile(USER_PAGE_VA as *mut u8, 0);
    }
}

fn stage(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    assert!(bytes.len() < USER_PAGE_LEN);
    unsafe {
        let dst = USER_PAGE_VA as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
    }
    USER_PAGE_VA as u64
}

fn open_with_flags(path: &[u8], flags: u32) -> i64 {
    let uva = stage(path);
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_OPEN,
            uva,
            flags as u64,
            0,
            0,
            0,
            0,
        )
    }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn fsync(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_FSYNC, fd as u64, 0, 0, 0, 0, 0) }
}

fn fdatasync(fd: i64) -> i64 {
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_FDATASYNC,
            fd as u64,
            0,
            0,
            0,
            0,
            0,
        )
    }
}

fn fsync_on_valid_fd_returns_zero() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 0, "open hostname: {}", fd);
    let r = fsync(fd);
    assert_eq!(r, 0, "fsync on valid VFS fd must succeed, got {}", r);
    close(fd);
}

fn fdatasync_on_valid_fd_returns_zero() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDWR);
    if fd < 0 {
        // Some FSes refuse RDWR on /etc/hostname; fall back to RDONLY
        // so the test still exercises the dispatch arm.
        let fd2 = open_with_flags(HOSTNAME_PATH, O_RDONLY);
        assert!(fd2 >= 0, "open hostname rdonly: {}", fd2);
        let r = fdatasync(fd2);
        assert_eq!(r, 0, "fdatasync on valid VFS fd must succeed, got {}", r);
        close(fd2);
        return;
    }
    let r = fdatasync(fd);
    assert_eq!(r, 0, "fdatasync on valid VFS fd must succeed, got {}", r);
    close(fd);
}

fn fsync_repeated_calls_stay_clean() {
    // RFC 0007 §wb_err errseq counter: with no writeback daemon (no
    // mapping wired, no #755), the inode's wb_err counter never
    // advances, so repeated fsync calls must each return zero —
    // never a stale-snapshot EIO.
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 0, "open hostname: {}", fd);
    for i in 0..4 {
        let r = fsync(fd);
        assert_eq!(r, 0, "fsync iteration {} must stay clean, got {}", i, r);
    }
    for i in 0..4 {
        let r = fdatasync(fd);
        assert_eq!(r, 0, "fdatasync iteration {} must stay clean, got {}", i, r);
    }
    close(fd);
}

fn fsync_bad_fd_ebadf() {
    let r = fsync(9999);
    assert_eq!(r, EBADF, "fsync on bad fd must return EBADF, got {}", r);
}

fn fdatasync_bad_fd_ebadf() {
    let r = fdatasync(9999);
    assert_eq!(r, EBADF, "fdatasync on bad fd must return EBADF, got {}", r);
}

fn fsync_after_close_ebadf() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 0, "open hostname: {}", fd);
    let r = close(fd);
    assert_eq!(r, 0, "close: {}", r);
    let r = fsync(fd);
    assert_eq!(r, EBADF, "fsync on closed fd must return EBADF, got {}", r);
}
