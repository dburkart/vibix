//! Integration test for issue #238: VFS-backed path syscalls — `open`,
//! `openat`, `stat`, `fstat`, `lstat`, `newfstatat`.
//!
//! Exercises the syscall dispatcher arms end-to-end through real
//! ramfs/devfs mounts on the booted kernel. The path_walk resolver is
//! the production `GlobalMountResolver`; the fd table is the one
//! `task::init()` wires up for the boot task.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::vfs::ops::Stat;
use vibix::fs::{EBADF, EINVAL, ENAMETOOLONG, ENOENT, ENOTDIR};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_OPEN: u64 = 2;
const SYS_STAT: u64 = 4;
const SYS_FSTAT: u64 = 5;
const SYS_LSTAT: u64 = 6;
const SYS_CLOSE: u64 = 3;
const SYS_OPENAT: u64 = 257;
const SYS_NEWFSTATAT: u64 = 262;
const SYS_GETCWD: u64 = 79;
const SYS_CHDIR: u64 = 80;

const AT_FDCWD_U64: u64 = (-100i64) as u64;

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
        ("stat_root_returns_dir", &(stat_root_returns_dir as fn())),
        ("stat_enoent_on_missing", &(stat_enoent_on_missing as fn())),
        ("fstat_ebadf_on_closed", &(fstat_ebadf_on_closed as fn())),
        (
            "openat_atfdcwd_absolute",
            &(openat_atfdcwd_absolute as fn()),
        ),
        (
            "openat_rejects_relative_without_atfdcwd",
            &(openat_rejects_relative_without_atfdcwd as fn()),
        ),
        (
            "newfstatat_rejects_unknown_flag",
            &(newfstatat_rejects_unknown_flag as fn()),
        ),
        (
            "newfstatat_empty_path_needs_at_empty_path",
            &(newfstatat_empty_path_needs_at_empty_path as fn()),
        ),
        (
            "lstat_same_as_stat_on_dir",
            &(lstat_same_as_stat_on_dir as fn()),
        ),
        (
            "open_o_directory_on_nondir_enotdir",
            &(open_o_directory_on_nondir_enotdir as fn()),
        ),
        ("getcwd_returns_root", &(getcwd_returns_root as fn())),
        ("getcwd_enametoolong", &(getcwd_enametoolong as fn())),
        ("chdir_changes_cwd", &(chdir_changes_cwd as fn())),
        (
            "chdir_rejects_non_directory",
            &(chdir_rejects_non_directory as fn()),
        ),
        (
            "chdir_enoent_on_missing",
            &(chdir_enoent_on_missing as fn()),
        ),
        (
            "stat_enametoolong_on_overlong_path",
            &(stat_enametoolong_on_overlong_path as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- User-staging helpers ------------------------------------------------

const USER_PAGE_VA: usize = 0x0000_2000_0000_0000;
const USER_PAGE_LEN: usize = 8 * 4096;

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
        // Touch every page to force demand-fault before any syscall
        // runs against these VAs.
        let dst = USER_PAGE_VA as *mut u8;
        let mut i = 0;
        while i < USER_PAGE_LEN {
            ptr::write_volatile(dst.add(i), 0);
            i += 4096;
        }
    }
}

/// Copy a NUL-terminated path into the staging page at offset 0.
fn stage_path(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    // Leave room for the staging page's `struct stat` half at +4096 so
    // overlong-path tests (PATH_MAX = 4096) don't collide with it.
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

/// Reserve the second half of the staging page as a `struct stat`
/// destination so path + stat live on the same VA.
fn statbuf_uva() -> u64 {
    install_user_staging_vma();
    (USER_PAGE_VA + 4096) as u64
}

fn read_stat() -> Stat {
    unsafe { ptr::read_volatile(statbuf_uva() as *const Stat) }
}

// --- Tests ---------------------------------------------------------------

fn stat_root_returns_dir() {
    let path = stage_path(b"/");
    let r = unsafe { syscall_dispatch(SYS_STAT, path, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r, 0, "stat(\"/\") should succeed, got {}", r);
    let st = read_stat();
    // S_IFDIR == 0o040_000.
    assert_eq!(
        st.st_mode & 0o170_000,
        0o040_000,
        "root should be a directory, st_mode={:#o}",
        st.st_mode
    );
}

fn stat_enoent_on_missing() {
    let path = stage_path(b"/no-such-thing");
    let r = unsafe { syscall_dispatch(SYS_STAT, path, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r, ENOENT, "expected ENOENT, got {}", r);
}

fn fstat_ebadf_on_closed() {
    let r = unsafe { syscall_dispatch(SYS_FSTAT, 9999, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r, EBADF, "expected EBADF on closed fd, got {}", r);
}

fn openat_atfdcwd_absolute() {
    // /dev/serial is a legacy-compat path, served by the SerialBackend
    // fast path in both `open` and `openat`.
    let path = stage_path(b"/dev/serial");
    let fd = unsafe { syscall_dispatch(SYS_OPENAT, AT_FDCWD_U64, path, 2, 0, 0, 0) };
    assert!(fd >= 3, "openat(/dev/serial) should give fd>=3, got {}", fd);
    let cr = unsafe { syscall_dispatch(SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) };
    assert_eq!(cr, 0, "close fresh fd failed: {}", cr);
}

fn openat_rejects_relative_without_atfdcwd() {
    // dfd != AT_FDCWD and path is relative: no per-process cwd yet, so
    // return EINVAL rather than silently treating dfd as ignored.
    let path = stage_path(b"relative/path");
    let r = unsafe { syscall_dispatch(SYS_OPENAT, 5u64, path, 0, 0, 0, 0) };
    assert_eq!(r, EINVAL, "expected EINVAL, got {}", r);
}

fn newfstatat_rejects_unknown_flag() {
    // 0x40000 is AT_RECURSIVE — not a flag we know, must be rejected.
    let path = stage_path(b"/");
    let r = unsafe {
        syscall_dispatch(
            SYS_NEWFSTATAT,
            AT_FDCWD_U64,
            path,
            statbuf_uva(),
            0x40000,
            0,
            0,
        )
    };
    assert_eq!(r, EINVAL, "unknown flag must yield EINVAL, got {}", r);
}

fn newfstatat_empty_path_needs_at_empty_path() {
    // Empty path without AT_EMPTY_PATH → ENOENT from path_walk.
    let path = stage_path(b"");
    let r = unsafe { syscall_dispatch(SYS_NEWFSTATAT, AT_FDCWD_U64, path, statbuf_uva(), 0, 0, 0) };
    assert_eq!(
        r, ENOENT,
        "empty path without AT_EMPTY_PATH → ENOENT, got {}",
        r
    );
}

fn lstat_same_as_stat_on_dir() {
    // With no symlinks in play, lstat(/) == stat(/).
    let path = stage_path(b"/");
    let r1 = unsafe { syscall_dispatch(SYS_STAT, path, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r1, 0);
    let st1 = read_stat();

    let path2 = stage_path(b"/");
    let r2 = unsafe { syscall_dispatch(SYS_LSTAT, path2, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r2, 0);
    let st2 = read_stat();
    assert_eq!(st1.st_ino, st2.st_ino);
    assert_eq!(st1.st_mode, st2.st_mode);
}

fn stat_enametoolong_on_overlong_path() {
    // VFS PATH_MAX is 4096. A user path of 4097 non-NUL bytes means
    // `copy_path_from_user` fills the whole kernel buffer (4096 + 1)
    // without seeing a NUL and must return ENAMETOOLONG. Stage the path
    // at page 4 of USER_PAGE_VA so it doesn't collide with the stat
    // destination at page 1.
    install_user_staging_vma();
    const OVERLONG: usize = 4097;
    let path_uva = (USER_PAGE_VA + 4 * 4096) as u64;
    unsafe {
        let dst = path_uva as *mut u8;
        let mut i = 0;
        while i < OVERLONG {
            ptr::write_volatile(dst.add(i), b'a');
            i += 1;
        }
        // Trailing NUL beyond PATH_MAX — the copy-in should stop with
        // ENAMETOOLONG before ever reading this byte.
        ptr::write_volatile(dst.add(OVERLONG), 0);
    }
    let r = unsafe { syscall_dispatch(SYS_STAT, path_uva, statbuf_uva(), 0, 0, 0, 0) };
    assert_eq!(r, ENAMETOOLONG, "expected ENAMETOOLONG, got {}", r);
}

fn open_o_directory_on_nondir_enotdir() {
    // /dev/serial is a character file via SerialBackend; but since the
    // legacy fast-path bypasses the VFS and returns a SerialBackend fd
    // directly, O_DIRECTORY can't be checked there. Use a devfs file
    // that is a real char inode: /dev/null.
    //
    // Actually since devfs is mounted at /dev and exposes null/zero/
    // console/tty as char inodes, /dev/null with O_DIRECTORY must
    // return ENOTDIR.
    const O_DIRECTORY: u64 = 0o200000;
    let path = stage_path(b"/dev/null");
    let r = unsafe { syscall_dispatch(SYS_OPEN, path, O_DIRECTORY, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOTDIR,
        "O_DIRECTORY on char file must be ENOTDIR, got {}",
        r
    );
}

// --- getcwd / chdir tests ------------------------------------------------

/// Staging area for getcwd output: second 4 KiB page of the user staging VA.
fn cwdbuf_uva() -> u64 {
    install_user_staging_vma();
    (USER_PAGE_VA + 2 * 4096) as u64
}

fn getcwd_returns_root() {
    // At boot, no chdir has been called, so cwd falls back to the VFS root.
    // getcwd should return "/\0" (2 bytes), return value 2.
    let r = unsafe { syscall_dispatch(SYS_GETCWD, cwdbuf_uva(), 4096, 0, 0, 0, 0) };
    assert!(r > 0, "getcwd should succeed, got {}", r);
    let buf = cwdbuf_uva() as *const u8;
    let first = unsafe { ptr::read_volatile(buf) };
    assert_eq!(
        first, b'/',
        "getcwd result should start with '/', got {}",
        first
    );
    let second = unsafe { ptr::read_volatile(buf.add(1)) };
    assert_eq!(
        second, 0,
        "getcwd of root should be '/\\0' (second byte NUL), got {}",
        second
    );
    assert_eq!(
        r, 2,
        "getcwd('/') should return 2 (length including NUL), got {}",
        r
    );
}

fn getcwd_enametoolong() {
    // Buffer length 1 is too small for even "/\0" (needs 2).
    let r = unsafe { syscall_dispatch(SYS_GETCWD, cwdbuf_uva(), 1, 0, 0, 0, 0) };
    let enametoolong: i64 = -36;
    assert_eq!(
        r, enametoolong,
        "getcwd with len=1 must return ENAMETOOLONG, got {}",
        r
    );
}

fn chdir_changes_cwd() {
    // chdir to /dev (which is mounted as devfs) should succeed and
    // cause getcwd to return "/dev\0".
    let path = stage_path(b"/dev");
    let r = unsafe { syscall_dispatch(SYS_CHDIR, path, 0, 0, 0, 0, 0) };
    assert_eq!(r, 0, "chdir(\"/dev\") should succeed, got {}", r);

    let r2 = unsafe { syscall_dispatch(SYS_GETCWD, cwdbuf_uva(), 4096, 0, 0, 0, 0) };
    assert!(r2 > 0, "getcwd after chdir should succeed, got {}", r2);

    let expected = b"/dev\0";
    let buf = cwdbuf_uva() as *const u8;
    for (i, &b) in expected.iter().enumerate() {
        let got = unsafe { ptr::read_volatile(buf.add(i)) };
        assert_eq!(got, b, "getcwd byte[{}]: expected {}, got {}", i, b, got);
    }

    // Restore cwd to root for subsequent tests.
    let root_path = stage_path(b"/");
    let _ = unsafe { syscall_dispatch(SYS_CHDIR, root_path, 0, 0, 0, 0, 0) };
}

fn chdir_rejects_non_directory() {
    // chdir to a non-directory (e.g. /dev/null is a char inode) must
    // return ENOTDIR.
    let path = stage_path(b"/dev/null");
    let r = unsafe { syscall_dispatch(SYS_CHDIR, path, 0, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOTDIR,
        "chdir to non-dir must return ENOTDIR, got {}",
        r
    );
}

fn chdir_enoent_on_missing() {
    let path = stage_path(b"/no-such-dir");
    let r = unsafe { syscall_dispatch(SYS_CHDIR, path, 0, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOENT,
        "chdir to missing path must return ENOENT, got {}",
        r
    );
}
