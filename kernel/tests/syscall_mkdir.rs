//! Integration test for issue #538: `mkdir(2)` / `mkdirat(2)` wired
//! to `InodeOps::mkdir`.
//!
//! Drives the new `sys_mkdir_impl` / `sys_mkdirat_impl` entry points
//! against the RamFs root:
//!
//! - `mkdir(path, mode)` creates a directory; a subsequent `stat`
//!   returns `S_IFDIR`.
//! - Re-creating the same path returns `-EEXIST`.
//! - `mkdir` under a non-directory parent returns `-ENOTDIR`.
//! - `mkdir` under a missing parent returns `-ENOENT`.
//! - `mkdir(".")` / `mkdir("..")` / `mkdir("")` return `-ENOENT`
//!   (the leaf-normalizer rejects them).
//! - `mkdirat(AT_FDCWD, path, mode)` creates a directory.
//! - `mkdirat(some_fd, "rel/path", mode)` returns `-EINVAL` — relative
//!   paths against a real fd aren't supported until per-fd walks land
//!   (issue #239).
//!
//! The test calls `sys_mkdir_impl` / `sys_mkdirat_impl` directly rather
//! than through `syscall_dispatch`, because the dispatch arm is gated
//! behind the RFC 0004 Workstream A ↔ B feature flag `vfs_creds` and
//! would return `-ENOSYS` until Workstream B lands per-task credentials.
//! Testing the impl function gives end-to-end coverage of the VFS
//! wiring without depending on that feature being flipped.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscalls::vfs::{sys_mkdir_impl, sys_mkdirat_impl, AT_FDCWD};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::{EEXIST, EINVAL, ENOENT, ENOTDIR};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

use vibix::arch::x86_64::syscall::syscall_dispatch;

const SYS_STAT: u64 = 4;

const S_IFMT: u32 = 0o170_000;
const S_IFDIR: u32 = 0o040_000;

const USER_PAGE_VA: usize = 0x0000_2003_0000_0000;
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
            "mkdir_creates_directory",
            &(mkdir_creates_directory as fn()),
        ),
        (
            "mkdir_existing_is_eexist",
            &(mkdir_existing_is_eexist as fn()),
        ),
        (
            "mkdir_under_file_is_enotdir",
            &(mkdir_under_file_is_enotdir as fn()),
        ),
        (
            "mkdir_missing_parent_is_enoent",
            &(mkdir_missing_parent_is_enoent as fn()),
        ),
        ("mkdir_dot_is_enoent", &(mkdir_dot_is_enoent as fn())),
        (
            "mkdir_trailing_slash_ok",
            &(mkdir_trailing_slash_ok as fn()),
        ),
        (
            "mkdirat_at_fdcwd_creates_directory",
            &(mkdirat_at_fdcwd_creates_directory as fn()),
        ),
        (
            "mkdirat_real_fd_relative_path_einval",
            &(mkdirat_real_fd_relative_path_einval as fn()),
        ),
        (
            "mkdir_strips_non_permission_bits",
            &(mkdir_strips_non_permission_bits as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_mkdir: {}", name);
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

fn read_stat() -> Stat {
    unsafe { ptr::read_volatile(statbuf_uva() as *const Stat) }
}

fn mkdir(path: &[u8], mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { sys_mkdir_impl(uva, mode) }
}

fn mkdirat(dfd: i32, path: &[u8], mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { sys_mkdirat_impl(dfd, uva, mode) }
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

// --- mknod helper to synthesize a non-directory parent ----------------

const SYS_MKNOD: u64 = 133;
const S_IFREG: u64 = 0o100_000;

fn mknod_reg(path: &[u8]) -> i64 {
    let uva = stage(path);
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_MKNOD,
            uva,
            S_IFREG | 0o644,
            0,
            0,
            0,
            0,
        )
    }
}

// --- Tests -----------------------------------------------------------------

fn mkdir_creates_directory() {
    let r = mkdir(b"/tmp/mkdir-basic", 0o755);
    assert_eq!(r, 0, "mkdir must return 0, got {}", r);
    // Verify the new inode is a directory.
    let r = stat(b"/tmp/mkdir-basic");
    assert_eq!(r, 0, "stat of new dir must succeed, got {}", r);
    let st = read_stat();
    assert_eq!(
        st.st_mode & S_IFMT,
        S_IFDIR,
        "new inode must have S_IFDIR set, got mode {:#o}",
        st.st_mode
    );
}

fn mkdir_existing_is_eexist() {
    let r = mkdir(b"/tmp/mkdir-eexist", 0o755);
    assert_eq!(r, 0);
    let r = mkdir(b"/tmp/mkdir-eexist", 0o755);
    assert_eq!(
        r, EEXIST,
        "re-mkdir of existing path must EEXIST, got {}",
        r
    );
}

fn mkdir_under_file_is_enotdir() {
    // Create a regular file, then attempt to mkdir under it.
    let r = mknod_reg(b"/tmp/mkdir-notdir-parent");
    assert_eq!(r, 0);
    let r = mkdir(b"/tmp/mkdir-notdir-parent/child", 0o755);
    assert_eq!(
        r, ENOTDIR,
        "mkdir under non-dir parent must ENOTDIR, got {}",
        r
    );
}

fn mkdir_missing_parent_is_enoent() {
    let r = mkdir(b"/tmp/nonexistent-parent-xyz/child", 0o755);
    assert_eq!(
        r, ENOENT,
        "mkdir under missing parent must ENOENT, got {}",
        r
    );
}

fn mkdir_dot_is_enoent() {
    // The leaf-normalizer in split_parent rejects ".", "..", and the
    // empty string — they can't be nameable leaves. The normalizer runs
    // *before* the EEXIST fast path, so these must always return ENOENT
    // (never EEXIST, even though `/tmp/.` resolves to the existing
    // `/tmp` inode).
    let r = mkdir(b"/tmp/.", 0o755);
    assert_eq!(r, ENOENT, "mkdir('/tmp/.') must ENOENT, got {}", r);
    let r = mkdir(b"/tmp/..", 0o755);
    assert_eq!(r, ENOENT, "mkdir('/tmp/..') must ENOENT, got {}", r);
    let r = mkdir(b"", 0o755);
    assert_eq!(r, ENOENT, "mkdir('') must ENOENT, got {}", r);
}

fn mkdir_trailing_slash_ok() {
    // POSIX: "mkdir(path)" with a trailing slash on `path` is equivalent
    // to mkdir without it. `split_parent` strips it for us.
    let r = mkdir(b"/tmp/mkdir-trailing/", 0o755);
    assert_eq!(r, 0, "mkdir with trailing slash must succeed, got {}", r);
    // Confirm the resulting inode is a directory.
    let r = stat(b"/tmp/mkdir-trailing");
    assert_eq!(r, 0);
    let st = read_stat();
    assert_eq!(st.st_mode & S_IFMT, S_IFDIR);
}

fn mkdirat_at_fdcwd_creates_directory() {
    let r = mkdirat(AT_FDCWD, b"/tmp/mkdirat-fdcwd", 0o755);
    assert_eq!(r, 0, "mkdirat(AT_FDCWD, abs) must return 0, got {}", r);
    let r = stat(b"/tmp/mkdirat-fdcwd");
    assert_eq!(r, 0);
    let st = read_stat();
    assert_eq!(st.st_mode & S_IFMT, S_IFDIR);
}

fn mkdirat_real_fd_relative_path_einval() {
    // Per-fd walks don't exist yet (#239) — a real fd + relative path
    // must bounce with -EINVAL, not silently walk from somewhere else.
    let r = mkdirat(3, b"rel/child", 0o755);
    assert_eq!(
        r, EINVAL,
        "mkdirat(real_fd, relative) must EINVAL, got {}",
        r
    );
}

fn mkdir_strips_non_permission_bits() {
    // Caller may (incorrectly) OR a type bit into `mode`; we strip it.
    // The new inode's mode must carry permission bits only — the VFS
    // layer sets S_IFDIR itself.
    let mode = 0o040_000 | 0o755; // S_IFDIR | 0o755
    let r = mkdir(b"/tmp/mkdir-strip", mode);
    assert_eq!(r, 0, "mkdir must ignore spurious type bits, got {}", r);
    let r = stat(b"/tmp/mkdir-strip");
    assert_eq!(r, 0);
    let st = read_stat();
    assert_eq!(
        st.st_mode & S_IFMT,
        S_IFDIR,
        "type bits come from VFS, not caller"
    );
    assert_eq!(
        st.st_mode & 0o7777,
        0o755,
        "permission bits must match caller's masked mode"
    );
}
