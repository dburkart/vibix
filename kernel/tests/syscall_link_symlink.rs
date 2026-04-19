//! Integration test for issue #540: `link`/`linkat`, `symlink`/
//! `symlinkat`, `readlink`/`readlinkat` wired to the existing
//! `InodeOps::link` / `InodeOps::symlink` / `InodeOps::readlink`
//! trait methods.
//!
//! The dispatcher arms for SYS_link (86), SYS_linkat (265),
//! SYS_symlink (88), SYS_symlinkat (266), SYS_readlink (89), and
//! SYS_readlinkat (267) are gated behind `#[cfg(feature =
//! "vfs_creds")]` per RFC 0004 Workstream A; until Workstream B turns
//! that feature on, those numbers fall through to the dispatcher's
//! default `-ENOSYS` arm. The shared impls (`sys_link_impl`, ...)
//! are always compiled — tests call the impl entry points directly
//! so they exercise the VFS wiring regardless of feature state.
//!
//! Coverage:
//! - `syscall_dispatch(SYS_link, ...)` returns `-ENOSYS` (anti-
//!   regression anchor for the A-before-B ordering until #546
//!   flips the gate on).
//! - `sys_symlink_impl` creates a symlink, `sys_readlink_impl` reads
//!   the bytes back — output is NOT NUL-terminated.
//! - `sys_link_impl` hard-links a regular file; the target inode's
//!   `nlink` increments (verified via `stat`).
//! - Errno coverage from RFC 0004 §Kernel-Userspace Interface:
//!   `EPERM` (link on a directory), `EEXIST` (link-path taken),
//!   `EINVAL` (readlink on a non-symlink, readlink with bufsize 0),
//!   `ENOENT` (readlink of a missing path).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::arch::x86_64::syscalls::vfs::{
    sys_link_impl, sys_mkdir_impl, sys_readlink_impl, sys_readlinkat_impl, sys_symlink_impl,
    sys_symlinkat_impl, sys_unlink_impl, sys_unlinkat_impl, AT_FDCWD, AT_REMOVEDIR,
};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::{EINVAL, ENOENT, EPERM};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_LINK: u64 = 86;
const SYS_SYMLINK: u64 = 88;
const SYS_READLINK: u64 = 89;
const SYS_STAT: u64 = 4;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;

const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;

const ENOSYS: i64 = -38;

// Two disjoint staging regions — one for the first path argument,
// one for the second. link/symlink/readlink take two user pointers,
// so we can't reuse a single staging region for both.
const USER_PAGE_A: usize = 0x0000_2006_0000_0000;
const USER_PAGE_B: usize = 0x0000_2006_0000_8000;
const USER_PAGE_C: usize = 0x0000_2006_0001_0000;
const USER_PAGE_D: usize = 0x0000_2006_0001_8000;
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
            "link_dispatcher_is_enosys_until_b_lands",
            &(link_dispatcher_is_enosys as fn()),
        ),
        (
            "symlink_dispatcher_is_enosys_until_b_lands",
            &(symlink_dispatcher_is_enosys as fn()),
        ),
        (
            "readlink_dispatcher_is_enosys_until_b_lands",
            &(readlink_dispatcher_is_enosys as fn()),
        ),
        (
            "symlink_then_readlink_round_trip",
            &(symlink_then_readlink_round_trip as fn()),
        ),
        (
            "readlink_does_not_nul_terminate",
            &(readlink_does_not_nul_terminate as fn()),
        ),
        (
            "readlink_truncates_to_bufsize",
            &(readlink_truncates_to_bufsize as fn()),
        ),
        (
            "readlink_on_regular_file_einval",
            &(readlink_on_regular_file_einval as fn()),
        ),
        (
            "readlink_bufsize_zero_einval",
            &(readlink_bufsize_zero_einval as fn()),
        ),
        (
            "readlink_missing_path_enoent",
            &(readlink_missing_path_enoent as fn()),
        ),
        ("link_increments_nlink", &(link_increments_nlink as fn())),
        (
            "link_on_directory_eperm",
            &(link_on_directory_eperm as fn()),
        ),
        (
            "symlinkat_atfdcwd_absolute",
            &(symlinkat_atfdcwd_absolute as fn()),
        ),
        (
            "readlinkat_atfdcwd_absolute",
            &(readlinkat_atfdcwd_absolute as fn()),
        ),
        (
            "link_on_symlink_default_hard_links_the_symlink",
            &(link_on_symlink_default_hard_links_the_symlink as fn()),
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
    for base in [USER_PAGE_A, USER_PAGE_B, USER_PAGE_C, USER_PAGE_D] {
        vibix::task::install_vma_on_current(Vma::new(
            base,
            base + USER_PAGE_LEN,
            0x3,
            prot_pte,
            Share::Private,
            AnonObject::new(Some(USER_PAGE_LEN / 4096)),
            0,
        ));
        unsafe {
            let dst = base as *mut u8;
            let mut i = 0;
            while i < USER_PAGE_LEN {
                ptr::write_volatile(dst.add(i), 0);
                i += 4096;
            }
        }
    }
}

fn stage_at(base: usize, bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    assert!(bytes.len() < 4096);
    unsafe {
        let dst = base as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
        ptr::write_volatile(dst.add(bytes.len()), 0);
    }
    base as u64
}

fn stage_a(bytes: &[u8]) -> u64 {
    stage_at(USER_PAGE_A, bytes)
}
fn stage_b(bytes: &[u8]) -> u64 {
    stage_at(USER_PAGE_B, bytes)
}

fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    let uva = stage_a(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, flags, mode, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn stat_path(path: &[u8], statbuf: u64) -> i64 {
    let uva = stage_a(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_STAT, uva, statbuf, 0, 0, 0, 0) }
}

fn create_regular(path: &[u8]) {
    let fd = open(path, O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "create({:?}) expected fd, got {}", path, fd);
    close(fd);
}

fn cleanup(path: &[u8]) {
    let uva = stage_a(path);
    let _ = unsafe { sys_unlink_impl(uva) };
}

fn cleanup_dir(path: &[u8]) {
    let uva = stage_a(path);
    let _ = unsafe { sys_unlinkat_impl(AT_FDCWD, uva, AT_REMOVEDIR) };
}

fn create_dir(path: &[u8]) {
    let uva = stage_a(path);
    let r = unsafe { sys_mkdir_impl(uva, 0o755) };
    assert_eq!(r, 0, "mkdir({:?}) must succeed, got {}", path, r);
}

// --- A-before-B dispatcher gates ----------------------------------------

#[cfg(not(feature = "vfs_creds"))]
fn link_dispatcher_is_enosys() {
    let a = stage_a(b"/tmp/a");
    let b = stage_b(b"/tmp/b");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_LINK, a, b, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOSYS,
        "SYS_link must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}
#[cfg(feature = "vfs_creds")]
fn link_dispatcher_is_enosys() {
    let a = stage_a(b"/tmp/a");
    let b = stage_b(b"/tmp/b");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_LINK, a, b, 0, 0, 0, 0) };
    assert!(
        r != ENOSYS,
        "SYS_link dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

#[cfg(not(feature = "vfs_creds"))]
fn symlink_dispatcher_is_enosys() {
    let t = stage_a(b"target");
    let l = stage_b(b"/tmp/link");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_SYMLINK, t, l, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOSYS,
        "SYS_symlink must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}
#[cfg(feature = "vfs_creds")]
fn symlink_dispatcher_is_enosys() {
    let t = stage_a(b"target");
    let l = stage_b(b"/tmp/link-gate");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_SYMLINK, t, l, 0, 0, 0, 0) };
    assert!(
        r != ENOSYS,
        "SYS_symlink dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

#[cfg(not(feature = "vfs_creds"))]
fn readlink_dispatcher_is_enosys() {
    let p = stage_a(b"/tmp/missing");
    let b = USER_PAGE_C as u64;
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_READLINK, p, b, 64, 0, 0, 0) };
    assert_eq!(
        r, ENOSYS,
        "SYS_readlink must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}
#[cfg(feature = "vfs_creds")]
fn readlink_dispatcher_is_enosys() {
    let p = stage_a(b"/tmp/missing-gate");
    let b = USER_PAGE_C as u64;
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_READLINK, p, b, 64, 0, 0, 0) };
    assert!(
        r != ENOSYS,
        "SYS_readlink dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

// --- Impl-level coverage (always runs) ----------------------------------

fn read_staging_c(n: usize) -> alloc::vec::Vec<u8> {
    install_user_staging_vma();
    let mut out = alloc::vec::Vec::with_capacity(n);
    unsafe {
        let src = USER_PAGE_C as *const u8;
        for i in 0..n {
            out.push(ptr::read_volatile(src.add(i)));
        }
    }
    out
}

fn clear_staging_c(n: usize) {
    install_user_staging_vma();
    unsafe {
        let dst = USER_PAGE_C as *mut u8;
        for i in 0..n {
            ptr::write_volatile(dst.add(i), 0xAAu8);
        }
    }
}

fn symlink_then_readlink_round_trip() {
    cleanup(b"/tmp/sym-rt");
    let target = b"/tmp/some-target-file";
    let target_uva = stage_a(target);
    let link_uva = stage_b(b"/tmp/sym-rt");
    let r = unsafe { sys_symlink_impl(target_uva, link_uva) };
    assert_eq!(r, 0, "symlink must return 0, got {}", r);

    // Read it back. Use a generous buffer, then check we got exactly
    // the target bytes (no NUL terminator appended).
    clear_staging_c(64);
    let link_uva2 = stage_a(b"/tmp/sym-rt");
    let r = unsafe { sys_readlink_impl(link_uva2, USER_PAGE_C as u64, 64) };
    assert_eq!(
        r,
        target.len() as i64,
        "readlink must return target byte count, got {}",
        r
    );
    let got = read_staging_c(64);
    assert_eq!(
        &got[..target.len()],
        target,
        "readlink contents must match target bytes"
    );
    // The byte immediately after the returned length must be the
    // pre-filled 0xAA sentinel — readlink must NOT write a terminator.
    assert_eq!(
        got[target.len()],
        0xAA,
        "readlink must NOT NUL-terminate output (sentinel byte clobbered)"
    );

    cleanup(b"/tmp/sym-rt");
}

fn readlink_does_not_nul_terminate() {
    cleanup(b"/tmp/sym-noterm");
    let target = b"abc";
    let t = stage_a(target);
    let l = stage_b(b"/tmp/sym-noterm");
    assert_eq!(unsafe { sys_symlink_impl(t, l) }, 0);

    clear_staging_c(16);
    let l2 = stage_a(b"/tmp/sym-noterm");
    let r = unsafe { sys_readlink_impl(l2, USER_PAGE_C as u64, 16) };
    assert_eq!(r, 3, "readlink must return 3 for 3-byte target, got {}", r);
    let got = read_staging_c(16);
    assert_eq!(&got[..3], b"abc");
    // Bytes 3..16 must remain untouched (0xAA sentinel). Confirms
    // readlink writes exactly `n` bytes, nothing else.
    for i in 3..16 {
        assert_eq!(
            got[i], 0xAA,
            "readlink wrote past returned length at byte {}",
            i
        );
    }
    cleanup(b"/tmp/sym-noterm");
}

fn readlink_truncates_to_bufsize() {
    cleanup(b"/tmp/sym-trunc");
    let target = b"0123456789abcdef"; // 16 bytes
    let t = stage_a(target);
    let l = stage_b(b"/tmp/sym-trunc");
    assert_eq!(unsafe { sys_symlink_impl(t, l) }, 0);

    clear_staging_c(16);
    let l2 = stage_a(b"/tmp/sym-trunc");
    // bufsize = 4 → expect truncation to 4 bytes.
    let r = unsafe { sys_readlink_impl(l2, USER_PAGE_C as u64, 4) };
    assert_eq!(r, 4, "readlink must truncate to bufsize, got {}", r);
    let got = read_staging_c(16);
    assert_eq!(&got[..4], b"0123");
    for i in 4..16 {
        assert_eq!(got[i], 0xAA, "readlink wrote past bufsize at byte {}", i);
    }
    cleanup(b"/tmp/sym-trunc");
}

fn readlink_on_regular_file_einval() {
    create_regular(b"/tmp/not-a-link");
    let p = stage_a(b"/tmp/not-a-link");
    let r = unsafe { sys_readlink_impl(p, USER_PAGE_C as u64, 64) };
    assert_eq!(
        r, EINVAL,
        "readlink on a regular file must EINVAL, got {}",
        r
    );
    cleanup(b"/tmp/not-a-link");
}

fn readlink_bufsize_zero_einval() {
    create_regular(b"/tmp/bufsize-zero-anchor");
    let p = stage_a(b"/tmp/bufsize-zero-anchor");
    let r = unsafe { sys_readlink_impl(p, USER_PAGE_C as u64, 0) };
    assert_eq!(r, EINVAL, "readlink(bufsize=0) must EINVAL, got {}", r);
    cleanup(b"/tmp/bufsize-zero-anchor");
}

fn readlink_missing_path_enoent() {
    let p = stage_a(b"/tmp/definitely-not-there-540");
    let r = unsafe { sys_readlink_impl(p, USER_PAGE_C as u64, 64) };
    assert_eq!(r, ENOENT, "readlink of missing path must ENOENT, got {}", r);
}

fn read_stat_from_d() -> Stat {
    install_user_staging_vma();
    let mut st = Stat::default();
    unsafe {
        let src = USER_PAGE_D as *const u8;
        let dst = &mut st as *mut Stat as *mut u8;
        for i in 0..core::mem::size_of::<Stat>() {
            ptr::write_volatile(dst.add(i), ptr::read_volatile(src.add(i)));
        }
    }
    st
}

fn link_increments_nlink() {
    cleanup(b"/tmp/link-src");
    cleanup(b"/tmp/link-dst");
    create_regular(b"/tmp/link-src");

    // Stat buffer is a user-VA staging page (USER_PAGE_D); `stat(2)`
    // goes through `copy_to_user` which rejects a kernel-stack pointer
    // under SMAP. Read the bytes back into a local Stat after each call.
    assert_eq!(stat_path(b"/tmp/link-src", USER_PAGE_D as u64), 0);
    let st_before = read_stat_from_d();

    let old_uva = stage_a(b"/tmp/link-src");
    let new_uva = stage_b(b"/tmp/link-dst");
    let r = unsafe { sys_link_impl(old_uva, new_uva) };
    assert_eq!(r, 0, "link must return 0, got {}", r);

    assert_eq!(stat_path(b"/tmp/link-src", USER_PAGE_D as u64), 0);
    let st_after = read_stat_from_d();
    assert_eq!(
        st_after.st_nlink,
        st_before.st_nlink + 1,
        "link must increment nlink (before={}, after={})",
        st_before.st_nlink,
        st_after.st_nlink
    );

    // Both names point at the same ino.
    assert_eq!(stat_path(b"/tmp/link-dst", USER_PAGE_D as u64), 0);
    let st_dst = read_stat_from_d();
    assert_eq!(
        st_dst.st_ino, st_after.st_ino,
        "hard link must share ino with source"
    );

    cleanup(b"/tmp/link-dst");
    cleanup(b"/tmp/link-src");
}

fn link_on_directory_eperm() {
    cleanup_dir(b"/tmp/link-dir-src");
    cleanup(b"/tmp/link-dir-dst");
    create_dir(b"/tmp/link-dir-src");
    let old_uva = stage_a(b"/tmp/link-dir-src");
    let new_uva = stage_b(b"/tmp/link-dir-dst");
    let r = unsafe { sys_link_impl(old_uva, new_uva) };
    assert_eq!(r, EPERM, "link on a directory source must EPERM, got {}", r);
    cleanup_dir(b"/tmp/link-dir-src");
}

fn symlinkat_atfdcwd_absolute() {
    cleanup(b"/tmp/symat");
    let t = stage_a(b"abc");
    let l = stage_b(b"/tmp/symat");
    let r = unsafe { sys_symlinkat_impl(t, AT_FDCWD, l) };
    assert_eq!(r, 0, "symlinkat(AT_FDCWD, abs) must return 0, got {}", r);
    cleanup(b"/tmp/symat");
}

fn readlinkat_atfdcwd_absolute() {
    cleanup(b"/tmp/rlat");
    let t = stage_a(b"xyz");
    let l = stage_b(b"/tmp/rlat");
    assert_eq!(unsafe { sys_symlink_impl(t, l) }, 0);

    clear_staging_c(16);
    let l2 = stage_a(b"/tmp/rlat");
    let r = unsafe { sys_readlinkat_impl(AT_FDCWD, l2, USER_PAGE_C as u64, 16) };
    assert_eq!(r, 3, "readlinkat must return 3, got {}", r);
    let got = read_staging_c(16);
    assert_eq!(&got[..3], b"xyz");
    cleanup(b"/tmp/rlat");
}

/// Regression for CodeRabbit finding: default POSIX `link(2)` on a
/// symlink source must hard-link the symlink itself, not return ELOOP.
/// Without `AT_SYMLINK_FOLLOW` the source must resolve to the terminal
/// symlink inode, not chase through it.
fn link_on_symlink_default_hard_links_the_symlink() {
    cleanup(b"/tmp/lk-sym-src");
    cleanup(b"/tmp/lk-sym-dst");

    // Create /tmp/lk-sym-src as a symlink pointing at a nonexistent
    // target. A real target isn't needed: the default `link(2)` walk
    // must never dereference the terminal symlink, so the target's
    // existence is irrelevant.
    let t = stage_a(b"/nowhere");
    let l = stage_b(b"/tmp/lk-sym-src");
    assert_eq!(
        unsafe { sys_symlink_impl(t, l) },
        0,
        "setup: symlink must succeed"
    );

    // Default link: must succeed (not ELOOP). The new name points at
    // the symlink inode itself.
    let old_uva = stage_a(b"/tmp/lk-sym-src");
    let new_uva = stage_b(b"/tmp/lk-sym-dst");
    let r = unsafe { sys_link_impl(old_uva, new_uva) };
    assert_eq!(
        r, 0,
        "default link on a symlink source must succeed (POSIX), got {}",
        r
    );

    cleanup(b"/tmp/lk-sym-dst");
    cleanup(b"/tmp/lk-sym-src");
}
