//! Integration test for issue #539: `unlink(2)` / `unlinkat(2)` wired
//! to `InodeOps::unlink` / `InodeOps::rmdir` (via `AT_REMOVEDIR`).
//!
//! The dispatcher arms for SYS_unlink (87) and SYS_unlinkat (263) are
//! gated behind `#[cfg(feature = "vfs_creds")]` per RFC 0004 Workstream
//! A; until Workstream B turns that feature on, both numbers fall
//! through to the dispatcher's default `-ENOSYS` arm. The shared impl
//! (`sys_unlink_impl` / `sys_unlinkat_impl`) is always compiled — tests
//! call the impl entry points directly so they exercise the VFS wiring
//! regardless of feature state, mirroring the convention established
//! by `sys_mkdir_impl` in #585.
//!
//! Coverage:
//! - `syscall_dispatch(SYS_unlink, ...)` returns `-ENOSYS` (the
//!   anti-regression anchor for the A-before-B ordering until #546
//!   flips the gate on).
//! - `sys_unlink_impl` removes a regular file; subsequent `stat`
//!   misses with `-ENOENT`.
//! - Errno table from RFC 0004 §Kernel-Userspace Interface:
//!   `EISDIR` (unlink on dir), `ENOTDIR` (rmdir on file), `ENOENT`
//!   (missing), `EINVAL` (unknown flag bit).
//! - `sys_unlinkat_impl(AT_REMOVEDIR)` dispatches to `rmdir` on an
//!   empty directory.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::arch::x86_64::syscalls::vfs::{
    sys_mkdir_impl, sys_unlink_impl, sys_unlinkat_impl, AT_FDCWD, AT_REMOVEDIR,
};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::{EINVAL, EISDIR, ENOENT, ENOTDIR};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_UNLINK: u64 = 87;
const SYS_STAT: u64 = 4;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;

const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;

const ENOSYS: i64 = -38;

const USER_PAGE_VA: usize = 0x0000_2004_0000_0000;
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
            "unlink_dispatcher_is_enosys_until_b_lands",
            &(unlink_dispatcher_is_enosys as fn()),
        ),
        (
            "unlink_removes_regular_file",
            &(unlink_removes_regular_file as fn()),
        ),
        (
            "unlink_on_missing_enoent",
            &(unlink_on_missing_enoent as fn()),
        ),
        ("unlink_on_dir_eisdir", &(unlink_on_dir_eisdir as fn())),
        (
            "unlinkat_atfdcwd_absolute",
            &(unlinkat_atfdcwd_absolute as fn()),
        ),
        (
            "unlinkat_at_removedir_on_dir",
            &(unlinkat_at_removedir_on_dir as fn()),
        ),
        (
            "unlinkat_at_removedir_on_file_enotdir",
            &(unlinkat_at_removedir_on_file_enotdir as fn()),
        ),
        (
            "unlinkat_rejects_unknown_flag",
            &(unlinkat_rejects_unknown_flag as fn()),
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

fn unlink(path: &[u8]) -> i64 {
    let uva = stage(path);
    unsafe { sys_unlink_impl(uva) }
}

fn unlinkat(dfd: i32, path: &[u8], flags: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_unlinkat_impl(dfd, uva, flags) }
}

fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, flags, mode, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn stat(path: &[u8], statbuf: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_STAT, uva, statbuf, 0, 0, 0, 0) }
}

fn create_regular(path: &[u8]) {
    let fd = open(path, O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "create({:?}) expected fd, got {}", path, fd);
    close(fd);
}

/// Seed a directory under `/tmp` (which is RamFs and writable). The
/// root `/` is TarFs at boot and refuses mkdir, so all directory
/// fixtures must live under `/tmp`.
fn create_dir(path: &[u8]) {
    let uva = stage(path);
    let r = unsafe { sys_mkdir_impl(uva, 0o755) };
    assert_eq!(r, 0, "mkdir({:?}) must succeed, got {}", path, r);
}

// --- A-before-B dispatcher gate -----------------------------------------

/// The RFC 0004 A-before-B ordering: until Workstream B's terminal PR
/// flips `vfs_creds` on, the SYS_unlink dispatcher arm is absent and
/// the syscall number falls through to the `-ENOSYS` default. A
/// non-ENOSYS return from the dispatcher under the default feature set
/// would mean the gate is leaking — block that regression here.
#[cfg(not(feature = "vfs_creds"))]
fn unlink_dispatcher_is_enosys() {
    let uva = stage(b"/tmp/anything");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_UNLINK, uva, 0, 0, 0, 0, 0) };
    assert_eq!(
        r, ENOSYS,
        "SYS_unlink must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}

/// With the feature on, the same dispatcher arm wires through to the
/// impl — confirm it is no longer ENOSYS (any other return is fine
/// because the path may or may not exist).
#[cfg(feature = "vfs_creds")]
fn unlink_dispatcher_is_enosys() {
    let uva = stage(b"/tmp/anything");
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_UNLINK, uva, 0, 0, 0, 0, 0) };
    assert!(
        r != ENOSYS,
        "SYS_unlink dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

// --- Impl-level coverage (always runs, regardless of feature) -----------

fn unlink_removes_regular_file() {
    create_regular(b"/tmp/unlink-target");
    let r = unlink(b"/tmp/unlink-target");
    assert_eq!(r, 0, "unlink on live regular file must return 0, got {}", r);
    // Follow-up stat must now miss.
    let mut sb = Stat::default();
    let r = stat(b"/tmp/unlink-target", &mut sb as *mut Stat as usize as u64);
    assert_eq!(r, ENOENT, "stat after unlink must ENOENT, got {}", r);
}

fn unlink_on_missing_enoent() {
    let r = unlink(b"/tmp/no-such-file-for-unlink");
    assert_eq!(r, ENOENT, "unlink of missing path must ENOENT, got {}", r);
}

fn unlink_on_dir_eisdir() {
    // `/tmp` itself is a mountpoint (the boot init mounts ramfs there,
    // see fs/vfs/init.rs) so unlink against `/tmp` returns EBUSY before
    // the kind dispatch. Seed a plain non-mountpoint directory under
    // `/tmp/` (which is the writable RamFs leg) to exercise the EISDIR
    // arm specifically.
    create_dir(b"/tmp/eisdir-target");
    let r = unlink(b"/tmp/eisdir-target");
    assert_eq!(r, EISDIR, "unlink on a directory must EISDIR, got {}", r);
    // Clean up via rmdir (AT_REMOVEDIR) so the test is idempotent.
    let _ = unlinkat(AT_FDCWD, b"/tmp/eisdir-target", AT_REMOVEDIR);
}

fn unlinkat_atfdcwd_absolute() {
    create_regular(b"/tmp/unlinkat-target");
    let r = unlinkat(AT_FDCWD, b"/tmp/unlinkat-target", 0);
    assert_eq!(r, 0, "unlinkat on live file must return 0, got {}", r);
}

fn unlinkat_at_removedir_on_dir() {
    // Seed a fresh subdirectory under `/tmp/` (the RamFs leg). The root
    // `/` is TarFs at boot and refuses mkdir, so directory fixtures must
    // live on RamFs.
    create_dir(b"/tmp/rmdir-target");
    let r = unlinkat(AT_FDCWD, b"/tmp/rmdir-target", AT_REMOVEDIR);
    assert_eq!(
        r, 0,
        "unlinkat(AT_REMOVEDIR) on empty dir must return 0, got {}",
        r
    );
}

fn unlinkat_at_removedir_on_file_enotdir() {
    create_regular(b"/tmp/rmdir-on-file");
    let r = unlinkat(AT_FDCWD, b"/tmp/rmdir-on-file", AT_REMOVEDIR);
    assert_eq!(
        r, ENOTDIR,
        "unlinkat(AT_REMOVEDIR) on a regular file must ENOTDIR, got {}",
        r
    );
    // Clean up.
    let _ = unlink(b"/tmp/rmdir-on-file");
}

fn unlinkat_rejects_unknown_flag() {
    // 0x8000 is not a defined `at_*` flag. Must be rejected with EINVAL.
    let r = unlinkat(AT_FDCWD, b"/tmp/anything", 0x8000);
    assert_eq!(
        r, EINVAL,
        "unlinkat must reject unknown flags with EINVAL, got {}",
        r
    );
}
