//! Integration test for issue #539 / RFC 0004 Workstream A:
//! `rmdir(2)` wired to `InodeOps::rmdir`.
//!
//! Drives the SYS_RMDIR dispatch arm end-to-end through the `/tmp`
//! ramfs mount. The test pre-populates directory state via the ramfs
//! `InodeOps::mkdir` (since the `mkdir` syscall is a separate wiring
//! issue, #538) and then verifies that the syscall path:
//!
//! - Removes an empty directory successfully (`rc == 0`).
//! - Returns `ENOTEMPTY` when the target contains entries.
//! - Returns `ENOENT` on a missing name.
//! - Returns `ENOTDIR` when the target is a regular file.
//! - Rejects `rmdir(".")` with `EINVAL`.
//! - Rejects `rmdir("..")` with `ENOTEMPTY` (Linux convention).
//! - Refuses to remove the mount root (`rmdir("/")` → `EBUSY`).
//! - Accepts and normalises a trailing-slash path.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::vfs::path_walk::{path_walk, LookupFlags, NameIdata};
use vibix::fs::vfs::{Credential, GlobalMountResolver, Inode};
use vibix::fs::{EBUSY, EINVAL, ENOENT, ENOTDIR, ENOTEMPTY};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_RMDIR: u64 = 84;

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
            "rmdir_removes_empty_dir",
            &(rmdir_removes_empty_dir as fn()),
        ),
        ("rmdir_enotempty", &(rmdir_enotempty as fn())),
        ("rmdir_enoent", &(rmdir_enoent as fn())),
        (
            "rmdir_enotdir_on_regular_file",
            &(rmdir_enotdir_on_regular_file as fn()),
        ),
        ("rmdir_dot_einval", &(rmdir_dot_einval as fn())),
        ("rmdir_dotdot_enotempty", &(rmdir_dotdot_enotempty as fn())),
        ("rmdir_root_ebusy", &(rmdir_root_ebusy as fn())),
        (
            "rmdir_trailing_slash_ok",
            &(rmdir_trailing_slash_ok as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- User-staging helpers ------------------------------------------------

const USER_PAGE_VA: usize = 0x0000_2004_0000_0000;
const USER_PAGE_LEN: usize = 4 * 4096;

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

fn stage_path(bytes: &[u8]) -> u64 {
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

fn rmdir(path: &[u8]) -> i64 {
    let uva = stage_path(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_RMDIR, uva, 0, 0, 0, 0, 0) }
}

// --- Direct VFS helpers (sidestep missing mkdir/create/unlink syscalls) --

/// Resolve `path` to an `Arc<Inode>` through `path_walk`, rooted at the
/// VFS namespace root. Panics on miss — the test authors seed only
/// known-good paths through this helper.
fn resolve(path: &[u8]) -> Arc<Inode> {
    let root = vibix::fs::vfs::root().expect("vfs root not live");
    let mut nd = NameIdata::new(
        root.clone(),
        root,
        Credential::kernel(),
        LookupFlags::default(),
    )
    .expect("seed namei");
    path_walk(&mut nd, path, &GlobalMountResolver).expect("path_walk");
    nd.path.inode.clone()
}

/// Create a subdirectory `name` under the `/tmp` ramfs root.
fn mkdir_in_tmp(name: &[u8]) -> Arc<Inode> {
    let tmp = resolve(b"/tmp");
    tmp.ops.mkdir(&tmp, name, 0o755).expect("mkdir in /tmp")
}

/// Create a regular file `name` under `/tmp` (used to drive the
/// `ENOTDIR` path — rmdir against a non-directory).
fn touch_in_tmp(name: &[u8]) {
    let tmp = resolve(b"/tmp");
    tmp.ops.create(&tmp, name, 0o644).expect("create in /tmp");
}

// --- Tests ---------------------------------------------------------------

fn rmdir_removes_empty_dir() {
    mkdir_in_tmp(b"rmdir-basic");
    let r = rmdir(b"/tmp/rmdir-basic");
    assert_eq!(r, 0, "rmdir(empty) must succeed, got {}", r);

    // Second attempt must fail because the dir is gone.
    let r = rmdir(b"/tmp/rmdir-basic");
    assert_eq!(
        r, ENOENT,
        "rmdir of already-removed dir must ENOENT, got {}",
        r
    );
}

fn rmdir_enotempty() {
    let child = mkdir_in_tmp(b"rmdir-enotempty");
    child
        .ops
        .create(&child, b"inner", 0o644)
        .expect("create inner");
    let r = rmdir(b"/tmp/rmdir-enotempty");
    assert_eq!(r, ENOTEMPTY, "rmdir(non-empty) must ENOTEMPTY, got {}", r);
}

fn rmdir_enoent() {
    let r = rmdir(b"/tmp/never-existed");
    assert_eq!(r, ENOENT, "rmdir(missing) must ENOENT, got {}", r);
}

fn rmdir_enotdir_on_regular_file() {
    touch_in_tmp(b"rmdir-regfile");
    let r = rmdir(b"/tmp/rmdir-regfile");
    assert_eq!(r, ENOTDIR, "rmdir(regfile) must ENOTDIR, got {}", r);
}

fn rmdir_dot_einval() {
    let r = rmdir(b".");
    assert_eq!(r, EINVAL, "rmdir(\".\") must EINVAL, got {}", r);

    // Also with a parent component ("foo/.").
    mkdir_in_tmp(b"rmdir-dot-parent");
    let r = rmdir(b"/tmp/rmdir-dot-parent/.");
    assert_eq!(r, EINVAL, "rmdir(\"/tmp/.../.\") must EINVAL, got {}", r);
    // Clean up.
    let r = rmdir(b"/tmp/rmdir-dot-parent");
    assert_eq!(r, 0, "cleanup rmdir failed: {}", r);
}

fn rmdir_dotdot_enotempty() {
    let r = rmdir(b"..");
    assert_eq!(r, ENOTEMPTY, "rmdir(\"..\") must ENOTEMPTY, got {}", r);

    mkdir_in_tmp(b"rmdir-dotdot-parent");
    let r = rmdir(b"/tmp/rmdir-dotdot-parent/..");
    assert_eq!(r, ENOTEMPTY, "rmdir(\".../..\") must ENOTEMPTY, got {}", r);
    // Clean up.
    let r = rmdir(b"/tmp/rmdir-dotdot-parent");
    assert_eq!(r, 0, "cleanup rmdir failed: {}", r);
}

fn rmdir_root_ebusy() {
    let r = rmdir(b"/");
    assert_eq!(r, EBUSY, "rmdir(\"/\") must EBUSY, got {}", r);
}

fn rmdir_trailing_slash_ok() {
    mkdir_in_tmp(b"rmdir-trailing");
    let r = rmdir(b"/tmp/rmdir-trailing/");
    assert_eq!(
        r, 0,
        "rmdir with trailing slash on empty dir must succeed, got {}",
        r
    );
}
