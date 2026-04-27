//! Integration test for issue #545: `access(2)` / `faccessat(2)` /
//! `faccessat2(2)` wired through `InodeOps::permission` with the POSIX
//! real-vs-effective UID distinction.
//!
//! Each impl is compiled unconditionally; the syscall dispatch arms
//! are gated behind `#[cfg(feature = "vfs_creds")]` per RFC 0004's
//! A-before-B ordering. Tests call `sys_*_impl` directly so the VFS
//! wiring is exercised regardless of feature state, mirroring the
//! mkdir/unlink/chmod convention.
//!
//! Coverage per the issue contract:
//! - `F_OK` on an existing file succeeds; on a missing path → `ENOENT`.
//! - `R_OK` / `W_OK` / `X_OK` round-trip against `default_permission`.
//! - A task with `ruid != euid` (the setuid-binary scenario) gets
//!   different answers from `access` (real ID) and `faccessat(...,
//!   AT_EACCESS)` (effective ID) — the central distinguishing feature.
//! - Unknown flag bits → `EINVAL`.
//! - Mode bits outside `R_OK | W_OK | X_OK` → `EINVAL`.
//! - Relative path with `dfd != AT_FDCWD` → `EINVAL` (per-fd dirfd
//!   resolution is tracked under #239).
//! - `faccessat2` returns the same answer as `faccessat` for
//!   well-formed inputs.
//! - Dispatch arms return `-ENOSYS` until `vfs_creds` flips on.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::{syscall_dispatch, syscall_nr};
use vibix::arch::x86_64::syscalls::vfs::{
    sys_access_impl, sys_chmod_impl, sys_chown_impl, sys_faccessat2_impl, sys_faccessat_impl,
    AT_EACCESS, AT_FDCWD, AT_SYMLINK_NOFOLLOW, F_OK, R_OK, W_OK, X_OK,
};
use vibix::fs::vfs::Credential;
use vibix::fs::{EACCES, EINVAL, ENOENT};
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

const O_WRONLY: u64 = 0o1;
const O_CREAT: u64 = 0o100;

const ENOSYS: i64 = -38;

const USER_PAGE_VA: usize = 0x0000_2008_0000_0000;
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
        ("access_f_ok_existing", &(access_f_ok_existing as fn())),
        (
            "access_f_ok_missing_enoent",
            &(access_f_ok_missing_enoent as fn()),
        ),
        ("access_r_ok_owner", &(access_r_ok_owner as fn())),
        (
            "access_w_ok_other_eaccess",
            &(access_w_ok_other_eaccess as fn()),
        ),
        (
            "access_x_ok_no_x_bit_eaccess",
            &(access_x_ok_no_x_bit_eaccess as fn()),
        ),
        (
            "access_uses_real_uid_not_effective",
            &(access_uses_real_uid_not_effective as fn()),
        ),
        (
            "faccessat_eaccess_uses_effective_uid",
            &(faccessat_eaccess_uses_effective_uid as fn()),
        ),
        (
            "faccessat_unknown_flag_einval",
            &(faccessat_unknown_flag_einval as fn()),
        ),
        (
            "faccessat_invalid_mode_einval",
            &(faccessat_invalid_mode_einval as fn()),
        ),
        (
            "faccessat_relative_with_dfd_einval",
            &(faccessat_relative_with_dfd_einval as fn()),
        ),
        (
            "faccessat2_matches_faccessat",
            &(faccessat2_matches_faccessat as fn()),
        ),
        (
            "access_dispatch_gate_enosys",
            &(access_dispatch_gate_enosys as fn()),
        ),
        (
            "faccessat_symlink_nofollow_accepted",
            &(faccessat_symlink_nofollow_accepted as fn()),
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

fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, flags, mode, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn chmod(path: &[u8], mode: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_chmod_impl(uva, mode as u64) }
}

fn chown(path: &[u8], uid: u32, gid: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_chown_impl(uva, uid as u64, gid as u64) }
}

fn access(path: &[u8], mode: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_access_impl(uva, mode as u64) }
}

fn faccessat(dfd: i32, path: &[u8], mode: u32, flags: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_faccessat_impl(dfd, uva, mode as u64, flags) }
}

fn faccessat2(dfd: i32, path: &[u8], mode: u32, flags: u32) -> i64 {
    let uva = stage(path);
    unsafe { sys_faccessat2_impl(dfd, uva, mode as u64, flags) }
}

fn create_regular(path: &[u8]) -> i64 {
    let fd = open(path, O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "create({:?}) expected fd, got {}", path, fd);
    fd
}

fn set_root_creds() {
    vibix::task::set_current_credentials(Credential::kernel());
}

/// Set ruid/euid/suid (and gid trio) directly so we can exercise the
/// real-vs-effective distinction. Supplementary groups left empty.
fn set_split_creds(ruid: u32, euid: u32, rgid: u32, egid: u32) {
    vibix::task::set_current_credentials(Credential::from_task_ids(
        ruid,
        euid,
        euid,
        rgid,
        egid,
        egid,
        alloc::vec::Vec::new(),
    ));
}

fn set_creds(uid: u32, gid: u32) {
    vibix::task::set_current_credentials(Credential::from_task_ids(
        uid,
        uid,
        uid,
        gid,
        gid,
        gid,
        alloc::vec::Vec::new(),
    ));
}

// --- Tests --------------------------------------------------------------

fn access_f_ok_existing() {
    set_root_creds();
    let fd = create_regular(b"/tmp/access-fok");
    close(fd);
    let r = access(b"/tmp/access-fok", F_OK);
    assert_eq!(r, 0, "F_OK on existing file must succeed, got {}", r);
}

fn access_f_ok_missing_enoent() {
    set_root_creds();
    let r = access(b"/tmp/no-such-file-for-access", F_OK);
    assert_eq!(r, ENOENT, "F_OK on missing path must be ENOENT, got {}", r);
}

fn access_r_ok_owner() {
    set_root_creds();
    let fd = create_regular(b"/tmp/access-rok-owner");
    close(fd);
    // Hand ownership to uid 1000 with mode 0o600 (owner rw, no one else).
    assert_eq!(chown(b"/tmp/access-rok-owner", 1000, 1000), 0);
    assert_eq!(chmod(b"/tmp/access-rok-owner", 0o600), 0);
    set_creds(1000, 1000);

    let r = access(b"/tmp/access-rok-owner", R_OK);
    assert_eq!(r, 0, "R_OK by owner must succeed, got {}", r);
    let r = access(b"/tmp/access-rok-owner", W_OK);
    assert_eq!(r, 0, "W_OK by owner must succeed, got {}", r);
    set_root_creds();
}

fn access_w_ok_other_eaccess() {
    set_root_creds();
    let fd = create_regular(b"/tmp/access-wok-other");
    close(fd);
    assert_eq!(chown(b"/tmp/access-wok-other", 1000, 1000), 0);
    // 0o644: owner rw, group r, other r — no W_OK for other.
    assert_eq!(chmod(b"/tmp/access-wok-other", 0o644), 0);
    set_creds(2000, 2000);

    let r = access(b"/tmp/access-wok-other", W_OK);
    assert_eq!(
        r, EACCES,
        "W_OK by non-owner non-group must be EACCES, got {}",
        r
    );
    // R_OK is granted by the `other` class.
    let r = access(b"/tmp/access-wok-other", R_OK);
    assert_eq!(r, 0, "R_OK by other class must succeed, got {}", r);
    set_root_creds();
}

fn access_x_ok_no_x_bit_eaccess() {
    set_root_creds();
    let fd = create_regular(b"/tmp/access-xok-noexec");
    close(fd);
    assert_eq!(chown(b"/tmp/access-xok-noexec", 1000, 1000), 0);
    assert_eq!(chmod(b"/tmp/access-xok-noexec", 0o644), 0);
    set_creds(1000, 1000);

    let r = access(b"/tmp/access-xok-noexec", X_OK);
    assert_eq!(
        r, EACCES,
        "X_OK on a non-executable file must be EACCES even for owner, got {}",
        r
    );
    set_root_creds();
}

/// The central real-vs-effective distinction. Set up a task whose
/// ruid != euid (the setuid-binary scenario) and confirm `access(2)`
/// (real ID) returns a *different* answer than `faccessat(...,
/// AT_EACCESS)` (effective ID).
fn access_uses_real_uid_not_effective() {
    set_root_creds();
    let fd = create_regular(b"/tmp/access-real-vs-eff");
    close(fd);
    // File owned by uid 1000, mode 0o600 (only owner can read/write).
    assert_eq!(chown(b"/tmp/access-real-vs-eff", 1000, 1000), 0);
    assert_eq!(chmod(b"/tmp/access-real-vs-eff", 0o600), 0);

    // Task: ruid=2000 (the "real user"), euid=1000 (the file owner —
    // as if they had just exec'd a setuid-1000 binary).
    set_split_creds(2000, 1000, 2000, 1000);

    // Default access(2) consults the *real* uid 2000, which is the
    // `other` class on this 0o600 file → EACCES.
    let r = access(b"/tmp/access-real-vs-eff", R_OK);
    assert_eq!(
        r, EACCES,
        "access(R_OK) under ruid=2000 must be EACCES (real ID is not the owner), got {}",
        r
    );

    // faccessat with AT_EACCESS consults the *effective* uid 1000,
    // which is the file owner → success.
    let r = faccessat(AT_FDCWD, b"/tmp/access-real-vs-eff", R_OK, AT_EACCESS);
    assert_eq!(
        r, 0,
        "faccessat(R_OK, AT_EACCESS) under euid=1000 must succeed (effective ID is the owner), got {}",
        r
    );

    set_root_creds();
}

fn faccessat_eaccess_uses_effective_uid() {
    set_root_creds();
    let fd = create_regular(b"/tmp/faccessat-eacc");
    close(fd);
    assert_eq!(chown(b"/tmp/faccessat-eacc", 1000, 1000), 0);
    assert_eq!(chmod(b"/tmp/faccessat-eacc", 0o600), 0);

    // ruid=1000 (file owner), euid=2000 (some other user). Mirror of
    // the setuid-on-binary-owned-by-others case.
    set_split_creds(1000, 2000, 1000, 2000);

    // Default: real uid 1000 → owner → success.
    let r = faccessat(AT_FDCWD, b"/tmp/faccessat-eacc", W_OK, 0);
    assert_eq!(
        r, 0,
        "faccessat(W_OK, 0) under ruid=1000 must succeed, got {}",
        r
    );

    // AT_EACCESS: effective uid 2000 → other class → EACCES.
    let r = faccessat(AT_FDCWD, b"/tmp/faccessat-eacc", W_OK, AT_EACCESS);
    assert_eq!(
        r, EACCES,
        "faccessat(W_OK, AT_EACCESS) under euid=2000 must be EACCES, got {}",
        r
    );

    set_root_creds();
}

fn faccessat_unknown_flag_einval() {
    set_root_creds();
    let fd = create_regular(b"/tmp/faccessat-bad-flag");
    close(fd);
    // 0x800 is not in {AT_EACCESS, AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH}.
    let r = faccessat(AT_FDCWD, b"/tmp/faccessat-bad-flag", F_OK, 0x800);
    assert_eq!(r, EINVAL, "unknown flag bit must be EINVAL, got {}", r);
}

fn faccessat_invalid_mode_einval() {
    set_root_creds();
    let fd = create_regular(b"/tmp/faccessat-bad-mode");
    close(fd);
    // Bits above the low three are reserved.
    let r = faccessat(AT_FDCWD, b"/tmp/faccessat-bad-mode", 0o10, 0);
    assert_eq!(
        r, EINVAL,
        "mode with reserved bit must be EINVAL, got {}",
        r
    );
}

fn faccessat_relative_with_dfd_einval() {
    set_root_creds();
    // Per-fd dirfd resolution is #239; relative path + non-AT_FDCWD
    // is rejected up front rather than silently resolving against
    // the namespace root.
    let r = faccessat(7, b"relative/path", F_OK, 0);
    assert_eq!(
        r, EINVAL,
        "relative path with dfd != AT_FDCWD must be EINVAL, got {}",
        r
    );
}

fn faccessat2_matches_faccessat() {
    set_root_creds();
    let fd = create_regular(b"/tmp/faccessat2-eq");
    close(fd);
    let a = faccessat(AT_FDCWD, b"/tmp/faccessat2-eq", R_OK, 0);
    let b = faccessat2(AT_FDCWD, b"/tmp/faccessat2-eq", R_OK, 0);
    assert_eq!(a, b, "faccessat2 must mirror faccessat for valid inputs");
    // And the strict-bit-check path also rejects unknown bits.
    let r = faccessat2(AT_FDCWD, b"/tmp/faccessat2-eq", F_OK, 0x4000);
    assert_eq!(
        r, EINVAL,
        "faccessat2 must reject unknown flag bits, got {}",
        r
    );
}

fn faccessat_symlink_nofollow_accepted() {
    set_root_creds();
    // AT_SYMLINK_NOFOLLOW is a recognised flag — must not be EINVAL
    // even on a regular (non-symlink) file. The result is just F_OK
    // success since the file exists.
    let fd = create_regular(b"/tmp/faccessat-nofollow");
    close(fd);
    let r = faccessat(
        AT_FDCWD,
        b"/tmp/faccessat-nofollow",
        F_OK,
        AT_SYMLINK_NOFOLLOW,
    );
    assert_eq!(
        r, 0,
        "AT_SYMLINK_NOFOLLOW on a regular file must succeed, got {}",
        r
    );
}

#[cfg(not(feature = "vfs_creds"))]
fn access_dispatch_gate_enosys() {
    set_root_creds();
    let uva = stage(b"/tmp/anything-access");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::ACCESS,
            uva,
            F_OK as u64,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_access must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::FACCESSAT,
            AT_FDCWD as u64,
            uva,
            F_OK as u64,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_faccessat must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::FACCESSAT2,
            AT_FDCWD as u64,
            uva,
            F_OK as u64,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_faccessat2 must dispatch to ENOSYS until vfs_creds flips on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn access_dispatch_gate_enosys() {
    set_root_creds();
    let fd = create_regular(b"/tmp/anything-access-on");
    close(fd);
    let uva = stage(b"/tmp/anything-access-on");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::ACCESS,
            uva,
            F_OK as u64,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, 0,
        "SYS_access dispatcher must reach the impl with vfs_creds on, got {}",
        r
    );
}
