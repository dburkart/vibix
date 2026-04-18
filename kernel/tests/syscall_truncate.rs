//! Integration test for issue #543: `truncate(path, length)` and
//! `ftruncate(fd, length)` wired to `InodeOps::setattr(SIZE)`.
//!
//! Each impl is compiled unconditionally; the syscall dispatch arms are
//! gated behind `#[cfg(feature = "vfs_creds")]` per RFC 0004's
//! A-before-B ordering. Tests call `sys_truncate_impl` /
//! `sys_ftruncate_impl` directly so the VFS wiring is exercised
//! regardless of feature state, mirroring the mkdir/unlink/chmod
//! convention.
//!
//! Coverage per the issue contract:
//! - `truncate` shrinks a regular file; `stat` reflects the new size.
//! - `truncate` grows a regular file; `read` sees the zero-filled tail.
//! - `ftruncate` on an open fd mutates the same inode.
//! - Negative `length` returns `EINVAL` (both forms).
//! - Target is a directory returns `EISDIR` (truncate).
//! - `ftruncate` on an out-of-range fd returns `EBADF`.
//! - Dispatch arms return `-ENOSYS` until `vfs_creds` flips on.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::{syscall_dispatch, syscall_nr};
use vibix::arch::x86_64::syscalls::vfs::{sys_ftruncate_impl, sys_truncate_impl};
use vibix::fs::vfs::ops::Stat;
use vibix::fs::vfs::Credential;
use vibix::fs::{EBADF, EINVAL, EISDIR};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_STAT: u64 = 4;

const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
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
        ("truncate_shrinks_file", &(truncate_shrinks_file as fn())),
        (
            "truncate_grows_with_zero_tail",
            &(truncate_grows_with_zero_tail as fn()),
        ),
        (
            "ftruncate_on_open_fd_observable_after_reopen",
            &(ftruncate_on_open_fd_observable_after_reopen as fn()),
        ),
        (
            "truncate_negative_length_einval",
            &(truncate_negative_length_einval as fn()),
        ),
        (
            "ftruncate_negative_length_einval",
            &(ftruncate_negative_length_einval as fn()),
        ),
        (
            "truncate_on_directory_eisdir",
            &(truncate_on_directory_eisdir as fn()),
        ),
        ("ftruncate_bad_fd_ebadf", &(ftruncate_bad_fd_ebadf as fn())),
        ("truncate_dispatch_gate", &(truncate_dispatch_gate as fn())),
        (
            "ftruncate_dispatch_gate",
            &(ftruncate_dispatch_gate as fn()),
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

/// Stage a NUL-terminated path at offset 0 of the user staging VMA.
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

/// Stage write-payload bytes at page 1 of the user VMA (offset 4 KiB)
/// so they don't overlap the path in page 0.
fn stage_payload(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    assert!(bytes.len() <= USER_PAGE_LEN - 4096);
    let va = USER_PAGE_VA as u64 + 4096;
    unsafe {
        let dst = va as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
    }
    va
}

/// VA used for `read(2)` buffers. Sits on page 2 of the staging VMA.
fn read_buf_va() -> u64 {
    install_user_staging_vma();
    USER_PAGE_VA as u64 + 2 * 4096
}

/// VA reserved for `struct stat` copy-out. Page 3 of the staging VMA
/// so it never overlaps the path or read/write buffers.
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

fn write_bytes(fd: i64, bytes: &[u8]) -> i64 {
    let uva = stage_payload(bytes);
    unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_WRITE,
            fd as u64,
            uva,
            bytes.len() as u64,
            0,
            0,
            0,
        )
    }
}

fn read_bytes(fd: i64, out: &mut [u8]) -> i64 {
    let buf_va = read_buf_va();
    let n = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            SYS_READ,
            fd as u64,
            buf_va,
            out.len() as u64,
            0,
            0,
            0,
        )
    };
    if n > 0 {
        unsafe {
            let src = buf_va as *const u8;
            for i in 0..n as usize {
                out[i] = ptr::read_volatile(src.add(i));
            }
        }
    }
    n
}

fn stat_of(path: &[u8]) -> Stat {
    let uva = stage(path);
    let r = unsafe {
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
    };
    assert_eq!(r, 0, "stat({:?}) must succeed, got {}", path, r);
    read_stat()
}

fn truncate(path: &[u8], length: i64) -> i64 {
    let uva = stage(path);
    unsafe { sys_truncate_impl(uva, length) }
}

fn ftruncate(fd: i64, length: i64) -> i64 {
    unsafe { sys_ftruncate_impl(fd as u64, length) }
}

fn set_root_creds() {
    vibix::task::set_current_credentials(Credential::kernel());
}

/// Create a fresh regular file at `path`, write `content`, and close.
fn seed_regular(path: &[u8], content: &[u8]) {
    let fd = open(path, O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "seed open({:?}) failed: {}", path, fd);
    if !content.is_empty() {
        let n = write_bytes(fd, content);
        assert_eq!(n, content.len() as i64, "seed write short: {}", n);
    }
    assert_eq!(close(fd), 0);
}

// --- Tests --------------------------------------------------------------

fn truncate_shrinks_file() {
    set_root_creds();
    seed_regular(b"/tmp/trunc-shrink", b"hello world");
    let sb = stat_of(b"/tmp/trunc-shrink");
    assert_eq!(sb.st_size, 11, "pre-truncate size");

    let r = truncate(b"/tmp/trunc-shrink", 5);
    assert_eq!(r, 0, "shrink truncate failed: {}", r);

    let sb = stat_of(b"/tmp/trunc-shrink");
    assert_eq!(sb.st_size, 5, "post-shrink size");

    // Content of the surviving prefix must be intact — RamFs resizes
    // the body vector without touching the head.
    let fd = open(b"/tmp/trunc-shrink", O_RDONLY, 0);
    assert!(fd >= 3);
    let mut buf = [0u8; 16];
    let n = read_bytes(fd, &mut buf);
    assert_eq!(n, 5, "read after shrink returned {}", n);
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(close(fd), 0);
}

fn truncate_grows_with_zero_tail() {
    set_root_creds();
    seed_regular(b"/tmp/trunc-grow", b"abc");
    let r = truncate(b"/tmp/trunc-grow", 10);
    assert_eq!(r, 0, "grow truncate failed: {}", r);

    let sb = stat_of(b"/tmp/trunc-grow");
    assert_eq!(sb.st_size, 10, "post-grow size");

    let fd = open(b"/tmp/trunc-grow", O_RDONLY, 0);
    assert!(fd >= 3);
    let mut buf = [0xaau8; 16]; // prime with a distinctive sentinel
    let n = read_bytes(fd, &mut buf);
    assert_eq!(n, 10, "read after grow returned {}", n);
    // The original three bytes survive; the tail must read as zero
    // (POSIX sparse-hole semantics — RamFs zero-fills eagerly).
    assert_eq!(&buf[..3], b"abc");
    for (i, &b) in buf[3..10].iter().enumerate() {
        assert_eq!(b, 0, "grown tail byte {} must be zero, got {:#x}", 3 + i, b);
    }
    assert_eq!(close(fd), 0);
}

fn ftruncate_on_open_fd_observable_after_reopen() {
    set_root_creds();
    seed_regular(b"/tmp/ftrunc-open", b"1234567890");
    // Open R/W so the fd's inode pin keeps it resolvable for stat below.
    let fd = open(b"/tmp/ftrunc-open", O_RDWR, 0);
    assert!(fd >= 3);

    let r = ftruncate(fd, 4);
    assert_eq!(r, 0, "ftruncate(fd, 4) failed: {}", r);

    // Still-open fd sees the new length via stat-on-path.
    let sb = stat_of(b"/tmp/ftrunc-open");
    assert_eq!(sb.st_size, 4, "post-ftruncate size");

    assert_eq!(close(fd), 0);

    // Reopen and read — should only see the first four bytes.
    let fd2 = open(b"/tmp/ftrunc-open", O_RDONLY, 0);
    assert!(fd2 >= 3);
    let mut buf = [0u8; 16];
    let n = read_bytes(fd2, &mut buf);
    assert_eq!(n, 4, "read after ftruncate returned {}", n);
    assert_eq!(&buf[..4], b"1234");
    assert_eq!(close(fd2), 0);
}

fn truncate_negative_length_einval() {
    set_root_creds();
    seed_regular(b"/tmp/trunc-neg", b"data");
    let r = truncate(b"/tmp/trunc-neg", -1);
    assert_eq!(r, EINVAL, "truncate(path, -1) must EINVAL, got {}", r);
    // Size must be unchanged.
    let sb = stat_of(b"/tmp/trunc-neg");
    assert_eq!(sb.st_size, 4);
}

fn ftruncate_negative_length_einval() {
    set_root_creds();
    seed_regular(b"/tmp/ftrunc-neg", b"data");
    let fd = open(b"/tmp/ftrunc-neg", O_RDWR, 0);
    assert!(fd >= 3);
    let r = ftruncate(fd, -5);
    assert_eq!(r, EINVAL, "ftruncate(fd, -5) must EINVAL, got {}", r);
    assert_eq!(close(fd), 0);
}

fn truncate_on_directory_eisdir() {
    set_root_creds();
    // `/tmp` is a RamFs-mounted directory — truncating a directory is
    // always EISDIR per POSIX.
    let r = truncate(b"/tmp", 0);
    assert_eq!(r, EISDIR, "truncate on directory must EISDIR, got {}", r);
}

fn ftruncate_bad_fd_ebadf() {
    set_root_creds();
    // 9999 is far outside any fd opened across this whole test binary.
    let r = ftruncate(9999, 0);
    assert_eq!(
        r, EBADF,
        "ftruncate on nonexistent fd must EBADF, got {}",
        r
    );
}

/// With `vfs_creds` off (the default), the new dispatch arms fall
/// through to the dispatcher's `-ENOSYS` default. Any non-ENOSYS return
/// from `syscall_dispatch(SYS_truncate, ...)` would mean the RFC 0004
/// A-before-B gate has leaked.
#[cfg(not(feature = "vfs_creds"))]
fn truncate_dispatch_gate() {
    set_root_creds();
    let uva = stage(b"/tmp/anything");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::TRUNCATE,
            uva,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_truncate must dispatch to ENOSYS until vfs_creds on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn truncate_dispatch_gate() {
    set_root_creds();
    seed_regular(b"/tmp/trunc-dispatch", b"abc");
    let uva = stage(b"/tmp/trunc-dispatch");
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::TRUNCATE,
            uva,
            1,
            0,
            0,
            0,
            0,
        )
    };
    assert!(
        r != ENOSYS,
        "SYS_truncate dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}

#[cfg(not(feature = "vfs_creds"))]
fn ftruncate_dispatch_gate() {
    set_root_creds();
    // fd 9999 is invalid; without the feature gate the dispatcher must
    // still return ENOSYS rather than reach the impl (which would
    // return EBADF).
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::FTRUNCATE,
            9999,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert_eq!(
        r, ENOSYS,
        "SYS_ftruncate must dispatch to ENOSYS until vfs_creds on, got {}",
        r
    );
}

#[cfg(feature = "vfs_creds")]
fn ftruncate_dispatch_gate() {
    set_root_creds();
    let r = unsafe {
        syscall_dispatch(
            core::ptr::null_mut(),
            syscall_nr::FTRUNCATE,
            9999,
            0,
            0,
            0,
            0,
            0,
        )
    };
    assert!(
        r != ENOSYS,
        "SYS_ftruncate dispatcher must reach the impl with vfs_creds on, got ENOSYS"
    );
}
