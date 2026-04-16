//! Integration test for issue #415: `fcntl(2)` syscall.
//!
//! Exercises the `SYS_FCNTL` dispatcher arm end-to-end:
//! - `F_GETFL` reflects the flags passed to `open`.
//! - `F_SETFL` mutates only `O_APPEND | O_NONBLOCK | O_ASYNC`; the access
//!   mode and other bits are preserved.
//! - `F_GETFD` / `F_SETFD` round-trip the `FD_CLOEXEC` bit.
//! - `F_DUPFD` allocates the lowest free fd `>= min_fd`.
//! - `F_DUPFD_CLOEXEC` sets `FD_CLOEXEC` on the new fd without
//!   touching the source fd.
//! - Unknown cmd returns `EINVAL`; bad fd returns `EBADF`.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{
    EAGAIN, EBADF, EINVAL, FD_CLOEXEC, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD,
    F_SETFL,
};
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
const SYS_FCNTL: u64 = 72;
const SYS_PIPE2: u64 = 293;

const O_RDONLY: u32 = 0o0;
const O_WRONLY: u32 = 0o1;
const O_RDWR: u32 = 0o2;
const O_CREAT: u32 = 0o100;
const O_APPEND: u32 = 0o2000;
const O_NONBLOCK: u32 = 0o4000;
const O_ASYNC: u32 = 0o20000;
const O_DIRECTORY: u32 = 0o200000;

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
            "fcntl_getfl_reflects_open_flags",
            &(fcntl_getfl_reflects_open_flags as fn()),
        ),
        (
            "fcntl_setfl_mutates_only_mutable_bits",
            &(fcntl_setfl_mutates_only_mutable_bits as fn()),
        ),
        (
            "fcntl_getfd_setfd_roundtrip_cloexec",
            &(fcntl_getfd_setfd_roundtrip_cloexec as fn()),
        ),
        ("fcntl_dupfd_uses_floor", &(fcntl_dupfd_uses_floor as fn())),
        (
            "fcntl_dupfd_cloexec_sets_bit_only_on_new",
            &(fcntl_dupfd_cloexec_sets_bit_only_on_new as fn()),
        ),
        (
            "fcntl_unknown_cmd_einval",
            &(fcntl_unknown_cmd_einval as fn()),
        ),
        ("fcntl_bad_fd_ebadf", &(fcntl_bad_fd_ebadf as fn())),
        (
            "fcntl_setfl_o_append_writes_at_eof",
            &(fcntl_setfl_o_append_writes_at_eof as fn()),
        ),
        (
            "fcntl_setfl_o_nonblock_on_pipe_read_returns_eagain",
            &(fcntl_setfl_o_nonblock_on_pipe_read_returns_eagain as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_fcntl: {}", name);
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
    unsafe { syscall_dispatch(SYS_OPEN, uva, flags as u64, 0, 0, 0, 0) }
}

fn open_rw(path: &[u8], flags: u32, mode: u32) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(SYS_OPEN, uva, flags as u64, mode as u64, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn fcntl(fd: i64, cmd: u32, arg: u64) -> i64 {
    unsafe { syscall_dispatch(SYS_FCNTL, fd as u64, cmd as u64, arg, 0, 0, 0) }
}

/// Copy `bytes` into a scratch region of the staging page that won't
/// collide with a path staged at USER_PAGE_VA. Returns the VA.
fn stage_payload(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    let va = USER_PAGE_VA as u64 + 4096;
    assert!(bytes.len() <= USER_PAGE_LEN - 4096);
    unsafe {
        let dst = va as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
    }
    va
}

fn write_bytes(fd: i64, bytes: &[u8]) -> i64 {
    let uva = stage_payload(bytes);
    unsafe { syscall_dispatch(SYS_WRITE, fd as u64, uva, bytes.len() as u64, 0, 0, 0) }
}

fn read_bytes(fd: i64, out: &mut [u8]) -> i64 {
    install_user_staging_vma();
    let buf_va = USER_PAGE_VA as u64 + 2 * 4096;
    let n = unsafe { syscall_dispatch(SYS_READ, fd as u64, buf_va, out.len() as u64, 0, 0, 0) };
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

/// Call sys_pipe2 and return [read_fd, write_fd] on success.
/// The pipefd array is written to the 3rd page of the staging VMA to
/// avoid clobbering staged paths or payloads.
fn pipe2(flags: u32) -> (i32, i32) {
    install_user_staging_vma();
    let fds_va = USER_PAGE_VA as u64 + 3 * 4096;
    // Zero the slot first so a failed syscall can't leave stale values.
    unsafe {
        let p = fds_va as *mut i32;
        ptr::write_volatile(p, 0);
        ptr::write_volatile(p.add(1), 0);
    }
    let r = unsafe { syscall_dispatch(SYS_PIPE2, fds_va, flags as u64, 0, 0, 0, 0) };
    assert_eq!(r, 0, "pipe2 failed: {}", r);
    unsafe {
        let p = fds_va as *const i32;
        (ptr::read_volatile(p), ptr::read_volatile(p.add(1)))
    }
}

fn fcntl_getfl_reflects_open_flags() {
    // Open read-only; F_GETFL must include O_RDONLY (value 0) and nothing
    // else mutable.
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3, "open failed: {}", fd);
    let fl = fcntl(fd, F_GETFL, 0);
    assert!(fl >= 0, "F_GETFL returned {}", fl);
    assert_eq!(fl as u32 & 0o3, O_RDONLY);
    assert_eq!(fl as u32 & O_NONBLOCK, 0);
    assert_eq!(fl as u32 & O_APPEND, 0);
    close(fd);

    // Open with O_NONBLOCK: F_GETFL must show the bit.
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY | O_NONBLOCK);
    assert!(fd >= 3);
    let fl = fcntl(fd, F_GETFL, 0);
    assert!(fl >= 0);
    assert_eq!(fl as u32 & O_NONBLOCK, O_NONBLOCK);
    close(fd);
}

fn fcntl_setfl_mutates_only_mutable_bits() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3);

    // Flip O_NONBLOCK on via F_SETFL; F_GETFL sees it.
    let r = fcntl(fd, F_SETFL, O_NONBLOCK as u64);
    assert_eq!(r, 0, "F_SETFL returned {}", r);
    let fl = fcntl(fd, F_GETFL, 0);
    assert_eq!(fl as u32 & O_NONBLOCK, O_NONBLOCK);
    // Access mode (O_RDONLY=0) is preserved — no O_WRONLY/O_RDWR snuck in.
    assert_eq!(fl as u32 & 0o3, O_RDONLY);

    // Flip O_APPEND + O_ASYNC on, O_NONBLOCK off in a single call.
    let r = fcntl(fd, F_SETFL, (O_APPEND | O_ASYNC) as u64);
    assert_eq!(r, 0);
    let fl = fcntl(fd, F_GETFL, 0) as u32;
    assert_eq!(fl & O_APPEND, O_APPEND);
    assert_eq!(fl & O_ASYNC, O_ASYNC);
    assert_eq!(fl & O_NONBLOCK, 0);

    // Non-mutable bits in the arg are silently ignored — access mode
    // doesn't get clobbered, O_DIRECTORY doesn't stick.
    let r = fcntl(fd, F_SETFL, O_DIRECTORY as u64);
    assert_eq!(r, 0);
    let fl = fcntl(fd, F_GETFL, 0) as u32;
    assert_eq!(fl & 0o3, O_RDONLY, "access mode must survive F_SETFL");
    assert_eq!(fl & O_DIRECTORY, 0, "O_DIRECTORY is not a mutable bit");

    close(fd);
}

fn fcntl_getfd_setfd_roundtrip_cloexec() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3);

    // Freshly-opened fds without O_CLOEXEC report FD_CLOEXEC=0.
    let r = fcntl(fd, F_GETFD, 0);
    assert_eq!(r, 0);

    // Set FD_CLOEXEC; F_GETFD must observe it.
    let r = fcntl(fd, F_SETFD, FD_CLOEXEC as u64);
    assert_eq!(r, 0);
    let r = fcntl(fd, F_GETFD, 0);
    assert_eq!(r as u32, FD_CLOEXEC);

    // Clear it again.
    let r = fcntl(fd, F_SETFD, 0);
    assert_eq!(r, 0);
    let r = fcntl(fd, F_GETFD, 0);
    assert_eq!(r, 0);

    close(fd);
}

fn fcntl_dupfd_uses_floor() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3);

    // Dup with a floor of 42: result must be >= 42.
    let new_fd = fcntl(fd, F_DUPFD, 42);
    assert!(new_fd >= 42, "F_DUPFD returned {} with floor 42", new_fd);

    // New fd starts with FD_CLOEXEC cleared.
    let r = fcntl(new_fd, F_GETFD, 0);
    assert_eq!(r, 0);

    close(new_fd);
    close(fd);
}

fn fcntl_dupfd_cloexec_sets_bit_only_on_new() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3);

    let new_fd = fcntl(fd, F_DUPFD_CLOEXEC, 10);
    assert!(new_fd >= 10);

    // New fd has FD_CLOEXEC set.
    let r = fcntl(new_fd, F_GETFD, 0);
    assert_eq!(r as u32, FD_CLOEXEC);
    // Source fd is untouched.
    let r = fcntl(fd, F_GETFD, 0);
    assert_eq!(r, 0);

    close(new_fd);
    close(fd);
}

fn fcntl_unknown_cmd_einval() {
    let fd = open_with_flags(HOSTNAME_PATH, O_RDONLY);
    assert!(fd >= 3);
    // 999 is not a defined F_* cmd.
    let r = fcntl(fd, 999, 0);
    assert_eq!(r, EINVAL);
    close(fd);
}

fn fcntl_bad_fd_ebadf() {
    // fd 4242 was never opened.
    let r = fcntl(4242, F_GETFL, 0);
    assert_eq!(r, EBADF);
    let r = fcntl(4242, F_SETFD, FD_CLOEXEC as u64);
    assert_eq!(r, EBADF);
    let r = fcntl(4242, F_DUPFD, 0);
    assert_eq!(r, EBADF);
}

/// Regression for issue #435 (VFS path): `fcntl(F_SETFL, O_APPEND)` on a
/// file that was opened without `O_APPEND` must cause subsequent writes
/// to snap to EOF. Before the fix, F_SETFL flipped the bit on
/// `FileDescription.flags` but not on the underlying `OpenFile.flags`
/// (the field the write-path actually consults), so appends silently
/// landed at the tracked offset instead.
fn fcntl_setfl_o_append_writes_at_eof() {
    // Clean slate: create (or truncate) the file, then seed it.
    let fd_seed = open_rw(
        b"/tmp/fcntl_setfl_append\0",
        O_WRONLY | O_CREAT | 0o1000, /* O_TRUNC */
        0o644,
    );
    assert!(fd_seed >= 3, "open seed failed: {}", fd_seed);
    assert_eq!(write_bytes(fd_seed, b"AAAA"), 4);
    assert_eq!(close(fd_seed), 0);

    // Open O_RDWR *without* O_APPEND. Flip O_APPEND on via F_SETFL and
    // write — the write must land at EOF (offset 4), not at the tracked
    // offset (0).
    let fd = open_rw(b"/tmp/fcntl_setfl_append\0", O_RDWR, 0);
    assert!(fd >= 3);
    let r = fcntl(fd, F_SETFL, O_APPEND as u64);
    assert_eq!(r, 0, "F_SETFL(O_APPEND) returned {}", r);
    // F_GETFL must now show O_APPEND — sanity for the description path.
    let fl = fcntl(fd, F_GETFL, 0);
    assert_eq!(fl as u32 & O_APPEND, O_APPEND);
    // Write something — it must append at EOF.
    assert_eq!(write_bytes(fd, b"BBBB"), 4);
    assert_eq!(close(fd), 0);

    // Read the file back: must be "AAAABBBB", not "BBBB" (that would
    // indicate the write clobbered the seed at offset 0, i.e. the
    // F_SETFL update didn't reach VfsBackend::write).
    let fd_r = open_rw(b"/tmp/fcntl_setfl_append\0", O_RDONLY, 0);
    assert!(fd_r >= 3);
    let mut buf = [0u8; 16];
    let n = read_bytes(fd_r, &mut buf);
    assert_eq!(n, 8, "file length after F_SETFL(O_APPEND) write");
    assert_eq!(
        &buf[..8],
        b"AAAABBBB",
        "F_SETFL(O_APPEND) must make next write land at EOF"
    );
    assert_eq!(close(fd_r), 0);
}

/// Regression for issue #435 (pipe path): `fcntl(F_SETFL, O_NONBLOCK)`
/// on the read end of an empty pipe must cause the next `read` to
/// return `EAGAIN` instead of blocking. Before the fix, F_SETFL flipped
/// the bit on `FileDescription.flags` but not on
/// `PipeReadEnd.nonblocking`, so the read would still park the caller.
fn fcntl_setfl_o_nonblock_on_pipe_read_returns_eagain() {
    // Create a blocking pipe (flags = 0).
    let (rfd, wfd) = pipe2(0);
    assert!(rfd >= 3 && wfd >= 3);

    // Flip O_NONBLOCK on the read end via F_SETFL.
    let r = fcntl(rfd as i64, F_SETFL, O_NONBLOCK as u64);
    assert_eq!(r, 0, "F_SETFL(O_NONBLOCK) on pipe rfd returned {}", r);
    let fl = fcntl(rfd as i64, F_GETFL, 0);
    assert_eq!(fl as u32 & O_NONBLOCK, O_NONBLOCK);

    // read on empty pipe must now return EAGAIN, not block. We call
    // read_bytes directly (not through a helper that asserts positive)
    // so we can check the errno.
    install_user_staging_vma();
    let buf_va = USER_PAGE_VA as u64 + 2 * 4096;
    let n = unsafe { syscall_dispatch(SYS_READ, rfd as u64, buf_va, 8, 0, 0, 0) };
    assert_eq!(
        n, EAGAIN,
        "F_SETFL(O_NONBLOCK) must make pipe read return EAGAIN on empty pipe, got {}",
        n
    );

    assert_eq!(close(rfd as i64), 0);
    assert_eq!(close(wfd as i64), 0);
}
