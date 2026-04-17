//! Integration test for issue #410: `lseek` syscall.
//!
//! Exercises the `SYS_LSEEK` dispatcher arm end-to-end:
//! - `SEEK_SET` repositions the shared offset on a rootfs regular file
//!   and a subsequent `SYS_READ` reads from the new position.
//! - `SEEK_CUR` advances the offset relative to the current position.
//! - `SEEK_END` positions relative to file size (tested via negative
//!   offset reaching into the payload).
//! - A negative resulting offset returns `EINVAL`.
//! - An unknown `whence` returns `EINVAL`.
//! - `lseek` on `/dev/stdin` (a `SerialBackend`) returns `ESPIPE`, per
//!   POSIX "lseek on a non-seekable backend".
//! - `lseek` on a closed / never-opened fd returns `EBADF`.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EBADF, EINVAL, ESPIPE};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

const SYS_READ: u64 = 0;
const SYS_OPEN: u64 = 2;
const SYS_CLOSE: u64 = 3;
const SYS_LSEEK: u64 = 8;

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;
const SEEK_END: u64 = 2;

/// Rootfs file populated by `xtask::ensure_initrd`. Content is the
/// 6-byte UTF-8 string `b"vibix\n"`; any drift here and the test fails
/// noisily, which is the point.
const HOSTNAME_PATH: &[u8] = b"/etc/hostname\0";
const HOSTNAME_CONTENT: &[u8] = b"vibix\n";

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
        ("lseek_set_rewinds", &(lseek_set_rewinds as fn())),
        ("lseek_cur_advances", &(lseek_cur_advances as fn())),
        ("lseek_end_negative", &(lseek_end_negative as fn())),
        (
            "lseek_negative_result_einval",
            &(lseek_negative_result_einval as fn()),
        ),
        (
            "lseek_unknown_whence_einval",
            &(lseek_unknown_whence_einval as fn()),
        ),
        ("lseek_on_stdio_espipe", &(lseek_on_stdio_espipe as fn())),
        (
            "lseek_on_closed_fd_ebadf",
            &(lseek_on_closed_fd_ebadf as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_lseek: {}", name);
        t.run();
    }
}

/// Install a single demand-paged anonymous VMA at `USER_PAGE_VA` so
/// tests can stage user-visible bytes there. Mirrors the pattern used
/// by `syscall_open_mmap.rs`.
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
        0x3, // PROT_READ | PROT_WRITE
        prot_pte,
        Share::Private,
        AnonObject::new(Some(USER_PAGE_LEN / 4096)),
        0,
    ));
    unsafe {
        ptr::write_volatile(USER_PAGE_VA as *mut u8, 0);
    }
}

/// Copy `bytes` to the user page at offset 0 and return the VA.
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

fn open_ro(path: &[u8]) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, 0, 0, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn lseek(fd: i64, off: i64, whence: u64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_LSEEK, fd as u64, off as u64, whence, 0, 0, 0) }
}

/// Read up to `len` bytes into a scratch region of the user page, then
/// copy them back into a kernel-side buffer for assertion.
fn read_bytes(fd: i64, out: &mut [u8]) -> i64 {
    // Stash the read at USER_PAGE_VA + 256 so it doesn't clobber the
    // path we just used for open.
    let buf_va = USER_PAGE_VA as u64 + 256;
    let n = unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_READ, fd as u64, buf_va, out.len() as u64, 0, 0, 0) };
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

fn lseek_set_rewinds() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3, "open /etc/hostname failed: {}", fd);
    let mut buf = [0u8; 6];
    let n = read_bytes(fd, &mut buf);
    assert_eq!(n, HOSTNAME_CONTENT.len() as i64);
    assert_eq!(&buf, HOSTNAME_CONTENT);

    // Rewind and re-read — offset must actually be reset.
    let new_off = lseek(fd, 0, SEEK_SET);
    assert_eq!(new_off, 0, "SEEK_SET to 0 must return 0, got {}", new_off);

    let mut buf2 = [0u8; 6];
    let n2 = read_bytes(fd, &mut buf2);
    assert_eq!(n2, HOSTNAME_CONTENT.len() as i64);
    assert_eq!(&buf2, HOSTNAME_CONTENT);

    assert_eq!(close(fd), 0);
}

fn lseek_cur_advances() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    // Read 2 bytes.
    let mut buf = [0u8; 2];
    assert_eq!(read_bytes(fd, &mut buf), 2);
    assert_eq!(&buf, b"vi");
    // SEEK_CUR +1 → position 3.
    assert_eq!(lseek(fd, 1, SEEK_CUR), 3);
    // Read next byte → 'i' (index 3 of b"vibix\n").
    let mut b = [0u8; 1];
    assert_eq!(read_bytes(fd, &mut b), 1);
    assert_eq!(b[0], b'i');
    close(fd);
}

fn lseek_end_negative() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    // Seek to 1 byte before EOF; should point at '\n'.
    assert_eq!(lseek(fd, -1, SEEK_END), (HOSTNAME_CONTENT.len() - 1) as i64);
    let mut b = [0u8; 1];
    assert_eq!(read_bytes(fd, &mut b), 1);
    assert_eq!(b[0], b'\n');
    close(fd);
}

fn lseek_negative_result_einval() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    // Try to seek before the start of the file.
    assert_eq!(lseek(fd, -1, SEEK_SET), EINVAL);
    close(fd);
}

fn lseek_unknown_whence_einval() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    assert_eq!(lseek(fd, 0, 99), EINVAL);
    close(fd);
}

fn lseek_on_stdio_espipe() {
    // fd 0 (stdin) is backed by SerialBackend, which has no seek offset.
    // The default FileBackend::lseek returns ESPIPE.
    assert_eq!(lseek(0, 0, SEEK_SET), ESPIPE);
    assert_eq!(lseek(1, 0, SEEK_CUR), ESPIPE);
}

fn lseek_on_closed_fd_ebadf() {
    // Very large fd — unambiguously never opened in any test flow.
    assert_eq!(lseek(9999, 0, SEEK_SET), EBADF);
}
