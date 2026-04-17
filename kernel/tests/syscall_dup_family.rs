//! Integration test for issue #414: `dup(2)`, `dup2(2)`, `dup3(2)` syscalls.
//!
//! Exercises the `SYS_DUP`, `SYS_DUP2`, `SYS_DUP3` dispatcher arms end-to-end:
//! - `dup(oldfd)` returns the lowest-numbered free fd aliasing `oldfd`.
//! - `dup2(oldfd, newfd)` closes `newfd` if open and reassigns it.
//! - `dup2(fd, fd)` is a no-op when `fd` is open.
//! - Duplicated fds share the open-file description's seek offset.
//! - `dup3(fd, fd, _)` returns `EINVAL`.
//! - `dup3(oldfd, newfd, O_CLOEXEC)` sets `FD_CLOEXEC` on `newfd` without
//!   touching the source fd's per-fd flags.
//! - `dup3(_, _, unknown_flag)` returns `EINVAL`.
//! - `dup`/`dup2`/`dup3` on a closed `oldfd` return `EBADF`.
//! - `dup`/`dup2`/`dup3` on a negative fd return `EBADF` (not EINVAL).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EBADF, EINVAL, FD_CLOEXEC, F_GETFD};
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
const SYS_DUP: u64 = 32;
const SYS_DUP2: u64 = 33;
const SYS_FCNTL: u64 = 72;
const SYS_DUP3: u64 = 292;

const SEEK_SET: u64 = 0;
const SEEK_CUR: u64 = 1;

const O_RDONLY: u32 = 0o0;
const O_NONBLOCK: u32 = 0o4000;
const O_CLOEXEC: u32 = 0o2000000;

/// Rootfs file populated by `xtask::ensure_initrd`. Content is `b"vibix\n"`.
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
        (
            "dup_returns_lowest_free_fd",
            &(dup_returns_lowest_free_fd as fn()),
        ),
        (
            "dup2_replaces_open_newfd",
            &(dup2_replaces_open_newfd as fn()),
        ),
        ("dup2_same_fd_noop", &(dup2_same_fd_noop as fn())),
        ("dup_shares_seek_offset", &(dup_shares_seek_offset as fn())),
        (
            "dup3_einval_on_equal_fd",
            &(dup3_einval_on_equal_fd as fn()),
        ),
        (
            "dup3_cloexec_sets_bit_only_on_new",
            &(dup3_cloexec_sets_bit_only_on_new as fn()),
        ),
        (
            "dup3_einval_on_unknown_flag",
            &(dup3_einval_on_unknown_flag as fn()),
        ),
        (
            "dup_family_ebadf_on_closed",
            &(dup_family_ebadf_on_closed as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_dup_family: {}", name);
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

fn open_ro(path: &[u8]) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_OPEN, uva, O_RDONLY as u64, 0, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn dup(fd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_DUP, fd as u64, 0, 0, 0, 0, 0) }
}

fn dup2(oldfd: i64, newfd: i64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_DUP2, oldfd as u64, newfd as u64, 0, 0, 0, 0) }
}

fn dup3(oldfd: i64, newfd: i64, flags: u32) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_DUP3, oldfd as u64, newfd as u64, flags as u64, 0, 0, 0) }
}

fn fcntl(fd: i64, cmd: u32, arg: u64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_FCNTL, fd as u64, cmd as u64, arg, 0, 0, 0) }
}

fn lseek(fd: i64, off: i64, whence: u64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), SYS_LSEEK, fd as u64, off as u64, whence, 0, 0, 0) }
}

fn read_bytes(fd: i64, out: &mut [u8]) -> i64 {
    // Stash the read at USER_PAGE_VA + 256 so it doesn't clobber the path.
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

fn dup_returns_lowest_free_fd() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3, "open /etc/hostname failed: {}", fd);
    // dup(fd) must allocate the lowest free fd, which is fd+1 here.
    let new_fd = dup(fd);
    assert_eq!(
        new_fd,
        fd + 1,
        "dup must return the lowest-numbered free fd"
    );
    // Both fds must be readable.
    let mut buf = [0u8; 6];
    assert_eq!(read_bytes(new_fd, &mut buf), HOSTNAME_CONTENT.len() as i64);
    assert_eq!(&buf, HOSTNAME_CONTENT);
    close(new_fd);
    close(fd);
}

fn dup2_replaces_open_newfd() {
    let fd_a = open_ro(HOSTNAME_PATH);
    let fd_b = open_ro(HOSTNAME_PATH);
    assert!(fd_a >= 3 && fd_b >= 3 && fd_a != fd_b);

    // Advance fd_a's offset so we can tell the two descriptions apart.
    assert_eq!(lseek(fd_a, 2, SEEK_SET), 2);

    // dup2(fd_a, fd_b): fd_b now aliases fd_a's description; its old
    // description is dropped. Reading from fd_b should see fd_a's offset.
    assert_eq!(dup2(fd_a, fd_b), fd_b);
    let mut buf = [0u8; 4];
    let n = read_bytes(fd_b, &mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf, b"bix\n");

    close(fd_a);
    close(fd_b);
}

fn dup2_same_fd_noop() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    assert_eq!(dup2(fd, fd), fd);
    // fd still readable after the no-op.
    let mut buf = [0u8; 6];
    assert_eq!(read_bytes(fd, &mut buf), HOSTNAME_CONTENT.len() as i64);
    assert_eq!(&buf, HOSTNAME_CONTENT);
    close(fd);
}

fn dup_shares_seek_offset() {
    // POSIX: dup'd fds share the open-file description, so the seek
    // offset is shared too. Prove it by reading through one fd and
    // observing that the other fd sees the advanced position.
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    let alias = dup(fd);
    assert!(alias >= 3);

    // Read 2 bytes via fd; the alias's offset advances too.
    let mut buf = [0u8; 2];
    assert_eq!(read_bytes(fd, &mut buf), 2);
    assert_eq!(&buf, b"vi");

    // Confirm the alias now starts at offset 2 by reading the next 2 bytes.
    let mut buf2 = [0u8; 2];
    assert_eq!(read_bytes(alias, &mut buf2), 2);
    assert_eq!(&buf2, b"bi");

    // SEEK_CUR +0 via the alias must report offset 4 — shared cursor.
    assert_eq!(lseek(alias, 0, SEEK_CUR), 4);

    close(alias);
    close(fd);
}

fn dup3_einval_on_equal_fd() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    assert_eq!(dup3(fd, fd, 0), EINVAL);
    assert_eq!(dup3(fd, fd, O_CLOEXEC), EINVAL);
    close(fd);
}

fn dup3_cloexec_sets_bit_only_on_new() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    // Pick a newfd well above any currently open fd.
    let newfd = (fd + 10) as i64;
    let r = dup3(fd, newfd, O_CLOEXEC);
    assert_eq!(r, newfd);

    // newfd has FD_CLOEXEC set.
    let flags_new = fcntl(newfd, F_GETFD, 0);
    assert_eq!(flags_new as u32, FD_CLOEXEC);
    // Source fd is untouched.
    let flags_old = fcntl(fd, F_GETFD, 0);
    assert_eq!(flags_old, 0);

    close(newfd);
    close(fd);
}

fn dup3_einval_on_unknown_flag() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    let newfd = (fd + 20) as i64;
    // O_NONBLOCK is a status flag, not a valid dup3 flag.
    assert_eq!(dup3(fd, newfd, O_NONBLOCK), EINVAL);
    // Arbitrary unknown bit.
    assert_eq!(dup3(fd, newfd, 0x1), EINVAL);
    close(fd);
}

fn dup_family_ebadf_on_closed() {
    // fd 9999 was never opened.
    assert_eq!(dup(9999), EBADF);
    assert_eq!(dup2(9999, 5), EBADF);
    assert_eq!(dup3(9999, 5, 0), EBADF);
    // Linux returns EBADF (not EINVAL) for negative fds across the dup family.
    assert_eq!(dup(-1), EBADF);
    assert_eq!(dup2(-1, 5), EBADF);
    assert_eq!(dup2(3, -1), EBADF);
    assert_eq!(dup3(-1, 5, 0), EBADF);
    assert_eq!(dup3(3, -1, 0), EBADF);
}
