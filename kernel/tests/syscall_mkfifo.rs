//! Integration test for issue #377: `mknod(2)` / `mknodat(2)` on FIFOs.
//!
//! Drives the SYS_MKNOD / SYS_MKNODAT dispatch arms end-to-end:
//! - `mknod(path, S_IFIFO|mode, 0)` creates a FIFO in ramfs.
//! - `open(path, O_NONBLOCK|O_WRONLY)` on a FIFO without a reader
//!   returns `-ENXIO`.
//! - `open(path, O_NONBLOCK|O_RDONLY)` on a FIFO without a writer
//!   succeeds.
//! - A write to the O_RDWR end of a FIFO is observable on a subsequent
//!   read from the same fd (same inode ring).
//! - `mknod` with `S_IFCHR` (unsupported) returns `-EPERM`.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EEXIST, ENXIO, EPERM};
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
const SYS_MKNOD: u64 = 133;
const SYS_MKNODAT: u64 = 259;

const AT_FDCWD: i64 = -100;

const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_NONBLOCK: u64 = 0o4000;

const S_IFIFO: u64 = 0o010_000;
const S_IFCHR: u64 = 0o020_000;

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
        ("mknod_creates_fifo", &(mknod_creates_fifo as fn())),
        (
            "mknod_fifo_then_open_eexist_on_recreate",
            &(mknod_fifo_then_open_eexist_on_recreate as fn()),
        ),
        (
            "open_nonblock_wronly_no_reader_enxio",
            &(open_nonblock_wronly_no_reader_enxio as fn()),
        ),
        (
            "open_nonblock_rdonly_no_writer_ok",
            &(open_nonblock_rdonly_no_writer_ok as fn()),
        ),
        (
            "fifo_rdwr_roundtrip_same_fd",
            &(fifo_rdwr_roundtrip_same_fd as fn()),
        ),
        (
            "mknodat_at_fdcwd_creates_fifo",
            &(mknodat_at_fdcwd_creates_fifo as fn()),
        ),
        (
            "mknod_unsupported_type_eperm",
            &(mknod_unsupported_type_eperm as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_mkfifo: {}", name);
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

fn stage_payload(bytes: &[u8]) -> u64 {
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

fn mknod(path: &[u8], mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(SYS_MKNOD, uva, mode, 0, 0, 0, 0) }
}

fn mknodat(dfd: i64, path: &[u8], mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(SYS_MKNODAT, dfd as u64, uva, mode, 0, 0, 0) }
}

fn open(path: &[u8], flags: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(SYS_OPEN, uva, flags, 0, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

fn write_bytes(fd: i64, bytes: &[u8]) -> i64 {
    let uva = stage_payload(bytes);
    unsafe { syscall_dispatch(SYS_WRITE, fd as u64, uva, bytes.len() as u64, 0, 0, 0) }
}

fn read_bytes(fd: i64, out: &mut [u8]) -> i64 {
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

// --- Tests ---------------------------------------------------------------

fn mknod_creates_fifo() {
    let r = mknod(b"/tmp/fifo-basic", S_IFIFO | 0o644);
    assert_eq!(r, 0, "mknod(S_IFIFO) must return 0, got {}", r);
}

fn mknod_fifo_then_open_eexist_on_recreate() {
    let r = mknod(b"/tmp/fifo-eexist", S_IFIFO | 0o644);
    assert_eq!(r, 0);
    let r = mknod(b"/tmp/fifo-eexist", S_IFIFO | 0o644);
    assert_eq!(
        r, EEXIST,
        "re-mknod of existing path must EEXIST, got {}",
        r
    );
}

fn open_nonblock_wronly_no_reader_enxio() {
    let r = mknod(b"/tmp/fifo-wronly", S_IFIFO | 0o644);
    assert_eq!(r, 0);
    let r = open(b"/tmp/fifo-wronly", O_WRONLY | O_NONBLOCK);
    assert_eq!(
        r, ENXIO,
        "O_NONBLOCK|O_WRONLY on FIFO w/o reader must ENXIO, got {}",
        r
    );
}

fn open_nonblock_rdonly_no_writer_ok() {
    let r = mknod(b"/tmp/fifo-rdonly", S_IFIFO | 0o644);
    assert_eq!(r, 0);
    let fd = open(b"/tmp/fifo-rdonly", O_RDONLY | O_NONBLOCK);
    assert!(
        fd >= 3,
        "O_NONBLOCK|O_RDONLY on FIFO w/o writer must succeed, got {}",
        fd
    );
    close(fd);
}

fn fifo_rdwr_roundtrip_same_fd() {
    let r = mknod(b"/tmp/fifo-rdwr", S_IFIFO | 0o644);
    assert_eq!(r, 0);
    // O_RDWR on a FIFO always succeeds and installs a dual-direction
    // backend; a write then read on the same fd is a legal round-trip.
    let fd = open(b"/tmp/fifo-rdwr", O_RDWR);
    assert!(fd >= 3, "O_RDWR on FIFO must succeed, got {}", fd);

    let payload = b"hello\0pipe";
    let n = write_bytes(fd, payload);
    assert_eq!(n as usize, payload.len(), "write returned {}", n);

    let mut out = [0u8; 16];
    let n = read_bytes(fd, &mut out[..payload.len()]);
    assert_eq!(n as usize, payload.len(), "read returned {}", n);
    assert_eq!(&out[..payload.len()], payload);

    close(fd);
}

fn mknodat_at_fdcwd_creates_fifo() {
    let r = mknodat(AT_FDCWD, b"/tmp/fifo-at", S_IFIFO | 0o644);
    assert_eq!(r, 0, "mknodat(AT_FDCWD, S_IFIFO) must return 0, got {}", r);
}

fn mknod_unsupported_type_eperm() {
    // S_IFCHR is not supported — no devtmpfs yet.
    let r = mknod(b"/tmp/char-dev", S_IFCHR | 0o644);
    assert_eq!(r, EPERM, "mknod(S_IFCHR) must return EPERM, got {}", r);
}
