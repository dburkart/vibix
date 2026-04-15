//! Integration test for issue #412: O_CREAT / O_EXCL / O_TRUNC / O_APPEND
//! semantics in `sys_openat`.
//!
//! Runs against the booted kernel's ramfs mount at `/tmp` so that the
//! write paths (create / truncate / append) exercise a real read-write
//! filesystem driver through the syscall dispatcher.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EEXIST, ENOENT};
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
const SYS_LSEEK: u64 = 8;

const O_RDONLY: u64 = 0o0;
const O_WRONLY: u64 = 0o1;
const O_RDWR: u64 = 0o2;
const O_CREAT: u64 = 0o100;
const O_EXCL: u64 = 0o200;
const O_TRUNC: u64 = 0o1000;
const O_APPEND: u64 = 0o2000;

const SEEK_END: u64 = 2;

const USER_PAGE_VA: usize = 0x0000_2002_0000_0000;
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
        ("create_new_file", &(create_new_file as fn())),
        ("create_without_excl_ok", &(create_without_excl_ok as fn())),
        ("excl_collision_eexist", &(excl_collision_eexist as fn())),
        (
            "open_missing_without_creat_enoent",
            &(open_missing_without_creat_enoent as fn()),
        ),
        ("trunc_zeroes_writable", &(trunc_zeroes_writable as fn())),
        ("append_writes_at_eof", &(append_writes_at_eof as fn())),
    ];
    for (name, t) in tests {
        serial_println!("syscall_open_flags: {}", name);
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
        // Touch every page to force-fault before any syscall.
        let dst = USER_PAGE_VA as *mut u8;
        let mut i = 0;
        while i < USER_PAGE_LEN {
            ptr::write_volatile(dst.add(i), 0);
            i += 4096;
        }
    }
}

/// Stage `bytes` at USER_PAGE_VA (+ NUL terminator) and return the VA.
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

/// Copy `bytes` to a scratch region within the staging page, returning
/// that region's VA. The staged path must not overlap; callers are
/// expected to stage the path first.
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

fn open(path: &[u8], flags: u64, mode: u64) -> i64 {
    let uva = stage(path);
    unsafe { syscall_dispatch(SYS_OPEN, uva, flags, mode, 0, 0, 0) }
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

fn lseek_end(fd: i64) -> i64 {
    unsafe { syscall_dispatch(SYS_LSEEK, fd as u64, 0, SEEK_END, 0, 0, 0) }
}

// --- Tests ---------------------------------------------------------------

fn create_new_file() {
    let fd = open(b"/tmp/creat-new\0", O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3, "O_CREAT on new path must succeed, got {}", fd);
    assert_eq!(close(fd), 0);

    // Reopen RDONLY — the file must exist now.
    let fd2 = open(b"/tmp/creat-new\0", O_RDONLY, 0);
    assert!(fd2 >= 3, "reopen after O_CREAT failed: {}", fd2);
    assert_eq!(close(fd2), 0);
}

fn create_without_excl_ok() {
    // O_CREAT without O_EXCL on an existing file opens it, doesn't error.
    let fd = open(b"/tmp/creat-idem\0", O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3);
    assert_eq!(close(fd), 0);
    let fd2 = open(b"/tmp/creat-idem\0", O_WRONLY | O_CREAT, 0o644);
    assert!(
        fd2 >= 3,
        "second O_CREAT w/o O_EXCL must succeed, got {}",
        fd2
    );
    assert_eq!(close(fd2), 0);
}

fn excl_collision_eexist() {
    let fd = open(b"/tmp/creat-excl\0", O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3);
    assert_eq!(close(fd), 0);
    let r = open(b"/tmp/creat-excl\0", O_WRONLY | O_CREAT | O_EXCL, 0o644);
    assert_eq!(
        r, EEXIST,
        "O_CREAT|O_EXCL on existing must be EEXIST, got {}",
        r
    );
}

fn open_missing_without_creat_enoent() {
    let r = open(b"/tmp/no-such-file-ever\0", O_RDONLY, 0);
    assert_eq!(
        r, ENOENT,
        "open missing without O_CREAT must be ENOENT, got {}",
        r
    );
}

fn trunc_zeroes_writable() {
    // Create + write some payload.
    let fd = open(b"/tmp/trunc\0", O_WRONLY | O_CREAT, 0o644);
    assert!(fd >= 3);
    let n = write_bytes(fd, b"hello world");
    assert_eq!(n, 11);
    assert_eq!(close(fd), 0);

    // Re-open with O_TRUNC — content must be gone.
    let fd2 = open(b"/tmp/trunc\0", O_WRONLY | O_TRUNC, 0);
    assert!(fd2 >= 3, "O_TRUNC open failed: {}", fd2);
    assert_eq!(close(fd2), 0);

    let fd3 = open(b"/tmp/trunc\0", O_RDONLY, 0);
    assert!(fd3 >= 3);
    let mut buf = [0u8; 16];
    let r = read_bytes(fd3, &mut buf);
    assert_eq!(r, 0, "read after O_TRUNC must see empty file, got n={}", r);
    assert_eq!(close(fd3), 0);
}

fn append_writes_at_eof() {
    // Seed with some content via two separate writes using O_APPEND.
    let fd = open(b"/tmp/append\0", O_RDWR | O_CREAT, 0o644);
    assert!(fd >= 3);
    let n = write_bytes(fd, b"AAAA");
    assert_eq!(n, 4);
    assert_eq!(close(fd), 0);

    // Open O_APPEND and write — must land at EOF regardless of offset.
    let fd2 = open(b"/tmp/append\0", O_WRONLY | O_APPEND, 0);
    assert!(fd2 >= 3, "O_APPEND open failed: {}", fd2);
    let n = write_bytes(fd2, b"BBBB");
    assert_eq!(n, 4);
    // Sanity: lseek to end reports 8.
    let eof = lseek_end(fd2);
    assert_eq!(eof, 8, "EOF after append must be 8, got {}", eof);
    assert_eq!(close(fd2), 0);

    // Read back and confirm the append landed after the initial content.
    let fd3 = open(b"/tmp/append\0", O_RDONLY, 0);
    assert!(fd3 >= 3);
    let mut buf = [0u8; 16];
    let r = read_bytes(fd3, &mut buf);
    assert_eq!(r, 8);
    assert_eq!(&buf[..8], b"AAAABBBB");
    assert_eq!(close(fd3), 0);
}
