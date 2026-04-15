//! Integration test for issue #411: `getdents64` syscall.
//!
//! Exercises the `SYS_GETDENTS64` dispatcher arm end-to-end on a rootfs
//! directory (`/etc`, populated by `xtask::ensure_initrd` with at least
//! `hostname` and `init/`). Parses the returned `linux_dirent64` records
//! and asserts their layout, end-of-directory signalling, resumption
//! across multiple calls with a small buffer, and error paths for a
//! non-directory fd, a too-small buffer, and a bad user pointer.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EFAULT, EINVAL, ENOTDIR};
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
const SYS_GETDENTS64: u64 = 217;

const ETC_PATH: &[u8] = b"/etc\0";
const HOSTNAME_PATH: &[u8] = b"/etc/hostname\0";

const DT_REG: u8 = 8;
const DT_DIR: u8 = 4;

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
        ("getdents_lists_etc", &(getdents_lists_etc as fn())),
        (
            "getdents_resumes_across_calls",
            &(getdents_resumes_across_calls as fn()),
        ),
        (
            "getdents_on_file_enotdir",
            &(getdents_on_file_enotdir as fn()),
        ),
        (
            "getdents_zero_len_einval",
            &(getdents_zero_len_einval as fn()),
        ),
        (
            "getdents_bad_ptr_efault",
            &(getdents_bad_ptr_efault as fn()),
        ),
    ];
    for (name, t) in tests {
        serial_println!("syscall_getdents: {}", name);
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
    unsafe { syscall_dispatch(SYS_OPEN, uva, 0, 0, 0, 0, 0) }
}

fn close(fd: i64) -> i64 {
    unsafe { syscall_dispatch(SYS_CLOSE, fd as u64, 0, 0, 0, 0, 0) }
}

/// Invoke getdents64 writing into a scratch region of the user page, then
/// copy the bytes back into a kernel-side Vec for parsing.
fn getdents(fd: i64, len: usize) -> (i64, Vec<u8>) {
    install_user_staging_vma();
    assert!(len + 256 < USER_PAGE_LEN);
    let buf_va = USER_PAGE_VA as u64 + 256;
    // Zero the region up front so stale bytes from a prior call can't
    // masquerade as valid records on short reads.
    unsafe {
        let dst = buf_va as *mut u8;
        for i in 0..len {
            ptr::write_volatile(dst.add(i), 0);
        }
    }
    let n = unsafe { syscall_dispatch(SYS_GETDENTS64, fd as u64, buf_va, len as u64, 0, 0, 0) };
    let mut out = Vec::new();
    if n > 0 {
        out.reserve(n as usize);
        unsafe {
            let src = buf_va as *const u8;
            for i in 0..n as usize {
                out.push(ptr::read_volatile(src.add(i)));
            }
        }
    }
    (n, out)
}

#[derive(Debug)]
struct Dirent {
    ino: u64,
    off: u64,
    #[allow(dead_code)]
    reclen: u16,
    dtype: u8,
    name: Vec<u8>,
}

fn parse_dirents(buf: &[u8]) -> Vec<Dirent> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 19 <= buf.len() {
        let ino = u64::from_le_bytes(buf[i..i + 8].try_into().unwrap());
        let off = u64::from_le_bytes(buf[i + 8..i + 16].try_into().unwrap());
        let reclen = u16::from_le_bytes(buf[i + 16..i + 18].try_into().unwrap());
        let dtype = buf[i + 18];
        assert!(reclen as usize >= 20, "reclen too small: {}", reclen);
        assert!(
            i + reclen as usize <= buf.len(),
            "reclen {} overruns buffer",
            reclen
        );
        assert_eq!(reclen as usize % 8, 0, "reclen must be 8-aligned");
        // Name is a NUL-terminated string starting at +19.
        let name_region = &buf[i + 19..i + reclen as usize];
        let nul = name_region
            .iter()
            .position(|&b| b == 0)
            .expect("dirent name must be NUL-terminated");
        out.push(Dirent {
            ino,
            off,
            reclen,
            dtype,
            name: name_region[..nul].to_vec(),
        });
        i += reclen as usize;
    }
    assert_eq!(i, buf.len(), "trailing bytes in dirent buffer");
    out
}

fn getdents_lists_etc() {
    let fd = open_ro(ETC_PATH);
    assert!(fd >= 3, "open /etc failed: {}", fd);

    let (n, buf) = getdents(fd, 1024);
    assert!(n > 0, "getdents64 returned {}", n);
    let entries = parse_dirents(&buf);
    assert!(!entries.is_empty(), "expected at least one dirent");

    // Validate presence of known rootfs entries.
    let names: Vec<&[u8]> = entries.iter().map(|d| d.name.as_slice()).collect();
    assert!(
        names.iter().any(|n| *n == b"hostname"),
        "expected 'hostname' in /etc"
    );
    assert!(
        names.iter().any(|n| *n == b"init"),
        "expected 'init' in /etc"
    );

    // d_type must match InodeKind: regular for hostname, dir for init.
    let hostname = entries.iter().find(|d| d.name == b"hostname").unwrap();
    assert_eq!(hostname.dtype, DT_REG);
    let init_dir = entries.iter().find(|d| d.name == b"init").unwrap();
    assert_eq!(init_dir.dtype, DT_DIR);

    // Cookies must be strictly monotonically increasing and non-zero.
    let mut last = 0u64;
    for e in &entries {
        assert!(e.off > last, "dirent cookie must be monotonic: {:?}", e);
        assert!(e.ino > 0);
        last = e.off;
    }

    // Next call returns 0 (EOF).
    let (n2, _) = getdents(fd, 1024);
    assert_eq!(n2, 0, "second getdents must be 0 at EOF, got {}", n2);

    close(fd);
}

fn getdents_resumes_across_calls() {
    // Use a very small buffer (one record) to force resumption.
    let fd = open_ro(ETC_PATH);
    assert!(fd >= 3);
    let mut all: Vec<Vec<u8>> = Vec::new();
    loop {
        let (n, buf) = getdents(fd, 32);
        if n == 0 {
            break;
        }
        assert!(n > 0, "getdents returned error {} mid-stream", n);
        let entries = parse_dirents(&buf);
        assert_eq!(entries.len(), 1, "32-byte buf must fit at most one dirent");
        all.push(entries[0].name.clone());
    }
    assert!(
        all.iter().any(|n| n == b"hostname"),
        "resumed listing missing 'hostname': {:?}",
        all
    );
    assert!(
        all.iter().any(|n| n == b"init"),
        "resumed listing missing 'init': {:?}",
        all
    );
    close(fd);
}

fn getdents_on_file_enotdir() {
    let fd = open_ro(HOSTNAME_PATH);
    assert!(fd >= 3);
    let (n, _) = getdents(fd, 256);
    assert_eq!(
        n, ENOTDIR,
        "getdents64 on a regular file must return ENOTDIR"
    );
    close(fd);
}

fn getdents_zero_len_einval() {
    let fd = open_ro(ETC_PATH);
    assert!(fd >= 3);
    let buf_va = USER_PAGE_VA as u64 + 256;
    let r = unsafe { syscall_dispatch(SYS_GETDENTS64, fd as u64, buf_va, 0, 0, 0, 0) };
    assert_eq!(r, EINVAL, "getdents64 with len=0 must return EINVAL");
    close(fd);
}

fn getdents_bad_ptr_efault() {
    let fd = open_ro(ETC_PATH);
    assert!(fd >= 3);
    // Kernel-half pointer — unambiguously outside the user range.
    let bad_va: u64 = 0xFFFF_8000_0000_0000;
    let r = unsafe { syscall_dispatch(SYS_GETDENTS64, fd as u64, bad_va, 256, 0, 0, 0) };
    assert_eq!(r, EFAULT, "getdents64 with bad ptr must return EFAULT");
    close(fd);
}
