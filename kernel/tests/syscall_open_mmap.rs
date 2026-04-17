//! Integration test for issue #125: the expanded syscall table's new
//! arms — `SYS_OPEN` (nr 2) and `SYS_MMAP` (nr 9). Boots the kernel,
//! initialises the task scheduler (so the current task has an fd table
//! and address space), then calls `syscall_dispatch` directly.
//!
//! Pre-VFS, `sys_open` only resolves four special paths
//! (`/dev/stdin|stdout|stderr|serial`) to a `SerialBackend`-backed fd;
//! anything else returns `-ENOENT`. `sys_mmap` is anonymous-only:
//! `MAP_ANONYMOUS | MAP_PRIVATE`, `fd == -1`, `off == 0`.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::vfs::path_walk::PATH_MAX;
use vibix::fs::{EBADF, EINVAL, ENAMETOOLONG, ENODEV, ENOENT};
use vibix::mem::pf::{MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

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
            "open_dev_stdout_returns_fd",
            &(open_dev_stdout_returns_fd as fn()),
        ),
        (
            "open_unknown_returns_enoent",
            &(open_unknown_returns_enoent as fn()),
        ),
        (
            "open_bad_user_ptr_returns_efault",
            &(open_bad_user_ptr_returns_efault as fn()),
        ),
        (
            "open_path_not_terminated",
            &(open_path_not_terminated as fn()),
        ),
        ("close_closes_opened_fd", &(close_closes_opened_fd as fn())),
        (
            "mmap_anonymous_returns_user_va",
            &(mmap_anonymous_returns_user_va as fn()),
        ),
        ("mmap_zero_len_einval", &(mmap_zero_len_einval as fn())),
        (
            "mmap_requires_anon_private",
            &(mmap_requires_anon_private as fn()),
        ),
        (
            "mmap_rejects_non_neg_fd",
            &(mmap_rejects_non_neg_fd as fn()),
        ),
        (
            "mmap_rejects_nonzero_off",
            &(mmap_rejects_nonzero_off as fn()),
        ),
        (
            "mmap_fixed_returns_requested_va",
            &(mmap_fixed_returns_requested_va as fn()),
        ),
        (
            "mmap_two_calls_return_disjoint",
            &(mmap_two_calls_return_disjoint as fn()),
        ),
        ("read_write_via_new_fd", &(read_write_via_new_fd as fn())),
        (
            "unknown_syscall_returns_enosys",
            &(unknown_syscall_returns_enosys as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- User-staging helpers ------------------------------------------------

/// Lower-half VA well clear of anything the kernel maps eagerly. The
/// `demand_paging` test uses the same slot; this file runs in its own
/// QEMU instance so there's no collision.
const USER_PAGE_VA: usize = 0x0000_2000_0000_0000;
const USER_PAGE_LEN: usize = 4 * 4096;

/// Install a single demand-paged anonymous VMA at `USER_PAGE_VA` so
/// tests can stage user-visible bytes there (e.g. NUL-terminated open
/// paths) and the `#PF` handler backs them with a real frame on first
/// touch.
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
    // First touch to force the VMA to demand-fault in before we invoke
    // syscall_dispatch; the dispatcher runs with SMAP bracketed by
    // stac/clac, but the fault handler itself must not race.
    unsafe {
        ptr::write_volatile(USER_PAGE_VA as *mut u8, 0);
    }
}

/// Copy a NUL-terminated path into the staged user page and return the
/// VA the kernel should see as `path_uva`.
fn stage_path(bytes: &[u8]) -> u64 {
    install_user_staging_vma();
    assert!(bytes.len() < USER_PAGE_LEN, "test path too long");
    unsafe {
        let dst = USER_PAGE_VA as *mut u8;
        for (i, b) in bytes.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
        // NUL terminator.
        ptr::write_volatile(dst.add(bytes.len()), 0);
    }
    USER_PAGE_VA as u64
}

fn open(path: &[u8], flags: u32) -> i64 {
    let uva = stage_path(path);
    unsafe { syscall_dispatch(core::ptr::null_mut(), 2, uva, flags as u64, 0, 0, 0, 0) }
}

fn close(fd: u32) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), 3, fd as u64, 0, 0, 0, 0, 0) }
}

fn mmap(addr: u64, len: u64, prot: u32, flags: u32, fd: i64, off: u64) -> i64 {
    unsafe { syscall_dispatch(core::ptr::null_mut(), 9, addr, len, prot as u64, flags as u64, fd as u64, off) }
}

// --- open() tests --------------------------------------------------------

fn open_dev_stdout_returns_fd() {
    let fd = open(b"/dev/stdout", 1 /* O_WRONLY */);
    assert!(fd >= 3, "expected fd >= 3, got {}", fd);
    assert_eq!(close(fd as u32), 0, "close of fresh fd failed");
}

fn open_unknown_returns_enoent() {
    let r = open(b"/nonexistent", 0);
    assert_eq!(r, ENOENT, "unknown path must return ENOENT, got {}", r);
}

fn open_bad_user_ptr_returns_efault() {
    // Kernel-half VA — check_user_range rejects it up front.
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), 2, 0xffff_ffff_8000_0000, 0, 0, 0, 0, 0) };
    assert_eq!(r, -14, "bad user ptr must return EFAULT, got {}", r);
}

fn open_path_not_terminated() {
    install_user_staging_vma();
    // Fill enough of the staging page with non-NUL bytes that the
    // kernel's `PATH_MAX + 1`-sized copy-in buffer exhausts before
    // hitting a terminator: the kernel reads up to PATH_MAX + 1 bytes
    // looking for a NUL.
    const UNTERMINATED_BYTES: usize = PATH_MAX + 1;
    unsafe {
        let dst = USER_PAGE_VA as *mut u8;
        let mut i = 0;
        while i < UNTERMINATED_BYTES {
            ptr::write_volatile(dst.add(i), b'A');
            i += 1;
        }
    }
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), 2, USER_PAGE_VA as u64, 0, 0, 0, 0, 0) };
    assert_eq!(
        r, ENAMETOOLONG,
        "unterminated path must return ENAMETOOLONG, got {}",
        r
    );
}

fn close_closes_opened_fd() {
    let fd = open(b"/dev/serial", 2 /* O_RDWR */);
    assert!(fd >= 3);
    assert_eq!(close(fd as u32), 0);
    // Closing the same fd again must fail with EBADF.
    assert_eq!(close(fd as u32), EBADF);
}

// --- mmap() tests --------------------------------------------------------

const USER_VA_END: u64 = 0x0000_8000_0000_0000;

fn mmap_anonymous_returns_user_va() {
    let r = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(r > 0, "mmap failed: {}", r);
    let va = r as u64;
    assert_eq!(va & 0xFFF, 0, "mmap returned unaligned VA {:#x}", va);
    assert!(va < USER_VA_END, "mmap returned kernel-half VA {:#x}", va);
    // The VMA must be visible in the current address space.
    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    let vma = guard.find(va as usize).expect("mmap'd VMA not found");
    assert_eq!(vma.start, va as usize);
    assert_eq!(vma.end, (va as usize) + 4096);
}

fn mmap_zero_len_einval() {
    let r = mmap(0, 0, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert_eq!(r, EINVAL);
}

fn mmap_requires_anon_private() {
    // Missing MAP_ANONYMOUS with fd=-1 → file-backed path is attempted
    // and returns ENODEV (no VFS yet) per RFC 0001.
    let r = mmap(0, 4096, PROT_READ, MAP_PRIVATE, -1, 0);
    assert_eq!(
        r, ENODEV,
        "MAP_PRIVATE without MAP_ANONYMOUS routes to file-backed path: ENODEV"
    );
    // Neither MAP_PRIVATE nor MAP_SHARED → EINVAL.
    let r = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS, -1, 0);
    assert_eq!(r, EINVAL);
}

fn mmap_rejects_non_neg_fd() {
    // fd != -1 routes to the (unsupported) file-backed path → ENODEV.
    let r = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    assert_eq!(r, ENODEV);
}

fn mmap_rejects_nonzero_off() {
    let r = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 4096);
    assert_eq!(r, EINVAL);
}

fn mmap_fixed_returns_requested_va() {
    // MAP_FIXED is now supported (RFC 0001): returns the requested VA,
    // silently evicting any overlap.
    let a = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    assert!(a > 0);
    let r = mmap(
        a as u64,
        4096,
        PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(r as u64, a as u64);
}

fn mmap_two_calls_return_disjoint() {
    let a = mmap(
        0,
        8192,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(a > 0);
    let b = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(b > 0);
    assert!(
        (b as u64) >= (a as u64) + 8192 || (a as u64) >= (b as u64) + 4096,
        "mmap regions overlap: a={:#x} b={:#x}",
        a,
        b
    );
}

// --- read()/write() via a fresh fd --------------------------------------

fn read_write_via_new_fd() {
    // Open /dev/stdout, write a small buffer through it via SYS_WRITE,
    // verifying the whole chain from syscall_dispatch through the fd
    // table to SerialBackend.
    let fd = open(b"/dev/stdout", 1);
    assert!(fd >= 3);
    let msg = b"syscall_open_mmap: write_via_new_fd ok\n";
    // Stage the message bytes at a distinct offset inside the user page
    // so we don't clobber the path we just used.
    let write_off = 256;
    let buf_va = USER_PAGE_VA as u64 + write_off as u64;
    unsafe {
        let dst = buf_va as *mut u8;
        for (i, b) in msg.iter().enumerate() {
            ptr::write_volatile(dst.add(i), *b);
        }
    }
    let n = unsafe { syscall_dispatch(core::ptr::null_mut(), 1, fd as u64, buf_va, msg.len() as u64, 0, 0, 0) };
    assert_eq!(n, msg.len() as i64, "write returned {}", n);
    assert_eq!(close(fd as u32), 0);
}

fn unknown_syscall_returns_enosys() {
    // Any syscall number not in the dispatcher's match returns -ENOSYS.
    // Using a high number well above anything we might implement soon.
    let r = unsafe { syscall_dispatch(core::ptr::null_mut(), 9999, 0, 0, 0, 0, 0, 0) };
    assert_eq!(r, -38, "expected ENOSYS, got {}", r);
}
