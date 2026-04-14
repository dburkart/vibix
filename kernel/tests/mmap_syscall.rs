//! Integration test: mmap / munmap / mprotect / madvise syscall implementations.
//!
//! Exercises the kernel-side implementations in the bootstrap task's address
//! space.  Memory access uses `copy_to_user` / `copy_from_user` so the
//! STAC/CLAC bracket makes demand-paging work under SMAP — direct
//! `ptr::read_volatile` of a USER_ACCESSIBLE page from ring-0 would trip SMAP
//! on the retry after the fault handler maps the PTE.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::uaccess;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

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
        ("mmap_anon_private_touch", &(mmap_anon_private_touch as fn())),
        ("mmap_hint_advances", &(mmap_hint_advances as fn())),
        ("mmap_fixed", &(mmap_fixed as fn())),
        ("mmap_fixed_noreplace_conflict", &(mmap_fixed_noreplace_conflict as fn())),
        ("munmap_returns_zero", &(munmap_returns_zero as fn())),
        ("munmap_vma_removed", &(munmap_vma_removed as fn())),
        ("mprotect_readwrite", &(mprotect_readwrite as fn())),
        ("madvise_dontneed_no_crash", &(madvise_dontneed_no_crash as fn())),
        ("mmap_invalid_args", &(mmap_invalid_args as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// Linux-ABI constants used by the tests.
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;
const MAP_FIXED_NOREPLACE: u64 = 0x0010_0000;
const MAP_ANON_PRIVATE: u64 = MAP_PRIVATE | MAP_ANONYMOUS;
const FD_NONE: u64 = u64::MAX; // -1 as u64
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EEXIST: i64 = -17;
const ENODEV: i64 = -19;
const PAGE: u64 = 4096;

// ---------------------------------------------------------------------------

/// Map a page, write a sentinel through `copy_to_user`, read it back, unmap.
fn mmap_anon_private_touch() {
    let addr = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0, "sys_mmap failed: {addr}");
    assert_eq!(addr as u64 % PAGE, 0, "addr not page-aligned");

    // Read initial content (zero) via copy_from_user — demand-pages the frame
    // under the STAC/CLAC bracket so SMAP is satisfied.
    let mut buf = [0xFFu8; 8];
    unsafe { uaccess::copy_from_user(&mut buf, addr as usize).expect("copy_from_user zero") };
    assert_eq!(buf, [0u8; 8], "fresh anon page should be zero");

    // Write a sentinel and read it back.
    let payload = [0xABu8; 8];
    unsafe { uaccess::copy_to_user(addr as usize, &payload).expect("copy_to_user") };
    let mut readback = [0u8; 8];
    unsafe { uaccess::copy_from_user(&mut readback, addr as usize).expect("copy_from_user readback") };
    assert_eq!(readback, payload, "write/readback mismatch");

    let rc = vibix::mem::mmap::sys_munmap(addr as u64, PAGE);
    assert_eq!(rc, 0, "sys_munmap failed: {rc}");
}

/// Two adjacent mmap calls without a hint should return non-overlapping ranges.
fn mmap_hint_advances() {
    let a1 = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    let a2 = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(a1 >= 0 && a2 >= 0, "mmap failed: a1={a1} a2={a2}");
    assert_ne!(a1, a2, "two mmaps returned same address");

    // Ranges must not overlap.
    let (lo, hi) = if a1 < a2 { (a1 as u64, a2 as u64) } else { (a2 as u64, a1 as u64) };
    assert!(lo + PAGE <= hi, "mmap ranges overlap: [{lo:#x},{}) and [{hi:#x},{})", lo + PAGE, hi + PAGE);

    let _ = vibix::mem::mmap::sys_munmap(a1 as u64, PAGE);
    let _ = vibix::mem::mmap::sys_munmap(a2 as u64, PAGE);
}

/// MAP_FIXED places the mapping at exactly the requested address.
fn mmap_fixed() {
    // Allocate one page to learn a free address, then free it.
    let base = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(base >= 0);
    let _ = vibix::mem::mmap::sys_munmap(base as u64, PAGE);

    // Place a MAP_FIXED mapping several pages above the freed address.
    let target = (base as u64 + 8 * PAGE) & !(PAGE - 1);
    let addr = vibix::mem::mmap::sys_mmap(
        target, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE | MAP_FIXED, FD_NONE, 0,
    );
    assert_eq!(addr as u64, target, "MAP_FIXED returned wrong address");

    // Write and verify through uaccess helpers.
    let payload = [0x42u8; 8];
    unsafe { uaccess::copy_to_user(target as usize, &payload).expect("copy_to_user MAP_FIXED") };
    let mut rb = [0u8; 8];
    unsafe { uaccess::copy_from_user(&mut rb, target as usize).expect("copy_from_user MAP_FIXED") };
    assert_eq!(rb, payload);

    let _ = vibix::mem::mmap::sys_munmap(target, PAGE);
}

/// MAP_FIXED_NOREPLACE returns -EEXIST when the range is already mapped.
fn mmap_fixed_noreplace_conflict() {
    let addr = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0);

    let rc = vibix::mem::mmap::sys_mmap(
        addr as u64, PAGE, PROT_READ | PROT_WRITE,
        MAP_ANON_PRIVATE | MAP_FIXED_NOREPLACE, FD_NONE, 0,
    );
    assert_eq!(rc, EEXIST, "MAP_FIXED_NOREPLACE should give EEXIST, got {rc}");

    let _ = vibix::mem::mmap::sys_munmap(addr as u64, PAGE);
}

/// munmap returns 0 for a mapped region, and also for an already-freed hole.
fn munmap_returns_zero() {
    let addr = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0);
    assert_eq!(vibix::mem::mmap::sys_munmap(addr as u64, PAGE), 0, "first munmap");
    // Second munmap on a hole must also succeed (POSIX conformant).
    assert_eq!(vibix::mem::mmap::sys_munmap(addr as u64, PAGE), 0, "hole munmap");
}

/// After munmap, the VMA is absent from the address space.
fn munmap_vma_removed() {
    let addr = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0);

    {
        let arc = vibix::task::current_address_space();
        let aspace = arc.read();
        assert!(aspace.find(addr as usize).is_some(), "VMA should exist after mmap");
    }

    assert_eq!(vibix::mem::mmap::sys_munmap(addr as u64, PAGE), 0);

    {
        let arc = vibix::task::current_address_space();
        let aspace = arc.read();
        assert!(aspace.find(addr as usize).is_none(), "VMA should be gone after munmap");
    }
}

/// mprotect promotes a PROT_READ mapping to PROT_READ|WRITE.
fn mprotect_readwrite() {
    // Map read-only.
    let addr = vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0, "sys_mmap failed");

    // Demand-page with a read under STAC bracket.
    let mut buf = [0u8; 4];
    unsafe { uaccess::copy_from_user(&mut buf, addr as usize).expect("initial read") };

    // Promote to read-write.
    assert_eq!(vibix::mem::mmap::sys_mprotect(addr as u64, PAGE, PROT_READ | PROT_WRITE), 0);

    // Write after mprotect — the PTE was remapped with WRITABLE.
    let payload = [0xCAu8; 4];
    unsafe { uaccess::copy_to_user(addr as usize, &payload).expect("write after mprotect") };
    let mut rb = [0u8; 4];
    unsafe { uaccess::copy_from_user(&mut rb, addr as usize).expect("read after mprotect") };
    assert_eq!(rb, payload, "readback after mprotect mismatch");

    let _ = vibix::mem::mmap::sys_munmap(addr as u64, PAGE);
}

/// MADV_DONTNEED does not crash and returns 0 on a backed mapping.
fn madvise_dontneed_no_crash() {
    let addr = vibix::mem::mmap::sys_mmap(0, 2 * PAGE, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0);
    assert!(addr >= 0);

    // Touch both pages (demand paging under STAC).
    let payload = [0x55u8; 8];
    unsafe {
        uaccess::copy_to_user(addr as usize, &payload).expect("touch page 0");
        uaccess::copy_to_user(addr as usize + PAGE as usize, &payload).expect("touch page 1");
    }

    // MADV_DONTNEED (4) should succeed and not crash.
    let rc = vibix::mem::mmap::sys_madvise(addr as u64, 2 * PAGE, 4);
    assert_eq!(rc, 0, "sys_madvise returned {rc}");

    // VMAs should still be present (madvise only drops PTEs, not VMAs).
    {
        let arc = vibix::task::current_address_space();
        let aspace = arc.read();
        assert!(aspace.find(addr as usize).is_some(), "VMA must survive MADV_DONTNEED");
    }

    let _ = vibix::mem::mmap::sys_munmap(addr as u64, 2 * PAGE);
}

/// Invalid argument combinations return appropriate error codes.
fn mmap_invalid_args() {
    // Zero length → EINVAL.
    assert_eq!(
        vibix::mem::mmap::sys_mmap(0, 0, PROT_READ | PROT_WRITE, MAP_ANON_PRIVATE, FD_NONE, 0),
        EINVAL, "len=0"
    );

    // File-backed (MAP_ANONYMOUS unset and/or fd != -1) → ENODEV.
    assert_eq!(
        vibix::mem::mmap::sys_mmap(0, PAGE, PROT_READ, MAP_PRIVATE, 3, 0),
        ENODEV, "file-backed"
    );

    // munmap with unaligned addr → EINVAL.
    assert_eq!(vibix::mem::mmap::sys_munmap(0x1001, PAGE), EINVAL, "unaligned munmap");

    // mprotect over a hole → ENOMEM.
    assert_eq!(
        vibix::mem::mmap::sys_mprotect(0x0000_0030_0000_0000, PAGE, PROT_READ),
        ENOMEM, "mprotect over hole"
    );
}
