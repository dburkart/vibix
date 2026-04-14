//! Integration coverage for issue #162 — the RFC 0001 `mmap` / `munmap`
//! / `mprotect` / `madvise` syscall surface. Drives `syscall_dispatch`
//! directly (no ring-3 driver) to verify:
//!
//! * MAP_FIXED_NOREPLACE returns EEXIST when the target VA overlaps.
//! * MAP_SHARED anon is accepted; fd != -1 returns ENODEV.
//! * munmap over a hole returns 0 (POSIX).
//! * munmap splits straddling VMAs at sub-range boundaries.
//! * mprotect returns ENOMEM only when a sub-page is literally unmapped;
//!   partial coverage of a single VMA is fine.
//! * MADV_DONTNEED on anon-private drops cached frames so the next
//!   touch returns a zero-filled page.
//! * A musl-style malloc workload (alloc N pages, free them, alloc
//!   again, grow) succeeds end-to-end.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::arch::x86_64::syscall::syscall_dispatch;
use vibix::fs::{EEXIST, EINVAL, ENODEV, ENOMEM};
use vibix::mem::pf::{
    MADV_DONTNEED, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, MAP_SHARED,
    PROT_READ, PROT_WRITE,
};
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
        ("mmap_fd_nonneg_enodev", &(mmap_fd_nonneg_enodev as fn())),
        (
            "mmap_requires_exactly_one_share",
            &(mmap_requires_exactly_one_share as fn()),
        ),
        (
            "mmap_shared_anon_succeeds",
            &(mmap_shared_anon_succeeds as fn()),
        ),
        (
            "mmap_fixed_noreplace_overlap_eexist",
            &(mmap_fixed_noreplace_overlap_eexist as fn()),
        ),
        (
            "mmap_fixed_noreplace_unused_succeeds",
            &(mmap_fixed_noreplace_unused_succeeds as fn()),
        ),
        (
            "munmap_returns_zero_on_hole",
            &(munmap_returns_zero_on_hole as fn()),
        ),
        (
            "munmap_splits_middle_of_vma",
            &(munmap_splits_middle_of_vma as fn()),
        ),
        (
            "mprotect_partial_vma_succeeds",
            &(mprotect_partial_vma_succeeds as fn()),
        ),
        (
            "mprotect_hole_in_range_enomem",
            &(mprotect_hole_in_range_enomem as fn()),
        ),
        (
            "mprotect_unknown_prot_bits_einval",
            &(mprotect_unknown_prot_bits_einval as fn()),
        ),
        (
            "madvise_dontneed_rezeroes_page",
            &(madvise_dontneed_rezeroes_page as fn()),
        ),
        (
            "madvise_unknown_advice_einval",
            &(madvise_unknown_advice_einval as fn()),
        ),
        (
            "malloc_workload_alloc_free_regrow",
            &(malloc_workload_alloc_free_regrow as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn mmap(addr: u64, len: u64, prot: u32, flags: u32, fd: i64, off: u64) -> i64 {
    unsafe { syscall_dispatch(9, addr, len, prot as u64, flags as u64, fd as u64, off) }
}

fn mprotect(addr: u64, len: u64, prot: u32) -> i64 {
    unsafe { syscall_dispatch(10, addr, len, prot as u64, 0, 0, 0) }
}

fn munmap(addr: u64, len: u64) -> i64 {
    unsafe { syscall_dispatch(11, addr, len, 0, 0, 0, 0) }
}

fn madvise(addr: u64, len: u64, advice: i32) -> i64 {
    unsafe { syscall_dispatch(28, addr, len, advice as u64, 0, 0, 0) }
}

fn anon_rw(len: u64) -> u64 {
    let r = mmap(
        0,
        len,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE,
        -1,
        0,
    );
    assert!(r > 0, "mmap failed: {}", r);
    r as u64
}

// ── Tests ────────────────────────────────────────────────────────────────

fn mmap_fd_nonneg_enodev() {
    // File-backed mappings are not implemented: fd != -1 must yield ENODEV
    // (not EINVAL) per RFC 0001.
    let r = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    assert_eq!(r, ENODEV, "expected ENODEV for fd=0, got {}", r);
}

fn mmap_requires_exactly_one_share() {
    // MAP_ANONYMOUS alone (no PRIVATE or SHARED) → EINVAL.
    let r = mmap(0, 4096, PROT_READ, MAP_ANONYMOUS, -1, 0);
    assert_eq!(r, EINVAL);
    // Both PRIVATE and SHARED → EINVAL.
    let r = mmap(
        0,
        4096,
        PROT_READ,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_SHARED,
        -1,
        0,
    );
    assert_eq!(r, EINVAL);
}

fn mmap_shared_anon_succeeds() {
    // RFC 0001: anon-shared is fully supported.
    let r = mmap(
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_SHARED,
        -1,
        0,
    );
    assert!(r > 0, "anon-shared mmap failed: {}", r);
    // Touch the page; should demand-fault without panicking.
    unsafe {
        ptr::write_volatile(r as *mut u8, 0x7Fu8);
        assert_eq!(ptr::read_volatile(r as *const u8), 0x7F);
    }
    let _ = munmap(r as u64, 4096);
}

fn mmap_fixed_noreplace_overlap_eexist() {
    let a = anon_rw(4096);
    // Re-requesting the same VA with MAP_FIXED_NOREPLACE must fail EEXIST.
    let r = mmap(
        a,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(r, EEXIST, "expected EEXIST on overlap, got {:#x}", r);
    // Bare MAP_FIXED at the same VA should succeed (silently evicts) and
    // return the requested address.
    let r = mmap(
        a,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(r as u64, a, "MAP_FIXED must return the requested VA");
    let _ = munmap(a, 4096);
}

fn mmap_fixed_noreplace_unused_succeeds() {
    // MAP_FIXED_NOREPLACE at an unused, aligned VA must honour the
    // requested address exactly and install a working VMA.
    let base: u64 = 0x0000_3000_1000_0000;
    let r = mmap(
        base,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(r as u64, base, "expected exact VA, got {:#x}", r);

    // The page must be usable — demand-fault on first write, read-back.
    unsafe {
        ptr::write_volatile(base as *mut u8, 0x5A);
        assert_eq!(ptr::read_volatile(base as *const u8), 0x5A);
    }

    assert_eq!(munmap(base, 4096), 0);

    // After unmap the VA is free again: a second NOREPLACE at the same
    // VA must succeed, proving the earlier VMA was cleanly removed.
    let r = mmap(
        base,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(r as u64, base);
    let _ = munmap(base, 4096);

    // Unaligned addr with MAP_FIXED_NOREPLACE must reject with EINVAL
    // (fixed mappings demand exact page alignment).
    let r = mmap(
        base + 1,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE,
        -1,
        0,
    );
    assert_eq!(r, EINVAL, "unaligned NOREPLACE must be EINVAL, got {}", r);
}

fn munmap_returns_zero_on_hole() {
    // A well-formed but entirely unmapped range returns 0, not ENOMEM.
    // Pick a range far from any mapping this test suite sets up.
    let base: u64 = 0x0000_3000_0000_0000;
    let r = munmap(base, 4096);
    assert_eq!(r, 0, "munmap of hole must return 0, got {}", r);
}

fn munmap_splits_middle_of_vma() {
    // Install an 8-page mapping, unmap the middle 4, verify the VMA tree
    // now holds two fragments with the correct sizes.
    let a = anon_rw(8 * 4096);
    let r = munmap(a + 2 * 4096, 4 * 4096);
    assert_eq!(r, 0);

    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    let left = guard.find(a as usize).expect("left fragment missing");
    assert_eq!(left.start, a as usize);
    assert_eq!(left.end, (a as usize) + 2 * 4096);
    let right = guard
        .find((a as usize) + 6 * 4096)
        .expect("right fragment missing");
    assert_eq!(right.start, (a as usize) + 6 * 4096);
    assert_eq!(right.end, (a as usize) + 8 * 4096);
    // The middle page must no longer be mapped.
    assert!(guard.find((a as usize) + 3 * 4096).is_none());
    drop(guard);

    let _ = munmap(a, 2 * 4096);
    let _ = munmap(a + 6 * 4096, 2 * 4096);
}

fn mprotect_partial_vma_succeeds() {
    // 4 pages RW — mprotect middle 2 to RO; both fragments must still exist.
    let a = anon_rw(4 * 4096);
    unsafe {
        ptr::write_volatile(a as *mut u8, 0xAA);
    }
    let r = mprotect(a + 4096, 2 * 4096, PROT_READ);
    assert_eq!(r, 0, "mprotect partial VMA failed: {}", r);

    let aspace = vibix::task::current_address_space();
    let guard = aspace.read();
    // The middle fragment is now PROT_READ only.
    let mid = guard.find((a as usize) + 4096).expect("middle fragment");
    assert_eq!(mid.prot_user, PROT_READ);
    // Outer fragments keep RW.
    let head = guard.find(a as usize).expect("head fragment");
    assert_eq!(head.prot_user, PROT_READ | PROT_WRITE);
    drop(guard);
    let _ = munmap(a, 4 * 4096);
}

fn mprotect_hole_in_range_enomem() {
    // Two disjoint mappings with a hole between them; mprotect across the
    // whole span must return ENOMEM because a sub-page is literally
    // unmapped.
    let a = anon_rw(4096);
    // Pick a deliberately-separated second VA so find_unmapped_region
    // cannot place them adjacent.
    let b = a + 0x0010_0000;
    let r = mmap(
        b,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
        -1,
        0,
    );
    assert_eq!(r as u64, b);

    let r = mprotect(a, (b - a) + 4096, PROT_READ);
    assert_eq!(
        r, ENOMEM,
        "mprotect across hole must return ENOMEM, got {}",
        r
    );

    let _ = munmap(a, 4096);
    let _ = munmap(b, 4096);
}

fn mprotect_unknown_prot_bits_einval() {
    let a = anon_rw(4096);
    let bogus: u32 = 0x8000_0000;
    let r = mprotect(a, 4096, bogus);
    assert_eq!(r, EINVAL);
    let _ = munmap(a, 4096);
}

fn madvise_dontneed_rezeroes_page() {
    // Write a byte, MADV_DONTNEED the page, touch it again, verify zero.
    let a = anon_rw(4096);
    unsafe {
        ptr::write_volatile(a as *mut u8, 0x42);
        assert_eq!(ptr::read_volatile(a as *const u8), 0x42);
    }
    let r = madvise(a, 4096, MADV_DONTNEED);
    assert_eq!(r, 0);
    unsafe {
        // The next read must see 0 — a fresh zero-filled frame.
        assert_eq!(ptr::read_volatile(a as *const u8), 0);
    }
    let _ = munmap(a, 4096);
}

fn madvise_unknown_advice_einval() {
    let a = anon_rw(4096);
    let r = madvise(a, 4096, 99);
    assert_eq!(r, EINVAL);
    let _ = munmap(a, 4096);
}

fn malloc_workload_alloc_free_regrow() {
    // Simulate a libc-style allocator: grab an arena, write a pattern
    // across every page, free it, grow a fresh arena, and verify the new
    // pages are zero. Exercises mmap → touch → munmap → mmap → touch
    // end-to-end.
    const PAGES: usize = 16;
    const LEN: usize = PAGES * 4096;

    let a = anon_rw(LEN as u64);
    unsafe {
        for p in 0..PAGES {
            let pattern = (p as u8).wrapping_mul(0x37).wrapping_add(0x11);
            ptr::write_volatile((a as *mut u8).add(p * 4096), pattern);
        }
        for p in 0..PAGES {
            let pattern = (p as u8).wrapping_mul(0x37).wrapping_add(0x11);
            assert_eq!(ptr::read_volatile((a as *const u8).add(p * 4096)), pattern);
        }
    }

    assert_eq!(munmap(a, LEN as u64), 0);

    let b = anon_rw((LEN * 2) as u64);
    unsafe {
        // Entire arena must be zero-initialised on first touch.
        for p in 0..(PAGES * 2) {
            assert_eq!(
                ptr::read_volatile((b as *const u8).add(p * 4096)),
                0,
                "fresh mmap page {} not zero",
                p
            );
        }
    }
    let _ = munmap(b, (LEN * 2) as u64);
}
