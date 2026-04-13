//! Integration test: the `Flusher` abstraction correctly invalidates
//! TLB entries for unmapped pages, so a remap to a different backing
//! frame isn't shadowed by a stale cached translation.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use vibix::mem::paging;
use vibix::mem::tlb::{Flusher, INLINE_CAP};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("stale_tlb_invalidated", &(stale_tlb_invalidated as fn())),
        ("overflow_path_works", &(overflow_path_works as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

const TEST_VA: u64 = 0xFFFF_C000_F1B0_0000;
const SENTINEL: u64 = 0xCAFE_F00D_DEAD_BEEF;
const FLAGS_RW: PageTableFlags =
    PageTableFlags::from_bits_truncate(PageTableFlags::PRESENT.bits() | PageTableFlags::WRITABLE.bits());

/// Map a page, stash a sentinel, unmap+flush via Flusher, then remap
/// the *same VA* to a fresh (zeroed) frame. The remap must be visible
/// — if the Flusher's finish didn't evict the old translation, the
/// read could still hit the original frame's sentinel.
fn stale_tlb_invalidated() {
    let va = VirtAddr::new(TEST_VA);
    assert!(
        paging::translate(va).is_none(),
        "picked test VA {va:?} is already mapped — pick another"
    );

    let page: Page<Size4KiB> = Page::from_start_address(va).expect("VA aligned");

    let mut f = Flusher::new_active();
    paging::map(page, FLAGS_RW, &mut f).expect("initial map");
    f.finish();

    let ptr = va.as_u64() as *mut u64;
    unsafe { ptr.write_volatile(SENTINEL) };

    let mut f = Flusher::new_active();
    paging::unmap_and_free(page, &mut f).expect("unmap");
    f.finish();
    assert!(paging::translate(va).is_none(), "unmap left PTE behind");

    let mut f = Flusher::new_active();
    let new_frame = paging::map(page, FLAGS_RW, &mut f).expect("remap");
    f.finish();

    // Zero the new frame through HHDM so the test result doesn't
    // depend on whether the allocator happened to hand us the same
    // (still-sentinel-bearing) frame back.
    let hhdm_ptr = (paging::hhdm_offset() + new_frame.start_address().as_u64()).as_mut_ptr::<u8>();
    unsafe { core::ptr::write_bytes(hhdm_ptr, 0, 4096) };

    let observed = unsafe { ptr.read_volatile() };
    assert_eq!(
        observed, 0,
        "stale TLB translation survived unmap: read {observed:#x}",
    );

    let mut f = Flusher::new_active();
    paging::unmap_and_free(page, &mut f).expect("cleanup unmap");
    f.finish();
}

/// Queueing past the inline cap must not panic and must leave the TLB
/// in a valid state. The Flusher latches into overflow mode and does a
/// whole-TLB reload in `finish`. After finish, a freshly-mapped VA is
/// readable — the CR3 reload didn't wedge the address space.
fn overflow_path_works() {
    let mut f = Flusher::new_active();
    for i in 0..(INLINE_CAP as u64 + 4) {
        f.invalidate(VirtAddr::new(0xFFFF_D000_0000_0000 + i * 0x1000));
    }
    assert!(f.overflowed(), "expected overflow latch");
    f.finish();

    // Address space still works end-to-end.
    let va = VirtAddr::new(0xFFFF_C000_F1B1_0000);
    let page: Page<Size4KiB> = Page::from_start_address(va).expect("VA aligned");
    let mut f = Flusher::new_active();
    paging::map(page, FLAGS_RW, &mut f).expect("post-overflow map");
    f.finish();
    let ptr = va.as_u64() as *mut u64;
    unsafe {
        ptr.write_volatile(0x1234_5678_9ABC_DEF0);
        assert_eq!(ptr.read_volatile(), 0x1234_5678_9ABC_DEF0);
    }
    let mut f = Flusher::new_active();
    paging::unmap_and_free(page, &mut f).expect("post-overflow unmap");
    f.finish();
}
