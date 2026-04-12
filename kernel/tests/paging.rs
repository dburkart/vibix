//! Integration test: the kernel mapper can map a fresh frame at a
//! chosen virtual address, survive a read/write round-trip, and unmap
//! cleanly.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
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
        ("map_roundtrip_unmap", &(map_roundtrip_unmap as fn())),
        (
            "map_unmap_loop_reclaims",
            &(map_unmap_loop_reclaims as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Pick a virt address well above HHDM and below the kernel's −2 GiB
/// load region. With 256 MiB of RAM in QEMU, HHDM tops out near
/// 0xFFFF_8000_1000_0000; the kernel sits at 0xFFFF_FFFF_8000_0000.
/// This address lives comfortably between them.
const TEST_VA: u64 = 0xFFFF_C000_DEAD_B000;

fn map_roundtrip_unmap() {
    use vibix::mem::paging;

    let va = VirtAddr::new(TEST_VA);
    assert!(
        paging::translate(va).is_none(),
        "picked test VA {va:?} is already mapped — pick another"
    );

    let page: Page<Size4KiB> = Page::containing_address(va);
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let _frame = paging::map(page, flags).expect("map failed");

    let phys = paging::translate(va).expect("translate after map returned None");
    serial_println!("  mapped {va:?} -> {phys:?}");

    let ptr = va.as_u64() as *mut u64;
    unsafe {
        ptr.write_volatile(0xCAFE_F00D_DEAD_BEEF);
        assert_eq!(ptr.read_volatile(), 0xCAFE_F00D_DEAD_BEEF);
    }

    paging::unmap_and_free(page).expect("unmap failed");
    assert!(
        paging::translate(va).is_none(),
        "translate after unmap still returned Some"
    );
}

/// Map / unmap in a loop and assert the free-frame count returns to
/// baseline — guards against the bump-allocator regression where every
/// unmap leaked a frame.
fn map_unmap_loop_reclaims() {
    use vibix::mem::{frame, paging};

    let va = VirtAddr::new(0xFFFF_C000_BEEF_0000);
    let page: Page<Size4KiB> = Page::from_start_address(va).unwrap();
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;

    // First map/unmap lazily allocates intermediate page-table frames
    // (PDPT/PD/PT) that stay populated across subsequent iterations.
    // Take the baseline *after* that one-time cost so we measure pure
    // leaf-frame accounting over the loop below.
    paging::map(page, flags).expect("warm-up map");
    paging::unmap_and_free(page).expect("warm-up unmap");

    let baseline = frame::global().lock().free_frames();

    for _ in 0..64 {
        paging::map(page, flags).expect("map failed in loop");
        paging::unmap_and_free(page).expect("unmap failed in loop");
    }

    let after = frame::global().lock().free_frames();
    assert_eq!(
        after, baseline,
        "frame accounting drifted: {baseline} → {after}"
    );
}
