//! Integration test: an installed `VmaKind::AnonZero` region is
//! resolved lazily by the `#PF` handler. Proves the demand-paging
//! path for #51 — first read faults, lands zero, write-then-read
//! preserves the sentinel across the same page.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::mem::vma::{Vma, VmaKind};
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
        ("anon_zero_first_touch", &(anon_zero_first_touch as fn())),
        ("anon_zero_readback", &(anon_zero_readback as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Lower-half VA well clear of anything the kernel maps eagerly.
const TEST_VA: usize = 0x0000_2000_0000_0000;
const TEST_LEN: usize = 8 * 4096;

fn install_test_vma() {
    vibix::task::install_vma_on_current(Vma::new(
        TEST_VA,
        TEST_VA + TEST_LEN,
        VmaKind::AnonZero,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ));
}

fn anon_zero_first_touch() {
    install_test_vma();
    // First touch faults; handler resolves via map_in_pml4 and the
    // read returns zero from the freshly-zeroed frame.
    let byte = unsafe { ptr::read_volatile(TEST_VA as *const u8) };
    assert_eq!(byte, 0, "fresh AnonZero page did not read as zero");
}

fn anon_zero_readback() {
    // TEST_VA is now backed by a real frame (installed above). Reuse
    // a different page in the same VMA to exercise one more fault +
    // verify write/read persistence on the resolved mapping.
    let va = TEST_VA + 4096;
    let p = va as *mut u64;
    let first = unsafe { ptr::read_volatile(p) };
    assert_eq!(first, 0, "second AnonZero page did not read as zero");
    unsafe { ptr::write_volatile(p, 0xDEAD_BEEF_CAFE_F00D) };
    let back = unsafe { ptr::read_volatile(p) };
    assert_eq!(back, 0xDEAD_BEEF_CAFE_F00D, "write/read mismatch");
}
