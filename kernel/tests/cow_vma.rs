//! Integration test: VmObject-backed VMAs — demand paging via AnonObject
//! and AddressSpace insert/find/remove round-trip.
//!
//! The CoW fork-divergence test (read source read-only, write triggers
//! private copy, verify divergence) requires `fork_address_space` and
//! is tracked in issue #160.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

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
            "anon_demand_paging_verify",
            &(anon_demand_paging_verify as fn()),
        ),
        (
            "vmatree_find_remove_roundtrip",
            &(vmatree_find_remove_roundtrip as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// Lower-half VA well clear of anything the kernel maps eagerly and
/// also clear of `demand_paging`'s `TEST_VA` so the two tests can
/// coexist in the same address space without aliasing.
const TEST_VA: usize = 0x0000_2000_1000_0000;

fn anon_demand_paging_verify() {
    let prot_pte =
        (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits();
    vibix::task::install_vma_on_current(Vma::new(
        TEST_VA,
        TEST_VA + 4096,
        0x3, // PROT_READ | PROT_WRITE
        prot_pte,
        Share::Private,
        AnonObject::new(Some(1)),
        0,
    ));

    // First touch faults; handler resolves via AnonObject::fault.
    // AnonObject zero-fills on first allocation, so the byte must be 0.
    let byte = unsafe { ptr::read_volatile(TEST_VA as *const u8) };
    assert_eq!(byte, 0, "AnonObject demand page was not zero");

    // Write and read back to confirm the page stays mapped writable.
    unsafe { ptr::write_volatile(TEST_VA as *mut u8, 0x42) };
    let back = unsafe { ptr::read_volatile(TEST_VA as *const u8) };
    assert_eq!(back, 0x42, "write/read-back mismatch on AnonObject page");
}

fn vmatree_find_remove_roundtrip() {
    // Covers AddressSpace::insert/find/remove: proves the round-trip
    // works correctly and does not disturb sibling regions.
    use vibix::mem::addrspace::AddressSpace;

    // SAFETY: running in a freshly-init'd kernel; new_empty allocates a
    // PML4 from the live frame allocator. We do not switch CR3 to it.
    let mut aspace = AddressSpace::new_empty();
    let prot_pte = (PageTableFlags::PRESENT | PageTableFlags::WRITABLE).bits();
    let a = Vma::new(
        0x1000,
        0x2000,
        0x3,
        prot_pte,
        Share::Private,
        AnonObject::new(Some(1)),
        0,
    );
    let b = Vma::new(
        0x3000,
        0x4000,
        0x3,
        prot_pte,
        Share::Private,
        AnonObject::new(Some(1)),
        0,
    );
    aspace.insert(a);
    aspace.insert(b);
    assert!(aspace.find(0x1000).is_some());
    assert!(aspace.find(0x3000).is_some());

    let removed = aspace.remove(0x1000).expect("remove returned None");
    assert_eq!(removed.start, 0x1000);
    assert!(aspace.find(0x1000).is_none(), "removed VMA still findable");
    assert!(aspace.find(0x3000).is_some(), "sibling VMA lost to remove");

    assert!(
        aspace.remove(0x9000).is_none(),
        "remove of absent start must be None"
    );
}
