//! Integration test: `AddressSpace::new_empty` allocates a fresh PML4
//! whose upper half (entries 256..512) matches the active kernel PML4
//! verbatim and whose lower half (entries 0..256) is empty. Two
//! consecutive calls produce distinct physical frames.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::mem::addrspace::AddressSpace;
use vibix::mem::paging::{active_pml4_phys, hhdm_offset};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
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
            "new_empty_produces_distinct_pml4s",
            &(new_empty_produces_distinct_pml4s as fn()),
        ),
        (
            "new_empty_kernel_half_matches_active",
            &(new_empty_kernel_half_matches_active as fn()),
        ),
        (
            "new_empty_lower_half_is_empty",
            &(new_empty_lower_half_is_empty as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn new_empty_produces_distinct_pml4s() {
    let a = AddressSpace::new_empty();
    let b = AddressSpace::new_empty();
    assert_ne!(
        a.page_table_frame().start_address(),
        b.page_table_frame().start_address(),
        "two independent AddressSpaces must own distinct PML4 frames",
    );
}

/// Read the 512 raw PTE slots of a PML4 through the HHDM.
unsafe fn pml4_slots(phys: u64) -> &'static [u64; 512] {
    let virt = hhdm_offset().as_u64() + phys;
    &*(virt as *const [u64; 512])
}

fn new_empty_kernel_half_matches_active() {
    let aspace = AddressSpace::new_empty();
    let new_phys = aspace.page_table_frame().start_address().as_u64();
    let active_phys = active_pml4_phys().as_u64();

    let new_slots = unsafe { pml4_slots(new_phys) };
    let active_slots = unsafe { pml4_slots(active_phys) };

    for i in 256..512 {
        assert_eq!(
            new_slots[i], active_slots[i],
            "PML4 entry {i} (upper/kernel half) must match active PML4",
        );
    }
}

fn new_empty_lower_half_is_empty() {
    let aspace = AddressSpace::new_empty();
    let new_phys = aspace.page_table_frame().start_address().as_u64();
    let new_slots = unsafe { pml4_slots(new_phys) };
    for i in 0..256 {
        assert_eq!(
            new_slots[i], 0,
            "PML4 entry {i} (lower/user half) must be zeroed in a fresh AddressSpace",
        );
    }
}
