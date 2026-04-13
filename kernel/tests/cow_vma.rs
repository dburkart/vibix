//! Integration test: a `VmaKind::Cow` region resolves read faults by
//! mapping the shared source frame read-only, and resolves write
//! faults by allocating a private copy. Verifies that the write side
//! diverges while the source frame retains its original content.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::ptr;

use vibix::mem::paging::{hhdm_offset, KernelFrameAllocator};
use vibix::mem::vma::{Vma, VmaKind};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::{FrameAllocator, PageTableFlags};

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
            "cow_read_then_write_diverges",
            &(cow_read_then_write_diverges as fn()),
        ),
        (
            "vma_list_remove_roundtrip",
            &(vma_list_remove_roundtrip as fn()),
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

fn cow_read_then_write_diverges() {
    // Allocate a source frame and stamp a known pattern through the
    // HHDM.
    let source = KernelFrameAllocator
        .allocate_frame()
        .expect("failed to allocate source frame");
    let hhdm = hhdm_offset();
    let src_virt = hhdm + source.start_address().as_u64();
    unsafe {
        let p = src_virt.as_mut_ptr::<u8>();
        for i in 0..4096 {
            *p.add(i) = 0xAA;
        }
    }

    vibix::task::install_vma_on_current(Vma::new(
        TEST_VA,
        TEST_VA + 4096,
        VmaKind::Cow { frame: source },
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ));

    // First access is a read → not-present fault → resolver maps the
    // source frame read-only. The byte read should be 0xAA.
    let first = unsafe { ptr::read_volatile(TEST_VA as *const u8) };
    assert_eq!(first, 0xAA, "cow read did not see source pattern");

    // Write → write-protection fault → resolver allocates a private
    // frame, memcpys source in, remaps writable. The write then
    // completes against the new frame.
    unsafe { ptr::write_volatile(TEST_VA as *mut u8, 0xBB) };

    // Readback reflects the write.
    let after = unsafe { ptr::read_volatile(TEST_VA as *const u8) };
    assert_eq!(after, 0xBB, "cow write did not land in private frame");

    // The original source frame, peeked via the HHDM, is unchanged.
    // This is the divergence property the ticket asks to verify.
    let src_byte = unsafe { ptr::read_volatile(src_virt.as_ptr::<u8>()) };
    assert_eq!(
        src_byte, 0xAA,
        "cow source frame was mutated by child write"
    );

    // And the rest of the private frame carries the full source
    // pattern, not a zero fill — proves the memcpy actually happened.
    let private_tail = unsafe { ptr::read_volatile((TEST_VA + 4095) as *const u8) };
    assert_eq!(private_tail, 0xAA, "cow private frame missing source bytes");
}

fn vma_list_remove_roundtrip() {
    // Covers VmaList::remove in isolation via the VMA installed by
    // the previous test — proves `find` → `remove` → `find` returns
    // None for that start, without disturbing other regions.
    use vibix::mem::vma::VmaList;

    let mut list = VmaList::new();
    let a = Vma::new(
        0x1000,
        0x2000,
        VmaKind::AnonZero,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    );
    let b = Vma::new(
        0x3000,
        0x4000,
        VmaKind::AnonZero,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    );
    list.insert(a);
    list.insert(b);
    assert!(list.find(0x1000).is_some());
    assert!(list.find(0x3000).is_some());

    let removed = list.remove(0x1000).expect("remove returned None");
    assert_eq!(removed.start, 0x1000);
    assert!(list.find(0x1000).is_none(), "removed VMA still findable");
    assert!(list.find(0x3000).is_some(), "sibling VMA lost to remove");

    assert!(
        list.remove(0x9000).is_none(),
        "remove of absent start must be None"
    );

    // clone_for_fork preserves entries.
    let child = list.clone_for_fork();
    assert!(child.find(0x3000).is_some(), "fork clone lost an entry");
}
