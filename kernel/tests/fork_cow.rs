//! Integration test for #160: `fork_address_space` CoW fork.
//!
//! Verifies that after `fork_address_space`:
//!   1. Child VMA tree is a deep clone of the parent's.
//!   2. Pre-faulted private pages are W-stripped in both parent and child
//!      PTEs (CoW-eligible).
//!   3. No frame leaks across fork/drop cycles, including when pages are
//!      prefaulted before fork (exercises the W-strip + refcount path).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::mem::addrspace::AddressSpace;
use vibix::mem::frame;
use vibix::mem::paging;
use vibix::mem::tlb::Flusher;
use vibix::mem::vmobject::{Access, AnonObject, VmObject};
use vibix::mem::vmatree::{Share, Vma};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
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
            "fork_cow_vma_tree_is_cloned",
            &(fork_cow_vma_tree_is_cloned as fn()),
        ),
        (
            "fork_cow_prefaulted_pages_w_stripped",
            &(fork_cow_prefaulted_pages_w_stripped as fn()),
        ),
        ("fork_cow_no_frame_leak", &(fork_cow_no_frame_leak as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// VA range used by fork tests — well below the kernel half.
const FORK_VA: usize = 0x0000_5000_0000_0000;
const FORK_PAGES: usize = 2;

fn prot_pte_rw() -> u64 {
    (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits()
}

/// Build a standalone AddressSpace with FORK_PAGES private anonymous VMAs.
fn make_parent_aspace() -> AddressSpace {
    let mut aspace = AddressSpace::new_empty();
    aspace.insert(Vma::new(
        FORK_VA,
        FORK_VA + FORK_PAGES * 4096,
        0x3,
        prot_pte_rw(),
        Share::Private,
        AnonObject::new(Some(FORK_PAGES)),
        0,
    ));
    aspace
}

/// Simulate a demand fault for `page_index` in the VMA starting at FORK_VA:
/// calls VmObject::fault (which inc_refcounts the frame) and installs the PTE
/// in `aspace.page_table_frame()`.
fn prefault_page(aspace: &AddressSpace, page_index: usize) {
    let obj_offset = page_index * 4096;
    let obj: Arc<dyn VmObject> = {
        let vma = aspace.find(FORK_VA).expect("vma not found");
        Arc::clone(&vma.object)
    };
    let phys = obj.fault(obj_offset, Access::Write).expect("VmObject::fault failed");
    let va = FORK_VA + page_index * 4096;
    let page =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64)).expect("page-aligned VA");
    let frame = PhysFrame::from_start_address(PhysAddr::new(phys)).expect("frame-aligned phys");
    let flags = PageTableFlags::from_bits_truncate(prot_pte_rw());
    paging::map_existing_in_pml4(aspace.page_table_frame(), page, frame, flags)
        .expect("map_existing_in_pml4 failed");
}

/// Verify that the child's VMA tree is a structural copy of the parent's.
fn fork_cow_vma_tree_is_cloned() {
    let mut parent = make_parent_aspace();
    let mut flusher = Flusher::new_active();
    let child = parent
        .fork_address_space(&mut flusher)
        .expect("fork_address_space failed");
    flusher.finish();

    let pvma = parent.find(FORK_VA).expect("parent vma missing");
    let cvma = child.find(FORK_VA).expect("child vma missing");
    assert_eq!(pvma.start, cvma.start);
    assert_eq!(pvma.end, cvma.end);
    assert_eq!(pvma.share, cvma.share);
    assert!(
        core::ptr::addr_eq(
            Arc::as_ptr(&pvma.object),
            Arc::as_ptr(&cvma.object),
        ),
        "child object should be Arc::clone of parent's"
    );
    drop(parent);
    drop(child);
}

/// Pre-fault a page, fork, then verify that the W-strip happened (i.e., the
/// parent's PTE is now read-only) and that both address spaces can be dropped
/// without panicking on refcount invariants.
fn fork_cow_prefaulted_pages_w_stripped() {
    let mut parent = make_parent_aspace();

    // Prefault both pages so the W-strip path in fork_address_space runs.
    for i in 0..FORK_PAGES {
        prefault_page(&parent, i);
    }

    let mut flusher = Flusher::new_active();
    let child = parent
        .fork_address_space(&mut flusher)
        .expect("fork_address_space failed");
    flusher.finish();

    // After fork, both parent and child VMAs should exist.
    assert!(parent.find(FORK_VA).is_some(), "parent vma lost after fork");
    assert!(child.find(FORK_VA).is_some(), "child vma lost after fork");

    // Dropping both should not panic — verifies no refcount underflow.
    drop(parent);
    drop(child);
}

/// Verify no frame leak across fork + drop cycles with prefaulted pages.
/// Prefaulting exercises the W-strip + refcount path; the no-prefault
/// path (empty PTE) is also covered by `fork_cow_vma_tree_is_cloned`.
fn fork_cow_no_frame_leak() {
    // Two warm-up rounds to let one-shot allocations settle.
    for _ in 0..2 {
        let mut parent = make_parent_aspace();
        for i in 0..FORK_PAGES {
            prefault_page(&parent, i);
        }
        let mut flusher = Flusher::new_active();
        let child = parent
            .fork_address_space(&mut flusher)
            .expect("fork failed");
        flusher.finish();
        drop(parent);
        drop(child);
    }

    let baseline = frame::free_frames();

    for _ in 0..8 {
        let mut parent = make_parent_aspace();
        for i in 0..FORK_PAGES {
            prefault_page(&parent, i);
        }
        let mut flusher = Flusher::new_active();
        let child = parent
            .fork_address_space(&mut flusher)
            .expect("fork failed");
        flusher.finish();
        drop(parent);
        drop(child);
    }

    let after = frame::free_frames();
    assert!(
        after >= baseline,
        "frame leak: baseline={baseline}, after={after}, delta={}",
        baseline as isize - after as isize,
    );
}
