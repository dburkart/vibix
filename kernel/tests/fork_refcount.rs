//! Integration test for #227: `fork_address_space` must refuse to
//! fork a page whose refcount is already pinned at `u16::MAX` rather
//! than silently under-counting (which would UAF on the `u16::MAX`-th
//! drop).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::Ordering;

use vibix::mem::addrspace::{AddressSpace, ForkError};
use vibix::mem::paging;
use vibix::mem::refcount;
use vibix::mem::tlb::Flusher;
use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::{Access, AnonObject, VmObject};
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
            "fork_refuses_saturated_private",
            &(fork_refuses_saturated_private as fn()),
        ),
        (
            "fork_refuses_saturated_shared",
            &(fork_refuses_saturated_shared as fn()),
        ),
        (
            "fork_saturated_parent_survives",
            &(fork_saturated_parent_survives as fn()),
        ),
        (
            "fork_late_saturation_restores_earlier_pte",
            &(fork_late_saturation_restores_earlier_pte as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

const FORK_VA: usize = 0x0000_5000_0000_0000;
const FORK_PAGES: usize = 2;

fn prot_pte_rw() -> u64 {
    (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits()
}

fn make_aspace(share: Share) -> AddressSpace {
    let mut aspace = AddressSpace::new_empty();
    aspace.insert(Vma::new(
        FORK_VA,
        FORK_VA + FORK_PAGES * 4096,
        0x3,
        prot_pte_rw(),
        share,
        AnonObject::new(Some(FORK_PAGES)),
        0,
    ));
    aspace
}

fn prefault_page(aspace: &AddressSpace, page_index: usize) -> u64 {
    let obj: Arc<dyn VmObject> = {
        let vma = aspace.find(FORK_VA).expect("vma not found");
        Arc::clone(&vma.object)
    };
    let phys = obj
        .fault(page_index * 4096, Access::Write)
        .expect("VmObject::fault failed");
    let va = FORK_VA + page_index * 4096;
    let page =
        Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64)).expect("page-aligned VA");
    let frame = PhysFrame::from_start_address(PhysAddr::new(phys)).expect("frame-aligned phys");
    let flags = PageTableFlags::from_bits_truncate(prot_pte_rw());
    paging::map_existing_in_pml4(aspace.page_table_frame(), page, frame, flags)
        .expect("map_existing_in_pml4 failed");
    phys
}

/// Prime the given frame's refcount to `value` and return the amount
/// we bumped it by, so the caller can restore it before `Drop for
/// AddressSpace` decrements. Uses the raw slot because `inc_refcount`
/// saturates silently and `try_inc_refcount` would refuse past MAX.
fn bump_refcount_to(phys: u64, value: u16) -> u16 {
    let slot = refcount::page_refcount(phys);
    let cur = slot.load(Ordering::Relaxed);
    assert!(value >= cur, "bump_refcount_to can only raise the slot");
    slot.store(value, Ordering::Relaxed);
    value - cur
}

/// Restore a previously-bumped slot by subtracting `delta`. The parent
/// aspace's `Drop` will still decrement the natural references, so we
/// only subtract the artificial inflation.
fn unbump_refcount(phys: u64, delta: u16) {
    let slot = refcount::page_refcount(phys);
    let cur = slot.load(Ordering::Relaxed);
    assert!(cur >= delta, "unbump underflow");
    slot.store(cur - delta, Ordering::Relaxed);
}

/// Prefault a Private VMA page, pin the frame's refcount at MAX, then
/// attempt to fork. Must return `RefcountSaturated` rather than bumping
/// past MAX and UAF'ing on drop.
fn fork_refuses_saturated_private() {
    let mut parent = make_aspace(Share::Private);
    let phys = prefault_page(&parent, 0);
    let delta = bump_refcount_to(phys, u16::MAX);

    let mut flusher = Flusher::new_active();
    let result = parent.fork_address_space(&mut flusher);
    flusher.finish();

    match result {
        Err(ForkError::RefcountSaturated) => {}
        Err(other) => panic!("expected RefcountSaturated, got {other:?}"),
        Ok(_) => panic!("fork_address_space must refuse saturated frames"),
    }

    // Drop the artificial inflation so parent's drop balances.
    unbump_refcount(phys, delta);
    drop(parent);
}

/// Same test for Shared VMAs — the second `try_inc_refcount` site.
fn fork_refuses_saturated_shared() {
    let mut parent = make_aspace(Share::Shared);
    let phys = prefault_page(&parent, 0);
    let delta = bump_refcount_to(phys, u16::MAX);

    let mut flusher = Flusher::new_active();
    let result = parent.fork_address_space(&mut flusher);
    flusher.finish();

    match result {
        Err(ForkError::RefcountSaturated) => {}
        Err(other) => panic!("expected RefcountSaturated, got {other:?}"),
        Ok(_) => panic!("fork_address_space must refuse saturated frames"),
    }

    unbump_refcount(phys, delta);
    drop(parent);
}

/// After a refused fork the parent must still be usable: the VMA is
/// still installed, the PTE still maps the same frame, and dropping the
/// parent does not panic on refcount invariants.
fn fork_saturated_parent_survives() {
    let mut parent = make_aspace(Share::Private);
    let phys = prefault_page(&parent, 0);
    let delta = bump_refcount_to(phys, u16::MAX);

    let mut flusher = Flusher::new_active();
    let result = parent.fork_address_space(&mut flusher);
    flusher.finish();
    match result {
        Err(ForkError::RefcountSaturated) => {}
        Err(other) => panic!("expected RefcountSaturated, got {other:?}"),
        Ok(_) => panic!("fork must fail on saturated refcount"),
    }

    // Parent VMA is still present.
    let vma = parent
        .find(FORK_VA)
        .expect("parent vma lost after failed fork");
    assert_eq!(vma.start, FORK_VA);

    // Parent PTE still points at the original frame (the refused fork
    // did not tear down the parent's mapping).
    let va = VirtAddr::new(FORK_VA as u64);
    let (pte_frame, _flags) = paging::translate_in_pml4(parent.page_table_frame(), va)
        .expect("parent PTE lost after failed fork");
    assert_eq!(pte_frame.start_address().as_u64(), phys);

    unbump_refcount(phys, delta);
    drop(parent);
}

/// Prefault two pages, pin page 1's refcount at MAX but leave page 0
/// nominal. Fork must fail at page 1, and after the error the parent's
/// page 0 PTE must still be WRITABLE (rolled back from the mid-walk
/// W-strip). Prevents the "late fork failure leaves earlier parent
/// pages W-stripped" regression flagged on #254.
fn fork_late_saturation_restores_earlier_pte() {
    let mut parent = make_aspace(Share::Private);
    let phys0 = prefault_page(&parent, 0);
    let phys1 = prefault_page(&parent, 1);
    let delta1 = bump_refcount_to(phys1, u16::MAX);

    let mut flusher = Flusher::new_active();
    let result = parent.fork_address_space(&mut flusher);
    flusher.finish();
    match result {
        Err(ForkError::RefcountSaturated) => {}
        Err(other) => panic!("expected RefcountSaturated, got {other:?}"),
        Ok(_) => panic!("fork must fail on mid-walk saturation"),
    }

    // Page 0 PTE must be restored to writable (the rollback path).
    let (frame0, flags0) =
        paging::translate_in_pml4(parent.page_table_frame(), VirtAddr::new(FORK_VA as u64))
            .expect("parent page 0 PTE lost after rollback");
    assert_eq!(frame0.start_address().as_u64(), phys0);
    assert!(
        flags0.contains(PageTableFlags::WRITABLE),
        "parent page 0 must remain WRITABLE after a mid-walk fork rollback",
    );

    // Page 1 PTE must still be present and unchanged.
    let (frame1, flags1) = paging::translate_in_pml4(
        parent.page_table_frame(),
        VirtAddr::new((FORK_VA + 4096) as u64),
    )
    .expect("parent page 1 PTE lost after rollback");
    assert_eq!(frame1.start_address().as_u64(), phys1);
    assert!(flags1.contains(PageTableFlags::WRITABLE));

    unbump_refcount(phys1, delta1);
    drop(parent);
}
