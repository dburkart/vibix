//! Integration coverage for RFC 0001 (issue #165): cross-cutting VMA
//! scenarios that exercise the full split/merge/fork/grow machinery on
//! a real `AddressSpace` backed by the live frame allocator and paging
//! subsystem.
//!
//! Out of scope for this file (tracked separately):
//! - `mprotect` downgrade → write SIGSEGV: needs a ring-3 userspace
//!   driver and the `#PF` test-hook dance.
//! - `MAP_FIXED_NOREPLACE` EEXIST: no syscall plumbing yet.
//! - Refcount saturation rollback in fork: the current fork path
//!   silently pins at `u16::MAX` rather than erroring, so there is no
//!   rollback to test until that lands.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::mem::addrspace::AddressSpace;
use vibix::mem::paging;
use vibix::mem::vmatree::{Share, Vma, VMA_GROWSDOWN};
use vibix::mem::vmobject::{Access, AnonObject};
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
        ("brk_grow_shrink_query", &(brk_grow_shrink_query as fn())),
        (
            "brk_past_max_returns_prior",
            &(brk_past_max_returns_prior as fn()),
        ),
        (
            "growsdown_one_page_per_fault",
            &(growsdown_one_page_per_fault as fn()),
        ),
        (
            "growsdown_multi_page_below_guard_segv",
            &(growsdown_multi_page_below_guard_segv as fn()),
        ),
        (
            "fork_cow_write_divergence",
            &(fork_cow_write_divergence as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn prot_pte_rw() -> u64 {
    (PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE).bits()
}

// --- brk ---------------------------------------------------------------

fn brk_grow_shrink_query() {
    let mut aspace = AddressSpace::new_empty();
    // The loader normally calls set_brk_start; for a fresh AddressSpace
    // brk_start defaults to mmap_base (0x4000_0000). sys_brk(0) returns
    // the current break.
    let initial = aspace.sys_brk(0);

    // Grow by 2 pages: the exact requested address is stored.
    let target = initial + 2 * 4096;
    let got = aspace.sys_brk(target);
    assert_eq!(got, target, "sys_brk grow returned wrong address");
    assert_eq!(
        aspace.sys_brk(0),
        target,
        "sys_brk(0) after grow should return the new break",
    );

    // Shrink by one page.
    let smaller = initial + 4096;
    let got = aspace.sys_brk(smaller);
    assert_eq!(got, smaller, "sys_brk shrink returned wrong address");

    // brk(0) always reports current without mutating.
    assert_eq!(aspace.sys_brk(0), smaller);
    assert_eq!(aspace.sys_brk(0), smaller);
}

fn brk_past_max_returns_prior() {
    let mut aspace = AddressSpace::new_empty();
    let initial = aspace.sys_brk(0);
    // A brk request far past any reasonable brk_max should be refused
    // and the prior break returned unchanged.
    let got = aspace.sys_brk(u64::MAX - 4096);
    assert_eq!(
        got, initial,
        "sys_brk past max must return the prior break unchanged"
    );
    // A request below brk_start must also be refused.
    let got = aspace.sys_brk(1);
    assert_eq!(
        got, initial,
        "sys_brk below brk_start must return the prior break unchanged"
    );
}

// --- MAP_GROWSDOWN stack --------------------------------------------------

const STACK_TOP: usize = 0x0000_6000_0000_0000;
const STACK_INITIAL_START: usize = STACK_TOP - 4096;

fn make_growsdown_aspace() -> AddressSpace {
    let mut aspace = AddressSpace::new_empty();
    let mut vma = Vma::new(
        STACK_INITIAL_START,
        STACK_TOP,
        0x3,
        prot_pte_rw(),
        Share::Private,
        AnonObject::new(Some(1)),
        0,
    );
    vma.vma_flags = VMA_GROWSDOWN;
    aspace.insert(vma);
    aspace
}

fn growsdown_one_page_per_fault() {
    let mut aspace = make_growsdown_aspace();
    // A fault exactly one page below the VMA start must succeed and
    // install a fresh single-page VMA at that page.
    let cr2 = STACK_INITIAL_START - 4096;
    let result = aspace.grow_stack(cr2);
    assert!(
        result.is_some(),
        "grow_stack one page below vma_start must succeed",
    );
    let (_, _, _, new_start) = result.unwrap();
    assert_eq!(
        new_start,
        STACK_INITIAL_START - 4096,
        "grow_stack must extend by exactly one page",
    );
    // The new VMA must be findable and carry VMA_GROWSDOWN.
    let v = aspace.find(new_start).expect("new growsdown VMA missing");
    assert_eq!(v.start, new_start);
    assert_eq!(v.end, new_start + 4096);
    assert_ne!(v.vma_flags & VMA_GROWSDOWN, 0);
}

fn growsdown_multi_page_below_guard_segv() {
    let mut aspace = make_growsdown_aspace();
    // A fault 257 pages below the VMA start is outside the 256-page
    // guard gap; check_growsdown must reject it (SIGSEGV path).
    let cr2 = STACK_INITIAL_START - 257 * 4096;
    let result = aspace.grow_stack(cr2);
    assert!(
        result.is_none(),
        "grow_stack beyond guard gap must return None (SIGSEGV)",
    );
}

// --- fork CoW write divergence -------------------------------------------

const FORK_VA: usize = 0x0000_7000_0000_0000;

fn make_cow_parent() -> AddressSpace {
    let mut aspace = AddressSpace::new_empty();
    aspace.insert(Vma::new(
        FORK_VA,
        FORK_VA + 4096,
        0x3,
        prot_pte_rw(),
        Share::Private,
        AnonObject::new(Some(1)),
        0,
    ));
    aspace
}

/// Install a demand-faulted page into `aspace` and return its phys address.
fn demand_fault(aspace: &AddressSpace) -> u64 {
    let vma = aspace.find(FORK_VA).expect("vma missing");
    let obj = Arc::clone(&vma.object);
    let phys = obj.fault(0, Access::Write).expect("VmObject::fault failed");
    let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(FORK_VA as u64))
        .expect("page-aligned VA");
    let frame = PhysFrame::from_start_address(PhysAddr::new(phys)).expect("frame-aligned phys");
    let flags = PageTableFlags::from_bits_truncate(prot_pte_rw());
    paging::map_existing_in_pml4(aspace.page_table_frame(), page, frame, flags)
        .expect("map_existing_in_pml4 failed");
    phys
}

/// Fork CoW divergence at the data level: after both sides demand-fault
/// independent frames, a write in one address space must not be visible
/// in the other. Complements `fork_cow.rs::fork_isolation_unfaulted_page`
/// which only checks phys-frame divergence, not data isolation.
fn fork_cow_write_divergence() {
    use vibix::mem::paging::hhdm_offset;
    use vibix::mem::tlb::Flusher;

    let mut parent = make_cow_parent();
    let mut flusher = Flusher::new_active();
    let child = parent
        .fork_address_space(&mut flusher)
        .expect("fork_address_space failed");
    flusher.finish();

    // Both sides demand-fault independently: unfaulted-at-fork pages
    // get distinct private frames (issue #188 behaviour).
    let parent_phys = demand_fault(&parent);
    let child_phys = demand_fault(&child);
    assert_ne!(
        parent_phys, child_phys,
        "parent and child must get distinct frames for CoW write divergence",
    );

    // Write distinct sentinels through the HHDM — we cannot switch CR3
    // to reach the user VA, so poke the physical frames directly.
    let hhdm = hhdm_offset().as_u64();
    let parent_ptr = (hhdm + parent_phys) as *mut u64;
    let child_ptr = (hhdm + child_phys) as *mut u64;
    unsafe {
        core::ptr::write_volatile(parent_ptr, 0xAAAA_AAAA_AAAA_AAAA);
        core::ptr::write_volatile(child_ptr, 0x5555_5555_5555_5555);
    }

    let parent_val = unsafe { core::ptr::read_volatile(parent_ptr) };
    let child_val = unsafe { core::ptr::read_volatile(child_ptr) };
    assert_eq!(parent_val, 0xAAAA_AAAA_AAAA_AAAA);
    assert_eq!(child_val, 0x5555_5555_5555_5555);

    drop(parent);
    drop(child);
}
