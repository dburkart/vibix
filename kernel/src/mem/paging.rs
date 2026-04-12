//! Kernel paging: wrap Limine's active page tables in an
//! [`OffsetPageTable`] and expose typed `map`/`unmap`/`translate`.
//!
//! Limine hands us a PML4 with the kernel image identity-ish-mapped at
//! −2 GiB and all of physical RAM HHDM-mapped. We keep that tree
//! (no CR3 switch here) and just take ownership of it through the
//! `x86_64` crate's mapper abstraction. Future milestones that need to
//! install mappings of their own — heap growth, IST guard pages, user
//! address spaces — go through this module instead of relying on
//! whatever Limine happened to set up.

use spin::{Mutex, Once};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{MapToError, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags, PhysFrame, Size4KiB,
    Translate,
};
use x86_64::{PhysAddr, VirtAddr};

use super::frame;
use crate::serial_println;

/// Frame allocator adapter: pulls 4 KiB frames from the global
/// `BumpFrameAllocator`. Zero-sized; construct ad-hoc wherever you need
/// to hand the mapper a `FrameAllocator`.
pub struct KernelFrameAllocator;

unsafe impl FrameAllocator<Size4KiB> for KernelFrameAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let phys = frame::global().lock().allocate_frame()?;
        Some(PhysFrame::containing_address(PhysAddr::new(phys)))
    }
}

static MAPPER: Once<Mutex<OffsetPageTable<'static>>> = Once::new();

/// Install the kernel mapper. Must be called after `frame::init` (page
/// tables allocated for new mappings come from the global allocator)
/// and before any caller tries to `map`/`unmap`.
pub fn init(hhdm_offset: VirtAddr) {
    let (cr3_frame, _) = Cr3::read();
    // Physical → virtual via HHDM. Limine guarantees the active PML4
    // is covered by the HHDM mapping it installed.
    let l4_virt = hhdm_offset + cr3_frame.start_address().as_u64();
    // SAFETY: Limine's PML4 lives for the life of the kernel, is
    // exclusively ours from this point on, and the HHDM mapping makes
    // the cast a valid `&mut PageTable`.
    let l4: &'static mut PageTable = unsafe { &mut *(l4_virt.as_mut_ptr::<PageTable>()) };
    let mapper = unsafe { OffsetPageTable::new(l4, hhdm_offset) };
    MAPPER.call_once(|| Mutex::new(mapper));
    serial_println!("paging: mapper online");
}

/// Run a closure with exclusive access to the kernel mapper. Acquires
/// the mapper lock for the duration of the call.
pub fn with_mapper<R>(f: impl FnOnce(&mut OffsetPageTable<'static>) -> R) -> R {
    let mapper = MAPPER.get().expect("paging::init not called");
    let mut guard = mapper.lock();
    f(&mut guard)
}

/// Map `page` to a freshly-allocated physical frame with `flags`.
/// Returns the frame so callers that care can recover its physical
/// address.
pub fn map(
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, MapToError<Size4KiB>> {
    let mut alloc = KernelFrameAllocator;
    let frame = alloc
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    with_mapper(|m| {
        // SAFETY: caller owns the virtual address; we allocated the
        // physical frame, so no aliasing. Flushing the TLB entry below.
        let flush = unsafe { m.map_to(page, frame, flags, &mut alloc)? };
        flush.flush();
        Ok(frame)
    })
}

/// Map `count` contiguous 4 KiB pages starting at `start`. Each page
/// gets an independent physical frame (frames are not guaranteed
/// contiguous). On partial failure earlier pages remain mapped.
pub fn map_range(
    start: VirtAddr,
    count: u64,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    for i in 0..count {
        let page = Page::<Size4KiB>::containing_address(start + i * 4096);
        map(page, flags)?;
    }
    Ok(())
}

/// Map a physical range into the HHDM window with the given flags.
///
/// Limine's HHDM covers usable RAM by default, but physical regions
/// we need to poke at (ACPI tables in reserved/ROM ranges, LAPIC /
/// IOAPIC MMIO) aren't included. This installs a read/write mapping
/// page-by-page at `hhdm_offset + phys` so callers can keep using the
/// uniform phys→HHDM translation pattern. Re-mapping an already-mapped
/// page is a no-op.
pub fn map_phys_into_hhdm(
    phys: u64,
    size: u64,
    flags: PageTableFlags,
) -> Result<(), MapToError<Size4KiB>> {
    if size == 0 {
        return Ok(());
    }
    let start = phys & !0xFFF;
    // Round the end up to the next page boundary with checked
    // arithmetic — firmware-provided sizes could in principle push
    // the sum past u64::MAX. Silent wrap would turn into a mis-map.
    let end = phys
        .checked_add(size - 1)
        .and_then(|v| v.checked_add(0x1000))
        .expect("map_phys_into_hhdm: physical range overflow")
        & !0xFFF;
    let hhdm_offset = with_mapper(|m| m.phys_offset());
    with_mapper(|m| {
        let mut alloc = KernelFrameAllocator;
        let mut addr = start;
        while addr < end {
            let page = Page::<Size4KiB>::containing_address(hhdm_offset + addr);
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(addr));
            // SAFETY: caller is responsible for ensuring the physical
            // range is safe to alias at this virtual address. For MMIO
            // and firmware-provided ACPI tables the kernel is the sole
            // user and we never hand these pages to the frame allocator.
            match unsafe { m.map_to(page, frame, flags, &mut alloc) } {
                Ok(flush) => flush.flush(),
                Err(MapToError::PageAlreadyMapped(_)) => {}
                Err(e) => return Err(e),
            }
            addr += 4096;
        }
        Ok(())
    })
}

/// Unmap `page` and flush the TLB. The backing frame is leaked — we
/// don't have a reclaiming frame allocator yet.
pub fn unmap(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, UnmapError> {
    with_mapper(|m| {
        let (frame, flush) = m.unmap(page)?;
        flush.flush();
        Ok(frame)
    })
}

/// Translate a virtual address to its backing physical address, if any.
pub fn translate(addr: VirtAddr) -> Option<PhysAddr> {
    with_mapper(|m| match m.translate(addr) {
        TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
    })
}
