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
