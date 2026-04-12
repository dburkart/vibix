//! Kernel paging: wrap Limine's page tables in an [`OffsetPageTable`],
//! then build a fresh kernel-owned PML4 and atomically switch CR3 to it.
//!
//! Boot flow: [`init`] wraps Limine's active tree so early subsystems
//! (heap, IST guard) can install mappings through the normal API. Once
//! those are in place, [`build_and_switch_kernel_pml4`] constructs a
//! clean tree that maps only what the kernel actually needs — kernel
//! image per section with tight flags, HHDM via 2 MiB pages, heap, IST
//! stack sans guard, framebuffer — and swaps CR3 to it. From that point
//! on Limine's original tree is unreachable; actually freeing it (and
//! the `BOOTLOADER_RECLAIMABLE` frames) is issue #46.

use spin::Mutex;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::mapper::{MapToError, TranslateResult, UnmapError};
use x86_64::structures::paging::{
    FrameAllocator, FrameDeallocator, Mapper, OffsetPageTable, Page, PageTable, PageTableFlags,
    PhysFrame, Size2MiB, Size4KiB, Translate,
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

impl FrameDeallocator<Size4KiB> for KernelFrameAllocator {
    unsafe fn deallocate_frame(&mut self, frame: PhysFrame<Size4KiB>) {
        frame::global()
            .lock()
            .deallocate_frame(frame.start_address().as_u64());
    }
}

/// The active kernel mapper. `None` before [`init`] runs; replaced
/// wholesale by [`build_and_switch_kernel_pml4`] when we swap CR3. A
/// plain `Mutex<Option<...>>` (instead of `Once`) so the switch can
/// install a fresh `OffsetPageTable` rooted at the new PML4.
static MAPPER: Mutex<Option<OffsetPageTable<'static>>> = Mutex::new(None);

/// HHDM offset, stashed at [`init`] so the switch code and the
/// per-frame zero helper can re-use it without re-reading the Limine
/// response.
static HHDM_OFFSET: Mutex<Option<VirtAddr>> = Mutex::new(None);

/// Install the kernel mapper over Limine's active PML4. Must be called
/// after `frame::init` and before any caller tries to `map`/`unmap`.
pub fn init(hhdm_offset: VirtAddr) {
    let (cr3_frame, _) = Cr3::read();
    let l4 = unsafe { pml4_as_mut(cr3_frame, hhdm_offset) };
    let mapper = unsafe { OffsetPageTable::new(l4, hhdm_offset) };
    *MAPPER.lock() = Some(mapper);
    *HHDM_OFFSET.lock() = Some(hhdm_offset);
    serial_println!("paging: mapper online");
}

/// Run a closure with exclusive access to the kernel mapper.
pub fn with_mapper<R>(f: impl FnOnce(&mut OffsetPageTable<'static>) -> R) -> R {
    let mut guard = MAPPER.lock();
    let m = guard.as_mut().expect("paging::init not called");
    f(m)
}

/// Map `page` to a freshly-allocated physical frame with `flags`.
pub fn map(
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, MapToError<Size4KiB>> {
    let mut alloc = KernelFrameAllocator;
    let frame = alloc
        .allocate_frame()
        .ok_or(MapToError::FrameAllocationFailed)?;
    with_mapper(|m| {
        let flush = unsafe { m.map_to(page, frame, flags, &mut alloc)? };
        flush.flush();
        Ok(frame)
    })
}

/// Map `count` contiguous 4 KiB pages starting at `start`.
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
    with_mapper(|m| {
        let hhdm_offset = m.phys_offset();
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
                // Already mapped via a 4 KiB PTE — no-op.
                Err(MapToError::PageAlreadyMapped(_)) => {}
                // A 2 MiB HHDM huge page already covers this address
                // with write-back cacheable flags. That's fine for RAM
                // (ACPI tables, reclaimable regions), but wrong for
                // device MMIO — caching LAPIC/IOAPIC reads silently
                // corrupts interrupt handling. Accept the collision
                // only when the caller isn't demanding a specific
                // memory type; otherwise treat it as a bug (a caller
                // wanting NO_CACHE means populate_hhdm should have
                // skipped this physical range).
                Err(e @ MapToError::ParentEntryHugePage) => {
                    let mmio_bits = PageTableFlags::NO_CACHE | PageTableFlags::WRITE_THROUGH;
                    if flags.intersects(mmio_bits) {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
            addr += 4096;
        }
        Ok(())
    })
}

/// Unmap `page` and flush the TLB. Returns the physical frame the page
/// was backed by. The caller owns that frame from here on — either
/// return it to the global allocator with [`unmap_and_free`], or hold
/// on to it (e.g. when unmapping a physical region the allocator never
/// owned, like the IST guard page which lives in `.bss`).
pub fn unmap(page: Page<Size4KiB>) -> Result<PhysFrame<Size4KiB>, UnmapError> {
    with_mapper(|m| {
        let (frame, flush) = m.unmap(page)?;
        flush.flush();
        Ok(frame)
    })
}

/// Unmap `page` and return its backing frame to the global frame
/// allocator. Use this for mappings whose frame originally came from
/// [`map`] / [`map_range`].
pub fn unmap_and_free(page: Page<Size4KiB>) -> Result<(), UnmapError> {
    let frame = unmap(page)?;
    // SAFETY: the caller's contract is that `page`'s frame came from
    // the global allocator — `map` is the only supported producer.
    unsafe { KernelFrameAllocator.deallocate_frame(frame) };
    Ok(())
}

/// Translate a virtual address to its backing physical address, if any.
pub fn translate(addr: VirtAddr) -> Option<PhysAddr> {
    with_mapper(|m| match m.translate(addr) {
        TranslateResult::Mapped { frame, offset, .. } => Some(frame.start_address() + offset),
        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
    })
}

/// Physical address of the currently-active PML4 (i.e. CR3).
pub fn active_pml4_phys() -> PhysAddr {
    Cr3::read().0.start_address()
}

// -- PML4 construction + CR3 swap ---------------------------------------

/// Build a fresh kernel PML4 and switch CR3 to it. Drops Limine's
/// original tree (leaks its intermediate tables until #46 reclaims
/// them explicitly).
pub fn build_and_switch_kernel_pml4() {
    let hhdm = HHDM_OFFSET
        .lock()
        .expect("paging::init must run before the CR3 switch");

    // SAFETY: we reserve this frame exclusively for the new PML4, zero
    // it through the HHDM, and only reference it through an
    // `OffsetPageTable` built over the same HHDM window.
    let new_pml4_frame = unsafe { alloc_zeroed_frame(hhdm) };

    {
        // Build mappings into the fresh tree.
        let mut alloc = KernelFrameAllocator;
        let l4 = unsafe { pml4_as_mut(new_pml4_frame, hhdm) };
        let mut new_mapper = unsafe { OffsetPageTable::new(l4, hhdm) };

        populate_hhdm(&mut new_mapper, hhdm, &mut alloc);
        populate_kernel_image(&mut new_mapper, &mut alloc);
        clone_heap(&mut new_mapper, &mut alloc);
        clone_ist_stack(&mut new_mapper, &mut alloc);
        clone_boot_stack(&mut new_mapper, &mut alloc);
        map_framebuffer(&mut new_mapper, &mut alloc);
    }

    // Atomic swap. IRQs off so no handler runs while CR3 and MAPPER
    // are in a mid-transition state. TLB is wholly flushed by the CR3
    // load.
    x86_64::instructions::interrupts::without_interrupts(|| {
        let (_old, flags) = Cr3::read();
        unsafe { Cr3::write(new_pml4_frame, flags) };
        let l4 = unsafe { pml4_as_mut(new_pml4_frame, hhdm) };
        let mapper = unsafe { OffsetPageTable::new(l4, hhdm) };
        *MAPPER.lock() = Some(mapper);
    });

    serial_println!("paging: switched to kernel PML4");
}

/// Allocate a 4 KiB frame, zero it through the HHDM. Returns the frame.
///
/// # Safety
/// The returned frame becomes the new caller's responsibility; no other
/// code may hold a reference to its contents.
unsafe fn alloc_zeroed_frame(hhdm: VirtAddr) -> PhysFrame<Size4KiB> {
    let mut alloc = KernelFrameAllocator;
    let frame = alloc
        .allocate_frame()
        .expect("out of frames allocating kernel PML4");
    let virt = hhdm + frame.start_address().as_u64();
    core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
    frame
}

/// Turn a PML4-bearing physical frame into a `&'static mut PageTable`
/// via the HHDM.
///
/// # Safety
/// `frame` must be a page-table frame with no other outstanding
/// references, and `hhdm` must be the active HHDM offset.
unsafe fn pml4_as_mut(frame: PhysFrame<Size4KiB>, hhdm: VirtAddr) -> &'static mut PageTable {
    let virt = hhdm + frame.start_address().as_u64();
    &mut *(virt.as_mut_ptr::<PageTable>())
}

/// Map the HHDM range (all memory-map-reported physical memory) into
/// the new tree using 2 MiB pages.
fn populate_hhdm(
    mapper: &mut OffsetPageTable<'static>,
    hhdm: VirtAddr,
    alloc: &mut KernelFrameAllocator,
) {
    const TWO_MIB: u64 = 2 * 1024 * 1024;

    let memmap = crate::boot::MEMMAP_REQUEST
        .get_response()
        .expect("Limine memory-map response missing");

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    // Iterate the memory-map entries and HHDM-map only ranges that
    // hold real RAM or firmware data. Skipping RESERVED and BAD_MEMORY
    // leaves MMIO holes (LAPIC/IOAPIC) uncovered so `map_phys_into_hhdm`
    // can install 4 KiB PTEs with the correct NO_CACHE/WRITE_THROUGH
    // attributes for device MMIO. Sparse high-address entries on real
    // hardware also don't force us to densely map every 2 MiB below them.
    use limine::memory_map::EntryType;
    for entry in memmap.entries() {
        match entry.entry_type {
            EntryType::USABLE
            | EntryType::BOOTLOADER_RECLAIMABLE
            | EntryType::EXECUTABLE_AND_MODULES
            | EntryType::FRAMEBUFFER
            | EntryType::ACPI_RECLAIMABLE
            | EntryType::ACPI_NVS => {}
            _ => continue,
        }
        let start = entry.base & !(TWO_MIB - 1);
        let end = (entry.base + entry.length + TWO_MIB - 1) & !(TWO_MIB - 1);
        let mut phys = start;
        while phys < end {
            let page = Page::<Size2MiB>::containing_address(hhdm + phys);
            let frame = PhysFrame::<Size2MiB>::containing_address(PhysAddr::new(phys));
            // SAFETY: HHDM into a fresh tree we own; flush unneeded
            // since this PML4 isn't live yet.
            match unsafe { mapper.map_to(page, frame, flags, alloc) } {
                Ok(f) => f.ignore(),
                // Adjacent entries may share a rounded-up 2 MiB page.
                Err(MapToError::PageAlreadyMapped(_)) => {}
                Err(e) => panic!("HHDM 2 MiB map {:#x} failed: {:?}", phys, e),
            }
            phys += TWO_MIB;
        }
    }
}

/// Map the kernel image section-by-section with tight permissions.
/// Pages that are unmapped in the *current* (old) tree are skipped so
/// that the IST guard unmap survives the switch.
fn populate_kernel_image(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    extern "C" {
        static __limine_requests_start: u8;
        static __limine_requests_end: u8;
        static __text_start: u8;
        static __text_end: u8;
        static __rodata_start: u8;
        static __rodata_end: u8;
        static __data_start: u8;
        static __data_end: u8;
    }

    let present_rw = PageTableFlags::PRESENT | PageTableFlags::WRITABLE;
    let text_flags = PageTableFlags::PRESENT; // RX
    let rodata_flags = PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE; // RO
    let data_flags = present_rw | PageTableFlags::NO_EXECUTE; // RW

    // SAFETY: these are link-time symbols with static addresses; taking
    // their address is always valid.
    let regions = unsafe {
        [
            (
                VirtAddr::from_ptr(&__limine_requests_start),
                VirtAddr::from_ptr(&__limine_requests_end),
                data_flags,
            ),
            (
                VirtAddr::from_ptr(&__text_start),
                VirtAddr::from_ptr(&__text_end),
                text_flags,
            ),
            (
                VirtAddr::from_ptr(&__rodata_start),
                VirtAddr::from_ptr(&__rodata_end),
                rodata_flags,
            ),
            (
                VirtAddr::from_ptr(&__data_start),
                VirtAddr::from_ptr(&__data_end),
                data_flags,
            ),
        ]
    };

    for (start, end, flags) in regions {
        clone_range(mapper, alloc, start, end, flags);
    }
}

/// Copy the mappings for `[start, end)` from the live (old) mapper into
/// `mapper` with `flags`. Pages not currently mapped in the old tree
/// are skipped — this is how the IST guard and any other intentional
/// hole propagates forward.
fn clone_range(
    mapper: &mut OffsetPageTable<'static>,
    alloc: &mut KernelFrameAllocator,
    start: VirtAddr,
    end: VirtAddr,
    flags: PageTableFlags,
) {
    let start = VirtAddr::new(start.as_u64() & !0xFFF);
    let end_aligned = VirtAddr::new((end.as_u64() + 0xFFF) & !0xFFF);
    let mut addr = start;
    while addr < end_aligned {
        if let Some(phys) = translate(addr) {
            let page = Page::<Size4KiB>::containing_address(addr);
            let frame =
                PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys.as_u64() & !0xFFF));
            // SAFETY: fresh tree, not yet live; we're installing a
            // mapping that already backs the kernel.
            unsafe {
                match mapper.map_to(page, frame, flags, alloc) {
                    Ok(f) => f.ignore(),
                    Err(MapToError::PageAlreadyMapped(_)) => {}
                    // Already covered by a 2 MiB HHDM huge page — e.g.
                    // Limine's boot stack lives in HHDM-mapped RAM, so
                    // its virtual address is reachable via the same
                    // backing frame through the huge page. Safe to
                    // skip; the translation is already correct.
                    Err(MapToError::ParentEntryHugePage) => {}
                    Err(e) => panic!("clone_range map_to {:#x} failed: {:?}", addr.as_u64(), e),
                }
            }
        }
        addr += 4096u64;
    }
}

fn clone_heap(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    let base = VirtAddr::new(super::heap::HEAP_BASE as u64);
    let end = base + super::heap::mapped_size() as u64;
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    clone_range(mapper, alloc, base, end, flags);
}

fn clone_ist_stack(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    // The #DF stack lives in .bss and is already cloned by
    // populate_kernel_image. Nothing extra to do here; kept as a seam
    // for when IST stacks move out of .bss into dedicated allocations.
    let _ = (mapper, alloc);
}

/// Preserve the current (Limine-provided) boot stack across the CR3
/// switch. Limine's `StackSizeRequest` stack is allocated from
/// bootloader-reclaimable memory and is NOT guaranteed to live in the
/// HHDM window — we must explicitly clone its virtual mapping into the
/// new tree or the CPU will fault on the very next push after CR3
/// reloads.
fn clone_boot_stack(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    // Read RSP at this exact frame — we know the stack lives somewhere
    // that contains this address. Limine gave us STACK_SIZE bytes; clone
    // a generous window of 2× on either side so we cover the whole
    // stack regardless of where RSP currently sits inside it. `clone_range`
    // skips pages that aren't mapped in the old tree, so over-covering
    // is harmless.
    let rsp: u64;
    // SAFETY: reading RSP is always defined.
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags));
    }
    let window = 2 * crate::boot::STACK_REQUEST.size();
    let base = VirtAddr::new(rsp.saturating_sub(window));
    let top = VirtAddr::new(rsp.saturating_add(window));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;
    clone_range(mapper, alloc, base, top, flags);
}

fn map_framebuffer(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    // The framebuffer lives inside HHDM (Limine maps it there), and
    // HHDM already covers every memory-map entry including
    // `EntryType::FRAMEBUFFER`. Nothing to do beyond HHDM. Kept as a
    // seam for later — direct non-HHDM framebuffer mapping (e.g. with
    // write-combining) is a follow-up.
    let _ = (mapper, alloc);
}
