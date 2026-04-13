//! Kernel paging: wrap Limine's page tables in an [`OffsetPageTable`],
//! then build a fresh kernel-owned PML4 and atomically switch CR3 to it.
//!
//! Boot flow: [`init`] wraps Limine's active tree so early subsystems
//! (heap, IST guard) can install mappings through the normal API. Once
//! those are in place, [`build_and_switch_kernel_pml4`] constructs a
//! clean tree that maps only what the kernel actually needs — kernel
//! image per section with tight flags, HHDM via 2 MiB pages, heap, IST
//! stack sans guard, framebuffer (4 KiB PTEs with PAT=WC) — and swaps
//! CR3 to it. From that point on Limine's original tree is unreachable;
//! actually freeing it (and the `BOOTLOADER_RECLAIMABLE` frames) is
//! issue #46.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
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

/// Frame allocator adapter: pulls 4 KiB frames from (and, via
/// [`FrameDeallocator`], returns them to) the global
/// [`BitmapFrameAllocator`](frame::BitmapFrameAllocator). Zero-sized;
/// construct ad-hoc wherever you need to hand the mapper a
/// `FrameAllocator`.
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

/// Physical address of the original Limine PML4, captured at [`init`]
/// before any CR3 change. Used by [`reclaim_bootloader_memory`] to walk
/// and account for the old tree's intermediate page-table frames.
static LIMINE_PML4_PHYS: Mutex<Option<PhysAddr>> = Mutex::new(None);

/// Install the kernel mapper over Limine's active PML4. Must be called
/// after `frame::init` and before any caller tries to `map`/`unmap`.
pub fn init(hhdm_offset: VirtAddr) {
    let (cr3_frame, _) = Cr3::read();
    // Stash the original Limine PML4 frame before any CR3 change so
    // reclaim_bootloader_memory can walk the old tree after the switch.
    *LIMINE_PML4_PHYS.lock() = Some(cr3_frame.start_address());
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

/// Read the page-table flags of the leaf PTE backing `addr`, if any.
/// Used by tests to verify that `populate_kernel_image` applied the
/// ELF-derived `{R, W, X}` flags correctly.
pub fn flags(addr: VirtAddr) -> Option<PageTableFlags> {
    with_mapper(|m| match m.translate(addr) {
        TranslateResult::Mapped { flags, .. } => Some(flags),
        TranslateResult::NotMapped | TranslateResult::InvalidFrameAddress(_) => None,
    })
}

/// Physical address of the currently-active PML4 (i.e. CR3).
pub fn active_pml4_phys() -> PhysAddr {
    Cr3::read().0.start_address()
}

/// Build a fresh PML4 for a new task, sharing the kernel's upper half.
///
/// The returned frame holds a page table whose lower half (entries
/// `0..256`) is zero and whose upper half (entries `256..512`) is a
/// verbatim copy of the currently-active PML4's upper half. That gives
/// the task its own lower-half VA space while all kernel mappings
/// (HHDM, heap, IST, kernel image, task stacks, framebuffer) remain
/// reachable at the same VAs.
///
/// # Invariant
///
/// Kernel upper-half L4 entries must be fully populated before this is
/// called for the first time, and must not subsequently gain *new* L4
/// entries. The kernel populates L4 entries 256 (HHDM), 384 (heap),
/// 416 (task stacks — populated when the first task stack is mapped),
/// and 511 (kernel image) during boot and first-task construction.
/// Further kernel mappings only populate lower levels below those L4
/// entries, which are shared by alias across all task PML4s. A future
/// feature that installs a brand-new upper-half L4 entry after tasks
/// exist would leave the older PML4s blind to it — that's the
/// groundwork #61/SMP-level TLB-shootdown will have to take care of.
pub fn new_task_pml4() -> PhysFrame<Size4KiB> {
    let hhdm = HHDM_OFFSET
        .lock()
        .expect("paging::init must run before new_task_pml4");
    // SAFETY: freshly allocated, exclusively owned, zeroed through HHDM.
    let new_frame = unsafe { alloc_zeroed_frame(hhdm) };
    let active = Cr3::read().0;

    // SAFETY: `active` is the live PML4 (CR3), which is always mapped in
    // the HHDM. `new_frame` was just allocated for our exclusive use.
    // PageTable is repr(C) `[PageTableEntry; 512]` and PageTableEntry is
    // repr(transparent) u64 — copy the raw 64-bit slots to avoid
    // depending on the entry type's Clone impl.
    unsafe {
        let src = pml4_as_mut(active, hhdm) as *const PageTable as *const u64;
        let dst = pml4_as_mut(new_frame, hhdm) as *mut PageTable as *mut u64;
        core::ptr::copy_nonoverlapping(src.add(256), dst.add(256), 256);
    }
    new_frame
}

/// Map `page` to a freshly-allocated zeroed frame in the PML4 rooted
/// at `pml4_frame`, with `flags`. Intended for the `#PF` demand-paging
/// resolver: the handler runs in the faulting task's address space, so
/// it passes `Cr3::read().0` for `pml4_frame`.
///
/// Flushes the TLB entry for `page` if `pml4_frame` is the currently
/// active PML4; otherwise the new mapping only becomes visible when a
/// later CR3 load installs this PML4 (at which point the load flushes
/// non-global TLB entries implicitly).
pub fn map_in_pml4(
    pml4_frame: PhysFrame<Size4KiB>,
    page: Page<Size4KiB>,
    flags: PageTableFlags,
) -> Result<PhysFrame<Size4KiB>, MapToError<Size4KiB>> {
    let hhdm = HHDM_OFFSET
        .lock()
        .expect("paging::init must run before map_in_pml4");
    let mut alloc = KernelFrameAllocator;
    // SAFETY: just-allocated frame, zeroed through HHDM, exclusive.
    let data_frame = unsafe { alloc_zeroed_frame(hhdm) };
    // SAFETY: `pml4_frame` is a valid page-table frame and `hhdm` is
    // the live HHDM offset. The temporary OffsetPageTable only lives
    // for this call; no aliasing handle to the same PML4 escapes.
    let l4 = unsafe { pml4_as_mut(pml4_frame, hhdm) };
    let mut mapper = unsafe { OffsetPageTable::new(l4, hhdm) };
    let flush = unsafe { mapper.map_to(page, data_frame, flags, &mut alloc)? };
    if Cr3::read().0 == pml4_frame {
        flush.flush();
    } else {
        flush.ignore();
    }
    Ok(data_frame)
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
        map_framebuffer(&mut new_mapper, hhdm, &mut alloc);
    }

    // Atomic swap. IRQs off so no handler runs while CR3 and MAPPER
    // are in a mid-transition state. TLB is wholly flushed by the CR3
    // load; WBINVD then drops any WB-cached lines (notably framebuffer
    // pixels written through Limine's WB HHDM mapping) so that the new
    // WC framebuffer mapping isn't silently clobbered by stale cache
    // evictions.
    x86_64::instructions::interrupts::without_interrupts(|| {
        let (_old, flags) = Cr3::read();
        unsafe { Cr3::write(new_pml4_frame, flags) };
        let l4 = unsafe { pml4_as_mut(new_pml4_frame, hhdm) };
        let mapper = unsafe { OffsetPageTable::new(l4, hhdm) };
        *MAPPER.lock() = Some(mapper);
        // SAFETY: WBINVD is serializing and has no operands. Safe to
        // issue in kernel mode with IRQs off.
        unsafe { core::arch::asm!("wbinvd", options(nostack, preserves_flags)) };
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
            | EntryType::ACPI_RECLAIMABLE
            | EntryType::ACPI_NVS => {}
            // FRAMEBUFFER is intentionally excluded: it gets its own
            // 4 KiB PTEs with PAT=WC installed by `map_framebuffer`.
            // A 2 MiB HHDM huge page here would force WB cacheability
            // on the same virtual range and defeat the point.
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

/// Map the kernel image segment-by-segment with tight permissions.
/// `{R, W, X}` is derived from each `PT_LOAD`'s `p_flags` via the ELF
/// program headers Limine hands back — a new kernel section picks up
/// the right flags without any code change here. Pages unmapped in
/// the current (old) tree are skipped so that the IST guard hole
/// survives the switch.
fn populate_kernel_image(mapper: &mut OffsetPageTable<'static>, alloc: &mut KernelFrameAllocator) {
    // PT_LOAD is byte-granular but a PTE is page-granular: two
    // segments touching the same 4 KiB page have to agree on flags.
    // Union per page before mapping (WRITABLE if any covering segment
    // is writable, NO_EXECUTE only if every covering segment is NX),
    // then map each page exactly once. Our linker script page-aligns
    // segment boundaries today, so in practice no page is covered
    // twice — but relying on that invariant silently would leave a
    // boundary page mis-permissioned the first time it breaks.
    let mut per_page: BTreeMap<u64, PageTableFlags> = BTreeMap::new();
    for seg in super::elf::kernel_load_segments() {
        let start = seg.vaddr.as_u64() & !0xFFF;
        let end = (seg.vaddr.as_u64() + seg.memsz + 0xFFF) & !0xFFF;
        let mut addr = start;
        while addr < end {
            let entry = per_page
                .entry(addr)
                .or_insert(PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE);
            if seg.flags.contains(PageTableFlags::WRITABLE) {
                *entry |= PageTableFlags::WRITABLE;
            }
            if !seg.flags.contains(PageTableFlags::NO_EXECUTE) {
                entry.remove(PageTableFlags::NO_EXECUTE);
            }
            addr += 0x1000;
        }
    }

    for (va, flags) in per_page {
        let page_va = VirtAddr::new(va);
        clone_range(mapper, alloc, page_va, page_va + 0x1000u64, flags);
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

/// Install the linear framebuffer at its HHDM VA with 4 KiB PTEs that
/// select the WC slot we programmed in `pat::init`. `populate_hhdm`
/// deliberately leaves FRAMEBUFFER memory-map entries uncovered so we
/// can own those virtual pages here with the right memory type.
fn map_framebuffer(
    mapper: &mut OffsetPageTable<'static>,
    hhdm: VirtAddr,
    alloc: &mut KernelFrameAllocator,
) {
    use limine::memory_map::EntryType;

    let memmap = crate::boot::MEMMAP_REQUEST
        .get_response()
        .expect("Limine memory-map response missing");

    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    for entry in memmap.entries() {
        if entry.entry_type != EntryType::FRAMEBUFFER {
            continue;
        }
        assert!(
            entry.base & 0xFFF == 0 && entry.length & 0xFFF == 0,
            "framebuffer range not 4 KiB-aligned: base={:#x} len={:#x}",
            entry.base,
            entry.length
        );
        let mut phys = entry.base;
        let end = entry.base + entry.length;
        while phys < end {
            let page = Page::<Size4KiB>::containing_address(hhdm + phys);
            let frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(phys));
            // SAFETY: fresh tree, not yet live. FRAMEBUFFER memory-map
            // entries are carved out of HHDM coverage above, so no
            // existing 2 MiB page straddles this range.
            match unsafe { mapper.map_to(page, frame, flags, alloc) } {
                Ok(f) => f.ignore(),
                Err(e) => panic!("framebuffer WC map {:#x} failed: {:?}", phys, e),
            }
            // SAFETY: the mapping we just installed is the only
            // reference to this PTE; OR-ing the PAT bit flips memory
            // type from default (WB, slot 0) to WC (slot 4).
            unsafe { set_pat_bit_4k(mapper, hhdm, page) };
            phys += 4096;
        }
    }
}

/// OR the PAT bit (bit 7) onto the L1 entry backing `page` in
/// `mapper`'s tree. Walks L4→L3→L2→L1 through the HHDM window.
///
/// # Safety
/// `mapper`'s tree must be a well-formed 4-level tree reachable via
/// `hhdm`, and `page` must already be mapped via 4 KiB PTEs (the walk
/// panics on a huge-page parent, which would mean a broken invariant
/// upstream in `populate_hhdm` — not a recoverable error).
unsafe fn set_pat_bit_4k(
    mapper: &mut OffsetPageTable<'static>,
    hhdm: VirtAddr,
    page: Page<Size4KiB>,
) {
    // SAFETY: the returned `&mut PageTable` aliases an HHDM view of a
    // distinct physical frame (the child table), never `parent` itself,
    // so no `&mut` overlap is created. Tying `'a` to `parent` keeps the
    // borrow relationship explicit; taking `&'a mut` anchors the
    // reborrow chain from the root `level_4_table()` down.
    unsafe fn next_table<'a>(
        parent: &'a mut PageTable,
        index: x86_64::structures::paging::page_table::PageTableIndex,
        hhdm: VirtAddr,
    ) -> &'a mut PageTable {
        let entry = &parent[index];
        assert!(
            !entry.flags().contains(PageTableFlags::HUGE_PAGE),
            "set_pat_bit_4k: walked into a huge-page parent"
        );
        let phys = entry
            .frame()
            .expect("set_pat_bit_4k: missing table")
            .start_address();
        let virt = hhdm + phys.as_u64();
        // SAFETY: page-table frames reached via HHDM, exclusive access
        // granted by the caller's `&mut OffsetPageTable`.
        unsafe { &mut *(virt.as_mut_ptr::<PageTable>()) }
    }

    let l4 = mapper.level_4_table_mut();
    // SAFETY: `next_table` is unsafe by signature (raw pointer deref into
    // HHDM). Each call walks to a distinct child table frame, so the
    // &'a mut reborrow chain doesn't alias.
    let l3 = unsafe { next_table(l4, page.p4_index(), hhdm) };
    let l2 = unsafe { next_table(l3, page.p3_index(), hhdm) };
    let l1 = unsafe { next_table(l2, page.p2_index(), hhdm) };
    let entry = &mut l1[page.p1_index()];
    let ptr = entry as *mut _ as *mut u64;
    // SAFETY: `entry` is a live &mut reference; writing through its raw
    // pointer is fine and avoids the `x86_64` crate's flag validation.
    unsafe {
        ptr.write_volatile(ptr.read_volatile() | super::pat::PAT_BIT_4K);
    }
}

// -- Bootloader memory reclamation ----------------------------------------

/// Release Limine's original PML4 intermediate page-table frames and all
/// `BOOTLOADER_RECLAIMABLE` physical regions back to the global frame
/// allocator. Must be called after [`build_and_switch_kernel_pml4`].
///
/// The original PML4's L3/L2/L1 intermediate frames are a subset of
/// `BOOTLOADER_RECLAIMABLE`; the broad region release below covers them.
/// We walk the old tree first purely for accounting so the log line
/// reports how many page-table frames were among the reclaimed memory.
///
/// The bootstrap task (`Task::bootstrap`) inherits the Limine boot stack
/// and runs on it permanently — its physical frames are excluded from
/// reclamation so the allocator cannot reuse them while the stack is
/// still live.
pub fn reclaim_bootloader_memory() {
    let hhdm = HHDM_OFFSET.lock().expect("paging::init not called");
    // Consume the stored PML4 address so subsequent calls are no-ops.
    let Some(orig_pml4_phys) = LIMINE_PML4_PHYS.lock().take() else {
        serial_println!("paging: bootloader memory already reclaimed; skipping");
        return;
    };
    assert_ne!(
        active_pml4_phys(),
        orig_pml4_phys,
        "reclaim_bootloader_memory must be called after build_and_switch_kernel_pml4",
    );

    // --- Boot stack protection -------------------------------------------
    // Translate the boot stack virtual address window to physical frames.
    // We use the same window as clone_boot_stack so we protect every page
    // that was explicitly cloned into the kernel PML4. translate() takes
    // the MAPPER lock per call, so we collect all frames before we acquire
    // the frame-allocator lock below (no nested locking).
    let rsp: u64;
    // SAFETY: reading RSP is always valid.
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nomem, nostack, preserves_flags)
        );
    }
    let stack_window = 2 * crate::boot::STACK_REQUEST.size();
    let stack_virt_base = rsp.saturating_sub(stack_window) & !0xFFFu64;
    let stack_virt_top = (rsp.saturating_add(stack_window) + 0xFFF) & !0xFFFu64;

    let mut boot_stack_phys: Vec<u64> = Vec::new();
    let mut virt = stack_virt_base;
    while virt < stack_virt_top {
        if let Some(phys) = translate(VirtAddr::new(virt)) {
            boot_stack_phys.push(phys.as_u64() & !0xFFFu64);
        }
        virt += 4096;
    }
    boot_stack_phys.sort_unstable();

    // --- Original PML4 walk (accounting only) ----------------------------
    // Walk the now-inactive Limine PML4 to count its intermediate L3/L2/L1
    // frames. The new kernel PML4's HHDM covers BOOTLOADER_RECLAIMABLE with
    // 2 MiB pages, so the old table frames remain readable via HHDM.
    //
    // SAFETY: orig_pml4_phys was captured before the CR3 switch. The new
    // PML4's HHDM window explicitly covers BOOTLOADER_RECLAIMABLE so the
    // old table frames are still reachable. No CPU walks the old tree (CR3
    // has been updated) and interrupts are off during mem::init.
    let table_frame_count = unsafe { count_pml4_intermediate_tables(orig_pml4_phys, hhdm) };

    // --- BOOTLOADER_RECLAIMABLE release ----------------------------------
    // Iterate the memory map and release every frame in BOOTLOADER_RECLAIMABLE
    // regions, skipping the frames that back the active boot stack.
    //
    // release_region is idempotent (clears bitmap bits unconditionally) so
    // releasing a frame that was already freed or that overlaps with the
    // PML4 intermediate-table walk above is harmless. We read the memory-
    // map response here — before releasing its physical frames — so the
    // data is still valid; the allocator never zeroes memory on release.
    use limine::memory_map::EntryType;
    let memmap = crate::boot::MEMMAP_REQUEST
        .get_response()
        .expect("Limine memory-map response missing");

    let mut total_bytes: u64 = 0;
    {
        let mut alloc = frame::global().lock();
        for entry in memmap.entries() {
            if entry.entry_type != EntryType::BOOTLOADER_RECLAIMABLE {
                continue;
            }
            let region_end = entry.base + entry.length;
            let mut phys = entry.base & !0xFFFu64;
            while phys < region_end {
                if boot_stack_phys.binary_search(&phys).is_err() {
                    alloc.release_region(super::Region::new(phys, super::FRAME_SIZE));
                    total_bytes += super::FRAME_SIZE;
                }
                phys += super::FRAME_SIZE;
            }
        }
    }

    serial_println!(
        "paging: reclaimed {} KiB bootloader memory \
         ({} L3/L2/L1 intermediate table frames, PML4={:#x})",
        total_bytes / 1024,
        table_frame_count,
        orig_pml4_phys.as_u64(),
    );
}

/// Walk the now-inactive Limine PML4 (accessible via the HHDM) and return
/// the total count of intermediate L3/L2/L1 page-table frames. Does not
/// free anything; frames are reclaimed by the broad `BOOTLOADER_RECLAIMABLE`
/// region release in [`reclaim_bootloader_memory`].
///
/// # Safety
/// * `pml4_phys` must be the physical address of a formerly-active PML4
///   whose frames are still mapped via `hhdm` (guaranteed when the new
///   kernel PML4's HHDM covers `BOOTLOADER_RECLAIMABLE`).
/// * No CPU may be walking the tree (CR3 must have been switched away).
unsafe fn count_pml4_intermediate_tables(pml4_phys: PhysAddr, hhdm: VirtAddr) -> usize {
    let mut count = 0usize;

    let l4_virt = hhdm + pml4_phys.as_u64();
    // SAFETY: l4_virt is in the HHDM window, pointing at the old PML4 frame.
    let l4: &PageTable = unsafe { &*(l4_virt.as_mut_ptr::<PageTable>()) };

    for l4_entry in l4.iter() {
        if !l4_entry.flags().contains(PageTableFlags::PRESENT) {
            continue;
        }
        // L4 entries in x86_64 cannot be huge pages; frame() always succeeds.
        let Ok(l3_frame) = l4_entry.frame() else {
            continue;
        };
        let l3_virt = hhdm + l3_frame.start_address().as_u64();
        let l3: &PageTable = unsafe { &*(l3_virt.as_mut_ptr::<PageTable>()) };
        count += 1; // this L3 frame is an intermediate page table

        for l3_entry in l3.iter() {
            if !l3_entry.flags().contains(PageTableFlags::PRESENT) {
                continue;
            }
            // 1 GiB huge page: L3 entry is a leaf; there is no L2 child table.
            if l3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                continue;
            }
            let Ok(l2_frame) = l3_entry.frame() else {
                continue;
            };
            let l2_virt = hhdm + l2_frame.start_address().as_u64();
            let l2: &PageTable = unsafe { &*(l2_virt.as_mut_ptr::<PageTable>()) };
            count += 1; // this L2 frame is an intermediate page table

            for l2_entry in l2.iter() {
                if !l2_entry.flags().contains(PageTableFlags::PRESENT) {
                    continue;
                }
                // 2 MiB huge page: L2 entry is a leaf; there is no L1 child table.
                if l2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
                    continue;
                }
                // L1 table frame: contains 4 KiB PTEs (leaf entries pointing at
                // actual data frames). We count the L1 frame itself as an
                // intermediate table but do not descend into its entries —
                // those leaf frames belong to kernel data or USABLE memory.
                if l2_entry.frame().is_ok() {
                    count += 1;
                }
            }
        }
    }

    count
}
