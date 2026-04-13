//! Per-process address space — the RFC 0001 anchor for every userspace VM
//! operation. Owns one PML4 frame, a sorted interval map of user VMAs, and
//! a pre-reserved `brk` window. Every syscall that mutates user memory
//! (`mmap`, `munmap`, `mprotect`, `brk`, `fork`, `exec`, `exit`) works
//! against an `AddressSpace`; the `#PF` resolver walks it to decide how to
//! back a faulting address.
//!
//! Richer facilities (the `VmObject` trait, the rewritten fault resolver,
//! reclaim-on-drop) were wired up in issues #155..#159. `AddressSpace` now
//! owns a `VmaTree` whose entries carry `Arc<dyn VmObject>` backing objects;
//! the `#PF` resolver calls `VmObject::fault` to obtain physical frames on
//! first touch.

use spin::RwLock;
use x86_64::VirtAddr;

use crate::mem::vmatree::{Vma, VmaTree};

/// First address **above** the userspace canonical lower half. The legal
/// user VA range is `[0, USER_VA_END)`; a `len`-rounded mapping that ends
/// at `USER_VA_END` is still legal, but any address at or above it is not.
/// Matches the RFC 0001 boundary and keeps user syscalls from touching the
/// kernel upper half.
pub const USER_VA_END: u64 = 0x0000_8000_0000_0000;

/// Default guard distance between the top of `brk` and `mmap_base`. Stops
/// a saturated heap from stranding later `mmap` allocations, and matches
/// the RFC 0001 Security advisory A8 default (non-zero guard).
pub const DEFAULT_BRK_GUARD: u64 = 1 * 1024 * 1024;

/// Per-process address space.
///
/// All fields are `pub(crate)` rather than `pub` so later issues can
/// evolve the representation (e.g. promote `brk_start`/`brk_cur` into a
/// dedicated struct) without breaking every downstream user.
#[allow(dead_code)] // rss_pages / vm_pages consumed by future syscall accounting
pub struct AddressSpace {
    /// Physical frame backing this address space's PML4. The lower half
    /// (entries `0..256`) is user-owned; the upper half (entries
    /// `256..512`) is a verbatim copy of the canonical kernel PML4
    /// installed at construction.
    #[cfg(target_os = "none")]
    pub(crate) page_table:
        x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,

    /// Sorted, non-overlapping interval tree of user VMAs. Each entry
    /// carries an `Arc<dyn VmObject>` whose `fault` method the `#PF`
    /// resolver calls on first touch to obtain a physical frame.
    pub(crate) vmas: VmaTree,

    /// First valid user VA for the initial `mmap` hint floor. Callers
    /// that place fixed mappings may go below this.
    pub(crate) mmap_base: VirtAddr,

    /// brk window: `[brk_start, brk_cur)`, grown by `sys_brk` up to
    /// `brk_max`.
    pub(crate) brk_start: VirtAddr,
    pub(crate) brk_cur: VirtAddr,
    pub(crate) brk_max: VirtAddr,

    /// Resident pages (PTE-present count). Bumped by the fault resolver
    /// as it installs frames; decremented by `unmap_range`.
    pub(crate) rss_pages: usize,
    /// Virtual pages covered by VMAs, independent of whether they have
    /// been faulted in. Bumped by `insert`, decremented by
    /// `unmap_range`.
    pub(crate) vm_pages: usize,

    /// `true` for the bootstrap task's address space, whose `page_table`
    /// is the live kernel PML4. `Drop` skips reclaim entirely in that
    /// case — freeing the kernel PML4 (or walking its lower half, which
    /// is empty anyway) would brick the system. All other constructors
    /// set this to `false`.
    pub(crate) bootstrap: bool,
}

impl AddressSpace {
    /// Build an `AddressSpace` for the bootstrap task: wraps the
    /// already-running kernel PML4 instead of allocating a new one. The
    /// bootstrap task inherits the kernel mappings as-is and never
    /// installs user VMAs, so the fields beyond `page_table` get the
    /// same defaults as [`new_empty`].
    #[cfg(target_os = "none")]
    pub fn for_bootstrap(
        page_table: x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,
    ) -> Self {
        let mmap_base = VirtAddr::new(0x0000_0000_4000_0000);
        let brk_start = mmap_base;
        Self {
            page_table,
            vmas: VmaTree::new(),
            mmap_base,
            brk_start,
            brk_cur: brk_start,
            brk_max: VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
            bootstrap: true,
        }
    }

    /// Build an empty address space: fresh PML4 with the canonical
    /// kernel upper half copied in, no VMAs, `brk` window pinned at
    /// `mmap_base` until a loader picks a real heap start.
    ///
    /// `mmap_base` defaults to `0x0000_0000_4000_0000` — a spot well
    /// above the usual static ELF load range but far below
    /// [`USER_VA_END`] so future `brk` and `mmap` both have room.
    ///
    /// # Panics
    ///
    /// Panics if called before `mem::paging::init`.
    #[cfg(target_os = "none")]
    pub fn new_empty() -> Self {
        let page_table = crate::mem::paging::new_task_pml4();
        let mmap_base = VirtAddr::new(0x0000_0000_4000_0000);
        let brk_start = mmap_base;
        Self {
            page_table,
            vmas: VmaTree::new(),
            mmap_base,
            brk_start,
            brk_cur: brk_start,
            brk_max: VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
            bootstrap: false,
        }
    }

    /// Test-only constructor: build an `AddressSpace` without touching
    /// the paging subsystem. Exposed as `pub(crate)` so host tests in
    /// this crate can exercise the [`find`](Self::find) logic.
    #[cfg(test)]
    pub(crate) fn new_for_test(mmap_base: u64) -> Self {
        Self {
            vmas: VmaTree::new(),
            mmap_base: VirtAddr::new(mmap_base),
            brk_start: VirtAddr::new(mmap_base),
            brk_cur: VirtAddr::new(mmap_base),
            brk_max: VirtAddr::new(mmap_base - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
            bootstrap: false,
        }
    }

    /// Physical frame backing this address space's PML4. Stable
    /// accessor so callers (task construction, the fork path, tests)
    /// don't need to reach into the struct field directly.
    #[cfg(target_os = "none")]
    pub fn page_table_frame(
        &self,
    ) -> x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB> {
        self.page_table
    }

    /// Insert `vma` into the VMA tree, merging with adjacent neighbours
    /// where possible. Panics if `vma` overlaps any existing entry —
    /// overlapping VMAs are a programmer error.
    pub fn insert(&mut self, vma: Vma) {
        let pages = (vma.end - vma.start) / 4096;
        self.vmas.insert(vma);
        self.vm_pages += pages;
    }

    /// Iterate VMAs in ascending start-address order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.iter()
    }

    /// Remove the VMA whose `start` matches exactly. Keyed on `start`
    /// (not an arbitrary inclusion address) so callers must name the
    /// region they installed — partial-range unmap uses
    /// `VmaTree::unmap_range` directly.
    pub fn remove(&mut self, start: usize) -> Option<Vma> {
        let removed = self.vmas.remove_exact(start)?;
        self.vm_pages -= (removed.end - removed.start) / 4096;
        Some(removed)
    }

    /// Find the VMA containing `addr`, if any. O(log n) via the
    /// underlying `VmaTree`.
    pub fn find(&self, addr: usize) -> Option<&Vma> {
        self.vmas.find(addr)
    }

    /// Returns `true` if `vma` lies entirely inside the userspace
    /// canonical lower half and does not cross [`USER_VA_END`].
    #[allow(dead_code)] // consumed by the mmap syscall
    pub(crate) fn vma_in_user_range(vma: &Vma) -> bool {
        (vma.end as u64) <= USER_VA_END
    }
}

/// Reclaim the address space when the last `Arc<RwLock<AddressSpace>>`
/// is dropped — closes #161 (and the leak documented in #146):
///
/// 1. Walk every VMA, unmap each page from this PML4, free the leaf
///    frame (`AnonZero` always; `Cow` only when the mapped frame is the
///    private post-write copy, never the shared source).
/// 2. Free every intermediate L3/L2/L1 page-table frame in the user
///    half via [`paging::free_user_page_tables`].
/// 3. Free the PML4 frame itself.
///
/// The bootstrap task's address space is exempt: its `page_table` is
/// the live kernel PML4 and its lower half is empty.
///
/// Runs from whatever context drops the last `Arc` — today that's the
/// `preempt_tick` reaper (timer ISR, IRQs masked). The reclaim path is
/// lock-free apart from the `HHDM_OFFSET` mutex, which is set once at
/// boot and only briefly read here, so it cannot deadlock the ISR.
///
#[cfg(target_os = "none")]
impl Drop for AddressSpace {
    fn drop(&mut self) {
        if self.bootstrap {
            return;
        }

        use crate::mem::paging;
        use x86_64::structures::paging::{FrameDeallocator, Page, Size4KiB};

        let pml4 = self.page_table;

        for vma in self.vmas.iter() {
            let mut va = vma.start;
            while va < vma.end {
                let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                    .expect("vma page VA aligned by construction");
                let obj_offset = (va - vma.start) + vma.object_offset;
                if let Ok(pte_frame) = paging::unmap_in_pml4(pml4, page) {
                    let cached = vma.object.frame_at(obj_offset);
                    if cached != Some(pte_frame.start_address().as_u64()) {
                        // PTE holds a private CoW copy that is not tracked
                        // by the VmObject's cache. Free it directly; the
                        // cached source frame is owned by the VmObject and
                        // freed when the Arc<dyn VmObject> drops below.
                        // SAFETY: private copy allocated from the global
                        // frame allocator by `cow_copy_and_remap`; no other
                        // PML4 references it at task-reap time.
                        unsafe {
                            paging::KernelFrameAllocator.deallocate_frame(pte_frame);
                        }
                    }
                    // cached == Some(pte_frame): frame owned by VmObject;
                    // freed when Arc<dyn VmObject> drops at end of this fn.
                }
                va += 4096;
            }
        }

        // SAFETY: this PML4 is no longer the active CR3 on any CPU
        // (the reaper switched away before dropping the Box<Task>),
        // every leaf VMA frame has just been unmapped above, and no
        // outstanding `&mut` references to its tables exist.
        unsafe {
            paging::free_user_page_tables(pml4);
            paging::free_pml4_frame(pml4);
        }
    }
}

/// `AddressSpace` wrapper that enforces the RFC 0001 IRQ-safety
/// contract. Every caller must be in task context with interrupts
/// enabled — page fault, syscall entry, fork, exec, exit. Interrupt
/// handlers and other IRQ-context code must defer to a task-context
/// worker rather than taking this lock directly.
///
/// The wrapper exists so the assertion is centralized: a future refactor
/// to per-CPU preempt counters (once SMP arrives) only needs to update
/// `debug_assert_task_ctx` below, not every call site.
pub struct AddressSpaceLock {
    inner: RwLock<AddressSpace>,
}

impl AddressSpaceLock {
    pub const fn new(aspace: AddressSpace) -> Self {
        Self {
            inner: RwLock::new(aspace),
        }
    }

    /// Take a read lock. Panics in debug builds if called from IRQ
    /// context (interrupts disabled); see RFC 0001 "IRQ-safety contract".
    pub fn read(&self) -> spin::RwLockReadGuard<'_, AddressSpace> {
        debug_assert_task_ctx();
        self.inner.read()
    }

    /// Take a write lock. Panics in debug builds if called from IRQ
    /// context (interrupts disabled); see RFC 0001 "IRQ-safety contract".
    pub fn write(&self) -> spin::RwLockWriteGuard<'_, AddressSpace> {
        debug_assert_task_ctx();
        self.inner.write()
    }
}

/// Panic in debug if we're running with interrupts off — a strong proxy
/// for "we're in interrupt context" pre-SMP. Once per-CPU preempt-depth
/// counters land this becomes `debug_assert!(!in_irq())`.
#[cfg(target_os = "none")]
#[inline]
fn debug_assert_task_ctx() {
    debug_assert!(
        x86_64::instructions::interrupts::are_enabled(),
        "AddressSpace lock taken from IRQ context (interrupts disabled); \
         RFC 0001 IRQ-safety contract forbids this",
    );
}

#[cfg(not(target_os = "none"))]
#[inline]
fn debug_assert_task_ctx() {
    // Host tests have no interrupt state to check.
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::vmatree::{Share, Vma};
    use crate::mem::vmobject::AnonObject;
    use alloc::sync::Arc;

    fn anon(start: usize, end: usize) -> Vma {
        let pages = (end - start) / 4096;
        Vma::new(
            start,
            end,
            0x3, /* PROT_READ|WRITE */
            0,
            Share::Private,
            AnonObject::new(Some(pages)),
            0,
        )
    }

    #[test]
    fn find_returns_none_on_empty() {
        let aspace = AddressSpace::new_for_test(0x4000_0000);
        assert!(aspace.find(0x1000).is_none());
    }

    #[test]
    fn find_hits_exact_start() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x2_0000);
        aspace.vmas.insert(vma);
        let hit = aspace.find(0x1_0000).expect("start is inclusive");
        assert_eq!(hit.start, 0x1_0000);
    }

    #[test]
    fn find_hits_interior() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x3_0000);
        aspace.vmas.insert(vma);
        let hit = aspace.find(0x2_5000).expect("addr is inside the vma");
        assert_eq!(hit.start, 0x1_0000);
        assert_eq!(hit.end, 0x3_0000);
    }

    #[test]
    fn find_misses_past_end() {
        // `end` is exclusive — the very last byte is in, the end address is out.
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x2_0000);
        aspace.vmas.insert(vma);
        assert!(aspace.find(0x2_0000).is_none());
        assert!(aspace.find(0x1_ffff).is_some());
    }

    #[test]
    fn find_misses_before_start() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x2_0000);
        aspace.vmas.insert(vma);
        assert!(aspace.find(0x0fff).is_none());
    }

    #[test]
    fn find_picks_the_right_neighbor_with_a_gap() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        // Use distinct Arc objects so VmaTree does not merge them.
        let a = anon(0x1_0000, 0x2_0000);
        let b = anon(0x5_0000, 0x6_0000);
        aspace.vmas.insert(a);
        aspace.vmas.insert(b);
        // In the gap: predecessor is A, but addr >= A.end → miss.
        assert!(aspace.find(0x3_0000).is_none());
        // Inside B.
        assert_eq!(aspace.find(0x5_1000).unwrap().start, 0x5_0000);
    }

    #[test]
    fn user_va_range_guard_rejects_kernel_half() {
        let obj: Arc<dyn crate::mem::vmobject::VmObject> = AnonObject::new(Some(1));
        let kernel_half = Vma::new(
            USER_VA_END as usize,
            (USER_VA_END as usize) + 0x1000,
            0,
            0,
            Share::Private,
            Arc::clone(&obj),
            0,
        );
        assert!(!AddressSpace::vma_in_user_range(&kernel_half));

        let high_user = Vma::new(
            (USER_VA_END as usize) - 0x2000,
            USER_VA_END as usize,
            0,
            0,
            Share::Private,
            obj,
            0,
        );
        assert!(AddressSpace::vma_in_user_range(&high_user));
    }

    #[test]
    fn brk_window_starts_closed_with_guard_below_mmap_base() {
        let aspace = AddressSpace::new_for_test(0x4000_0000);
        assert_eq!(aspace.brk_start, aspace.brk_cur);
        assert!(aspace.brk_max.as_u64() + DEFAULT_BRK_GUARD == aspace.mmap_base.as_u64());
    }
}
