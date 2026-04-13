//! Per-process address space — the RFC 0001 anchor for every userspace VM
//! operation. Owns one PML4 frame, a sorted interval map of user VMAs, and
//! a pre-reserved `brk` window. Every syscall that mutates user memory
//! (`mmap`, `munmap`, `mprotect`, `brk`, `fork`, `exec`, `exit`) works
//! against an `AddressSpace`; the `#PF` resolver walks it to decide how to
//! back a faulting address.
//!
//! This is the skeleton introduced by RFC 0001. Richer facilities (VMA
//! split/merge, the `VmObject` trait, the rewritten fault resolver, task
//! integration, reclaim-on-drop) land in their own follow-up issues
//! (#155..#161). What lives here today: the struct, kernel-half PML4 copy,
//! the IRQ-safety contract on the lock, and the `find(addr)` lookup that
//! every later caller will build on.

use alloc::collections::BTreeMap;

use spin::RwLock;
use x86_64::VirtAddr;

use crate::mem::vma::Vma;

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
/// evolve the representation (e.g. swap the VMA `BTreeMap` for a richer
/// `VmaTree`, promote `brk_start`/`brk_cur` into a dedicated struct)
/// without breaking every downstream user.
#[allow(dead_code)] // fields consumed by follow-up issues #155..#161
pub struct AddressSpace {
    /// Physical frame backing this address space's PML4. The lower half
    /// (entries `0..256`) is user-owned; the upper half (entries
    /// `256..512`) is a verbatim copy of the canonical kernel PML4
    /// installed at construction.
    #[cfg(target_os = "none")]
    pub(crate) page_table:
        x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>,

    /// Sorted interval map of user VMAs keyed by `start`. Half-open
    /// `[start, end)` intervals that never overlap (enforced by the
    /// insertion path once #156 lands; for now this map is empty on
    /// construction and read-only via [`AddressSpace::find`]).
    pub(crate) vmas: BTreeMap<usize, Vma>,

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
            vmas: BTreeMap::new(),
            mmap_base,
            brk_start,
            brk_cur: brk_start,
            brk_max: VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
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
            vmas: BTreeMap::new(),
            mmap_base,
            brk_start,
            brk_cur: brk_start,
            brk_max: VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
        }
    }

    /// Test-only constructor: build an `AddressSpace` without touching
    /// the paging subsystem. Exposed as `pub(crate)` so host tests in
    /// this crate can exercise the [`find`](Self::find) logic.
    #[cfg(test)]
    pub(crate) fn new_for_test(mmap_base: u64) -> Self {
        Self {
            vmas: BTreeMap::new(),
            mmap_base: VirtAddr::new(mmap_base),
            brk_start: VirtAddr::new(mmap_base),
            brk_cur: VirtAddr::new(mmap_base),
            brk_max: VirtAddr::new(mmap_base - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
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

    /// Insert `vma`, panicking if it overlaps any existing entry.
    /// Overlapping VMAs are a programmer error, not a runtime
    /// condition to recover from. O(log n) lookup of the candidate
    /// neighbours via `BTreeMap::range`.
    pub fn insert(&mut self, vma: Vma) {
        // Predecessor whose start < vma.end could still overlap if its
        // end > vma.start.
        if let Some((_, prev)) = self.vmas.range(..vma.start).next_back() {
            assert!(prev.end <= vma.start, "VMA overlaps existing range");
        }
        if let Some((_, next)) = self.vmas.range(vma.start..).next() {
            assert!(vma.end <= next.start, "VMA overlaps existing range");
        }
        let pages = (vma.end - vma.start) / 4096;
        self.vmas.insert(vma.start, vma);
        self.vm_pages += pages;
    }

    /// Iterate VMAs in ascending start-address order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.vmas.values()
    }

    /// Remove the VMA whose `start` matches exactly. Keyed on `start`
    /// (not an arbitrary inclusion address) so callers must name the
    /// region they installed — partial-range unmap is a separate
    /// concern (#160).
    pub fn remove(&mut self, start: usize) -> Option<Vma> {
        let removed = self.vmas.remove(&start)?;
        self.vm_pages -= (removed.end - removed.start) / 4096;
        Some(removed)
    }

    /// Find the VMA containing `addr`, if any. Uses a `BTreeMap::range`
    /// walk backward from `addr` — O(log n) — so this is the intended
    /// hot-path lookup for the page-fault resolver.
    pub fn find(&self, addr: usize) -> Option<&Vma> {
        self.vmas
            .range(..=addr)
            .next_back()
            .map(|(_, v)| v)
            .filter(|v| addr < v.end)
    }

    /// Returns `true` if `vma` lies entirely inside the userspace
    /// canonical lower half and does not cross [`USER_VA_END`].
    #[allow(dead_code)] // consumed by #156 (VmaTree::insert) and the mmap syscall
    pub(crate) fn vma_in_user_range(vma: &Vma) -> bool {
        (vma.end as u64) <= USER_VA_END
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
    use crate::mem::vma::{Vma, VmaKind};
    use x86_64::structures::paging::PageTableFlags;

    fn anon(start: usize, end: usize) -> Vma {
        Vma::new(start, end, VmaKind::AnonZero, PageTableFlags::PRESENT)
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
        aspace.vmas.insert(vma.start, vma);
        let hit = aspace.find(0x1_0000).expect("start is inclusive");
        assert_eq!(hit.start, 0x1_0000);
    }

    #[test]
    fn find_hits_interior() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x3_0000);
        aspace.vmas.insert(vma.start, vma);
        let hit = aspace.find(0x2_5000).expect("addr is inside the vma");
        assert_eq!(hit.start, 0x1_0000);
        assert_eq!(hit.end, 0x3_0000);
    }

    #[test]
    fn find_misses_past_end() {
        // `end` is exclusive — the very last byte is in, the end address is out.
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x2_0000);
        aspace.vmas.insert(vma.start, vma);
        assert!(aspace.find(0x2_0000).is_none());
        assert!(aspace.find(0x1_ffff).is_some());
    }

    #[test]
    fn find_misses_before_start() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let vma = anon(0x1_0000, 0x2_0000);
        aspace.vmas.insert(vma.start, vma);
        assert!(aspace.find(0x0fff).is_none());
    }

    #[test]
    fn find_picks_the_right_neighbor_with_a_gap() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let a = anon(0x1_0000, 0x2_0000);
        let b = anon(0x5_0000, 0x6_0000);
        aspace.vmas.insert(a.start, a);
        aspace.vmas.insert(b.start, b);
        // In the gap: predecessor is A, but addr >= A.end → miss.
        assert!(aspace.find(0x3_0000).is_none());
        // Inside B.
        assert_eq!(aspace.find(0x5_1000).unwrap().start, 0x5_0000);
    }

    #[test]
    fn user_va_range_guard_rejects_kernel_half() {
        let kernel_half = Vma::new(
            USER_VA_END as usize,
            (USER_VA_END as usize) + 0x1000,
            VmaKind::AnonZero,
            PageTableFlags::PRESENT,
        );
        assert!(!AddressSpace::vma_in_user_range(&kernel_half));

        let high_user = Vma::new(
            (USER_VA_END as usize) - 0x2000,
            USER_VA_END as usize,
            VmaKind::AnonZero,
            PageTableFlags::PRESENT,
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
