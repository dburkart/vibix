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

    /// Maximum stack size in bytes; enforced by `grow_stack`. Default is
    /// `DEFAULT_STACK_RLIMIT` (8 MiB). Future `setrlimit(RLIMIT_STACK)`
    /// syscall writes this field.
    pub(crate) stack_rlimit: u64,

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
            stack_rlimit: crate::mem::pf::DEFAULT_STACK_RLIMIT,
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
    /// Panics if called before `mem::paging::init` or if the frame
    /// allocator is exhausted.
    #[cfg(target_os = "none")]
    pub fn new_empty() -> Self {
        Self::try_new_empty().expect("frame allocator exhausted during AddressSpace::new_empty")
    }

    /// Fallible variant of [`new_empty`]: returns `Err(ForkError::OutOfMemory)`
    /// when the frame allocator cannot satisfy the PML4 allocation, instead
    /// of panicking. Used by `fork_address_space` so frame exhaustion during
    /// fork is handled gracefully.
    #[cfg(target_os = "none")]
    pub fn try_new_empty() -> Result<Self, ForkError> {
        let page_table = crate::mem::paging::try_new_task_pml4().ok_or(ForkError::OutOfMemory)?;
        let mmap_base = VirtAddr::new(0x0000_0000_4000_0000);
        let brk_start = mmap_base;
        Ok(Self {
            page_table,
            vmas: VmaTree::new(),
            mmap_base,
            brk_start,
            brk_cur: brk_start,
            brk_max: VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD),
            rss_pages: 0,
            vm_pages: 0,
            stack_rlimit: crate::mem::pf::DEFAULT_STACK_RLIMIT,
            bootstrap: false,
        })
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
            stack_rlimit: crate::mem::pf::DEFAULT_STACK_RLIMIT,
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

    /// Unmap all user-half VMAs and their PTE frames, free L1/L2/L3
    /// intermediate page-table frames, and reset the `brk`/`mmap` layout —
    /// but keep the PML4 frame and its kernel upper-half entries intact.
    ///
    /// Used by `execve()` to clear the old process image before loading
    /// a new ELF into the same address-space slot. After this call the
    /// lower half of the PML4 is empty and ready for `load_user_elf`.
    #[cfg(target_os = "none")]
    pub fn clear_for_exec(&mut self) {
        use crate::mem::paging;
        use x86_64::structures::paging::{FrameDeallocator, Page, Size4KiB};

        let pml4 = self.page_table;
        for vma in self.vmas.iter() {
            let mut va = vma.start;
            while va < vma.end {
                let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                    .expect("vma page VA aligned");
                if let Ok(pte_frame) = paging::unmap_in_pml4(pml4, page) {
                    // SAFETY: frame belongs to this address space.
                    unsafe {
                        paging::KernelFrameAllocator.deallocate_frame(pte_frame);
                    }
                }
                va += 4096;
            }
        }
        // Drop all VMA objects (releases AnonObject caches and their frames).
        self.vmas = crate::mem::vmatree::VmaTree::new();
        self.vm_pages = 0;
        self.rss_pages = 0;

        // Free the now-empty L1/L2/L3 page-table frames in the user half.
        // SAFETY: all leaf PTEs were removed above; the PML4 itself stays.
        unsafe {
            paging::free_user_page_tables(pml4);
        }

        // Reset brk/mmap to the constructor defaults so the new process
        // image starts with a clean virtual-address layout.
        let mmap_base = VirtAddr::new(0x0000_0000_4000_0000);
        self.mmap_base = mmap_base;
        self.brk_start = mmap_base;
        self.brk_cur = mmap_base;
        self.brk_max = VirtAddr::new(mmap_base.as_u64() - DEFAULT_BRK_GUARD);
    }

    /// Set the heap base to `image_end` (the page-aligned address one byte
    /// past the last `PT_LOAD` segment). Called after `load_user_elf_with_vmas`
    /// so that `sys_brk` starts the heap immediately after the ELF image
    /// rather than at the arbitrary `mmap_base` placeholder.
    ///
    /// If `image_end > brk_max` (e.g. an extremely large ELF), the heap window
    /// would be zero-sized or inverted, so the call is a no-op — callers should
    /// handle this by falling back to the existing brk_start.
    pub fn set_brk_start(&mut self, image_end: VirtAddr) {
        if image_end > self.brk_max {
            // Heap window would be empty; leave the existing placeholder.
            return;
        }
        self.brk_start = image_end;
        self.brk_cur = image_end;
        // brk_max stays at mmap_base − DEFAULT_BRK_GUARD.
    }

    /// Implement the `brk(2)` contract (Linux-compatible):
    ///
    /// - `addr == 0`: return the current break without moving it.
    /// - `addr > brk_max`: heap limit exceeded — return current break unchanged.
    /// - `addr < brk_start`: cannot shrink below heap base — return unchanged.
    /// - Otherwise: grow or shrink the heap and return the new break.
    ///
    /// The heap is maintained as a **single** anonymous-private VMA
    /// `[brk_start, brk_cur)` with an unbounded `AnonObject` backing.
    /// On grow the existing VMA is replaced with a larger one (same
    /// `AnonObject` Arc so already-faulted frames are preserved). On shrink,
    /// the old PTEs in the freed range are unmapped and the VMA is replaced
    /// with a smaller one.
    ///
    /// Returns the new (or unchanged) break address. No errno is set on
    /// failure — returning the old break is the POSIX failure signal.
    #[cfg(target_os = "none")]
    pub fn sys_brk(&mut self, addr: u64) -> u64 {
        use crate::mem::vmatree::{Share, Vma};
        use crate::mem::vmobject::{AnonObject, VmObject};
        use alloc::sync::Arc;
        use x86_64::structures::paging::{PageTableFlags, Size4KiB};
        use x86_64::VirtAddr;

        if addr == 0 {
            return self.brk_cur.as_u64();
        }

        // Reject non-canonical addresses and overflow before constructing
        // VirtAddr — VirtAddr::new panics on non-canonical values.
        // USER_VA_END is the first non-canonical lower-half address.
        if addr >= USER_VA_END {
            return self.brk_cur.as_u64();
        }
        // Overflow-safe page-align upward.
        let new_brk_raw = match addr.checked_add(4095) {
            Some(v) => v & !4095,
            None => return self.brk_cur.as_u64(), // would overflow u64
        };
        if new_brk_raw >= USER_VA_END {
            return self.brk_cur.as_u64(); // rounded up into non-canonical range
        }
        // Linux stores the EXACT requested address in mm->brk (not the
        // page-aligned value), so glibc/musl sbrk tracking is correct.
        let exact_brk = VirtAddr::new(addr);

        // Validate exact address against brk_start BEFORE page-rounding.
        // A value in (brk_start - PAGE, brk_start) rounds UP to brk_start and
        // would otherwise pass the page-aligned lower-bound check, then write
        // an exact brk_cur below the heap base.
        if exact_brk < self.brk_start {
            return self.brk_cur.as_u64();
        }

        // Construct the page-aligned address used for VMA extent decisions.
        let new_brk = VirtAddr::new(new_brk_raw);

        if new_brk > self.brk_max {
            return self.brk_cur.as_u64();
        }
        // No page-mapping change needed if we stay inside the same page.
        let old_brk_page = VirtAddr::new((self.brk_cur.as_u64() + 4095) & !4095);
        if new_brk == old_brk_page {
            self.brk_cur = exact_brk;
            return exact_brk.as_u64();
        }

        // Use page-aligned values for VMA extent decisions; store the exact
        // requested address in brk_cur (Linux semantics: mm->brk is exact).
        let old_brk = old_brk_page; // page-aligned old break
        let brk_start = self.brk_start;
        let brk_start_usize = brk_start.as_u64() as usize;

        let heap_flags = PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE;

        if new_brk > old_brk {
            // Grow: remove existing heap VMA (if any), keep its AnonObject,
            // then reinsert with a larger end. New pages are demand-faulted.
            let obj: Arc<dyn VmObject> = if old_brk > brk_start {
                // There is already a heap VMA — clone its AnonObject so the
                // already-faulted frames are not freed when we remove the VMA.
                let old = self
                    .vmas
                    .remove_exact(brk_start_usize)
                    .expect("heap VMA missing despite brk_cur > brk_start");
                self.vm_pages -= (old_brk - brk_start) as usize / 4096;
                let arc = Arc::clone(&old.object);
                drop(old);
                arc
            } else {
                // First brk call — create a fresh unbounded AnonObject.
                AnonObject::new(None)
            };

            let vma = Vma::new(
                brk_start_usize,
                new_brk.as_u64() as usize,
                0x3, // PROT_READ|WRITE
                heap_flags.bits(),
                Share::Private,
                obj,
                0,
            );
            self.vmas.insert(vma);
            self.vm_pages += (new_brk - brk_start) as usize / 4096;
        } else {
            // Shrink: free PTEs for [new_brk, old_brk), then reinsert a
            // smaller VMA with the same AnonObject so its Drop path can
            // release the cache frames when the process exits.
            let pml4 = self.page_table;
            let mut va = new_brk.as_u64() as usize;
            while va < old_brk.as_u64() as usize {
                use x86_64::structures::paging::{FrameDeallocator, Page};
                let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64))
                    .expect("page aligned");
                if let Ok(frame) = crate::mem::paging::unmap_in_pml4(pml4, page) {
                    // Release the PTE's reference. AnonObject still holds
                    // the cache reference so the frame's refcount drops to
                    // 1, not 0 — it will be freed by AnonObject::drop.
                    unsafe {
                        crate::mem::paging::KernelFrameAllocator.deallocate_frame(frame);
                    }
                    self.rss_pages = self.rss_pages.saturating_sub(1);
                }
                va += 4096;
            }

            if old_brk > brk_start {
                let old = self
                    .vmas
                    .remove_exact(brk_start_usize)
                    .expect("heap VMA missing despite brk_cur > brk_start");
                self.vm_pages -= (old_brk - brk_start) as usize / 4096;
                if new_brk > brk_start {
                    let obj = Arc::clone(&old.object);
                    // Trim the VmObject's frame cache for the freed range so
                    // cached frames are released now rather than at exit.
                    let from_page = (new_brk - brk_start) as usize / 4096;
                    obj.truncate_from_page(from_page);
                    drop(old);
                    let vma = Vma::new(
                        brk_start_usize,
                        new_brk.as_u64() as usize,
                        0x3,
                        heap_flags.bits(),
                        Share::Private,
                        obj,
                        0,
                    );
                    self.vmas.insert(vma);
                    self.vm_pages += (new_brk - brk_start) as usize / 4096;
                }
            }
        }

        // Store the exact requested address per Linux mm->brk semantics;
        // page-aligned values were used only to decide VMA extent changes.
        self.brk_cur = exact_brk;
        exact_brk.as_u64()
    }

    /// Handle a growsdown stack fault at `cr2`. If the address is within
    /// the growsdown gap of a `VMA_GROWSDOWN` VMA, inserts a **new
    /// single-page VMA** for the faulting page so its AnonObject cache
    /// index is always 0 — this avoids object-offset aliasing with
    /// previously faulted pages in the existing stack VMA. Returns the
    /// new page's object/offset/prot so the caller can install the PTE.
    ///
    /// Returns `None` (SIGSEGV path) if validation fails.
    pub fn grow_stack(
        &mut self,
        cr2: usize,
    ) -> Option<(
        alloc::sync::Arc<dyn crate::mem::vmobject::VmObject>,
        usize,
        crate::mem::vmatree::ProtPte,
        usize, // new_vma_start: the page the new VMA was installed at
    )> {
        use crate::mem::pf::{check_growsdown, GrowResult, STACK_GUARD_GAP_PAGES};
        use crate::mem::vmatree::{Share, Vma, VMA_GROWSDOWN, VMA_STACK_GUARD};
        use crate::mem::vmobject::AnonObject;

        // Find the growsdown VMA whose start is just above cr2.
        let above = self.vmas.find_above(cr2)?;
        if above.vma_flags & VMA_GROWSDOWN == 0 {
            return None;
        }
        let vma_start = above.start;
        let prot_pte = above.prot_pte;
        let prot_user = above.prot_user;

        // Walk upward through contiguous VMA_GROWSDOWN fragments to find the
        // true (fixed) stack top. After multiple growths, `find_above` returns
        // the lowest single-page fragment whose `.end` is only one page above
        // its own start — not USER_STACK_TOP. The original stack VMA (or the
        // highest fragment) holds the real ceiling.
        let stack_top = self.vmas.growsdown_stack_top(vma_start) as u64;

        let result = check_growsdown(
            cr2 as u64,
            vma_start as u64,
            stack_top,
            self.stack_rlimit,
            STACK_GUARD_GAP_PAGES,
        );

        let new_start = match result {
            GrowResult::Grow { new_start } => new_start as usize,
            GrowResult::Segv => return None,
        };
        let new_end = new_start + 4096; // exactly one new page

        // Collision: reject if any VMA already occupies the new page.
        if self.vmas.find(new_start).is_some() {
            return None;
        }
        // Guard VMA collision: reject if a guard VMA would cover new_start.
        if let Some(below) = self.vmas.last_below(vma_start) {
            if below.vma_flags & VMA_STACK_GUARD != 0 && below.end > new_start {
                return None;
            }
        }

        // Insert a fresh single-page VMA for the new stack page.
        // Using an independent AnonObject per page ensures object_offset=0
        // always maps to this specific page — no aliasing with cached frames
        // in the parent stack VMA.
        let new_obj: alloc::sync::Arc<dyn crate::mem::vmobject::VmObject> =
            AnonObject::new(Some(1));
        let mut new_vma = Vma::new(
            new_start,
            new_end,
            prot_user,
            prot_pte,
            Share::Private,
            alloc::sync::Arc::clone(&new_obj),
            0,
        );
        new_vma.vma_flags = VMA_GROWSDOWN;
        self.vmas.insert(new_vma);
        self.vm_pages += 1;

        Some((new_obj, 0, prot_pte, new_start))
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
    #[allow(dead_code)] // kept for future mmap(MAP_FIXED) bounds check
    pub(crate) fn vma_in_user_range(vma: &Vma) -> bool {
        (vma.end as u64) <= USER_VA_END
    }

    /// Find a free VA window of size `len` bytes for a fresh anonymous
    /// `mmap`. Scans upwards from `mmap_base`, skipping any existing
    /// VMAs. Returns the chosen start address, or `None` when no window
    /// of that size fits below [`USER_VA_END`].
    ///
    /// `len` must be a non-zero multiple of the 4 KiB page size;
    /// callers round up before calling.
    pub fn find_unmapped_region(&self, len: usize) -> Option<usize> {
        debug_assert!(len > 0 && len % 4096 == 0, "find_unmapped_region: bad len");

        let mut cursor = self.mmap_base.as_u64() as usize;
        for vma in self.vmas.iter() {
            if vma.end <= cursor {
                continue;
            }
            if vma.start >= cursor && vma.start - cursor >= len {
                return Some(cursor);
            }
            if vma.end > cursor {
                cursor = vma.end;
            }
        }
        if (USER_VA_END as usize).checked_sub(cursor)? >= len {
            Some(cursor)
        } else {
            None
        }
    }
}

/// Error returned by [`AddressSpace::fork_address_space`].
#[derive(Debug)]
pub enum ForkError {
    /// The frame allocator could not satisfy an intermediate page-table
    /// allocation needed to build the child's PML4. The child is rolled
    /// back automatically before this error is returned.
    OutOfMemory,
}

/// Clone the address space for a child task (fork CoW).
///
/// For each `Share::Private` VMA: walk present PTEs, increment the
/// frame's refcount, strip `WRITABLE` from both parent and child
/// PTEs (CoW — the `#PF` handler resolves write faults by copying the
/// frame), and queue a TLB invalidation for the parent VA. For
/// `Share::Shared` VMAs: increment refcount and copy PTE verbatim
/// to the child.
///
/// The child inherits the parent's `brk`/`mmap` layout. The caller is
/// responsible for calling `flusher.finish()` after this returns to
/// flush stale parent TLB entries.
///
/// On `Err(ForkError::OutOfMemory)` the child is dropped cleanly
/// (its partially-built PTEs are unmapped and frame refcounts are
/// decremented by `Drop for AddressSpace`) before the error is returned.
#[cfg(target_os = "none")]
impl AddressSpace {
    pub fn fork_address_space(
        &mut self,
        flusher: &mut crate::mem::tlb::Flusher,
    ) -> Result<AddressSpace, ForkError> {
        use crate::mem::vmatree::{Share, Vma as VmaEntry};
        use crate::mem::{paging, refcount};
        use alloc::sync::Arc;
        use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};

        // Allocate child PML4 + copy kernel upper half.
        let mut child = AddressSpace::try_new_empty()?;
        // Inherit brk/mmap layout from parent.
        child.mmap_base = self.mmap_base;
        child.brk_start = self.brk_start;
        child.brk_cur = self.brk_cur;
        child.brk_max = self.brk_max;
        child.stack_rlimit = self.stack_rlimit;

        // Collect VMAs first (avoids borrow conflict when we later
        // mutate the child and call paging helpers on self.page_table).
        // vma_flags is included so growsdown/guard behaviour carries over.
        type VmaSnap = (
            usize,
            usize,
            u32,
            u64,
            Share,
            Arc<dyn crate::mem::vmobject::VmObject>,
            usize,
            crate::mem::vmatree::VmaFlags,
        );
        let vma_snapshot: alloc::vec::Vec<VmaSnap> = self
            .vmas
            .iter()
            .map(|v| {
                (
                    v.start,
                    v.end,
                    v.prot_user,
                    v.prot_pte,
                    v.share,
                    Arc::clone(&v.object),
                    v.object_offset,
                    v.vma_flags,
                )
            })
            .collect();

        for (start, end, prot_user, prot_pte, share, object, object_offset, vma_flags) in
            &vma_snapshot
        {
            let prot_user = *prot_user;
            let prot_pte = *prot_pte;
            let share = *share;
            let start = *start;
            let end = *end;
            let object_offset = *object_offset;
            let vma_flags = *vma_flags;

            // Private VMAs get an independent empty cache; Shared VMAs alias the same frames.
            let child_object = match share {
                Share::Private => object.clone_private(),
                Share::Shared => Arc::clone(object),
            };
            let mut child_vma = VmaEntry::new(
                start,
                end,
                prot_user,
                prot_pte,
                share,
                child_object,
                object_offset,
            );
            child_vma.vma_flags = vma_flags; // preserve growsdown/guard flags
            child.vmas.insert(child_vma);
            child.vm_pages += (end - start) / 4096;

            let mut va = start;
            while va < end {
                let page = Page::<Size4KiB>::from_start_address(x86_64::VirtAddr::new(va as u64))
                    .expect("vma VA page-aligned");

                if let Some((pte_frame, pte_flags)) =
                    paging::translate_in_pml4(self.page_table, x86_64::VirtAddr::new(va as u64))
                {
                    let phys = pte_frame.start_address().as_u64();

                    match share {
                        Share::Private => {
                            let ro_flags = pte_flags & !PageTableFlags::WRITABLE;
                            // Acquire child PTE reference.
                            refcount::inc_refcount(phys);
                            if let Err(_) = paging::map_existing_in_pml4(
                                child.page_table,
                                page,
                                pte_frame,
                                ro_flags,
                            ) {
                                // Roll back the child PTE increment.
                                refcount::dec_refcount(phys);
                                return Err(ForkError::OutOfMemory);
                            }
                            // W-strip parent PTE: unmap (old PTE reference now
                            // floating), release the old reference, then acquire
                            // a fresh reference for the new read-only parent PTE.
                            let _ = paging::unmap_in_pml4(self.page_table, page);
                            // Release the old parent PTE's reference that was
                            // acquired by AnonObject::fault when the page was
                            // first demand-faulted.
                            crate::mem::frame::put(phys);
                            // Acquire reference for the new parent PTE.
                            refcount::inc_refcount(phys);
                            if let Err(_) = paging::map_existing_in_pml4(
                                self.page_table,
                                page,
                                pte_frame,
                                ro_flags,
                            ) {
                                // Roll back the new parent PTE increment.
                                refcount::dec_refcount(phys);
                                return Err(ForkError::OutOfMemory);
                            }
                            flusher.invalidate(x86_64::VirtAddr::new(va as u64));
                        }
                        Share::Shared => {
                            // Shared mapping: child gets same frame + flags.
                            refcount::inc_refcount(phys);
                            if let Err(_) = paging::map_existing_in_pml4(
                                child.page_table,
                                page,
                                pte_frame,
                                pte_flags,
                            ) {
                                refcount::dec_refcount(phys);
                                return Err(ForkError::OutOfMemory);
                            }
                        }
                    }
                }
                // Pages not yet faulted in have no PTE; child will demand-fault
                // them independently.

                va += 4096;
            }
        }

        Ok(child)
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
                if let Ok(pte_frame) = paging::unmap_in_pml4(pml4, page) {
                    // Release this PTE's reference to the frame. Every
                    // mapped PTE holds one reference (acquired via
                    // `AnonObject::fault`'s `inc_refcount` or
                    // `fork_address_space`'s `inc_refcount`); private CoW
                    // copies have refcount=1 (from `alloc_zeroed_page`) and
                    // are freed here. Cached frames have their remaining
                    // cache-reference released by `AnonObject::drop` when
                    // `self.vmas` drops after this function returns.
                    // SAFETY: frame was mapped into this PML4 and is now
                    // exclusively reachable via this drop path.
                    unsafe {
                        paging::KernelFrameAllocator.deallocate_frame(pte_frame);
                    }
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

    #[test]
    fn brk_constructor_sets_start_eq_cur() {
        // new_for_test initialises brk_start == brk_cur == mmap_base.
        // sys_brk(0) behaviour is only testable in QEMU (cfg=none); this
        // test just verifies the constructor invariant.
        let aspace = AddressSpace::new_for_test(0x4000_0000);
        assert_eq!(aspace.brk_start, aspace.brk_cur);
    }

    #[test]
    fn set_brk_start_advances_heap_base() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        let img_end = x86_64::VirtAddr::new(0x0060_0000);
        aspace.set_brk_start(img_end);
        assert_eq!(aspace.brk_start, img_end);
        assert_eq!(aspace.brk_cur, img_end);
        // brk_max unchanged
        assert!(aspace.brk_max.as_u64() < aspace.mmap_base.as_u64());
    }

    #[test]
    fn find_unmapped_region_empty_returns_mmap_base() {
        let aspace = AddressSpace::new_for_test(0x4000_0000);
        assert_eq!(aspace.find_unmapped_region(4096), Some(0x4000_0000));
    }

    #[test]
    fn find_unmapped_region_skips_existing_vma() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        aspace.vmas.insert(anon(0x4000_0000, 0x4000_2000));
        assert_eq!(aspace.find_unmapped_region(4096), Some(0x4000_2000));
    }

    #[test]
    fn find_unmapped_region_uses_gap_between_vmas() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        // Two VMAs with a 2-page gap at [0x4000_2000, 0x4000_4000).
        aspace.vmas.insert(anon(0x4000_0000, 0x4000_2000));
        aspace.vmas.insert(anon(0x4000_4000, 0x4000_6000));
        // Request fits in the gap.
        assert_eq!(aspace.find_unmapped_region(4096), Some(0x4000_2000));
        assert_eq!(aspace.find_unmapped_region(2 * 4096), Some(0x4000_2000));
    }

    #[test]
    fn find_unmapped_region_skips_too_small_gap() {
        let mut aspace = AddressSpace::new_for_test(0x4000_0000);
        aspace.vmas.insert(anon(0x4000_0000, 0x4000_2000));
        aspace.vmas.insert(anon(0x4000_3000, 0x4000_5000));
        // Single-page gap at 0x4000_2000 too small for 2 pages — jump
        // past the second VMA.
        assert_eq!(aspace.find_unmapped_region(2 * 4096), Some(0x4000_5000));
    }

    #[test]
    fn find_unmapped_region_respects_user_va_end() {
        // Place mmap_base so there is less than a page left below
        // USER_VA_END — any request should fail.
        let near_top = USER_VA_END as usize - 2 * 4096;
        let mut aspace = AddressSpace::new_for_test(near_top as u64);
        aspace.vmas.insert(anon(near_top, near_top + 4096));
        // Only one page free between [near_top+4096, USER_VA_END); a
        // two-page request must return None.
        assert_eq!(aspace.find_unmapped_region(2 * 4096), None);
        assert_eq!(aspace.find_unmapped_region(4096), Some(near_top + 4096));
    }
}
