//! Virtual memory areas: per-task descriptors for regions that are
//! resolved lazily by the `#PF` handler instead of eagerly mapped at
//! spawn time.
//!
//! Two kinds today:
//! - [`VmaKind::AnonZero`] — anonymous, zero-filled on first touch.
//!   Each page is backed by a freshly-allocated frame zeroed via the
//!   HHDM before it is mapped.
//! - [`VmaKind::Cow`] — copy-on-write over a shared source frame. A
//!   read fault maps the source read-only; a subsequent write fault
//!   allocates a private frame, copies the source into it, and remaps
//!   the page writable. The source frame is never freed by the CoW
//!   resolver — other PML4s (post-`clone_for_fork`) may still alias it.

use alloc::vec::Vec;
use x86_64::structures::paging::{PageTableFlags, PhysFrame, Size4KiB};

/// Kind of backing a VMA describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmaKind {
    /// Anonymous, zero-filled on first touch.
    AnonZero,
    /// Copy-on-write over `frame`. Reads map `frame` read-only; writes
    /// trigger a private copy.
    Cow { frame: PhysFrame<Size4KiB> },
}

/// A half-open `[start, end)` VA range with a backing kind and the
/// flags the `#PF` resolver should apply when it installs a page.
///
/// `start` and `end` are byte addresses and must be 4 KiB-aligned; the
/// constructor enforces that.
#[derive(Clone, Copy, Debug)]
pub struct Vma {
    pub start: usize,
    pub end: usize,
    pub kind: VmaKind,
    pub flags: PageTableFlags,
}

impl Vma {
    pub fn new(start: usize, end: usize, kind: VmaKind, flags: PageTableFlags) -> Self {
        assert!(start % 4096 == 0, "vma start must be page aligned");
        assert!(end % 4096 == 0, "vma end must be page aligned");
        assert!(start < end, "vma range must be non-empty");
        Self {
            start,
            end,
            kind,
            flags,
        }
    }

    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.start && addr < self.end
    }
}

/// Per-task list of VMAs. Small and linear — we expect a handful of
/// regions per task, not thousands. Lookup is O(n).
#[derive(Default)]
pub struct VmaList {
    entries: Vec<Vma>,
}

impl VmaList {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Insert `vma` if it doesn't overlap anything already present.
    /// Panics on overlap — overlapping VMAs are a programmer error,
    /// not a runtime condition to recover from.
    pub fn insert(&mut self, vma: Vma) {
        for existing in &self.entries {
            let overlap = vma.start < existing.end && existing.start < vma.end;
            assert!(!overlap, "VMA overlaps existing range");
        }
        self.entries.push(vma);
    }

    /// Find the VMA containing `addr`, if any.
    pub fn find(&self, addr: usize) -> Option<Vma> {
        self.entries.iter().copied().find(|v| v.contains(addr))
    }

    /// Remove the VMA whose `start` matches exactly and return it.
    /// Keyed on `start` (not an arbitrary inclusion address) so
    /// `munmap`-style callers must name the region they installed —
    /// partial-range unmap is out of scope here.
    pub fn remove(&mut self, start: usize) -> Option<Vma> {
        let idx = self.entries.iter().position(|v| v.start == start)?;
        Some(self.entries.swap_remove(idx))
    }

    /// Iterate all entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &Vma> {
        self.entries.iter()
    }

    /// Duplicate this list for a child address space. Metadata is
    /// cloned verbatim — including any `Cow { frame }` kinds, which
    /// means the child shares the source frames with the parent until
    /// a write fault in either address space diverges them.
    ///
    /// Callers that fork mapped `AnonZero` pages should convert them
    /// to `Cow` *before* calling this — `AnonZero` carries no frame,
    /// so copying it verbatim leaves the child with no visibility into
    /// whatever frames the parent's page-table already backs the
    /// region with.
    pub fn clone_for_fork(&self) -> VmaList {
        VmaList {
            entries: self.entries.clone(),
        }
    }
}
