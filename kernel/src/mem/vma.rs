//! Virtual memory areas: per-task descriptors for regions that are
//! resolved lazily by the `#PF` handler instead of eagerly mapped at
//! spawn time.
//!
//! Today the only supported kind is [`VmaKind::AnonZero`] — anonymous
//! zero-filled memory. A task installs a VMA via
//! [`crate::task::install_vma_on_current`]; the first access to a page
//! inside the range takes a `#PF` that the handler satisfies by
//! allocating a zeroed frame and mapping it with the VMA's flags.
//!
//! This is the minimal groundwork for #51 — fork-time copy-on-write
//! lives behind a richer VMA kind that isn't here yet.

use alloc::vec::Vec;
use x86_64::structures::paging::PageTableFlags;

/// Kind of backing a VMA describes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VmaKind {
    /// Anonymous, zero-filled on first touch. Each page is backed by a
    /// freshly-allocated frame zeroed via the HHDM before it is mapped.
    AnonZero,
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
}
