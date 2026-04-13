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
