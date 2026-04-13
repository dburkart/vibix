//! TLB-invalidation batching.
//!
//! Every paging mutation (`map`, `unmap`, `map_range`, ...) takes a
//! `&mut Flusher`. Callers `invalidate(va)` on the Flusher once per
//! modified page, then `finish()` to apply the batch — per-page
//! `invlpg` under the inline cap, or a whole-TLB reload past it.
//!
//! Threading a Flusher through *now*, even as a single-CPU operation,
//! lets the RFC-0001 SMP-shootdown follow-up slot its IPI logic into
//! one location (`Flusher::finish`) instead of revisiting every call
//! site.
//!
//! **Invariant:** every `Flusher` must be consumed by [`finish`]. The
//! `Drop` impl panics otherwise — a Flusher dropped without `finish`
//! means a paging mutation went live without its TLB entry being
//! invalidated. Under `panic = "abort"` the drop-from-panic path is
//! moot; under unwind the double-panic aborts, which is what we want
//! for a kernel-correctness bug.
//!
//! [`finish`]: Flusher::finish

use x86_64::VirtAddr;

/// Queue depth before falling back to a whole-TLB reload. Sized to
/// cover the single largest batch the kernel currently produces
/// (heap grow: 16 pages) with headroom. Past the cap, per-page
/// `invlpg` loses to a single CR3 reload anyway.
pub const INLINE_CAP: usize = 32;

/// Batched TLB invalidation. See module docs.
pub struct Flusher {
    pages: [u64; INLINE_CAP],
    len: usize,
    overflow: bool,
    finished: bool,
}

impl Flusher {
    /// Flusher targeting the currently-active address space. `finish`
    /// invalidates on the CPU that calls it.
    pub const fn new_active() -> Self {
        Self {
            pages: [0; INLINE_CAP],
            len: 0,
            overflow: false,
            finished: false,
        }
    }

    /// Queue `va` for invalidation. Once the queue is full, subsequent
    /// calls latch the Flusher into overflow mode — `finish` will do a
    /// whole-TLB reload instead of per-page `invlpg`.
    pub fn invalidate(&mut self, va: VirtAddr) {
        if self.overflow {
            return;
        }
        if self.len == INLINE_CAP {
            self.overflow = true;
            return;
        }
        self.pages[self.len] = va.as_u64();
        self.len += 1;
    }

    /// Number of queued pages. Caps at [`INLINE_CAP`] once overflow
    /// latches — further `invalidate` calls don't increment it.
    pub fn queued(&self) -> usize {
        self.len
    }

    /// True once the queue overflowed past [`INLINE_CAP`].
    pub fn overflowed(&self) -> bool {
        self.overflow
    }

    /// Apply queued invalidations. Consumes `self`; the `Drop` guard
    /// trips if a caller forgets to call this.
    pub fn finish(mut self) {
        self.apply();
        self.finished = true;
    }

    fn apply(&mut self) {
        #[cfg(target_os = "none")]
        {
            if self.overflow {
                use x86_64::registers::control::Cr3;
                let (frame, flags) = Cr3::read();
                // SAFETY: reloading the active CR3 with the same
                // frame+flags is well-defined and flushes non-global
                // TLB entries — exactly what we want as the overflow
                // fallback.
                unsafe { Cr3::write(frame, flags) };
            } else {
                for i in 0..self.len {
                    x86_64::instructions::tlb::flush(VirtAddr::new(self.pages[i]));
                }
            }
        }
    }
}

impl Drop for Flusher {
    fn drop(&mut self) {
        assert!(
            self.finished,
            "Flusher dropped without finish(): {} queued, overflow={}",
            self.len, self.overflow,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_finish_is_fine() {
        Flusher::new_active().finish();
    }

    #[test]
    fn invalidate_accumulates() {
        let mut f = Flusher::new_active();
        f.invalidate(VirtAddr::new(0x1000));
        f.invalidate(VirtAddr::new(0x2000));
        assert_eq!(f.queued(), 2);
        assert!(!f.overflowed());
        f.finish();
    }

    #[test]
    fn overflow_latches_past_cap() {
        let mut f = Flusher::new_active();
        for i in 0..INLINE_CAP as u64 {
            f.invalidate(VirtAddr::new(0x1000 + i * 0x1000));
        }
        assert!(!f.overflowed());
        f.invalidate(VirtAddr::new(0xdead_0000));
        assert!(f.overflowed());
        // Further invalidations are silent no-ops once latched.
        f.invalidate(VirtAddr::new(0xbeef_0000));
        assert!(f.overflowed());
        f.finish();
    }

    #[test]
    #[should_panic(expected = "Flusher dropped without finish()")]
    fn drop_without_finish_panics() {
        let _f = Flusher::new_active();
    }
}
