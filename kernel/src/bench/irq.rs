//! PIT IRQ entry→exit latency.
//!
//! `timer_interrupt` records its entry TSC before doing any work and
//! its exit TSC just before returning. The delta is written into a
//! lock-free ring; the bench task drains the ring after enough
//! samples have accumulated.
//!
//! Writes happen from interrupt context, so the producer side
//! **must** be lock-free and allocation-free. A fixed array plus a
//! wrapping `AtomicUsize` index satisfies both.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::{rdtsc_end, rdtsc_start, Stats};

/// Ring capacity. Sized so collect(500) samples fit without
/// overwrite at PIT 100 Hz for ~5 s.
const RING_LEN: usize = 1024;

/// Samples are stored as `u64` cycle deltas. Zero means "not yet
/// written"; this is safe because a real IRQ handler round-trip is
/// strictly positive.
static SAMPLES: [AtomicU64; RING_LEN] = {
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; RING_LEN]
};

/// Monotonically-incrementing write index. `fetch_add % RING_LEN` is
/// the slot each write claims.
static WRITE_IDX: AtomicUsize = AtomicUsize::new(0);

/// Per-CPU-ish scratchpad for the entry timestamp. With the scheduler
/// still single-CPU this is literally "the last entry timestamp";
/// once SMP lands the ISR will need one slot per LAPIC id, but
/// that's #30's problem.
static LAST_ENTRY: AtomicU64 = AtomicU64::new(0);

/// Called at the top of `timer_interrupt`. Records the entry TSC so
/// `record_exit` can compute the delta.
#[inline(always)]
pub fn record_entry() {
    LAST_ENTRY.store(rdtsc_start(), Ordering::Relaxed);
}

/// Called just before the ISR returns. Pushes `now - LAST_ENTRY`
/// into the ring.
#[inline(always)]
pub fn record_exit() {
    let t0 = LAST_ENTRY.load(Ordering::Relaxed);
    if t0 == 0 {
        return;
    }
    let t1 = rdtsc_end();
    let delta = t1.wrapping_sub(t0);
    let idx = WRITE_IDX.fetch_add(1, Ordering::Relaxed) % RING_LEN;
    SAMPLES[idx].store(delta, Ordering::Relaxed);
}

/// Block the calling task long enough to observe `expected` IRQ
/// round-trips, then reduce the collected samples to [`Stats`].
///
/// `expected` is capped at `RING_LEN - 1` so we never wait for more
/// samples than the ring can hold without overwrite.
pub fn collect(expected: u32) -> Stats {
    let expected = (expected as usize).min(RING_LEN - 1);
    let start = WRITE_IDX.load(Ordering::Relaxed);

    // Wait until the write index has advanced by `expected`. Each
    // PIT tick (100 Hz) bumps it by one.
    loop {
        let written = WRITE_IDX.load(Ordering::Relaxed).saturating_sub(start);
        if written >= expected {
            break;
        }
        x86_64::instructions::hlt();
    }

    // Snapshot the most recent `expected` samples. `WRITE_IDX` may
    // advance while we're reading; that's fine — the ring is stable
    // under single-CPU semantics because the ISR can't preempt our
    // read atomically between slots.
    let end = WRITE_IDX.load(Ordering::Relaxed);
    let taken = (end - start).min(expected);
    let mut out = alloc::vec::Vec::with_capacity(taken);
    for i in 0..taken {
        let idx = (start + i) % RING_LEN;
        let v = SAMPLES[idx].load(Ordering::Relaxed);
        if v != 0 {
            out.push(v);
        }
    }
    Stats::from_samples(&mut out)
}
