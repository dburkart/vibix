//! Cold-mmap fault-latency host benchmark for the vibix page cache
//! (RFC 0007 §Testing strategy).
//!
//! ## What this measures
//!
//! The cold path of a file-backed mmap fault, modelled host-side:
//!
//! 1. The faulting task calls `PageCache::install_or_get(pgoff, ...)`.
//!    On a cold inode the page is not yet indexed, so the caller wins
//!    the install race and is handed a freshly allocated stub with
//!    `PG_LOCKED` set and `PG_UPTODATE` clear.
//! 2. The caller invokes `AddressSpaceOps::readpage(pgoff, &mut buf)`
//!    to fill the page. The default readahead is `0` pages on cold
//!    inode (RFC 0007 §Read-ahead heuristic — 0 on cold, ramps with
//!    sequential streak; an early draft mistakenly defaulted to 8 and
//!    would have regressed execve latency).
//! 3. The caller publishes `PG_UPTODATE` and clears `PG_LOCKED` with
//!    the documented Release ordering, waking any losers parked on
//!    the page's wait queue.
//!
//! ## Why this is a faithful model, not a wrapper
//!
//! The kernel `mem::page_cache` module is `#[cfg(any(target_os =
//! "none", test))]`, so it is not reachable from a stock host build.
//! Rather than add a host gate to the kernel surface (the issue
//! explicitly forbids modifying the kernel page-cache types), this
//! crate mirrors the data structures and the install-race protocol
//! one-for-one:
//!
//! - `CachePage` carries the same `PG_LOCKED` / `PG_UPTODATE` /
//!   `PG_DIRTY` / `PG_IN_FLIGHT` / `PG_WRITEBACK` state bits and the
//!   same Acquire/Release publish discipline as
//!   `kernel/src/mem/page_cache.rs`.
//! - `PageCache::install_or_get` uses the same `BTreeMap` index and
//!   the same winner/loser split (`InstallOutcome::InstalledNew` vs
//!   `AlreadyPresent`).
//! - `AddressSpaceOps::readpage` matches the trait signature drafted
//!   in RFC 0007 §`AddressSpaceOps`. The stub impl simulates a
//!   deterministic per-page filler cost so the resulting numbers are
//!   reproducible run-to-run.
//!
//! When #737 lands the real `AddressSpaceOps` and #738 stabilises
//! `FileObject`, this crate can switch to consuming the real kernel
//! types without changing the shape of the measurement.
//!
//! ## Determinism
//!
//! The benchmark is deterministic by construction:
//!
//! - Page contents are produced by a tiny xorshift PRNG seeded from
//!   `pgoff`; no syscalls, no clock-driven randomness.
//! - The simulated readpage cost is a fixed-iteration `black_box`
//!   spin loop (`SIM_READPAGE_SPINS`), not a `sleep`. This holds the
//!   *work* per page constant; the wall-clock measurement is what
//!   varies with the host.
//! - The bench runs `WARMUP_PAGES` warm-up pages before
//!   `BENCH_PAGES` measured pages so cache effects on the host
//!   `BTreeMap` and allocator are out of the first-fault number.
//! - Per-page timings are sorted to compute p50/p90/p99 — order is
//!   total within the run.
//!
//! The reported baseline is the *shape* (relative quantiles, total
//! pages/sec) plus an absolute median; the absolute value will drift
//! across hosts but the relative shape catches algorithmic
//! regressions.

use std::cell::UnsafeCell;
use std::collections::BTreeMap;
use std::hint::black_box;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;

// --- State bits (mirror RFC 0007 / kernel/src/mem/page_cache.rs) ---------

const PG_UPTODATE: u8 = 1 << 0;
#[allow(dead_code)]
const PG_DIRTY: u8 = 1 << 1;
#[allow(dead_code)]
const PG_IN_FLIGHT: u8 = 1 << 2;
#[allow(dead_code)]
const PG_WRITEBACK: u8 = 1 << 3;
const PG_LOCKED: u8 = 1 << 4;

// --- CachePage -----------------------------------------------------------

/// Host model of `kernel::mem::page_cache::CachePage`.
///
/// The 64-byte alignment is preserved so the host bench measures the
/// same allocation footprint per page as the kernel does, and so a
/// future SMP-aware regression test can be layered on without
/// re-shaping the entry.
#[repr(align(64))]
struct CachePage {
    /// Synthetic physical-frame stand-in. The bench never derefs
    /// this; it exists so the bench-side stub looks shape-identical
    /// to the kernel-side stub.
    #[allow(dead_code)]
    phys: u64,
    pgoff: u64,
    state: AtomicU8,
    /// Page contents — 4 KiB, just like the real cache page.
    /// `Box`ed so each page allocation is independent on the host
    /// allocator (matches the per-frame allocation cost in the
    /// kernel).
    ///
    /// Wrapped in `UnsafeCell` because the filler-success protocol
    /// (RFC 0007 §State-bit ordering) relies on the per-page
    /// `PG_LOCKED` bit — not Rust's borrow checker — to serialise
    /// writes during the fill. While `PG_LOCKED` is set, only the
    /// install-winner has logical access to the bytes; once
    /// `publish_uptodate_and_unlock` releases the bit, any observer
    /// that sees the unlock with `Acquire` ordering may read the
    /// bytes (read-only). This matches the kernel layout, where the
    /// page is mapped through an HHDM window without any compiler
    /// borrow-tracking either.
    ///
    /// `Sync` is unsafely asserted on `CachePage` below; the bench
    /// is single-threaded so this is conservative for the
    /// measurement, and it documents the same discipline the kernel
    /// pays.
    data: Box<UnsafeCell<[u8; 4096]>>,
}

// SAFETY: `data` is logically owned by whichever task holds the
// page's `PG_LOCKED` bit (filler) or has observed `PG_LOCKED` clear
// with `Acquire` (read-only observer). The bench is single-threaded,
// so the `Sync` assertion is not load-bearing here, but it documents
// the same lock-vs-borrow-checker tradeoff the kernel makes.
unsafe impl Sync for CachePage {}
unsafe impl Send for CachePage {}

impl CachePage {
    fn new_locked(phys: u64, pgoff: u64) -> Arc<Self> {
        Arc::new(Self {
            phys,
            pgoff,
            state: AtomicU8::new(PG_LOCKED),
            data: Box::new(UnsafeCell::new([0u8; 4096])),
        })
    }

    #[inline]
    fn is_locked(&self) -> bool {
        self.state.load(Ordering::Acquire) & PG_LOCKED != 0
    }

    #[inline]
    fn is_uptodate(&self) -> bool {
        self.state.load(Ordering::Acquire) & PG_UPTODATE != 0
    }

    /// Filler-success publish — same Release/Release pattern as the
    /// kernel's `publish_uptodate_and_unlock`.
    fn publish_uptodate_and_unlock(&self) {
        self.state.fetch_or(PG_UPTODATE, Ordering::Release);
        self.state.fetch_and(!PG_LOCKED, Ordering::Release);
    }
}

// --- PageCache -----------------------------------------------------------

enum InstallOutcome {
    InstalledNew(Arc<CachePage>),
    #[allow(dead_code)]
    AlreadyPresent(Arc<CachePage>),
}

/// Host model of `kernel::mem::page_cache::PageCache`.
///
/// `std::sync::Mutex` stands in for the kernel's `BlockingMutex`.
/// The bench is single-threaded by construction (cold-fault
/// micro-benchmark; the install-race protocol is exercised from a
/// single faulter so the measurement reflects the no-contention
/// path), so `Mutex` is conservative and matches the "lock acquired
/// for index update" cost the kernel pays.
struct PageCache {
    inner: std::sync::Mutex<BTreeMap<u64, Arc<CachePage>>>,
}

impl PageCache {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(BTreeMap::new()),
        }
    }

    fn install_or_get<F>(&self, pgoff: u64, make_stub: F) -> InstallOutcome
    where
        F: FnOnce() -> Arc<CachePage>,
    {
        let mut inner = self.inner.lock().expect("page cache index poisoned");
        if let Some(existing) = inner.get(&pgoff) {
            return InstallOutcome::AlreadyPresent(existing.clone());
        }
        let stub = make_stub();
        debug_assert_eq!(stub.pgoff, pgoff);
        debug_assert!(stub.is_locked() && !stub.is_uptodate());
        inner.insert(pgoff, stub.clone());
        InstallOutcome::InstalledNew(stub)
    }
}

// --- AddressSpaceOps stub ------------------------------------------------

/// The trait shape mirrors the `AddressSpaceOps` draft in RFC 0007
/// §`AddressSpaceOps` so a future swap-in to the real trait is a
/// rename, not a refactor.
trait AddressSpaceOps {
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64>;
}

/// Deterministic stub that simulates a synchronous `readpage`.
///
/// Two knobs:
///
/// - `spin_iters` — fixed-count `black_box` busy-wait per page.
///   Models the per-page CPU cost the real `readpage` would pay
///   walking the buffer cache + memcpy. Constant per call so the
///   measurement is a faithful "all pages cost the same simulated
///   amount; the host overhead is what we're isolating".
/// - The page contents are produced by a tiny xorshift PRNG seeded
///   from `pgoff`. Same `pgoff` always produces the same bytes —
///   keeps the bench output deterministic across runs.
struct StubOps {
    spin_iters: u64,
}

impl AddressSpaceOps for StubOps {
    fn readpage(&self, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
        // Simulated filler cost. `black_box` defeats the optimiser so
        // the loop isn't elided and the cost stays roughly constant
        // per call.
        let mut x: u64 = pgoff.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0xDEAD_BEEF;
        for _ in 0..self.spin_iters {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            black_box(x);
        }

        // Produce deterministic page contents from `pgoff`. xorshift
        // is enough to keep the memcpy hot; this is *not* a CSPRNG.
        let mut s = pgoff.wrapping_add(1).wrapping_mul(0xDABA_5E13);
        for chunk in buf.chunks_mut(8) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let bytes = s.to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
                *dst = *src;
            }
        }
        Ok(4096)
    }
}

// --- Bench -------------------------------------------------------------

/// Number of warm-up pages faulted before the measurement window
/// opens. Pulls the host allocator and `BTreeMap` paths out of the
/// first measured sample.
const WARMUP_PAGES: u64 = 64;

/// Number of pages faulted inside the measurement window. Sized so
/// each baseline run takes O(10 ms) on a normal host — large enough
/// for the histogram quantiles to be stable, small enough not to
/// inflate CI wall-clock.
const BENCH_PAGES: u64 = 4096;

/// Spin-loop iteration count per simulated `readpage`. Calibrated so
/// the per-page time on a typical CI host lands in the low
/// microseconds — same order of magnitude as a real cold-page fault
/// would pay walking the buffer cache. The absolute number isn't
/// load-bearing; the *shape* of the histogram is.
const SIM_READPAGE_SPINS: u64 = 256;

/// Cold-fault one page: install_or_get → readpage → publish.
///
/// Inlined into the measurement loop on purpose so the call edge
/// itself is part of what we measure.
#[inline]
fn cold_fault_one(cache: &PageCache, ops: &dyn AddressSpaceOps, pgoff: u64) {
    match cache.install_or_get(pgoff, || {
        // Synthetic phys; the bench never reads it, but its shape
        // matches the kernel stub-allocation path.
        CachePage::new_locked(0x1_0000_0000 + pgoff * 4096, pgoff)
    }) {
        InstallOutcome::InstalledNew(stub) => {
            // Caller won the install race: drive the fill.
            //
            // The kernel uses an HHDM window onto `phys`; on the
            // host we go through the `UnsafeCell<[u8; 4096]>` in
            // `stub.data`. The `PG_LOCKED` bit (set on the stub
            // before insertion into the cache index) is what
            // serialises mutation against any observer — exactly
            // the discipline RFC 0007 §State-bit ordering
            // describes.
            //
            // SAFETY: the install-winner is the unique writer
            // while `PG_LOCKED` is set. No other reference to
            // `stub.data`'s contents is yielded by this code path
            // until `publish_uptodate_and_unlock` releases the
            // bit; the bench is single-threaded so there are no
            // concurrent observers either way. Going through
            // `UnsafeCell::get` (rather than a `&T → &mut T`
            // cast) is the well-defined way to acquire the
            // exclusive `&mut` here — the `&T → &mut T` form is
            // UB regardless of whether the reference is used
            // (rustc denies it under
            // `invalid_reference_casting`).
            let buf: &mut [u8; 4096] = unsafe { &mut *stub.data.get() };
            let _ = ops.readpage(pgoff, buf).expect("stub readpage never fails");
            stub.publish_uptodate_and_unlock();
            black_box(&stub);
        }
        InstallOutcome::AlreadyPresent(_) => {
            // Cold faulter on a fresh cache: never happens. If it
            // did, the bench would silently understate latency, so
            // panic loudly.
            panic!(
                "bench-page-cache: install_or_get returned AlreadyPresent on cold pgoff={}; \
                 bench harness is broken",
                pgoff,
            );
        }
    }
}

/// Fault `count` cold pages and return per-page latencies in
/// nanoseconds.
fn run_cold_fault(count: u64, spin_iters: u64) -> Vec<u64> {
    let cache = PageCache::new();
    let ops = StubOps { spin_iters };

    // Warm-up: populates the allocator's free lists and the BTreeMap
    // splay so the first measured sample isn't a one-off cold miss
    // on host infrastructure.
    for pgoff in 0..WARMUP_PAGES {
        cold_fault_one(&cache, &ops, pgoff);
    }

    let mut samples = Vec::with_capacity(count as usize);
    // Distinct pgoff range for the measurement window so every
    // sample is genuinely a cold install (no AlreadyPresent
    // shortcut).
    let base = WARMUP_PAGES;
    for i in 0..count {
        let pgoff = base + i;
        let t0 = Instant::now();
        cold_fault_one(&cache, &ops, pgoff);
        let dt = t0.elapsed();
        // Saturate at u64::MAX rather than panic if Instant::elapsed
        // ever returns something pathological; baselines are
        // shape-driven so a single saturated sample is preferable
        // to crashing the whole run.
        let ns = u64::try_from(dt.as_nanos()).unwrap_or(u64::MAX);
        samples.push(ns);
    }
    samples
}

#[derive(Debug)]
struct Stats {
    n: u64,
    total_ns: u64,
    min_ns: u64,
    p50_ns: u64,
    p90_ns: u64,
    p99_ns: u64,
    max_ns: u64,
    mean_ns: u64,
}

fn summarise(mut samples: Vec<u64>) -> Stats {
    assert!(!samples.is_empty(), "summarise: empty sample vec");
    samples.sort_unstable();
    let n = samples.len() as u64;
    let total_ns: u64 = samples.iter().sum();
    let mean_ns = total_ns / n;
    let pick = |q: f64| -> u64 {
        let idx = ((samples.len() as f64) * q) as usize;
        samples[idx.min(samples.len() - 1)]
    };
    Stats {
        n,
        total_ns,
        min_ns: samples[0],
        p50_ns: pick(0.50),
        p90_ns: pick(0.90),
        p99_ns: pick(0.99),
        max_ns: *samples.last().unwrap(),
        mean_ns,
    }
}

fn print_report(stats: &Stats) {
    // The output format is plain text on purpose. The PR body
    // captures the baseline numbers verbatim; future regression
    // detection can grep these lines.
    println!("=== bench-page-cache: cold-mmap fault latency ===");
    println!("RFC 0007 §Testing strategy — host-side baseline");
    println!("model: install_or_get -> readpage(stub) -> publish_uptodate");
    println!("readahead: 0 pages on cold inode (RFC 0007 default)");
    println!();
    println!("samples           : {}", stats.n);
    println!("warmup pages      : {}", WARMUP_PAGES);
    println!("sim_readpage_spins: {}", SIM_READPAGE_SPINS);
    println!();
    println!("min   : {:>8} ns", stats.min_ns);
    println!("p50   : {:>8} ns", stats.p50_ns);
    println!("p90   : {:>8} ns", stats.p90_ns);
    println!("p99   : {:>8} ns", stats.p99_ns);
    println!("max   : {:>8} ns", stats.max_ns);
    println!("mean  : {:>8} ns", stats.mean_ns);
    println!("total : {:>8} ns", stats.total_ns);
    println!(
        "rate  : {:>8.2} kpages/s",
        (stats.n as f64) * 1.0e6 / (stats.total_ns as f64)
    );
}

fn main() {
    let samples = run_cold_fault(BENCH_PAGES, SIM_READPAGE_SPINS);
    let stats = summarise(samples);
    print_report(&stats);
}

// --- Self-tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_fault_publishes_uptodate() {
        // Smallest possible bench: one page, one spin iter — verifies
        // the install_or_get → publish discipline as the bench
        // performs it.
        let cache = PageCache::new();
        let ops = StubOps { spin_iters: 1 };
        cold_fault_one(&cache, &ops, 0);
        let entry = {
            let inner = cache.inner.lock().unwrap();
            inner.get(&0).cloned().expect("page must be indexed")
        };
        assert!(entry.is_uptodate());
        assert!(!entry.is_locked());
    }

    #[test]
    fn cold_faults_are_independent_pgoffs() {
        // Distinct pgoffs each take the InstalledNew arm; running
        // again at the same pgoff would be AlreadyPresent — but the
        // bench only ever cold-faults distinct pgoffs, so the
        // measurement window never sees AlreadyPresent.
        let cache = PageCache::new();
        let ops = StubOps { spin_iters: 1 };
        cold_fault_one(&cache, &ops, 0);
        cold_fault_one(&cache, &ops, 1);
        cold_fault_one(&cache, &ops, 2);
        let inner = cache.inner.lock().unwrap();
        assert_eq!(inner.len(), 3);
    }

    #[test]
    #[should_panic(expected = "AlreadyPresent on cold pgoff")]
    fn rebenching_same_pgoff_panics() {
        // Defence-in-depth: the harness invariant that every
        // measurement-window pgoff is cold is enforced with a panic,
        // not silently absorbed. If a refactor ever reuses pgoffs
        // inside the window, this assertion fires.
        let cache = PageCache::new();
        let ops = StubOps { spin_iters: 1 };
        cold_fault_one(&cache, &ops, 0);
        cold_fault_one(&cache, &ops, 0);
    }

    #[test]
    fn summarise_orders_quantiles() {
        let samples = vec![10u64, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let stats = summarise(samples);
        assert_eq!(stats.n, 10);
        assert_eq!(stats.min_ns, 10);
        assert_eq!(stats.max_ns, 100);
        assert!(stats.p50_ns <= stats.p90_ns);
        assert!(stats.p90_ns <= stats.p99_ns);
        assert!(stats.p99_ns <= stats.max_ns);
    }

    #[test]
    fn run_cold_fault_returns_expected_count() {
        let samples = run_cold_fault(8, 1);
        assert_eq!(samples.len(), 8);
    }
}
