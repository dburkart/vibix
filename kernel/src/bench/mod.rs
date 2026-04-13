//! In-kernel microbenchmark harness. Gated behind the `bench` cargo
//! feature so normal boots compile the code out entirely.
//!
//! # Usage
//!
//! `cargo xtask run --bench` builds the kernel with `--features bench`
//! and boots it under QEMU. At boot, after the scheduler and shell are
//! up, a dedicated bench task runs each seed benchmark once, then
//! prints a summary table over serial.
//!
//! # Timing
//!
//! Cycles come from `rdtsc` bracketed with `lfence` / `rdtscp` so the
//! measured region isn't smeared by out-of-order execution into the
//! surrounding code. Three aggregates per benchmark: min, median, p99.
//! Absolute cycle counts are **not** portable across hosts — the
//! numbers are for eyeballing regressions against a known-good run on
//! the same machine.

use alloc::vec::Vec;

mod alloc_bench;
pub(crate) mod irq;

/// Summary statistics for a batch of timed samples.
#[derive(Clone, Copy)]
pub struct Stats {
    pub iters: u32,
    pub min: u64,
    pub median: u64,
    pub p99: u64,
}

impl Stats {
    /// Sort the samples in place and extract min / median / p99.
    /// Median is the `n/2`th element, p99 is `(n * 99) / 100` clamped
    /// to the last index — both exact quantile definitions rather than
    /// interpolated, since N is small and interpolation adds no value
    /// for a regression eyeball.
    pub fn from_samples(samples: &mut [u64]) -> Self {
        if samples.is_empty() {
            return Self {
                iters: 0,
                min: 0,
                median: 0,
                p99: 0,
            };
        }
        samples.sort_unstable();
        let n = samples.len();
        let p99_idx = ((n * 99) / 100).min(n - 1);
        Self {
            iters: n as u32,
            min: samples[0],
            median: samples[n / 2],
            p99: samples[p99_idx],
        }
    }
}

/// Start-of-region timestamp: serialize with `lfence` before sampling
/// so prior loads / stores have retired.
///
/// We use `lfence; rdtsc` rather than `rdtscp` because the default
/// QEMU CPU (`qemu64`) doesn't advertise `RDTSCP` in CPUID and hitting
/// the instruction raises `#UD`. `lfence; rdtsc; lfence` is a
/// well-known surrogate that's been the recommended pattern in Intel's
/// benchmarking whitepaper since the `rdtscp`-less era.
#[inline(always)]
pub fn rdtsc_start() -> u64 {
    unsafe {
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_rdtsc()
    }
}

/// End-of-region timestamp. Symmetric with [`rdtsc_start`]: an
/// `lfence` brackets the `rdtsc` on both sides so neither prior nor
/// subsequent instructions can slip past the measurement.
#[inline(always)]
pub fn rdtsc_end() -> u64 {
    unsafe {
        core::arch::x86_64::_mm_lfence();
        let v = core::arch::x86_64::_rdtsc();
        core::arch::x86_64::_mm_lfence();
        v
    }
}

/// Time `body` for `iters` iterations and reduce to [`Stats`]. The
/// closure should encapsulate exactly the region you want measured;
/// everything else (loop bookkeeping, the `rdtsc` pair) is amortised
/// out by the min/median/p99 reduction.
pub fn measure<F: FnMut()>(iters: u32, mut body: F) -> Stats {
    let mut samples: Vec<u64> = Vec::with_capacity(iters as usize);
    for _ in 0..iters {
        let t0 = rdtsc_start();
        body();
        let t1 = rdtsc_end();
        samples.push(t1.wrapping_sub(t0));
    }
    Stats::from_samples(&mut samples)
}

/// Top-level bench entry point. Spawned by `main` at boot when the
/// `bench` feature is enabled. Runs each seed benchmark, prints a
/// summary, then parks the task on `hlt` — the kernel keeps running
/// so the framebuffer / shell remain responsive.
///
/// Context-switch timing is intentionally not in this harness: a
/// ping-pong between two tasks currently rotates through the entire
/// ready queue (shell, cursor-blink, bootstrap), so the measurement
/// reflects PIT-slice cost more than scheduler trip cost. Tracked as
/// a follow-up — it needs priority-directed handoff in `task` first.
pub fn run_all() -> ! {
    use crate::serial_println;

    // Let the shell and cursor-blink tasks settle before the irq
    // sampling ring starts recording — the first handful of ticks
    // after boot carry one-shot setup noise.
    for _ in 0..20 {
        x86_64::instructions::hlt();
    }

    serial_println!("bench: start");

    let alloc_stats = alloc_bench::run();
    // Collect across roughly 5 seconds of PIT ticks so the
    // distribution has a few hundred samples to chew on.
    let irq_stats = irq::collect(500);

    dump(&alloc_stats, irq_stats);

    serial_println!("bench: done");
    loop {
        x86_64::instructions::hlt();
    }
}

fn dump(alloc_stats: &[(usize, Stats)], irq: Stats) {
    use crate::{kinfo, serial_println};
    serial_println!(
        "bench: {:<16} {:>6} {:>8} {:>8} {:>8}",
        "name",
        "iters",
        "min",
        "median",
        "p99"
    );
    kinfo!("bench results (cycles)");
    for (size, s) in alloc_stats {
        use alloc::format;
        let name = format!("kmalloc/{size}");
        print_row(&name, *s);
    }
    print_row("irq", irq);
}

fn print_row(name: &str, s: Stats) {
    use crate::{kinfo, serial_println};
    serial_println!(
        "bench: {:<16} {:>6} {:>8} {:>8} {:>8}",
        name,
        s.iters,
        s.min,
        s.median,
        s.p99
    );
    kinfo!(
        "bench {} iters={} min={} median={} p99={}",
        name,
        s.iters,
        s.min,
        s.median,
        s.p99
    );
}

