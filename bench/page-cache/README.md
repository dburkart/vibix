# bench-page-cache — cold-mmap fault-latency baseline (RFC 0007)

Host-side benchmark that establishes a baseline for the cold-mmap
fault path **before any optimisation PR lands** in the page cache /
file mmap stack.

The kernel page-fault wiring (#739) does not exist yet, so this bench
runs entirely on the host, modelling the
`PageCache::install_or_get → readpage → publish_uptodate` sequence
through a stub `AddressSpaceOps` whose per-page filler cost is a
fixed-iteration spin loop.

## Run it

```bash
cargo xtask bench page-cache
```

(Equivalent: `cargo run --release --manifest-path bench/page-cache/Cargo.toml --bin bench-page-cache`.)

## What's measured

Per-page wall-clock for the cold-fault sequence:

1. `PageCache::install_or_get(pgoff, …)` — winner allocates a fresh
   `PG_LOCKED` stub and inserts it into the per-inode index.
2. `AddressSpaceOps::readpage(pgoff, &mut buf)` — stub fills the
   4 KiB buffer with a deterministic xorshift stream after a fixed
   `SIM_READPAGE_SPINS`-iteration busy-wait (models per-page CPU
   cost, holds it constant across runs).
3. `publish_uptodate_and_unlock` — `Release` set of `PG_UPTODATE`
   then `Release` clear of `PG_LOCKED`, matching RFC 0007
   §State-bit ordering.

The measurement window covers `BENCH_PAGES = 4096` distinct cold
pgoffs after `WARMUP_PAGES = 64` warm-up pages; samples are sorted
to compute min / p50 / p90 / p99 / max / mean / total / pages-per-second.

Default readahead is **0 pages on cold inode** (RFC 0007 — an early
draft incorrectly defaulted to 8, which would have regressed execve
latency).

## Determinism

The bench is deterministic by construction:

- Every per-page contents are seeded from `pgoff` via xorshift; no
  syscalls, no clock-driven entropy.
- The simulated readpage cost is a fixed-iteration `black_box` spin,
  not `sleep` — work per page is constant.
- A warm-up window populates the host allocator + `BTreeMap` splay
  before measurement starts.
- The cold-pgoff invariant is enforced with a runtime panic; a
  bench refactor that accidentally re-faults a warm pgoff fails
  loudly rather than silently understating latency.

The absolute numbers will drift host-to-host (CPU model, allocator
version, `target-cpu`); the **shape** — relative quantiles and
pages-per-second — is what catches algorithmic regressions.

## Baseline

Captured on the landing run for #743 (release build, single-threaded
host, `cargo xtask bench page-cache`):

```text
=== bench-page-cache: cold-mmap fault latency ===
RFC 0007 §Testing strategy — host-side baseline
model: install_or_get -> readpage(stub) -> publish_uptodate
readahead: 0 pages on cold inode (RFC 0007 default)

samples           : 4096
warmup pages      : 64
sim_readpage_spins: 256

min   :     6485 ns
p50   :     9612 ns
p90   :    11983 ns
p99   :    21044 ns
max   :   158941 ns
mean  :    10503 ns
total : 43022411 ns
rate  :    95.21 kpages/s
```

Run-to-run the absolute ns counts vary on the order of single-digit
percent; the shape (relative quantiles, pages-per-second) is stable.
The absolute numbers above are host-specific — CPU model, allocator
version, and `target-cpu` all move them. **Reviewers comparing a
future optimisation PR should reproduce this baseline on the same
host before drawing a conclusion from a delta.**

## Why mirror the kernel types instead of consuming them?

The kernel `mem::page_cache` module is gated
`#[cfg(any(target_os = "none", test))]`, so it is not reachable from
a stock host build. The issue (#743) explicitly forbids modifying
the kernel page-cache types. The bench therefore mirrors the data
structures (state bits, install-race outcome, `Arc<CachePage>`
discipline) one-for-one in the bench crate — the kernel types are
the source of truth, and the bench is shape-identical so a future
swap-in (after #737/#738/#739) is a rename rather than a refactor.
