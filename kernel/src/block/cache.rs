//! Read-through block cache for the virtio-blk layer.
//!
//! Sits between [`super::read`]/[`super::write`] and the underlying
//! driver. Caches 4 KiB pages (8 sectors) in a 4-way set-associative
//! table with 8 sets, for a total of 32 resident pages (128 KiB of
//! `.bss`). Reads miss on cold pages, fill the line from the backend,
//! then copy into the caller's buffer. Writes invalidate any cache
//! line whose range overlaps the write and forward straight to the
//! backend — write-through / write-back is deferred per the issue.
//!
//! The cache data structure is kernel-free: a generic [`Cache<LINES>`]
//! driven by a [`Backend`] trait so host `cargo test` exercises hits,
//! misses, eviction, and invalidation without pulling in a real disk.
//! The glue that wires virtio-blk in as the backend is the only part
//! gated on `target_os = "none"`.

use super::{BlkError, SECTOR_SIZE};

use core::sync::atomic::{AtomicU64, Ordering};

/// Bytes per cache line. One page covers eight 512-byte sectors — the
/// largest transfer the virtio-blk bounce buffer can issue in a single
/// descriptor, so a fill or invalidating write fits in one backend op.
pub const LINE_BYTES: usize = 4096;
/// Sectors per line.
pub const LINE_SECTORS: u64 = (LINE_BYTES / SECTOR_SIZE) as u64;

const _: () = assert!(LINE_BYTES == SECTOR_SIZE * LINE_SECTORS as usize);

/// Number of sets in the associative cache. Power of two so the index
/// computation is a mask, not a modulo.
pub const NUM_SETS: usize = 8;
/// Ways (lines) per set.
pub const WAYS: usize = 4;
/// Total lines resident (sets × ways).
pub const TOTAL_LINES: usize = NUM_SETS * WAYS;

const _: () = assert!(NUM_SETS.is_power_of_two());

/// Snapshot of hit/miss counters. Returned by [`stats`] as a point-in-
/// time view; monotonic, never reset across a boot.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    /// Reads that found the covering page already resident.
    pub hits: u64,
    /// Reads that had to pull the page from the backend.
    pub misses: u64,
    /// Lines dropped because a write overlapped their range.
    pub invalidations: u64,
    /// Lines brought in from the backend (miss fills + replacement
    /// fills). Distinct from `misses` in future variants that may
    /// prefetch; today tracks 1:1.
    pub fills: u64,
}

/// Trait the cache talks to on miss/fill/write. Implemented for
/// virtio-blk in the kernel build and for a `MockDisk` in host tests.
pub trait Backend {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlkError>;
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlkError>;
}

/// One cache line: a full page plus the page-aligned LBA it currently
/// holds. `valid=false` means the slot is empty and `page_lba` is junk.
#[derive(Clone, Copy)]
struct Line {
    page_lba: u64,
    valid: bool,
    age: u8,
    data: [u8; LINE_BYTES],
}

impl Line {
    const fn empty() -> Self {
        Self {
            page_lba: 0,
            valid: false,
            age: 0,
            data: [0u8; LINE_BYTES],
        }
    }
}

/// Fixed-capacity set-associative cache, parameterized only by total
/// line count so a host test can instantiate a smaller one cheaply.
pub struct Cache<const LINES: usize> {
    lines: [Line; LINES],
}

impl<const LINES: usize> Cache<LINES> {
    /// Creates an all-invalid cache. `LINES` must equal `NUM_SETS * WAYS`
    /// of this module for the indexing math to match the callers in
    /// [`read_through`] / [`write_invalidate`]; smaller hand-wired
    /// [`Cache`]s in tests size their set/way pair themselves.
    pub const fn new() -> Self {
        Self {
            lines: [Line::empty(); LINES],
        }
    }

    /// Read `buf.len()` bytes starting at sector `lba` through the
    /// cache, using `backend` on every miss.
    ///
    /// Uses `stats` (atomic counters) rather than returning per-call
    /// metrics so the public [`stats`] function can be lock-free.
    pub fn read_through(
        &mut self,
        lba: u64,
        buf: &mut [u8],
        backend: &mut dyn Backend,
        stats: &CacheCounters,
        sets: usize,
        ways: usize,
    ) -> Result<(), BlkError> {
        if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(BlkError::BadAlign);
        }
        let sectors = (buf.len() / SECTOR_SIZE) as u64;
        let end = lba + sectors;
        let mut cur = lba;
        let mut out_off = 0;
        while cur < end {
            let page_lba = cur & !(LINE_SECTORS - 1);
            let intra_sector = (cur - page_lba) as usize;
            let sectors_in_page =
                core::cmp::min(LINE_SECTORS as usize - intra_sector, (end - cur) as usize);
            let bytes = sectors_in_page * SECTOR_SIZE;
            let src_off = intra_sector * SECTOR_SIZE;

            let set = set_index(page_lba, sets);
            match self.lookup(set, ways, page_lba) {
                Some(way) => {
                    stats.hits.fetch_add(1, Ordering::Relaxed);
                    self.touch(set, ways, way);
                    let line = &self.lines[set * ways + way];
                    buf[out_off..out_off + bytes]
                        .copy_from_slice(&line.data[src_off..src_off + bytes]);
                }
                None => {
                    stats.misses.fetch_add(1, Ordering::Relaxed);
                    let way = self.pick_victim(set, ways);
                    let mut page = [0u8; LINE_BYTES];
                    backend.read(page_lba, &mut page)?;
                    stats.fills.fetch_add(1, Ordering::Relaxed);
                    let slot = &mut self.lines[set * ways + way];
                    slot.page_lba = page_lba;
                    slot.valid = true;
                    slot.data = page;
                    self.touch(set, ways, way);
                    let line = &self.lines[set * ways + way];
                    buf[out_off..out_off + bytes]
                        .copy_from_slice(&line.data[src_off..src_off + bytes]);
                }
            }

            cur += sectors_in_page as u64;
            out_off += bytes;
        }
        Ok(())
    }

    /// Invalidate any cache line whose page overlaps `[lba, lba+sectors)`,
    /// then write through to the backend. Counts invalidations in
    /// `stats`.
    pub fn write_invalidate(
        &mut self,
        lba: u64,
        buf: &[u8],
        backend: &mut dyn Backend,
        stats: &CacheCounters,
        sets: usize,
        ways: usize,
    ) -> Result<(), BlkError> {
        if buf.is_empty() || buf.len() % SECTOR_SIZE != 0 {
            return Err(BlkError::BadAlign);
        }
        let sectors = (buf.len() / SECTOR_SIZE) as u64;
        self.invalidate_range(lba, sectors, stats, sets, ways);
        backend.write(lba, buf)
    }

    /// Drop every valid line overlapping `[lba, lba+sectors)`.
    pub fn invalidate_range(
        &mut self,
        lba: u64,
        sectors: u64,
        stats: &CacheCounters,
        sets: usize,
        ways: usize,
    ) {
        let end = lba + sectors;
        let first_page = lba & !(LINE_SECTORS - 1);
        let last_page = (end - 1) & !(LINE_SECTORS - 1);
        let mut page = first_page;
        while page <= last_page {
            let set = set_index(page, sets);
            for way in 0..ways {
                let slot = &mut self.lines[set * ways + way];
                if slot.valid && slot.page_lba == page {
                    slot.valid = false;
                    stats.invalidations.fetch_add(1, Ordering::Relaxed);
                }
            }
            page += LINE_SECTORS;
        }
    }

    fn lookup(&self, set: usize, ways: usize, page_lba: u64) -> Option<usize> {
        for way in 0..ways {
            let line = &self.lines[set * ways + way];
            if line.valid && line.page_lba == page_lba {
                return Some(way);
            }
        }
        None
    }

    /// Pick a way in `set` to evict: prefer any invalid slot; otherwise
    /// the oldest (highest `age`) valid line.
    fn pick_victim(&self, set: usize, ways: usize) -> usize {
        for way in 0..ways {
            if !self.lines[set * ways + way].valid {
                return way;
            }
        }
        let mut worst = 0;
        let mut worst_age = self.lines[set * ways].age;
        for way in 1..ways {
            let a = self.lines[set * ways + way].age;
            if a > worst_age {
                worst_age = a;
                worst = way;
            }
        }
        worst
    }

    /// Mark `way` as most-recently-used in `set`: reset its age to 0
    /// and age every other valid line in the set. Saturating so a line
    /// that never gets touched can't wrap around.
    fn touch(&mut self, set: usize, ways: usize, way: usize) {
        for w in 0..ways {
            let line = &mut self.lines[set * ways + w];
            if w == way {
                line.age = 0;
            } else if line.valid {
                line.age = line.age.saturating_add(1);
            }
        }
    }
}

fn set_index(page_lba: u64, sets: usize) -> usize {
    let pages = page_lba / LINE_SECTORS;
    (pages as usize) & (sets - 1)
}

/// Atomic-backed hit/miss counters, separated from the mutex-protected
/// [`Cache`] so callers of [`stats`] don't need to take the cache lock.
pub struct CacheCounters {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub invalidations: AtomicU64,
    pub fills: AtomicU64,
}

impl CacheCounters {
    pub const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            invalidations: AtomicU64::new(0),
            fills: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> CacheStats {
        CacheStats {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            invalidations: self.invalidations.load(Ordering::Relaxed),
            fills: self.fills.load(Ordering::Relaxed),
        }
    }
}

// ---- Kernel wiring ---------------------------------------------------------

#[cfg(target_os = "none")]
use spin::Mutex;

#[cfg(target_os = "none")]
static CACHE: Mutex<Cache<TOTAL_LINES>> = Mutex::new(Cache::new());
#[cfg(target_os = "none")]
static COUNTERS: CacheCounters = CacheCounters::new();

#[cfg(target_os = "none")]
struct VirtioBackend;

#[cfg(target_os = "none")]
impl Backend for VirtioBackend {
    fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlkError> {
        super::virtio_blk::read(lba, buf)
    }
    fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlkError> {
        super::virtio_blk::write(lba, buf)
    }
}

/// Initialize the cache. Safe to call once `block::init()` has brought
/// up the backend — a no-op today because the static is already zeroed,
/// but reserved so a future revision can warm or audit at boot.
#[cfg(target_os = "none")]
pub fn init() {
    // All lines start invalid via `Line::empty()`. Nothing to do.
}

/// Route a caller read through the cache.
#[cfg(target_os = "none")]
pub fn read_through(lba: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    let mut backend = VirtioBackend;
    CACHE
        .lock()
        .read_through(lba, buf, &mut backend, &COUNTERS, NUM_SETS, WAYS)
}

/// Route a caller write through invalidation + backend.
#[cfg(target_os = "none")]
pub fn write_invalidate(lba: u64, buf: &[u8]) -> Result<(), BlkError> {
    let mut backend = VirtioBackend;
    CACHE
        .lock()
        .write_invalidate(lba, buf, &mut backend, &COUNTERS, NUM_SETS, WAYS)
}

/// Monotonic counter snapshot. Lock-free.
#[cfg(target_os = "none")]
pub fn stats() -> CacheStats {
    COUNTERS.snapshot()
}

// ---- Tests -----------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    /// In-memory backend for host tests. Addresses sectors as a flat
    /// `Vec<[u8; SECTOR_SIZE]>` and counts calls so a test can assert
    /// that cached reads don't hit the disk twice.
    struct MockDisk {
        sectors: Vec<[u8; SECTOR_SIZE]>,
        reads: u64,
        writes: u64,
    }

    impl MockDisk {
        fn new(n: usize) -> Self {
            let mut s = Vec::with_capacity(n);
            for i in 0..n {
                let mut sec = [0u8; SECTOR_SIZE];
                // Fill each sector with its LBA so reads are verifiable.
                for b in sec.iter_mut() {
                    *b = (i as u8).wrapping_mul(7);
                }
                s.push(sec);
            }
            Self {
                sectors: s,
                reads: 0,
                writes: 0,
            }
        }
    }

    impl Backend for MockDisk {
        fn read(&mut self, lba: u64, buf: &mut [u8]) -> Result<(), BlkError> {
            self.reads += 1;
            let n = buf.len() / SECTOR_SIZE;
            for i in 0..n {
                buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE]
                    .copy_from_slice(&self.sectors[(lba as usize) + i]);
            }
            Ok(())
        }
        fn write(&mut self, lba: u64, buf: &[u8]) -> Result<(), BlkError> {
            self.writes += 1;
            let n = buf.len() / SECTOR_SIZE;
            for i in 0..n {
                self.sectors[(lba as usize) + i]
                    .copy_from_slice(&buf[i * SECTOR_SIZE..(i + 1) * SECTOR_SIZE]);
            }
            Ok(())
        }
    }

    #[test]
    fn miss_then_hit() {
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(64);
        let mut buf = [0u8; SECTOR_SIZE];
        c.read_through(0, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        c.read_through(0, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        let s = ctrs.snapshot();
        assert_eq!(s.misses, 1);
        assert_eq!(s.hits, 1);
        assert_eq!(s.fills, 1);
        assert_eq!(disk.reads, 1, "second read must be served from cache");
    }

    #[test]
    fn write_invalidates_overlapping_line() {
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(64);
        let mut buf = [0u8; SECTOR_SIZE];
        c.read_through(0, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        // Write sector 3 — same page as the read we just did.
        let w = [0xAAu8; SECTOR_SIZE];
        c.write_invalidate(3, &w, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        assert_eq!(ctrs.snapshot().invalidations, 1);
        // Next read of sector 0 must refill from the (now-updated) backend.
        let mut back = [0u8; SECTOR_SIZE];
        c.read_through(0, &mut back, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        assert_eq!(disk.reads, 2, "cache must refill after invalidation");
    }

    #[test]
    fn write_outside_cached_range_no_invalidation() {
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(128);
        let mut buf = [0u8; SECTOR_SIZE];
        c.read_through(0, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        // Page 0 covers LBAs 0..=7. Write well past it: sector 64.
        let w = [0x55u8; SECTOR_SIZE];
        c.write_invalidate(64, &w, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        assert_eq!(ctrs.snapshot().invalidations, 0);
    }

    #[test]
    fn eviction_is_lru_within_set() {
        // With NUM_SETS=8 and WAYS=4, each set holds 4 pages. Pages that
        // hash to set 0: page LBAs 0, 8*NUM_SETS, 16*NUM_SETS, ...
        let stride = LINE_SECTORS * NUM_SETS as u64; // next page in same set
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        // MockDisk must cover at least 5 stride-spaced pages; size it
        // generously so a whole page read never falls off the end.
        let needed = ((stride * 5) + LINE_SECTORS) as usize;
        let mut disk = MockDisk::new(needed);
        let mut buf = [0u8; SECTOR_SIZE];
        // Fill set 0 with pages A, B, C, D.
        let pages = [0, stride, 2 * stride, 3 * stride];
        for &p in &pages {
            c.read_through(p, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
                .unwrap();
        }
        // Re-touch A, B, C so D is the LRU.
        for &p in &pages[..3] {
            c.read_through(p, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
                .unwrap();
        }
        // Bring in E → should evict D.
        let e = 4 * stride;
        c.read_through(e, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        // A, B, C still resident (hits), D evicted (miss on re-read).
        let before = disk.reads;
        for &p in &pages[..3] {
            c.read_through(p, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
                .unwrap();
        }
        assert_eq!(disk.reads, before, "A/B/C should stay in cache");
        c.read_through(pages[3], &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        assert_eq!(disk.reads, before + 1, "D must refill after eviction");
    }

    #[test]
    fn multi_page_unaligned_read() {
        // Read 6 sectors starting at sector 5. Spans page 0 (LBAs 0-7)
        // and page 1 (LBAs 8-15): 3 sectors from page 0 + 3 from page 1.
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(64);
        let mut buf = [0u8; 6 * SECTOR_SIZE];
        c.read_through(5, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        // First sector returned should be sector 5's content; MockDisk
        // filled each sector with (lba * 7).
        assert_eq!(buf[0], 5u8.wrapping_mul(7));
        assert_eq!(buf[SECTOR_SIZE], 6u8.wrapping_mul(7));
        assert_eq!(buf[5 * SECTOR_SIZE], 10u8.wrapping_mul(7));
        assert_eq!(ctrs.snapshot().misses, 2, "two pages crossed");
    }

    #[test]
    fn bad_align_rejected() {
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(8);
        let mut short = [0u8; 10];
        assert_eq!(
            c.read_through(0, &mut short, &mut disk, &ctrs, NUM_SETS, WAYS),
            Err(BlkError::BadAlign)
        );
        let mut empty = [0u8; 0];
        assert_eq!(
            c.read_through(0, &mut empty, &mut disk, &ctrs, NUM_SETS, WAYS),
            Err(BlkError::BadAlign)
        );
    }

    #[test]
    fn write_spanning_two_pages_invalidates_both() {
        let mut c = Cache::<TOTAL_LINES>::new();
        let ctrs = CacheCounters::new();
        let mut disk = MockDisk::new(32);
        // Warm both page 0 and page 1.
        let mut buf = [0u8; SECTOR_SIZE];
        c.read_through(0, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        c.read_through(8, &mut buf, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        // Write 4 sectors starting at LBA 6 → covers pages 0 and 1.
        let w = [0u8; 4 * SECTOR_SIZE];
        c.write_invalidate(6, &w, &mut disk, &ctrs, NUM_SETS, WAYS)
            .unwrap();
        assert_eq!(ctrs.snapshot().invalidations, 2);
    }
}
