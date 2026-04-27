//! Block buffer cache — `bread` / `mark_dirty` / `sync_dirty_buffer` /
//! `release` with CLOCK-Pro eviction.
//!
//! Implements RFC 0004 §Buffer cache (Workstream C, wave 1, issue #553)
//! on top of the skeleton from #552.
//!
//! Scope of this module:
//!
//! - [`BufferHead`] — one block-sized slab + state bits + the CLOCK-Pro
//!   reference bit.
//! - [`BlockCache`] — owns an `Arc<dyn BlockDevice>`, the per-device
//!   `block_size`, the `(DeviceId, u64)`-keyed entry map, and the
//!   CLOCK-Pro hot/cold/non-resident metadata.
//! - [`BlockCache::bread`] — populate-on-miss read with CLOCK-Pro
//!   eviction and [`BlockError::NoMemory`] fallback when no buffer is
//!   evictable.
//! - [`BlockCache::mark_dirty`] — mark a resident buffer dirty +
//!   enlist it into the dirty set.
//! - [`BlockCache::sync_dirty_buffer`] — synchronously flush one buffer
//!   to the device with the `LOCKED_IO` handshake.
//! - [`BlockCache::release`] — advisory hint to drop one strong ref; real
//!   GC runs through `Arc` drop.
//! - [`DeviceId`] — opaque index allocated by the cache via
//!   [`BlockCache::register_device`]. Keeps the key narrow (8 bytes of
//!   hot map key vs. a full `Arc` pointer) and lets the cache host
//!   multiple mounts backed by the same `Arc<dyn BlockDevice>` without
//!   aliasing.
//! - [`default_cache`] / [`init_default_cache`] — the `Arc<BlockCache>`
//!   singleton hook the VFS mount path will eventually plug into.
//!
//! # CLOCK-Pro summary
//!
//! Per Jiang & Zhang (USENIX ATC 2005), every cached key is classified
//! as **HOT**, **COLD-resident**, or **COLD-non-resident**. HOT and
//! COLD-resident keys hold a [`BufferHead`] in `entries`; COLD-non-resident
//! keys hold only a ghost entry in `non_resident` (bounded by
//! `max_buffers`) so a re-reference within its cold-to-hot window is
//! recognized and the re-loaded buffer is installed directly into the
//! HOT queue.
//!
//! On eviction, `clock_hand` rotates through `entries`, setting /
//! clearing `clock_ref` and demoting HOT → COLD / promoting COLD → HOT
//! on reference-bit hits. The first COLD-resident buffer found with
//! `clock_ref=0` and no pin and no `DIRTY | LOCKED_IO` bit is evicted
//! (its key is migrated into `non_resident`). If a full sweep turns up
//! no evictable buffer, `bread` returns [`BlockError::NoMemory`]
//! instead of blocking or flushing dirty buffers — see RFC 0004
//! §Buffer cache, normative invariants 1–4.
//!
//! # Normative invariants enforced here
//!
//! 1. **Never evict a pinned buffer.** Any `BufferHead` whose
//!    `Arc::strong_count > 1` is skipped by the sweep — the map holds
//!    one strong ref, and any external handle from a prior `bread`
//!    bumps that count to at least 2.
//! 2. **Never evict a buffer with `DIRTY | LOCKED_IO` set.** A buffer
//!    mid-`sync_dirty_buffer` is skipped regardless of classification.
//! 3. **`bread` never performs synchronous writeback during eviction.**
//!    If the sweep yields zero victims, `bread` returns `NoMemory`.
//! 4. **Single-cache-entry invariant.** `bread` re-checks `entries`
//!    under lock before installing its freshly-allocated buffer; if
//!    another thread won the race, the loser drops its `Arc` and
//!    returns the winner's.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use spin::{Once, RwLock};

use super::{BlockDevice, BlockError};
use crate::debug_lockdep::{assert_no_spinlocks_held, SpinLock};

/// Valid bit — the in-memory slab reflects the on-disk block as of its
/// most recent read-back.
pub const STATE_VALID: u8 = 1;

/// Dirty bit — the in-memory slab has writes not yet flushed to the
/// device.
pub const STATE_DIRTY: u8 = 2;

/// I/O-lock bit — a block I/O is in flight against this buffer. Guards
/// the `bread` / `sync_dirty_buffer` handshake so eviction never races a
/// concurrent transfer.
pub const STATE_LOCKED_IO: u8 = 4;

/// Opaque per-device index allocated by [`BlockCache::register_device`].
///
/// Kept distinct from `Arc<dyn BlockDevice>` so the cache key
/// (`(DeviceId, u64)`) stays narrow — two concurrent ext2 mounts sharing
/// the same ramdisk must not alias each other's `(dev, blk)` pairs.
/// `DeviceId` is `Copy`/`Ord`, which is what `BTreeMap` and `BTreeSet`
/// want.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(u32);

impl DeviceId {
    /// Raw integer representation — stable within a boot, not meaningful
    /// across reboots. Exposed so callers and tests can print it.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// One cached block.
///
/// `data` holds the block-sized slab; its exact length equals the owning
/// cache's `block_size`. `state` is the `VALID | DIRTY | LOCKED_IO`
/// bitmask. `clock_ref` is the CLOCK-Pro reference bit — set by the
/// lookup / `bread` hit path and cleared by the eviction sweep. The
/// eviction algorithm itself lands in a follow-up.
pub struct BufferHead {
    /// Block-sized scratch buffer. `RwLock` so multiple readers can pull
    /// from a `VALID` block while a writer (the `bread` populate path
    /// in the follow-up) holds it exclusively.
    pub data: RwLock<Box<[u8]>>,
    /// `VALID | DIRTY | LOCKED_IO` bitmask. `AtomicU8` so state checks
    /// don't need to take any lock.
    pub state: AtomicU8,
    /// CLOCK-Pro reference bit. `AtomicBool` so the hit path can set it
    /// without synchronizing with the eviction sweep. Set on every
    /// `bread` / `lookup` hit; cleared by the eviction sweep when it
    /// demotes a HOT buffer or promotes a COLD-resident buffer.
    pub clock_ref: AtomicBool,
}

impl BufferHead {
    /// Allocate a zeroed, `VALID=0 | DIRTY=0 | LOCKED_IO=0`, `clock_ref=0`
    /// buffer of `block_size` bytes. The buffer is **not** `VALID` — a
    /// caller that needs contents must populate them and then set
    /// [`STATE_VALID`].
    fn new(block_size: usize) -> Self {
        Self {
            data: RwLock::new(vec![0u8; block_size].into_boxed_slice()),
            state: AtomicU8::new(0),
            clock_ref: AtomicBool::new(false),
        }
    }

    /// `true` iff every bit in `mask` is set in `state`. Convenience
    /// for future call sites; not used by the skeleton's unit tests.
    pub fn state_has(&self, mask: u8) -> bool {
        self.state.load(Ordering::Acquire) & mask == mask
    }
}

/// The `(DeviceId, u64)`-keyed buffer cache.
///
/// One instance per mount — `BlockCache::new` takes the already-registered
/// `Arc<dyn BlockDevice>` and the mount's logical `block_size`. Multiple
/// mounts share nothing by default; the `DeviceId` keeps their entries
/// disjoint even when the underlying device is the same ramdisk.
///
/// This skeleton only exposes synchronous insert / lookup / remove and
/// the device-registration plumbing. `bread`, `mark_dirty`,
/// `sync_dirty_buffer`, and CLOCK-Pro eviction land in follow-ups.
/// CLOCK-Pro classification for each resident entry.
///
/// Hot pages are kept through at least one sweep cycle; cold pages are
/// the first eviction candidates. A reference-bit hit promotes a cold
/// entry to hot (it was accessed during its cold-to-hot window) and
/// keeps a hot entry hot for another cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClockClass {
    /// High-recency buffer. Survives one reference-bit sweep before
    /// getting a chance to demote to cold.
    Hot,
    /// First-eviction candidate. Promoted to [`ClockClass::Hot`] on
    /// reference-bit hit.
    Cold,
}

/// Inner state guarded by a single mutex so eviction, insertion, and the
/// `entries` lookup all observe a consistent `(entries, classes,
/// clock_hand, non_resident)` snapshot.
///
/// Folded into one mutex rather than one per field: CLOCK-Pro needs
/// cross-field atomicity (demoting hot→cold while rotating the clock
/// hand and removing a non-resident ghost), and the buffer cache does
/// not need lock concurrency between its own operations — the hot path
/// critical sections are tiny (map lookup / insert / hand rotation).
struct CacheInner {
    /// Cache body. `(DeviceId, u64)` is `Ord + Copy`, so `BTreeMap` is
    /// the natural fit under `no_std` (no `HashMap` without extra
    /// hashing infra). RFC 0004 sketches a `HashMap` but explicitly
    /// notes the key shape is what matters, not the container.
    entries: BTreeMap<(DeviceId, u64), Arc<BufferHead>>,
    /// CLOCK-Pro classification of every resident key in `entries`.
    /// Invariant: `classes.contains_key(k) ⇔ entries.contains_key(k)`.
    classes: BTreeMap<(DeviceId, u64), ClockClass>,
    /// CLOCK-Pro non-resident ghost queue. Stores keys that were
    /// recently evicted; a re-reference within its cold-to-hot window
    /// is installed as [`ClockClass::Hot`] on return. Bounded by
    /// `max_buffers` to cap the metadata cost. `VecDeque` so oldest
    /// ghost expires first on insertion pressure.
    non_resident: VecDeque<(DeviceId, u64)>,
    /// CLOCK-Pro hand. `None` when the cache is empty; points at the
    /// next candidate key when the sweep runs. The sweep advances the
    /// hand in BTreeMap key order (deterministic, no container
    /// dependency).
    clock_hand: Option<(DeviceId, u64)>,
}

pub struct BlockCache {
    /// Backing device shared by every entry. `Arc<dyn BlockDevice>` so
    /// the writeback daemon and the mount point can hold their own
    /// clones.
    device: Arc<dyn BlockDevice>,
    /// Next `DeviceId` to hand out from [`register_device`](Self::register_device).
    next_device_id: AtomicU32,
    /// Logical block size in bytes. Carried on the cache (not per
    /// entry) so the CLOCK-Pro sweep never has to dereference the
    /// `BlockDevice` to size a fresh slab.
    block_size: u32,
    /// Cache body + CLOCK-Pro metadata. Guarded together so the
    /// eviction sweep sees a consistent view of residency + classes +
    /// hand.
    inner: SpinLock<CacheInner>,
    /// Dirty-set mirror used by the writeback daemon (populated by
    /// `mark_dirty`, cleared by `sync_dirty_buffer`). Stored as keys,
    /// not `Weak` handles — the daemon re-looks-up the `Arc` out of
    /// `entries` on each sweep so an evicted-then-reloaded buffer
    /// still flushes correctly. A separate mutex so the writeback
    /// daemon (future) can snapshot the dirty set without contending
    /// on the CLOCK-Pro critical section.
    dirty: SpinLock<BTreeSet<(DeviceId, u64)>>,
    /// Cap beyond which eviction must start reclaiming. Observed by
    /// `bread` when deciding whether to run a CLOCK-Pro sweep.
    max_buffers: usize,
}

impl BlockCache {
    /// Construct an empty cache bound to `device` with entries sized at
    /// `block_size`. Caps the resident entry count at `max_buffers`; the
    /// cap is enforced by the eviction follow-up (#553), not here.
    ///
    /// # Panics
    ///
    /// Panics if `block_size` is zero or not a whole multiple of
    /// `device.block_size()`. Every future `bread` / `sync_dirty_buffer`
    /// call would translate a cache-block index into a byte offset of
    /// `blk * block_size`, and the device's `read_at` / `write_at`
    /// reject any non-device-aligned offset with
    /// [`BlockError::BadAlign`](super::BlockError::BadAlign). Catching
    /// the geometry mismatch at construction is the difference between
    /// "cache can never do I/O" (silent) and "misuse is caught at mount
    /// time" (loud). Panicking is acceptable: `BlockCache::new` runs
    /// only on the boot / mount paths, never inside a syscall.
    pub fn new(device: Arc<dyn BlockDevice>, block_size: u32, max_buffers: usize) -> Arc<Self> {
        assert!(block_size > 0, "BlockCache: block_size must be non-zero");
        let dev_bs = device.block_size();
        assert!(
            dev_bs > 0 && block_size % dev_bs == 0,
            "BlockCache: cache block_size ({}) must be a whole multiple of device block_size ({})",
            block_size,
            dev_bs,
        );
        Arc::new(Self {
            device,
            next_device_id: AtomicU32::new(0),
            block_size,
            inner: SpinLock::new(CacheInner {
                entries: BTreeMap::new(),
                classes: BTreeMap::new(),
                non_resident: VecDeque::new(),
                clock_hand: None,
            }),
            dirty: SpinLock::new(BTreeSet::new()),
            max_buffers,
        })
    }

    /// Allocate a fresh [`DeviceId`] for this cache. Each logical mount
    /// backed by this cache calls `register_device` once at mount time;
    /// the returned id is stamped into every subsequent `(DeviceId, u64)`
    /// key so parallel mounts don't collide.
    ///
    /// # Panics
    ///
    /// Panics if `u32` id space has been exhausted. `AtomicU32::fetch_add`
    /// would otherwise wrap and silently alias a freshly-handed-out
    /// `DeviceId` with an already-resident one, violating the
    /// "two mounts don't alias" invariant (RFC 0004 §Buffer cache). At
    /// one mount per `register_device` call, 2³² ≈ 4.3 B is an extreme
    /// upper bound we do not expect to reach; widening to `AtomicU64`
    /// would double the `(DeviceId, u64)` key width for no practical
    /// gain. Catch-on-overflow preserves correctness without bloating
    /// the hot map key.
    pub fn register_device(&self) -> DeviceId {
        // CAS-style bump: if a panic-catcher ever swallows the
        // exhaustion panic, the counter must not have already wrapped
        // to 0 — otherwise the next `register_device` call would hand
        // out `DeviceId(0)`, aliasing whichever mount owned it first.
        // `fetch_update` leaves the atomic untouched on `None`.
        let id = self
            .next_device_id
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                cur.checked_add(1)
            })
            .expect("BlockCache: exhausted 2^32 DeviceId space — mount churn is far above design");
        DeviceId(id)
    }

    /// Logical block size in bytes.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Soft cap on resident entries. The eviction follow-up reads this
    /// when deciding whether to sweep.
    pub fn max_buffers(&self) -> usize {
        self.max_buffers
    }

    /// Return a cloned reference to the backing device. The VFS / ext2
    /// driver use this to keep the device alive for the lifetime of the
    /// mount.
    pub fn device(&self) -> Arc<dyn BlockDevice> {
        self.device.clone()
    }

    /// Return `true` if a buffer for `(dev, blk)` is resident in the
    /// cache. Does not touch `clock_ref`.
    pub fn contains(&self, dev: DeviceId, blk: u64) -> bool {
        self.inner.lock().entries.contains_key(&(dev, blk))
    }

    /// Current number of resident entries. Primarily for tests and
    /// debug output.
    pub fn len(&self) -> usize {
        self.inner.lock().entries.len()
    }

    /// `true` iff the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().entries.is_empty()
    }

    /// Look up `(dev, blk)`. Returns `None` on miss.
    ///
    /// On hit, sets `clock_ref=true` on the returned buffer so the
    /// CLOCK-Pro sweep observes the access.
    pub fn lookup(&self, dev: DeviceId, blk: u64) -> Option<Arc<BufferHead>> {
        let guard = self.inner.lock();
        let bh = guard.entries.get(&(dev, blk))?.clone();
        bh.clock_ref.store(true, Ordering::Relaxed);
        Some(bh)
    }

    /// Allocate a fresh `BufferHead` sized to [`block_size`](Self::block_size)
    /// and insert it under `(dev, blk)` — **without** consulting the
    /// CLOCK-Pro eviction path or the backing device.
    ///
    /// Deliberately narrow primitive used by [`BlockCache::bread`] (after
    /// a successful eviction sweep) and by tests that need to seed the
    /// cache synchronously. If one is already resident, returns the
    /// existing `Arc` unchanged and leaves the map untouched, which
    /// preserves the single-cache-entry invariant (RFC 0004
    /// §Eviction invariants #4). Does **not** populate `data` — the
    /// caller is responsible for reading from the device (or writing a
    /// synthetic payload, in test code) and then flipping
    /// [`STATE_VALID`].
    ///
    /// Does not check `max_buffers`: an `insert_empty` past the cap is
    /// allowed so `bread`'s post-eviction install never races a
    /// capacity boundary check.
    pub fn insert_empty(&self, dev: DeviceId, blk: u64) -> Arc<BufferHead> {
        let mut guard = self.inner.lock();
        if let Some(existing) = guard.entries.get(&(dev, blk)) {
            return existing.clone();
        }
        let bh = Arc::new(BufferHead::new(self.block_size as usize));
        guard.entries.insert((dev, blk), bh.clone());
        // A fresh insert on a key that was recently a non-resident ghost
        // bumps the entry straight into the HOT queue: CLOCK-Pro treats
        // a non-resident hit as evidence the key deserves HOT. Drop the
        // ghost from `non_resident` now that it is resident again.
        let was_ghost = guard
            .non_resident
            .iter()
            .position(|k| *k == (dev, blk))
            .map(|pos| {
                guard.non_resident.remove(pos);
            })
            .is_some();
        let class = if was_ghost {
            ClockClass::Hot
        } else {
            ClockClass::Cold
        };
        guard.classes.insert((dev, blk), class);
        if guard.clock_hand.is_none() {
            guard.clock_hand = Some((dev, blk));
        }
        bh
    }

    /// Remove `(dev, blk)` from the cache if present. Also clears the
    /// dirty-set entry so a later reinsert with the same key starts
    /// clean. Returns the evicted `Arc<BufferHead>`, or `None` if the
    /// key wasn't resident.
    ///
    /// The caller is responsible for not removing a buffer that has
    /// outstanding [`STATE_LOCKED_IO`]; the CLOCK-Pro sweep enforces
    /// that, but this primitive is a raw map operation.
    pub fn remove(&self, dev: DeviceId, blk: u64) -> Option<Arc<BufferHead>> {
        let mut guard = self.inner.lock();
        let bh = guard.entries.remove(&(dev, blk));
        guard.classes.remove(&(dev, blk));
        if guard.clock_hand == Some((dev, blk)) {
            // Hand was pointing at the entry we just pulled — advance
            // it to the next resident key, or clear it if none remain.
            guard.clock_hand = guard.entries.keys().next().copied();
        }
        drop(guard);
        self.dirty.lock().remove(&(dev, blk));
        bh
    }

    /// Hit-or-populate read. If `(dev, blk)` is resident, returns the
    /// buffer (with `clock_ref` bumped); otherwise allocates a fresh
    /// buffer, reads from the backing device, and installs it.
    ///
    /// # Errors
    ///
    /// - [`BlockError::NoMemory`] — the cache is at `max_buffers` and
    ///   the CLOCK-Pro sweep finds no evictable resident entry (every
    ///   entry is either pinned or mid-I/O). **The read path never
    ///   synchronously flushes dirty buffers** (RFC 0004 §Buffer cache,
    ///   normative invariant #3).
    /// - Any error propagated from the backing device's `read_at`.
    ///
    /// # Single-cache-entry invariant
    ///
    /// Between the fast-path miss and the final install, `bread`
    /// re-acquires the `inner` lock and re-checks residency. If another
    /// thread won a concurrent miss on the same key, the loser drops
    /// its freshly-read buffer and returns the winner's `Arc` — the
    /// call still yields exactly one `Arc<BufferHead>` for that key
    /// (RFC 0004 §Eviction invariants #4).
    pub fn bread(&self, dev: DeviceId, blk: u64) -> Result<Arc<BufferHead>, BlockError> {
        // Fast path: already resident.
        if let Some(bh) = self.lookup(dev, blk) {
            return Ok(bh);
        }

        // Miss. If we're at capacity, run a CLOCK-Pro sweep first — but
        // do it *before* allocating so we don't push transient slack
        // past the cap, and don't block on an allocation we might have
        // to throw away on `NoMemory`.
        {
            let mut guard = self.inner.lock();
            if guard.entries.len() >= self.max_buffers {
                // Sweep yields `Ok(())` with the victim removed, or
                // `Err(NoMemory)` if nothing is evictable.
                Self::clock_pro_evict(&mut guard, self.max_buffers)?;
            }
        }

        // Allocate + read *outside* the inner lock. The `data` RwLock
        // on a freshly-made `BufferHead` is uncontended, but we
        // explicitly drop the `entries` mutex before issuing I/O so the
        // device call never holds a spinlock that VFS callers contend
        // on (RFC 0004 §Buffer cache, OS-engineer B5 hazard).
        let fresh = Arc::new(BufferHead::new(self.block_size as usize));
        fresh.state.store(STATE_LOCKED_IO, Ordering::Release);
        {
            let mut data = fresh.data.write();
            let offset = blk
                .checked_mul(self.block_size as u64)
                .ok_or(BlockError::OutOfRange)?;
            // RFC 0004 §Buffer cache normative invariant: no spin
            // lock may be held across a block-I/O wait. The cache
            // dropped its `inner` SpinLock above (the eviction
            // sweep block ended at L459); this assertion is the
            // tripwire that fires loudly if a future caller layer
            // re-enters `bread` while still holding one.
            assert_no_spinlocks_held("BlockCache::bread \u{2192} device.read_at");
            self.device.read_at(offset, &mut data[..])?;
        }
        fresh.state.store(STATE_VALID, Ordering::Release);

        // Install under the inner lock, re-checking residency.
        let mut guard = self.inner.lock();
        if let Some(winner) = guard.entries.get(&(dev, blk)) {
            // Another thread won the miss race while we were reading.
            // Drop `fresh` (it's about to go out of scope) and return
            // the winner. `winner.clock_ref` was set by its own
            // inserter; give the caller the same treatment a `lookup`
            // hit would.
            let bh = winner.clone();
            bh.clock_ref.store(true, Ordering::Relaxed);
            return Ok(bh);
        }
        // Re-check capacity under the install lock. Another thread
        // may have won a *different*-key miss race while we were
        // reading; if it pushed the cache up to `max_buffers` in the
        // window between our pre-read sweep and now, we need a second
        // sweep before installing or we'd silently exceed the cap.
        // On `NoMemory` here the read is wasted but the invariant
        // holds: `entries.len() <= max_buffers` after every `bread`.
        if guard.entries.len() >= self.max_buffers {
            Self::clock_pro_evict(&mut guard, self.max_buffers)?;
        }
        guard.entries.insert((dev, blk), fresh.clone());
        let was_ghost = guard
            .non_resident
            .iter()
            .position(|k| *k == (dev, blk))
            .map(|pos| {
                guard.non_resident.remove(pos);
            })
            .is_some();
        let class = if was_ghost {
            ClockClass::Hot
        } else {
            ClockClass::Cold
        };
        guard.classes.insert((dev, blk), class);
        if guard.clock_hand.is_none() {
            guard.clock_hand = Some((dev, blk));
        }
        // A freshly-installed buffer is "just-referenced" — set its
        // reference bit so the next sweep doesn't tear it out before
        // the caller gets one chance to use it.
        fresh.clock_ref.store(true, Ordering::Relaxed);
        Ok(fresh)
    }

    /// Mark `bh` as dirty: sets [`STATE_DIRTY`] and inserts its key into
    /// the dirty set. Idempotent.
    ///
    /// `bh` is expected to be the `Arc` returned by
    /// [`BlockCache::bread`] or [`BlockCache::lookup`]; callers
    /// identify the key by scanning `entries` for a matching `Arc`
    /// pointer. A buffer that is no longer resident (evicted) is
    /// silently not enlisted into the dirty set — the caller owns the
    /// `Arc`, so the bit is still set on the struct and a subsequent
    /// `bread` on the same key will observe it and re-enlist.
    pub fn mark_dirty(&self, bh: &Arc<BufferHead>) {
        bh.state.fetch_or(STATE_DIRTY, Ordering::AcqRel);
        let guard = self.inner.lock();
        if let Some(key) = guard
            .entries
            .iter()
            .find(|(_, v)| Arc::ptr_eq(v, bh))
            .map(|(k, _)| *k)
        {
            drop(guard);
            self.dirty.lock().insert(key);
        }
    }

    /// Synchronously flush `bh` to the backing device.
    ///
    /// Sequence (RFC 0004 §Buffer cache, LOCKED_IO handshake):
    ///
    /// 1. Set [`STATE_LOCKED_IO`] — prevents eviction and a racing
    ///    `sync_dirty_buffer`.
    /// 2. Snapshot the block contents under `BufferHead.data.read()`,
    ///    then **release the inner data lock** before issuing the
    ///    device I/O. The device call may take arbitrarily long; a
    ///    reader that wanted the cached contents must not block on us
    ///    holding the inner `RwLock` across a device wait.
    /// 3. Issue `device.write_at(offset, &snapshot)`. If the device
    ///    returns `Err`, surface it — the `DIRTY | LOCKED_IO` pair is
    ///    cleared before returning so a retry path can try again, but
    ///    the caller must decide whether to remark-dirty.
    /// 4. Atomically clear `DIRTY | LOCKED_IO` and drop the dirty-set
    ///    key.
    ///
    /// Returns `Ok(())` if the device accepted the write (or if `bh`
    /// was not dirty to begin with — harmless no-op).
    pub fn sync_dirty_buffer(&self, bh: &Arc<BufferHead>) -> Result<(), BlockError> {
        // Fast clean-buffer bail-out. A buffer that isn't DIRTY has no
        // bytes to flush; taking LOCKED_IO + snapshotting + issuing a
        // redundant device write would be pure overhead and would
        // spuriously fence eviction for no reason. Load DIRTY once,
        // acquire-ordered so any preceding `mark_dirty` is visible;
        // if it's clear we're done.
        if bh.state.load(Ordering::Acquire) & STATE_DIRTY == 0 {
            return Ok(());
        }

        // Step 1: take the LOCKED_IO bit. If another flusher already
        // has it, spin briefly — in the single-threaded kernel today
        // this path is never concurrent-contended, but the bit also
        // fences us against eviction.
        loop {
            let old = bh.state.load(Ordering::Acquire);
            if old & STATE_LOCKED_IO != 0 {
                // Another flusher has it. In a multithreaded world
                // we'd wait on a condvar; for now, bail with success —
                // the other flusher will carry the write through. A
                // real concurrent flusher is a correctness hazard to
                // investigate, not a behaviour this layer can repair.
                return Ok(());
            }
            // Another window: `mark_dirty` → `sync_dirty_buffer` races
            // can see DIRTY cleared by a concurrent flusher in the
            // gap between the fast-path load above and this CAS. If
            // DIRTY was cleared, bail out — there's nothing to flush.
            if old & STATE_DIRTY == 0 {
                return Ok(());
            }
            if bh
                .state
                .compare_exchange(
                    old,
                    old | STATE_LOCKED_IO,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                break;
            }
        }

        // Identify the key so we can drop it from the dirty-set and
        // compute the device offset. If the buffer isn't resident any
        // more (evicted while we weren't holding a strong ref), we
        // still owe the flush — the RFC requires `sync_dirty_buffer`
        // on a live `Arc` to reach the device.
        let key = self
            .inner
            .lock()
            .entries
            .iter()
            .find(|(_, v)| Arc::ptr_eq(v, bh))
            .map(|(k, _)| *k);

        // Step 2: snapshot + release the data lock. `Box<[u8]>` so
        // the caller can mutate the in-cache buffer under the write
        // lock immediately after we release; the snapshot is what we
        // commit to disk.
        let snapshot: Box<[u8]> = {
            let data = bh.data.read();
            let mut v = vec![0u8; data.len()];
            v.copy_from_slice(&data[..]);
            v.into_boxed_slice()
        };

        // Step 3: issue the device write with *no cache or data lock
        // held* — RFC 0004 §Buffer cache, OS-engineer B5 hazard.
        let result = if let Some((_, blk)) = key {
            let offset = match blk.checked_mul(self.block_size as u64) {
                Some(o) => o,
                None => {
                    // Clear LOCKED_IO and surface OutOfRange; the
                    // DIRTY bit stays set so the caller can retry
                    // after adjusting the key.
                    bh.state.fetch_and(!STATE_LOCKED_IO, Ordering::AcqRel);
                    return Err(BlockError::OutOfRange);
                }
            };
            // RFC 0004 §Buffer cache normative invariant: the
            // `BufferHead.data` RwLock was released above (snapshot
            // was taken inside its own scope at L631-L636) and the
            // cache `inner` / `dirty` SpinLocks were released after
            // the residency lookup at L619-L625. Trip loudly if a
            // future caller layer re-enters `sync_dirty_buffer`
            // while still holding any spinlock.
            assert_no_spinlocks_held("BlockCache::sync_dirty_buffer \u{2192} device.write_at");
            self.device.write_at(offset, &snapshot)
        } else {
            // Not resident and we don't know the block number. This
            // is a caller bug — `sync_dirty_buffer` on an orphaned
            // buffer has nowhere to flush. Clear LOCKED_IO and return
            // success; the bit fence is what mattered.
            bh.state.fetch_and(!STATE_LOCKED_IO, Ordering::AcqRel);
            return Ok(());
        };

        // Step 4: clear DIRTY + LOCKED_IO atomically on success; on
        // device error, clear only LOCKED_IO so the caller can retry.
        match result {
            Ok(()) => {
                bh.state
                    .fetch_and(!(STATE_DIRTY | STATE_LOCKED_IO), Ordering::AcqRel);
                if let Some(key) = key {
                    self.dirty.lock().remove(&key);
                }
                Ok(())
            }
            Err(e) => {
                bh.state.fetch_and(!STATE_LOCKED_IO, Ordering::AcqRel);
                Err(e)
            }
        }
    }

    /// Advisory hint: drops the caller's `Arc` at the end of the
    /// current scope. Real GC runs through `Arc` destructor chaining —
    /// this helper exists to give call sites a single point to express
    /// "I'm done with this buffer". The cache map retains its own
    /// strong ref, so the buffer remains resident (and eligible for
    /// CLOCK-Pro eviction) after `release` returns.
    ///
    /// Takes `Arc<BufferHead>` by value so the caller's strong ref is
    /// demonstrably released; takes `&self` so the signature is
    /// ergonomically callable on a shared `Arc<BlockCache>`.
    pub fn release(&self, _bh: Arc<BufferHead>) {
        // Intentionally empty — the `Arc` drops at end of scope. In a
        // future revision we might decrement a usage counter or hint
        // the CLOCK-Pro sweep; today the `Arc::strong_count`-based
        // pinning check is what matters, and `Arc` drop already
        // decrements it.
    }

    /// Flush every dirty buffer owned by `device_id` to the backing
    /// device, in ascending `(DeviceId, u64)` key order.
    ///
    /// Implements RFC 0004 §Buffer cache `sync_fs` — the per-mount
    /// writeback primitive. Wired by the VFS layer into
    /// `SuperOps::sync_fs` and called from the `umount` path before the
    /// superblock is detached so on-disk state is consistent across a
    /// remount.
    ///
    /// # Filtering
    ///
    /// Only keys whose `DeviceId` equals `device_id` are flushed. The
    /// cache may host multiple mounts backed by the same
    /// `Arc<dyn BlockDevice>` (each with its own `DeviceId` allocated
    /// via [`register_device`](Self::register_device)); `sync_fs` on
    /// one mount must not flush another mount's dirty buffers.
    ///
    /// # Best-effort error propagation
    ///
    /// No batching: each matching dirty key is handed to
    /// [`sync_dirty_buffer`](Self::sync_dirty_buffer) in turn. The
    /// first `Err(BlockError)` is captured and returned; subsequent
    /// flushes continue so a transient failure on one buffer doesn't
    /// leave the rest of the mount's dirty state on the floor. Buffers
    /// that fail keep `STATE_DIRTY` set (per `sync_dirty_buffer`'s
    /// contract) and remain enlisted in the dirty set, so a retry
    /// (e.g. from the writeback daemon) will pick them up.
    ///
    /// # Concurrent mutation
    ///
    /// The dirty-set snapshot is taken under the dirty-set mutex then
    /// released before issuing any I/O, so concurrent `mark_dirty` /
    /// `sync_dirty_buffer` callers don't contend on the set for the
    /// duration of the sweep. A buffer enlisted after the snapshot
    /// won't be observed by this call — that's acceptable: a
    /// just-dirtied buffer is covered by the next `sync_fs` (or by the
    /// writeback daemon). A buffer whose key is in the snapshot but
    /// has since been evicted is silently skipped via the residency
    /// lookup inside `sync_dirty_buffer`.
    pub fn sync_fs(&self, device_id: DeviceId) -> Result<(), BlockError> {
        // Snapshot the dirty keys for this device under the dirty-set
        // mutex, then release it: issuing device I/O with a spinlock
        // held violates the OS-engineer B5 hazard (RFC 0004 §Buffer
        // cache) and would starve concurrent `mark_dirty` callers.
        let keys: alloc::vec::Vec<(DeviceId, u64)> = {
            let dirty = self.dirty.lock();
            dirty
                .iter()
                .filter(|(dev, _)| *dev == device_id)
                .copied()
                .collect()
        };

        let mut first_err: Option<BlockError> = None;
        for key in keys {
            // Re-look-up the buffer out of `entries` under the inner
            // lock. If it was evicted between snapshot and now, there's
            // nothing for us to flush — `sync_dirty_buffer` itself has
            // the same "not resident → success" fallback, but doing the
            // lookup here lets us skip the state CAS entirely.
            let bh = {
                let inner = self.inner.lock();
                inner.entries.get(&key).cloned()
            };
            let bh = match bh {
                Some(bh) => bh,
                None => {
                    // Evicted since snapshot. Drop the stale dirty-set
                    // entry so we don't keep re-observing it.
                    self.dirty.lock().remove(&key);
                    continue;
                }
            };
            if let Err(e) = self.sync_dirty_buffer(&bh) {
                // Best-effort: keep flushing the rest of the mount.
                // Surface only the first error so the caller has a
                // single actionable failure to log.
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// CLOCK-Pro eviction sweep.
    ///
    /// Rotates `clock_hand` through resident entries in BTreeMap key
    /// order. For each visited entry:
    ///
    /// - If `Arc::strong_count(buf) > 1` or `state & (DIRTY |
    ///   LOCKED_IO) != 0`, **skip unconditionally** — do not even
    ///   consume its `clock_ref` bit. A pinned/mid-I/O buffer is
    ///   invisible to the sweep (normative invariants 1 & 2).
    /// - If `clock_ref == true`: clear the bit; if the class is
    ///   [`ClockClass::Cold`], promote to [`ClockClass::Hot`] (it was
    ///   accessed during its cold-to-hot window).
    /// - If `clock_ref == false`: if the class is [`ClockClass::Cold`],
    ///   **this is the victim**. Remove from `entries`, `classes`, and
    ///   the dirty set; push the key onto `non_resident` (bounded by
    ///   `max_buffers`); return `Ok(())`.
    ///   If the class is [`ClockClass::Hot`], demote to
    ///   [`ClockClass::Cold`] and move on.
    ///
    /// If the hand completes a full revolution without finding a
    /// cold-and-unreferenced victim, returns [`BlockError::NoMemory`].
    /// The caller (`bread`) converts that into the user-visible
    /// ENOMEM (normative invariant 3).
    fn clock_pro_evict(inner: &mut CacheInner, max_buffers: usize) -> Result<(), BlockError> {
        // Worst case for convergence of this simplified CLOCK-Pro:
        //
        // - Revolution 1 clears every buffer's reference bit (and may
        //   promote Cold → Hot).
        // - Revolution 2 demotes unreferenced Hot → Cold.
        // - Revolution 3 evicts the first unreferenced Cold buffer.
        //
        // `3 * N + 1` iterations is therefore enough to either evict
        // or prove every entry is pin/dirty/locked-protected. The `+1`
        // guards against an off-by-one on the final advance.
        let n = inner.entries.len();
        let budget = n.saturating_mul(3).saturating_add(1).max(1);
        for _ in 0..budget {
            let hand = match inner.clock_hand {
                Some(k) => k,
                None => return Err(BlockError::NoMemory),
            };

            // Inspect the buffer through a borrow — we deliberately
            // **do not clone the `Arc` for the inspection step**.
            // `Arc::strong_count` counts every live `Arc<BufferHead>`,
            // including any temporary clone we'd take here, so a clone
            // would inflate the count and make every entry look pinned
            // (off-by-one bug). Borrowing through the map keeps the
            // count at exactly the number of external pins + 1
            // (the map slot itself).
            //
            // Normative invariant 1: pinned buffer is invisible.
            // Normative invariant 2: DIRTY | LOCKED_IO is invisible.
            let (pinned, busy_io, dirty, referenced) = {
                let bh = match inner.entries.get(&hand) {
                    Some(bh) => bh,
                    None => {
                        // Hand points at a key that was removed (by
                        // `remove` e.g.) — reset to first key and
                        // retry.
                        inner.clock_hand = inner.entries.keys().next().copied();
                        continue;
                    }
                };
                let pinned = Arc::strong_count(bh) > 1;
                let state = bh.state.load(Ordering::Acquire);
                let busy_io = state & STATE_LOCKED_IO != 0;
                let dirty = state & STATE_DIRTY != 0;
                // Only consume the reference bit on a non-skipped
                // entry — a pinned/dirty/locked buffer must not have
                // its CLOCK-Pro state perturbed by the sweep.
                let referenced = if pinned || busy_io || dirty {
                    false
                } else {
                    bh.clock_ref.swap(false, Ordering::AcqRel)
                };
                (pinned, busy_io, dirty, referenced)
            };
            if pinned || busy_io || dirty {
                // Advance the hand past this entry without changing
                // its classification or reference bit.
                inner.clock_hand = next_after(&inner.entries, hand);
                continue;
            }

            let class = *inner
                .classes
                .get(&hand)
                .expect("classes map mirrors entries");

            if referenced {
                if class == ClockClass::Cold {
                    // Cold + referenced → promote to hot; the sweep
                    // keeps going.
                    inner.classes.insert(hand, ClockClass::Hot);
                }
                // Hot + referenced → stay hot (bit already cleared).
                inner.clock_hand = next_after(&inner.entries, hand);
                continue;
            }

            // Unreferenced.
            match class {
                ClockClass::Cold => {
                    // Evict. Advance hand *before* the remove so we
                    // don't point at a key that no longer exists.
                    let advance_to = next_after(&inner.entries, hand);
                    inner.entries.remove(&hand);
                    inner.classes.remove(&hand);
                    // Bound `non_resident` at `max_buffers` (Jiang &
                    // Zhang §3.2): total resident + ghost metadata ≤
                    // 2 * max_buffers. Pop oldest ghosts until the
                    // push fits.
                    while inner.non_resident.len() >= max_buffers {
                        inner.non_resident.pop_front();
                    }
                    inner.non_resident.push_back(hand);
                    inner.clock_hand = advance_to;
                    return Ok(());
                }
                ClockClass::Hot => {
                    // Demote hot → cold; keep going.
                    inner.classes.insert(hand, ClockClass::Cold);
                    inner.clock_hand = next_after(&inner.entries, hand);
                }
            }
        }

        // Budget elapsed without finding a victim — everything
        // resident is pinned or mid-I/O.
        Err(BlockError::NoMemory)
    }
}

/// Return the first key strictly greater than `key` in `map`, wrapping
/// to the minimum key if there is no greater key. Returns `None` only
/// when the map is empty.
fn next_after(
    map: &BTreeMap<(DeviceId, u64), Arc<BufferHead>>,
    key: (DeviceId, u64),
) -> Option<(DeviceId, u64)> {
    // BTreeMap's range is sorted, so the first key > `key` is the
    // natural successor. If none exists, wrap to the smallest key.
    if let Some((&k, _)) = map
        .range((core::ops::Bound::Excluded(key), core::ops::Bound::Unbounded))
        .next()
    {
        Some(k)
    } else {
        map.keys().next().copied()
    }
}

/// The default `Arc<BlockCache>` singleton — populated once by the boot
/// path and read thereafter by the mount / filesystem code.
///
/// `Once` rather than `Lazy` because construction needs a live
/// [`BlockDevice`] that doesn't exist until virtio-blk probes. Tests
/// construct their own `BlockCache` via [`BlockCache::new`] and don't
/// touch this singleton.
static DEFAULT_CACHE: Once<Arc<BlockCache>> = Once::new();

/// Install `cache` as the default cache. First caller wins; subsequent
/// calls are ignored by `spin::Once::call_once`. Intended for the boot
/// path.
pub fn init_default_cache(cache: Arc<BlockCache>) {
    DEFAULT_CACHE.call_once(|| cache);
}

/// Return the default cache, if one has been installed.
pub fn default_cache() -> Option<Arc<BlockCache>> {
    DEFAULT_CACHE.get().cloned()
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use crate::block::{BlockError, SECTOR_SIZE};
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, AtomicUsize};
    use spin::Mutex;

    /// In-memory stand-in for a real `BlockDevice`. Only the bits the
    /// cache skeleton's trivial tests consult (`block_size`, `capacity`)
    /// are meaningful; `read_at` / `write_at` error so mis-wired callers
    /// fail loudly.
    struct StubDevice {
        block_size: u32,
        capacity: u64,
    }

    impl BlockDevice for StubDevice {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> Result<(), BlockError> {
            Err(BlockError::DeviceError)
        }
        fn write_at(&self, _offset: u64, _buf: &[u8]) -> Result<(), BlockError> {
            Err(BlockError::DeviceError)
        }
        fn block_size(&self) -> u32 {
            self.block_size
        }
        fn capacity(&self) -> u64 {
            self.capacity
        }
    }

    fn stub_cache(block_size: u32) -> Arc<BlockCache> {
        let dev: Arc<dyn BlockDevice> = Arc::new(StubDevice {
            block_size: SECTOR_SIZE as u32,
            capacity: 1 << 20,
        });
        BlockCache::new(dev, block_size, 64)
    }

    /// Working in-memory `BlockDevice` — backing store for `bread`,
    /// eviction, and writeback tests. Counts `read_at` / `write_at`
    /// invocations so tests can assert that the cache avoids the
    /// device on hit paths and drives it on miss paths.
    struct RamDisk {
        block_size: u32,
        storage: Mutex<Vec<u8>>,
        reads: AtomicU32,
        writes: AtomicU32,
    }

    impl RamDisk {
        fn new(block_size: u32, blocks: usize) -> Arc<Self> {
            let bytes = (block_size as usize) * blocks;
            Arc::new(Self {
                block_size,
                storage: Mutex::new(vec![0u8; bytes]),
                reads: AtomicU32::new(0),
                writes: AtomicU32::new(0),
            })
        }

        /// Pre-seed the block at `blk` with a deterministic byte
        /// pattern keyed by `seed` so tests can verify `bread` brought
        /// the right bytes back.
        fn seed_block(&self, blk: u64, seed: u8) {
            let mut s = self.storage.lock();
            let off = (blk as usize) * (self.block_size as usize);
            for (i, b) in s[off..off + self.block_size as usize]
                .iter_mut()
                .enumerate()
            {
                *b = seed.wrapping_add(i as u8);
            }
        }

        fn reads(&self) -> u32 {
            self.reads.load(Ordering::Relaxed)
        }
        fn writes(&self) -> u32 {
            self.writes.load(Ordering::Relaxed)
        }
    }

    impl BlockDevice for RamDisk {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            self.reads.fetch_add(1, Ordering::Relaxed);
            let bs = self.block_size as u64;
            if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
                return Err(BlockError::BadAlign);
            }
            let storage = self.storage.lock();
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or(BlockError::OutOfRange)?;
            if end > storage.len() as u64 {
                return Err(BlockError::OutOfRange);
            }
            let off = offset as usize;
            buf.copy_from_slice(&storage[off..off + buf.len()]);
            Ok(())
        }
        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
            self.writes.fetch_add(1, Ordering::Relaxed);
            let bs = self.block_size as u64;
            if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
                return Err(BlockError::BadAlign);
            }
            let mut storage = self.storage.lock();
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or(BlockError::Enospc)?;
            if end > storage.len() as u64 {
                return Err(BlockError::Enospc);
            }
            let off = offset as usize;
            storage[off..off + buf.len()].copy_from_slice(buf);
            Ok(())
        }
        fn block_size(&self) -> u32 {
            self.block_size
        }
        fn capacity(&self) -> u64 {
            self.storage.lock().len() as u64
        }
    }

    /// Build a `BlockCache` bound to a fresh `RamDisk`. The returned
    /// tuple lets tests drive the cache and assert on device-side
    /// counters.
    fn ramdisk_cache(
        block_size: u32,
        blocks: usize,
        max_buffers: usize,
    ) -> (Arc<BlockCache>, Arc<RamDisk>, DeviceId) {
        let disk = RamDisk::new(block_size, blocks);
        let cache = BlockCache::new(
            disk.clone() as Arc<dyn BlockDevice>,
            block_size,
            max_buffers,
        );
        let dev_id = cache.register_device();
        (cache, disk, dev_id)
    }

    #[test]
    fn state_bit_layout_matches_rfc() {
        // RFC 0004 pins the exact bitmask values: VALID=1, DIRTY=2,
        // LOCKED_IO=4. A renumber would silently invalidate on-wire
        // state logs and test fixtures, so pin the values here.
        assert_eq!(STATE_VALID, 1);
        assert_eq!(STATE_DIRTY, 2);
        assert_eq!(STATE_LOCKED_IO, 4);
    }

    #[test]
    fn buffer_head_new_is_block_sized_and_clear() {
        let bh = BufferHead::new(1024);
        assert_eq!(bh.data.read().len(), 1024);
        assert_eq!(bh.state.load(Ordering::Relaxed), 0);
        assert!(!bh.clock_ref.load(Ordering::Relaxed));
        assert!(!bh.state_has(STATE_VALID));
        assert!(!bh.state_has(STATE_DIRTY));
        assert!(!bh.state_has(STATE_LOCKED_IO));

        // `state_has` checks AND-of-mask: a single bit lit does not
        // satisfy a two-bit mask.
        bh.state.store(STATE_VALID, Ordering::Release);
        assert!(bh.state_has(STATE_VALID));
        assert!(!bh.state_has(STATE_VALID | STATE_DIRTY));
        bh.state.store(STATE_VALID | STATE_DIRTY, Ordering::Release);
        assert!(bh.state_has(STATE_VALID | STATE_DIRTY));
    }

    #[test]
    fn register_device_allocates_disjoint_ids() {
        let cache = stub_cache(1024);
        let a = cache.register_device();
        let b = cache.register_device();
        let c = cache.register_device();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
        // Ids are strictly monotonic — the eviction follow-up does not
        // depend on this, but it's the easiest implementation and the
        // cheapest to pin.
        assert_eq!(a.as_u32() + 1, b.as_u32());
        assert_eq!(b.as_u32() + 1, c.as_u32());
    }

    /// Core skeleton contract: insert / lookup / remove round-trip
    /// without exercising the read or eviction paths.
    #[test]
    fn insert_lookup_remove_roundtrip() {
        let cache = stub_cache(1024);
        let dev = cache.register_device();

        // Miss before insertion.
        assert!(cache.lookup(dev, 7).is_none());
        assert!(!cache.contains(dev, 7));
        assert_eq!(cache.len(), 0);
        assert!(cache.is_empty());

        // Insert.
        let bh = cache.insert_empty(dev, 7);
        assert_eq!(bh.data.read().len(), 1024);
        assert_eq!(cache.len(), 1);
        assert!(cache.contains(dev, 7));

        // Hit.
        let hit = cache.lookup(dev, 7).expect("lookup hit");
        assert!(Arc::ptr_eq(&hit, &bh));
        // Lookup set the CLOCK-Pro reference bit.
        assert!(hit.clock_ref.load(Ordering::Relaxed));

        // Reinsert under the same key returns the existing Arc (single
        // cache entry invariant).
        let reinsert = cache.insert_empty(dev, 7);
        assert!(Arc::ptr_eq(&reinsert, &bh));
        assert_eq!(cache.len(), 1);

        // Remove.
        let removed = cache.remove(dev, 7).expect("remove hit");
        assert!(Arc::ptr_eq(&removed, &bh));
        assert_eq!(cache.len(), 0);
        assert!(!cache.contains(dev, 7));
        assert!(cache.lookup(dev, 7).is_none());

        // Double-remove is idempotent.
        assert!(cache.remove(dev, 7).is_none());
    }

    /// Two registered device ids with the same block number must not
    /// alias — this is the whole point of the `(DeviceId, u64)` key
    /// shape (RFC 0004 §Buffer cache).
    #[test]
    fn device_ids_do_not_alias_on_same_block_number() {
        let cache = stub_cache(512);
        let dev_a = cache.register_device();
        let dev_b = cache.register_device();

        let bh_a = cache.insert_empty(dev_a, 42);
        let bh_b = cache.insert_empty(dev_b, 42);

        assert!(!Arc::ptr_eq(&bh_a, &bh_b));
        assert_eq!(cache.len(), 2);

        // Mutate each buffer distinctly; changes must not bleed.
        bh_a.data.write().iter_mut().for_each(|b| *b = 0xaa);
        bh_b.data.write().iter_mut().for_each(|b| *b = 0x55);

        let read_a = cache.lookup(dev_a, 42).unwrap();
        let read_b = cache.lookup(dev_b, 42).unwrap();
        assert!(read_a.data.read().iter().all(|b| *b == 0xaa));
        assert!(read_b.data.read().iter().all(|b| *b == 0x55));

        // Removing one device's entry leaves the other intact.
        cache.remove(dev_a, 42);
        assert!(!cache.contains(dev_a, 42));
        assert!(cache.contains(dev_b, 42));
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn block_size_is_carried_on_cache_not_entry() {
        let cache = stub_cache(4096);
        assert_eq!(cache.block_size(), 4096);
        let dev = cache.register_device();
        let bh = cache.insert_empty(dev, 0);
        assert_eq!(bh.data.read().len(), 4096);

        // A second cache at a different block size stays independent —
        // there is no per-entry block_size field, so the entry inherits
        // its cache's size at insert time.
        let other = stub_cache(1024);
        let other_dev = other.register_device();
        let other_bh = other.insert_empty(other_dev, 0);
        assert_eq!(other_bh.data.read().len(), 1024);
        assert_eq!(cache.block_size(), 4096);
    }

    #[test]
    fn default_cache_singleton_round_trip() {
        // `DEFAULT_CACHE` is a process-wide `Once`, so parallel host
        // tests share the slot. Checking `default_cache().is_none()`
        // up front and then calling `init_default_cache` is racy — a
        // sibling test could install between the check and the init.
        //
        // Assert the only thing that's actually guaranteed: after a
        // best-effort init (no-op if the slot was already claimed),
        // the getter returns `Some`, and repeated calls observe the
        // exact same `Arc`. That holds whether our init or a
        // sibling's init won the race.
        let our_cache = stub_cache(512);
        init_default_cache(our_cache);

        let a = default_cache().expect("default cache present after init");
        let b = default_cache().expect("default cache still present");
        assert!(
            Arc::ptr_eq(&a, &b),
            "default_cache() must return the same Arc on every call",
        );
    }

    /// Smoke-sanity that `Vec` is in scope — keeps the test file tight
    /// against future refactors that drop the import.
    #[test]
    fn imports_compile() {
        let _: Vec<u8> = Vec::new();
    }

    /// Zero `block_size` is rejected at construction — otherwise every
    /// future `bread` would translate to an offset-0 read that silently
    /// no-ops.
    #[test]
    #[should_panic(expected = "block_size must be non-zero")]
    fn new_rejects_zero_block_size() {
        let dev: Arc<dyn BlockDevice> = Arc::new(StubDevice {
            block_size: 512,
            capacity: 1 << 20,
        });
        let _ = BlockCache::new(dev, 0, 64);
    }

    /// A cache block size that is not a whole multiple of the device
    /// block size would produce device-misaligned I/O on every
    /// follow-up `bread`, which the `BlockDevice` layer already
    /// rejects with `BadAlign`. Fail loudly at mount time instead.
    #[test]
    #[should_panic(expected = "whole multiple of device block_size")]
    fn new_rejects_incompatible_block_size() {
        let dev: Arc<dyn BlockDevice> = Arc::new(StubDevice {
            block_size: 512,
            capacity: 1 << 20,
        });
        // 1023 is not a multiple of 512.
        let _ = BlockCache::new(dev, 1023, 64);
    }

    /// Equal block_size and multiple-of-512 are both accepted — locks
    /// in the "whole multiple, including 1x" contract.
    #[test]
    fn new_accepts_compatible_block_sizes() {
        // Exactly equal.
        let dev: Arc<dyn BlockDevice> = Arc::new(StubDevice {
            block_size: 512,
            capacity: 1 << 20,
        });
        let cache = BlockCache::new(dev, 512, 16);
        assert_eq!(cache.block_size(), 512);

        // 8× device block size (ext2-4KiB-on-512-sector case).
        let dev: Arc<dyn BlockDevice> = Arc::new(StubDevice {
            block_size: 512,
            capacity: 1 << 20,
        });
        let cache = BlockCache::new(dev, 4096, 16);
        assert_eq!(cache.block_size(), 4096);
    }

    // ---------- bread / mark_dirty / sync_dirty_buffer / release ----------

    /// Miss then hit. First `bread` calls `read_at`; the second does
    /// not — it's a pure cache hit.
    #[test]
    fn bread_hit_path_returns_cached_buffer_without_device_io() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 8);
        disk.seed_block(3, 0xa0);

        assert_eq!(disk.reads(), 0);
        let first = cache.bread(dev, 3).expect("bread miss populates");
        assert_eq!(disk.reads(), 1, "miss should drive one device read");
        assert!(first.state_has(STATE_VALID));
        // Seed pattern: 0xa0, 0xa1, 0xa2 ...
        {
            let data = first.data.read();
            assert_eq!(data[0], 0xa0);
            assert_eq!(data[1], 0xa1);
            assert_eq!(data[511], 0xa0u8.wrapping_add(511u16 as u8));
        }

        // Hit: no device traffic.
        let second = cache.bread(dev, 3).expect("bread hit");
        assert!(Arc::ptr_eq(&first, &second), "hit returns same Arc");
        assert_eq!(disk.reads(), 1, "hit must not re-issue read_at");
        // The reference bit got set on the hit — required for
        // CLOCK-Pro sweep to see the access.
        assert!(second.clock_ref.load(Ordering::Relaxed));
    }

    /// Miss path populates the buffer with device bytes and marks the
    /// entry `VALID`.
    #[test]
    fn bread_miss_populates_from_device() {
        let (cache, disk, dev) = ramdisk_cache(512, 32, 8);
        disk.seed_block(17, 0x42);

        assert!(!cache.contains(dev, 17));
        let bh = cache.bread(dev, 17).expect("bread miss");
        assert!(cache.contains(dev, 17));
        assert!(bh.state_has(STATE_VALID));
        assert!(!bh.state_has(STATE_DIRTY));
        assert!(!bh.state_has(STATE_LOCKED_IO));
        {
            let data = bh.data.read();
            assert_eq!(data[0], 0x42);
            assert_eq!(data[5], 0x42u8.wrapping_add(5));
        }
        assert_eq!(disk.reads(), 1);
    }

    /// Eviction evicts the cold-queue victim before any hot-queue
    /// entry. Seeds a full cache with one unreferenced HOT block
    /// (originally seeded COLD but not accessed again) and one
    /// repeatedly-accessed COLD block (promoted to HOT). A new miss
    /// must evict the low-priority block.
    #[test]
    fn eviction_prefers_cold_over_hot() {
        // max_buffers = 2 so the third bread must evict exactly one.
        let (cache, disk, dev) = ramdisk_cache(512, 8, 2);
        for b in 0..8 {
            disk.seed_block(b, (b as u8).wrapping_mul(0x11));
        }

        let _a = cache.bread(dev, 0).expect("bread 0");
        let _b = cache.bread(dev, 1).expect("bread 1");
        assert_eq!(cache.len(), 2);

        // Drop external handles so eviction isn't pin-blocked.
        drop(_a);
        drop(_b);

        // Heat up block 1 by repeated bread hits — sets `clock_ref`
        // and, on sweep, promotes its class Cold→Hot.
        for _ in 0..3 {
            let h = cache.bread(dev, 1).expect("bread 1 hit");
            drop(h);
        }

        // Manually run a sweep so block 1 gets promoted before we
        // pressure-test. The sweep won't find a victim on first pass
        // because block 0's ref bit was also set during its bread —
        // but it will demote hot→cold / promote cold→hot.
        //
        // We drive the sweep indirectly by a miss:
        let _c = cache.bread(dev, 2).expect("bread 2 evicts one of 0/1");
        assert_eq!(cache.len(), 2, "still capped at max_buffers=2");

        // Block 1 (the frequently-accessed one) must still be
        // resident; block 0 (the unrepeated-access one) is the
        // victim.
        assert!(cache.contains(dev, 1), "hot-queue block 1 survived");
        assert!(
            !cache.contains(dev, 0),
            "cold-queue block 0 should have been evicted first",
        );
    }

    /// Eviction refuses to evict a pinned buffer (strong_count > 1).
    /// With a max_buffers=1 cache holding one pinned buffer, a second
    /// miss must return `NoMemory` rather than steal the pinned slot.
    #[test]
    fn eviction_refuses_pinned_buffer() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 1);
        disk.seed_block(0, 0x11);
        disk.seed_block(1, 0x22);

        // Hold the pin live across the next bread.
        let _pin = cache.bread(dev, 0).expect("bread 0");
        assert_eq!(Arc::strong_count(&_pin), 2, "map + local handle");

        // Second miss cannot evict block 0 (pinned) and the cache is
        // at max_buffers.
        // Drop the `Ok` side so we don't require `Debug` on
        // `Arc<BufferHead>`.
        let err = cache
            .bread(dev, 1)
            .map(|_| ())
            .expect_err("ENOMEM expected");
        assert_eq!(err, BlockError::NoMemory);

        // Drop the pin, retry — now it succeeds.
        drop(_pin);
        let _ok = cache.bread(dev, 1).expect("bread 1 after unpin");
        assert!(!cache.contains(dev, 0), "unpinned 0 was evicted");
        assert!(cache.contains(dev, 1));
    }

    /// Eviction refuses to evict a DIRTY+LOCKED_IO buffer (normative
    /// invariant 2). Simulate mid-flight IO by setting both bits, then
    /// pressure the cache.
    #[test]
    fn eviction_refuses_dirty_locked_io_buffer() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 1);
        disk.seed_block(5, 0x77);
        disk.seed_block(6, 0x88);

        let victim = cache.bread(dev, 5).expect("bread 5");
        // Pretend writeback is in flight: DIRTY + LOCKED_IO both set.
        victim.state.store(
            STATE_VALID | STATE_DIRTY | STATE_LOCKED_IO,
            Ordering::Release,
        );
        // Drop the external pin so only DIRTY+LOCKED_IO is what
        // protects it.
        drop(victim);

        let err = cache
            .bread(dev, 6)
            .map(|_| ())
            .expect_err("should not flush-and-evict");
        assert_eq!(err, BlockError::NoMemory);

        // Block 5 is still resident; invariant 2 held.
        assert!(cache.contains(dev, 5));
        // The evictor must not have called write_at — normative
        // invariant 3: never synchronously flush from `bread`.
        assert_eq!(disk.writes(), 0, "bread must never flush dirty");
    }

    /// With max_buffers reached and every entry pinned, `bread`
    /// returns `NoMemory`.
    #[test]
    fn bread_returns_enomem_when_all_pinned() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 3);
        for b in 0..8 {
            disk.seed_block(b, b as u8);
        }

        // Fill cache to capacity with pins held live.
        let p0 = cache.bread(dev, 0).expect("0");
        let p1 = cache.bread(dev, 1).expect("1");
        let p2 = cache.bread(dev, 2).expect("2");
        assert_eq!(cache.len(), 3);

        // Fourth miss — all three are pinned, eviction must fail.
        let err = cache.bread(dev, 3).map(|_| ()).expect_err("ENOMEM");
        assert_eq!(err, BlockError::NoMemory);

        // Keep pins alive so the test doesn't accidentally succeed
        // via a post-drop retry.
        let _keep = (p0, p1, p2);
        assert_eq!(cache.len(), 3);
    }

    /// Single-cache-entry invariant: if the cache already has a
    /// buffer for `(dev, blk)` when a late `insert_empty` runs (which
    /// models a concurrent-miss loser), the existing `Arc` is what's
    /// returned. `bread`'s actual race window — between read + install
    /// — is exercised indirectly by `insert_empty` returning the
    /// current resident `Arc` in the same lock hold.
    #[test]
    fn single_cache_entry_under_concurrent_miss() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 4);
        disk.seed_block(9, 0x9a);

        let winner = cache.bread(dev, 9).expect("first bread");
        // Model the race: a second bread that started before `winner`
        // installed would find the winner's entry at install time and
        // return its `Arc`. We emulate the "found winner at install
        // time" step by calling `insert_empty` under the same key —
        // it must return the winner.
        let loser = cache.insert_empty(dev, 9);
        assert!(Arc::ptr_eq(&winner, &loser));
        assert_eq!(cache.len(), 1);

        // A third `bread` call from a different caller still gets the
        // same `Arc` — there is exactly one buffer per key.
        let third = cache.bread(dev, 9).expect("third bread");
        assert!(Arc::ptr_eq(&winner, &third));
    }

    /// `mark_dirty` flips the DIRTY bit and enlists the key into the
    /// dirty set. Idempotent.
    #[test]
    fn mark_dirty_sets_bit_and_enlists_key() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 4);
        disk.seed_block(2, 0x01);

        let bh = cache.bread(dev, 2).expect("bread 2");
        assert!(!bh.state_has(STATE_DIRTY));
        assert!(!cache.dirty.lock().contains(&(dev, 2)));

        cache.mark_dirty(&bh);
        assert!(bh.state_has(STATE_DIRTY));
        assert!(cache.dirty.lock().contains(&(dev, 2)));

        // Idempotent — second call is a no-op in observable state.
        cache.mark_dirty(&bh);
        assert!(bh.state_has(STATE_DIRTY));
        assert_eq!(cache.dirty.lock().len(), 1);
    }

    /// `sync_dirty_buffer` writes bytes to the device, clears DIRTY +
    /// LOCKED_IO, and drops the dirty-set key.
    #[test]
    fn sync_dirty_buffer_writes_and_clears_bits() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 4);
        disk.seed_block(4, 0x00);

        let bh = cache.bread(dev, 4).expect("bread 4");
        // Mutate the in-cache buffer.
        {
            let mut data = bh.data.write();
            for (i, b) in data.iter_mut().enumerate() {
                *b = i as u8;
            }
        }
        cache.mark_dirty(&bh);
        assert!(bh.state_has(STATE_DIRTY));
        assert!(cache.dirty.lock().contains(&(dev, 4)));

        let writes_before = disk.writes();
        cache.sync_dirty_buffer(&bh).expect("flush ok");
        assert_eq!(
            disk.writes(),
            writes_before + 1,
            "sync must drive one device write",
        );

        // DIRTY and LOCKED_IO are both clear.
        assert!(!bh.state_has(STATE_DIRTY));
        assert!(!bh.state_has(STATE_LOCKED_IO));
        assert!(bh.state_has(STATE_VALID));

        // Dirty-set key dropped.
        assert!(!cache.dirty.lock().contains(&(dev, 4)));

        // Device storage matches the pattern we wrote.
        {
            let storage = disk.storage.lock();
            let off = 4 * 512;
            assert_eq!(storage[off], 0);
            assert_eq!(storage[off + 1], 1);
            assert_eq!(storage[off + 511], 511u16 as u8);
        }
    }

    /// `release` drops one strong ref (the caller's) but leaves the
    /// cache's entry intact. Eviction-on-release is *not* required by
    /// this helper — the map's strong ref keeps the buffer resident
    /// until a CLOCK-Pro sweep evicts it.
    #[test]
    fn release_preserves_cache_residency() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 4);
        disk.seed_block(1, 0x22);

        let bh = cache.bread(dev, 1).expect("bread 1");
        assert_eq!(Arc::strong_count(&bh), 2, "map + local");
        cache.release(bh);
        // Cache still holds its strong ref — buffer is still resident.
        assert!(cache.contains(dev, 1));
        // A follow-up bread still hits — no re-read from device.
        let reads_before = disk.reads();
        let _again = cache.bread(dev, 1).expect("bread 1 still hits");
        assert_eq!(disk.reads(), reads_before, "still a cache hit");
    }

    /// `non_resident` ghost queue stays bounded by `max_buffers`. Every
    /// evicted key pushes a ghost; after many evictions the queue's
    /// length never exceeds `max_buffers`.
    #[test]
    fn non_resident_ghost_queue_is_bounded() {
        let (cache, disk, dev) = ramdisk_cache(512, 32, 2);
        for b in 0..32 {
            disk.seed_block(b, b as u8);
        }
        // Churn 20 distinct blocks through a size-2 cache. No pins
        // held, so every miss evicts one — the ghost queue builds up
        // but stays ≤ max_buffers.
        for b in 0..20 {
            let bh = cache.bread(dev, b).expect("bread");
            drop(bh);
        }
        assert!(
            cache.inner.lock().non_resident.len() <= 2,
            "non_resident must stay ≤ max_buffers=2, got {}",
            cache.inner.lock().non_resident.len(),
        );
    }

    /// CLOCK-Pro non-resident hit: re-reading a recently-evicted block
    /// installs it directly as HOT (not COLD). Observable via the
    /// `classes` map under the inner lock.
    #[test]
    fn non_resident_hit_installs_as_hot() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 2);
        disk.seed_block(0, 0x10);
        disk.seed_block(1, 0x20);
        disk.seed_block(2, 0x30);

        // Fill + churn: 0 and 1 resident; reading 2 evicts one of
        // them into non_resident.
        let _a = cache.bread(dev, 0).expect("0");
        let _b = cache.bread(dev, 1).expect("1");
        drop(_a);
        drop(_b);
        let _c = cache.bread(dev, 2).expect("2");
        drop(_c);

        // Find which one became a ghost.
        let ghost_key = {
            let inner = cache.inner.lock();
            inner.non_resident.iter().copied().next()
        };
        let ghost = ghost_key.expect("one non-resident ghost expected");

        // Re-read the ghost. It should come back as HOT because it
        // was non-resident.
        let _revive = cache.bread(ghost.0, ghost.1).expect("bread revives ghost");
        let class = *cache
            .inner
            .lock()
            .classes
            .get(&ghost)
            .expect("revived entry has a class");
        assert_eq!(class, ClockClass::Hot, "non-resident hit installs HOT");
    }

    /// `sync_dirty_buffer` must release the inner `data` RwLock before
    /// issuing the device write. Verify by holding a `data.read()` on
    /// another reference after marking dirty — if the flush were still
    /// holding the write/read lock, it would deadlock; if released, it
    /// completes.
    ///
    /// In the single-threaded host test we can't actually hold a
    /// concurrent lock across the call, so we assert the weaker
    /// property that a reader can take the RwLock *after* the flush
    /// returned, which would fail if `sync_dirty_buffer` poisoned or
    /// stuck the lock.
    #[test]
    fn sync_dirty_buffer_releases_inner_data_lock() {
        let (cache, disk, dev) = ramdisk_cache(512, 4, 4);
        disk.seed_block(0, 0x00);
        let bh = cache.bread(dev, 0).expect("bread");
        cache.mark_dirty(&bh);
        cache.sync_dirty_buffer(&bh).expect("flush ok");
        // Write lock acquirable — RwLock was not left poisoned or
        // held across the device write.
        let _w = bh.data.write();
        assert_eq!(_w.len(), 512);
    }

    /// Smoke: the cache's `AtomicUsize` type import is consumed so
    /// rustc doesn't prune it from `use core::sync::atomic`. Keeps
    /// the test-only import wired even if future refactors drop the
    /// direct reference.
    #[test]
    fn unused_atomic_import_stays_live() {
        let _ = AtomicUsize::new(0);
    }

    /// `sync_dirty_buffer` on a buffer that is **not** DIRTY issues
    /// no device write. Prevents a redundant `write_at` from a caller
    /// that opportunistically flushes without checking the bit.
    #[test]
    fn sync_dirty_buffer_skips_clean_buffer() {
        let (cache, disk, dev) = ramdisk_cache(512, 4, 4);
        disk.seed_block(0, 0x00);
        let bh = cache.bread(dev, 0).expect("bread");
        assert!(!bh.state_has(STATE_DIRTY));

        let writes_before = disk.writes();
        cache.sync_dirty_buffer(&bh).expect("clean flush is noop");
        assert_eq!(
            disk.writes(),
            writes_before,
            "clean buffer must not drive a device write",
        );
        // LOCKED_IO was never taken — fast-path bailed before CAS.
        assert!(!bh.state_has(STATE_LOCKED_IO));
    }

    // ---------- sync_fs (issue #554) ----------

    /// `sync_fs` on a mount with no dirty buffers is a successful no-op
    /// that issues no device writes.
    #[test]
    fn sync_fs_on_clean_cache_is_noop() {
        let (cache, disk, dev) = ramdisk_cache(512, 8, 4);
        disk.seed_block(0, 0x11);
        let _bh = cache.bread(dev, 0).expect("bread");
        let writes_before = disk.writes();
        cache.sync_fs(dev).expect("clean sync_fs ok");
        assert_eq!(
            disk.writes(),
            writes_before,
            "no dirty buffers → no device writes",
        );
    }

    /// `sync_fs` flushes every dirty buffer owned by the target
    /// `DeviceId`, clears the dirty bit, and drops the dirty-set keys.
    #[test]
    fn sync_fs_flushes_all_dirty_for_device() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 8);
        for b in 0..4 {
            disk.seed_block(b, 0);
        }

        // Dirty four buffers under `dev`.
        let mut handles = alloc::vec::Vec::new();
        for b in 0..4u64 {
            let bh = cache.bread(dev, b).expect("bread");
            {
                let mut data = bh.data.write();
                for slot in data.iter_mut() {
                    *slot = b as u8;
                }
            }
            cache.mark_dirty(&bh);
            assert!(bh.state_has(STATE_DIRTY));
            handles.push(bh);
        }
        assert_eq!(cache.dirty.lock().len(), 4);

        let writes_before = disk.writes();
        cache.sync_fs(dev).expect("sync_fs");
        assert_eq!(
            disk.writes(),
            writes_before + 4,
            "one device write per dirty buffer",
        );

        // DIRTY bits cleared, dirty set drained.
        for bh in &handles {
            assert!(!bh.state_has(STATE_DIRTY));
            assert!(!bh.state_has(STATE_LOCKED_IO));
        }
        assert!(cache.dirty.lock().is_empty());

        // On-disk bytes match what we wrote.
        {
            let storage = disk.storage.lock();
            for b in 0..4usize {
                let off = b * 512;
                assert!(
                    storage[off..off + 512].iter().all(|byte| *byte == b as u8),
                    "block {} not flushed correctly",
                    b,
                );
            }
        }
    }

    /// `sync_fs(dev_a)` must not flush buffers owned by `dev_b`, even
    /// when both devices share the same underlying `Arc<dyn BlockDevice>`.
    /// This is the whole point of filtering by `DeviceId` — one mount's
    /// sync is not allowed to affect another mount.
    #[test]
    fn sync_fs_is_scoped_to_device_id() {
        let (cache, disk, dev_a) = ramdisk_cache(512, 16, 8);
        // Second DeviceId on the same cache (models two concurrent mounts
        // sharing the same ramdisk — RFC 0004 §Buffer cache).
        let dev_b = cache.register_device();

        let bh_a = cache.bread(dev_a, 0).expect("bread a");
        {
            let mut data = bh_a.data.write();
            for slot in data.iter_mut() {
                *slot = 0xaa;
            }
        }
        cache.mark_dirty(&bh_a);

        let bh_b = cache.bread(dev_b, 0).expect("bread b");
        {
            let mut data = bh_b.data.write();
            for slot in data.iter_mut() {
                *slot = 0x55;
            }
        }
        cache.mark_dirty(&bh_b);

        assert!(bh_a.state_has(STATE_DIRTY));
        assert!(bh_b.state_has(STATE_DIRTY));
        assert_eq!(cache.dirty.lock().len(), 2);

        let writes_before = disk.writes();
        cache.sync_fs(dev_a).expect("sync_fs dev_a");
        assert_eq!(
            disk.writes(),
            writes_before + 1,
            "sync_fs(dev_a) flushes exactly one buffer",
        );

        // dev_a buffer: clean. dev_b buffer: still dirty (untouched).
        assert!(!bh_a.state_has(STATE_DIRTY), "dev_a buffer flushed");
        assert!(
            bh_b.state_has(STATE_DIRTY),
            "dev_b buffer must be left dirty"
        );
        assert!(!cache.dirty.lock().contains(&(dev_a, 0)));
        assert!(cache.dirty.lock().contains(&(dev_b, 0)));
    }

    /// `sync_fs` propagates the first `BlockError` from the underlying
    /// device but continues flushing the rest of the mount's dirty
    /// buffers (best-effort).
    #[test]
    fn sync_fs_best_effort_on_device_error() {
        /// Device that fails the Nth write (1-indexed); all other
        /// writes succeed and land in an in-memory backing store.
        struct FailingDisk {
            block_size: u32,
            storage: Mutex<alloc::vec::Vec<u8>>,
            writes: AtomicU32,
            fail_on_nth: u32,
        }
        impl BlockDevice for FailingDisk {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
                let storage = self.storage.lock();
                let off = offset as usize;
                if off + buf.len() > storage.len() {
                    return Err(BlockError::OutOfRange);
                }
                buf.copy_from_slice(&storage[off..off + buf.len()]);
                Ok(())
            }
            fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
                let n = self.writes.fetch_add(1, Ordering::Relaxed) + 1;
                if n == self.fail_on_nth {
                    return Err(BlockError::DeviceError);
                }
                let mut storage = self.storage.lock();
                let off = offset as usize;
                storage[off..off + buf.len()].copy_from_slice(buf);
                Ok(())
            }
            fn block_size(&self) -> u32 {
                self.block_size
            }
            fn capacity(&self) -> u64 {
                self.storage.lock().len() as u64
            }
        }

        let disk = Arc::new(FailingDisk {
            block_size: 512,
            storage: Mutex::new(vec![0u8; 512 * 16]),
            writes: AtomicU32::new(0),
            // Fail the *second* device write of the sweep.
            fail_on_nth: 2,
        });
        let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
        let dev = cache.register_device();

        // Dirty three buffers. Flush order follows BTreeSet iteration —
        // ascending `(dev, blk)` — so block 1 will be the 2nd (failing)
        // write.
        let mut handles = alloc::vec::Vec::new();
        for b in 0..3u64 {
            let bh = cache.bread(dev, b).expect("bread");
            {
                let mut data = bh.data.write();
                for slot in data.iter_mut() {
                    *slot = (b + 1) as u8;
                }
            }
            cache.mark_dirty(&bh);
            handles.push(bh);
        }

        let err = cache.sync_fs(dev).expect_err("first device error surfaces");
        assert_eq!(err, BlockError::DeviceError);

        // Device saw three writes — the sweep did not bail on the first
        // error, it best-effort continued.
        assert_eq!(disk.writes.load(Ordering::Relaxed), 3);

        // Block 0 and block 2 are clean; block 1 is still dirty (kept
        // enlisted for a retry).
        assert!(!handles[0].state_has(STATE_DIRTY));
        assert!(handles[1].state_has(STATE_DIRTY));
        assert!(!handles[2].state_has(STATE_DIRTY));
        assert!(cache.dirty.lock().contains(&(dev, 1)));
        assert!(!cache.dirty.lock().contains(&(dev, 0)));
        assert!(!cache.dirty.lock().contains(&(dev, 2)));
    }

    /// A dirty key whose buffer was evicted between snapshot and flush
    /// is silently skipped (and dropped from the dirty set) — `sync_fs`
    /// must not error on a stale dirty-set entry.
    #[test]
    fn sync_fs_skips_evicted_dirty_keys() {
        let (cache, disk, dev) = ramdisk_cache(512, 16, 4);
        disk.seed_block(7, 0x00);
        let bh = cache.bread(dev, 7).expect("bread");
        cache.mark_dirty(&bh);
        assert!(cache.dirty.lock().contains(&(dev, 7)));

        // Simulate eviction of the buffer while the dirty-set entry
        // lingers. Clear the DIRTY bit so the pulled-out `Arc` doesn't
        // fence the inner-lock eviction path; the dirty *set* key is
        // what `sync_fs` iterates.
        bh.state.fetch_and(!STATE_DIRTY, Ordering::AcqRel);
        drop(bh);
        // Forcibly remove the entry from the cache.
        {
            let mut inner = cache.inner.lock();
            inner.entries.remove(&(dev, 7));
            inner.classes.remove(&(dev, 7));
        }
        // Re-inject a stale dirty-set entry that no longer has a
        // resident buffer.
        cache.dirty.lock().insert((dev, 7));

        let writes_before = disk.writes();
        cache.sync_fs(dev).expect("stale dirty entry tolerated");
        assert_eq!(
            disk.writes(),
            writes_before,
            "evicted buffer must not drive a write",
        );
        assert!(
            !cache.dirty.lock().contains(&(dev, 7)),
            "stale dirty-set entry must be dropped",
        );
    }
}
