//! Block buffer cache — data-structure skeleton.
//!
//! Implements the **data structures** for the `(DeviceId, u64)`-keyed
//! block buffer cache described in RFC 0004 §Buffer cache (Workstream C,
//! wave 1).
//!
//! Scope of this module as it lands:
//!
//! - [`BufferHead`] — one block-sized slab + state bits + a reserved
//!   CLOCK-Pro reference bit.
//! - [`BlockCache`] — owns an `Arc<dyn BlockDevice>`, the per-device
//!   `block_size`, and the `(DeviceId, u64)`-keyed entry map. Exposes
//!   insert / lookup / remove primitives suitable for driving a unit
//!   test; the `bread` / `mark_dirty` / `sync_dirty_buffer` read and
//!   write-back paths are follow-up issues (#553+).
//! - [`DeviceId`] — opaque index allocated by the cache via
//!   [`BlockCache::register_device`]. Keeps the key narrow (8 bytes of
//!   hot map key vs. a full `Arc` pointer) and lets the cache host
//!   multiple mounts backed by the same `Arc<dyn BlockDevice>` without
//!   aliasing.
//! - [`default_cache`] / [`init_default_cache`] — the `Arc<BlockCache>`
//!   singleton hook the VFS mount path will eventually plug into.
//!
//! Out of scope (tracked in follow-up issues):
//!
//! - `bread` (populate-on-miss read path) and its `LOCKED_IO`
//!   bit-handshake with the backing device.
//! - `mark_dirty` / `sync_dirty_buffer` write-back path.
//! - CLOCK-Pro eviction. [`BufferHead::clock_ref`] is wired in now so
//!   the eviction issue can land without touching `BufferHead`.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use spin::{Mutex, Once, RwLock};

use super::BlockDevice;

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
    /// without synchronizing with the eviction sweep. Reserved for
    /// #553 — nothing in this module consults it yet.
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
    /// Cache body. `(DeviceId, u64)` is `Ord + Copy`, so `BTreeMap` is
    /// the natural fit under `no_std` (no `HashMap` without extra
    /// hashing infra). RFC 0004 sketches a `HashMap` but explicitly
    /// notes the key shape is what matters, not the container.
    entries: Mutex<BTreeMap<(DeviceId, u64), Arc<BufferHead>>>,
    /// Dirty-set mirror used by the writeback daemon (to be wired up
    /// with `mark_dirty`). Stored as keys, not `Weak` handles — the
    /// daemon re-looks-up the `Arc` out of `entries` on each sweep so
    /// an evicted-then-reloaded buffer still flushes correctly.
    dirty: Mutex<BTreeSet<(DeviceId, u64)>>,
    /// CLOCK-Pro hand. `None` until the first insertion reaches
    /// `max_buffers`. Reserved for #553 — nothing in this module
    /// advances it, so silence dead-code until the eviction sweep
    /// lands.
    #[allow(dead_code)]
    clock_hand: Mutex<Option<(DeviceId, u64)>>,
    /// Cap beyond which eviction must start reclaiming. Observed by
    /// the eviction follow-up; this module only stores it.
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
            entries: Mutex::new(BTreeMap::new()),
            dirty: Mutex::new(BTreeSet::new()),
            clock_hand: Mutex::new(None),
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
        let id = self.next_device_id.fetch_add(1, Ordering::Relaxed);
        assert!(
            id != u32::MAX,
            "BlockCache: exhausted 2^32 DeviceId space — mount churn is far above design",
        );
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
        self.entries.lock().contains_key(&(dev, blk))
    }

    /// Current number of resident entries. Primarily for tests and
    /// debug output.
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// `true` iff the cache holds no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }

    /// Look up `(dev, blk)`. Returns `None` on miss.
    ///
    /// On hit, sets `clock_ref=true` on the returned buffer so the
    /// CLOCK-Pro sweep (follow-up) observes the access.
    pub fn lookup(&self, dev: DeviceId, blk: u64) -> Option<Arc<BufferHead>> {
        let guard = self.entries.lock();
        let bh = guard.get(&(dev, blk))?.clone();
        bh.clock_ref.store(true, Ordering::Relaxed);
        Some(bh)
    }

    /// Allocate a fresh `BufferHead` sized to [`block_size`](Self::block_size)
    /// and insert it under `(dev, blk)`.
    ///
    /// **Skeleton behaviour:** this is a deliberately narrow primitive —
    /// the caller (tests today, `bread` in #553) must not already hold a
    /// buffer under this key. If one is resident, `insert_empty` returns
    /// the existing `Arc` unchanged and leaves the map untouched, which
    /// preserves the RFC's "single-cache-entry invariant" (§Eviction
    /// invariants #4). It does not populate `data` — the caller is
    /// responsible for reading from the device (or writing a synthetic
    /// payload, in test code) and then flipping [`STATE_VALID`].
    pub fn insert_empty(&self, dev: DeviceId, blk: u64) -> Arc<BufferHead> {
        let mut guard = self.entries.lock();
        if let Some(existing) = guard.get(&(dev, blk)) {
            return existing.clone();
        }
        let bh = Arc::new(BufferHead::new(self.block_size as usize));
        guard.insert((dev, blk), bh.clone());
        bh
    }

    /// Remove `(dev, blk)` from the cache if present. Also clears the
    /// dirty-set entry so a later reinsert with the same key starts
    /// clean. Returns the evicted `Arc<BufferHead>`, or `None` if the
    /// key wasn't resident.
    ///
    /// The caller is responsible for not removing a buffer that has
    /// outstanding [`STATE_LOCKED_IO`] — the eviction follow-up (#553)
    /// will add the sweep-time check; this primitive is a raw map
    /// operation.
    pub fn remove(&self, dev: DeviceId, blk: u64) -> Option<Arc<BufferHead>> {
        let bh = self.entries.lock().remove(&(dev, blk));
        self.dirty.lock().remove(&(dev, blk));
        bh
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

    /// In-memory stand-in for a real `BlockDevice`. Only the bits the
    /// cache skeleton consults (`block_size`, `capacity`) are
    /// meaningful; `read_at` / `write_at` are defined so the type is
    /// trait-complete but are not exercised by the skeleton's tests.
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
        // `init_default_cache` is a `Once`, so this test is only
        // meaningful on the first call within a test binary — other
        // test-runs that already installed a cache will see that
        // cache, not ours. Guard by inspecting the current state and
        // only asserting the shape we know holds.
        if default_cache().is_none() {
            let cache = stub_cache(512);
            init_default_cache(cache.clone());
            let fetched = default_cache().expect("default cache present after init");
            assert!(Arc::ptr_eq(&fetched, &cache));
        } else {
            // Something else already installed a cache in this test
            // binary. Just assert the getter is idempotent.
            let a = default_cache().unwrap();
            let b = default_cache().unwrap();
            assert!(Arc::ptr_eq(&a, &b));
        }
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
}
