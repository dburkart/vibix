//! Block-device layer.
//!
//! A thin public facade over whatever backend driver probed successfully
//! at boot. Today that's virtio-blk only; further backends would plug in
//! the same way.
//!
//! Exposes synchronous polled `read(lba, buf)` and `write(lba, buf)`
//! against the first detected virtio-blk device. No caching, no
//! interrupts — polled I/O only (issue #81 added the write path on top
//! of the original step-1 read-only driver from #43).
//!
//! # `BlockDevice` trait
//!
//! Per RFC 0004 (Workstream C), the block-device interface consumed by
//! the buffer cache and filesystem drivers is the byte-offset
//! [`BlockDevice`] trait — not the LBA-indexed module-level `read`/
//! `write` helpers. The trait object is what `BlockCache` and the ext2
//! driver hold (`Arc<dyn BlockDevice>`); the module-level API is retained
//! verbatim for the boot-time probe in `main.rs` and any remaining
//! pre-cache callers.

#[cfg(any(test, target_os = "none"))]
pub mod cache;
#[cfg(any(test, target_os = "none"))]
pub mod virtio_blk;

#[cfg(any(test, target_os = "none"))]
use alloc::sync::Arc;
#[cfg(any(test, target_os = "none"))]
use spin::Mutex;

/// Size of one disk sector in bytes. The virtio-blk spec fixes this at
/// 512 regardless of the underlying medium's physical block size.
pub const SECTOR_SIZE: usize = 512;

/// Block-layer error enum, consumable by the buffer cache, filesystem
/// drivers, and the legacy module-level `read`/`write` API.
///
/// Mappable onto kernel errnos at the VFS syscall boundary:
///
/// | Variant         | errno    |
/// |-----------------|----------|
/// | `DeviceError`   | `EIO`    |
/// | `Enospc`        | `ENOSPC` |
/// | `BadAlign`      | `EINVAL` |
/// | `NotInitialized`| `ENODEV` |
/// | `Timeout`       | `EIO`    |
/// | `OutOfRange`    | `EINVAL` |
/// | `NoMemory`      | `ENOMEM` |
///
/// Kept deliberately small — the cache and ext2 driver only need to
/// distinguish "retry is useless" from "range was invalid" from
/// "no space on device".
///
/// Pre-RFC-0004 code (the virtio-blk driver and the legacy `read`/
/// `write` helpers) used a narrower `BlkError { NotInitialized, BadAlign,
/// DeviceError, Timeout }`; the two names now refer to the same enum via
/// the [`BlkError`] alias.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// No block backend was successfully brought up during init.
    NotInitialized,
    /// Offset or buffer length violates the backend's alignment /
    /// granularity requirements (must be a non-zero multiple of
    /// `block_size()`, and — for virtio-blk step-1 — ≤ 4 KiB).
    BadAlign,
    /// Device reported or the driver inferred an I/O error (bad status
    /// byte, DMA fault, unrecoverable read).
    DeviceError,
    /// Bounded spin-wait for request completion elapsed.
    Timeout,
    /// Write would have extended the device past its capacity.
    Enospc,
    /// The requested byte range lies outside `[0, capacity())`.
    OutOfRange,
    /// Cache is full and eviction could find no victim buffer to reclaim.
    /// Every resident entry was either pinned (external `Arc` handle held
    /// by a caller) or mid-I/O (`DIRTY | LOCKED_IO`). Returned by
    /// [`cache::BlockCache::bread`] in lieu of synchronously flushing dirty
    /// buffers from the read path (RFC 0004 §Buffer cache, normative
    /// invariant #3). Maps to userspace `ENOMEM`.
    NoMemory,
}

/// Legacy error alias. See [`BlockError`] for the full taxonomy.
///
/// New code (the buffer cache, filesystem drivers) should prefer
/// [`BlockError`] directly; this alias exists so existing virtio-blk and
/// `block::read`/`write` call sites continue to compile unchanged.
pub type BlkError = BlockError;

/// Byte-offset block-device interface consumed by the buffer cache and
/// filesystem drivers.
///
/// Implementations are expected to be **synchronous and polled** for this
/// epic — no IRQ-driven or async I/O (see RFC 0004 Workstream C). Reads
/// and writes block the caller until the device acks or the
/// implementation-defined timeout elapses.
///
/// # Invariants
///
/// - `offset` and `buf.len()` are each a non-zero multiple of
///   [`block_size`](BlockDevice::block_size); violating implementations
///   return [`BlockError::BadAlign`].
/// - `offset + buf.len() as u64 <= capacity()`; violating implementations
///   return [`BlockError::OutOfRange`].
/// - `read_at` does not observe writes from a concurrent `write_at` on
///   the same device unless the write has already returned `Ok`.
///
/// # Why byte-offset and not LBA
///
/// The buffer cache keys on `(DeviceId, block_no)` but `block_no` is
/// cache-block-sized (typically 1024 or 4096 bytes), not 512-byte
/// sectors — which is what the virtio-blk wire protocol and other
/// future backends (loopback file, ramdisk) work in. Byte-offset is
/// the narrowest common denominator that lets the same trait object
/// serve a 1 KiB ext2 and a 4 KiB ext4 mount without a conversion
/// layer at each call site.
///
/// `BlockDevice` is `Send + Sync` so it can live inside
/// `Arc<dyn BlockDevice>`: the cache, the writeback daemon, and the
/// mount point all need to share one logical device.
pub trait BlockDevice: Send + Sync {
    /// Read `buf.len()` bytes starting at byte `offset`.
    ///
    /// `offset` and `buf.len()` must both be non-zero multiples of
    /// [`block_size`](Self::block_size); otherwise
    /// [`BlockError::BadAlign`] is returned. `offset + buf.len()` must
    /// not exceed [`capacity`](Self::capacity); otherwise
    /// [`BlockError::OutOfRange`] is returned.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError>;

    /// Write `buf.len()` bytes starting at byte `offset`.
    ///
    /// Same alignment / bounds rules as [`read_at`](Self::read_at).
    /// Writes that would extend past `capacity()` return
    /// [`BlockError::Enospc`] rather than `OutOfRange` — it's a
    /// distinct user-facing failure.
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError>;

    /// Logical block size in bytes. The minimum granularity for
    /// `read_at`/`write_at`. Typically 512 for virtio-blk; the buffer
    /// cache and filesystem layer can stack larger logical block sizes
    /// on top.
    fn block_size(&self) -> u32;

    /// Total addressable capacity in bytes.
    fn capacity(&self) -> u64;
}

/// Default block device brought up at boot. Populated by [`init`] and
/// read by the buffer cache / filesystem mount path. `None` if no
/// backend probed successfully.
#[cfg(any(test, target_os = "none"))]
static DEFAULT_DEVICE: Mutex<Option<Arc<dyn BlockDevice>>> = Mutex::new(None);

/// Return the default block device registered at boot, if any.
///
/// The returned `Arc<dyn BlockDevice>` is cheap to clone — the buffer
/// cache holds one, each mount holds one, etc.
#[cfg(any(test, target_os = "none"))]
pub fn default_device() -> Option<Arc<dyn BlockDevice>> {
    DEFAULT_DEVICE.lock().clone()
}

/// Register `dev` as the default block device. Idempotent in the sense
/// that a second call simply replaces the slot; there is currently no
/// buffer cache attached that would need to be torn down first. Intended
/// for the boot probe path and for tests that inject a ramdisk.
#[cfg(any(test, target_os = "none"))]
pub fn set_default_device(dev: Arc<dyn BlockDevice>) {
    *DEFAULT_DEVICE.lock() = Some(dev);
}

/// Probe PCI and bring up the first supported block device. Called once
/// from the main init sequence after `pci::scan()` and `mem::init()`.
#[cfg(target_os = "none")]
pub fn init() {
    virtio_blk::init();
    if virtio_blk::ready() {
        set_default_device(Arc::new(virtio_blk::VirtioBlk::new()) as Arc<dyn BlockDevice>);
    }
}

/// Read `buf.len() / 512` sectors starting at `lba` into `buf`.
///
/// `buf.len()` must be a non-zero multiple of [`SECTOR_SIZE`]. Blocks the
/// calling task on a polled spin-wait; intended for boot-time probes and
/// the not-yet-existent filesystem layer, not for general user traffic.
#[cfg(target_os = "none")]
pub fn read(lba: u64, buf: &mut [u8]) -> Result<(), BlockError> {
    virtio_blk::read(lba, buf)
}

/// Write `buf.len() / 512` sectors from `buf` starting at `lba`.
///
/// Same shape as [`read`]: `buf.len()` must be a non-zero multiple of
/// [`SECTOR_SIZE`] and must not exceed a single 4 KiB page (the bounce
/// buffer cap). Blocks on a polled spin-wait until the device reports
/// completion or the poll budget elapses.
#[cfg(target_os = "none")]
pub fn write(lba: u64, buf: &[u8]) -> Result<(), BlockError> {
    virtio_blk::write(lba, buf)
}

/// `true` once a backend has completed bring-up.
#[cfg(target_os = "none")]
pub fn ready() -> bool {
    virtio_blk::ready()
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use spin::Mutex;

    /// In-memory block device used to exercise the [`BlockDevice`] trait
    /// round-trip without standing up virtio-blk.
    struct RamBlockDevice {
        block_size: u32,
        storage: Mutex<Vec<u8>>,
    }

    impl RamBlockDevice {
        fn new(block_size: u32, blocks: usize) -> Self {
            let bytes = (block_size as usize) * blocks;
            Self {
                block_size,
                storage: Mutex::new(vec![0u8; bytes]),
            }
        }
    }

    impl BlockDevice for RamBlockDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
            let bs = self.block_size as u64;
            if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
                return Err(BlockError::BadAlign);
            }
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or(BlockError::OutOfRange)?;
            let storage = self.storage.lock();
            if end > storage.len() as u64 {
                return Err(BlockError::OutOfRange);
            }
            let off = offset as usize;
            buf.copy_from_slice(&storage[off..off + buf.len()]);
            Ok(())
        }

        fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
            let bs = self.block_size as u64;
            if buf.is_empty() || (buf.len() as u64) % bs != 0 || offset % bs != 0 {
                return Err(BlockError::BadAlign);
            }
            let end = offset
                .checked_add(buf.len() as u64)
                .ok_or(BlockError::Enospc)?;
            let mut storage = self.storage.lock();
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

    /// Trait-object round-trip: write via `&dyn BlockDevice`, read back
    /// via the same trait object, assert the bytes match. Exercises the
    /// full virtual dispatch path the buffer cache will use.
    #[test]
    fn trait_object_roundtrip() {
        let dev: Arc<dyn BlockDevice> = Arc::new(RamBlockDevice::new(512, 16));
        assert_eq!(dev.block_size(), 512);
        assert_eq!(dev.capacity(), 512 * 16);

        let mut payload = [0u8; 512];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(3).wrapping_add(0x5a);
        }
        dev.write_at(512 * 4, &payload).expect("write_at");

        let mut readback = [0u8; 512];
        dev.read_at(512 * 4, &mut readback).expect("read_at");
        assert_eq!(readback, payload);

        // Untouched block is still zeros — proves the write hit the
        // right offset and didn't spill.
        let mut other = [0xffu8; 512];
        dev.read_at(0, &mut other).expect("read_at lba 0");
        assert!(other.iter().all(|b| *b == 0));
    }

    #[test]
    fn misaligned_offset_and_length_are_rejected() {
        let dev: Arc<dyn BlockDevice> = Arc::new(RamBlockDevice::new(512, 4));
        let mut buf = [0u8; 512];

        // Misaligned offset.
        assert_eq!(
            dev.read_at(1, &mut buf),
            Err(BlockError::BadAlign),
            "offset 1 should be rejected"
        );

        // Misaligned length.
        let mut short = [0u8; 511];
        assert_eq!(
            dev.read_at(0, &mut short),
            Err(BlockError::BadAlign),
            "511-byte read should be rejected"
        );

        // Empty buffer.
        let mut empty: [u8; 0] = [];
        assert_eq!(dev.read_at(0, &mut empty), Err(BlockError::BadAlign));
    }

    #[test]
    fn out_of_range_read_returns_oor() {
        let dev: Arc<dyn BlockDevice> = Arc::new(RamBlockDevice::new(512, 4));
        // Capacity is 4 * 512 = 2048. Offset 2048 is one past the last
        // byte, so any non-zero read should fail.
        let mut buf = [0u8; 512];
        assert_eq!(dev.read_at(2048, &mut buf), Err(BlockError::OutOfRange));
        assert_eq!(
            dev.read_at(1536, &mut [0u8; 1024]),
            Err(BlockError::OutOfRange)
        );
    }

    #[test]
    fn out_of_range_write_returns_enospc() {
        let dev: Arc<dyn BlockDevice> = Arc::new(RamBlockDevice::new(512, 4));
        let buf = [0u8; 512];
        assert_eq!(dev.write_at(2048, &buf), Err(BlockError::Enospc));
    }

    /// Exercises the `set_default_device` / `default_device` registry
    /// path the boot probe uses. Host-only — the target-side init path
    /// is covered by the QEMU boot log.
    #[test]
    fn default_device_registry_roundtrip() {
        // Leave the slot in whatever state we found it in — other tests
        // running in the same binary might have set it. We assert only
        // that a set call followed by a get returns our exact device.
        let dev: Arc<dyn BlockDevice> = Arc::new(RamBlockDevice::new(1024, 8));
        let ptr = Arc::as_ptr(&dev) as *const ();
        set_default_device(dev);
        let fetched = default_device().expect("default_device after set_default_device");
        assert_eq!(Arc::as_ptr(&fetched) as *const (), ptr);
        assert_eq!(fetched.block_size(), 1024);
        assert_eq!(fetched.capacity(), 1024 * 8);
    }

    /// Pin `BlkError` as a compatibility alias for `BlockError` so old
    /// match arms keep working — protects the virtio-blk driver and the
    /// legacy `block::read`/`write` helpers from silent breakage.
    #[test]
    fn blkerror_is_block_error() {
        let e: BlkError = BlockError::BadAlign;
        assert_eq!(e, BlockError::BadAlign);

        // Every legacy variant still resolves through the alias.
        let _: BlkError = BlkError::NotInitialized;
        let _: BlkError = BlkError::BadAlign;
        let _: BlkError = BlkError::DeviceError;
        let _: BlkError = BlkError::Timeout;
    }
}
