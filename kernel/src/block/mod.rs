//! Block-device layer.
//!
//! A thin public facade over whatever backend driver probed successfully
//! at boot. Today that's virtio-blk only; further backends would plug in
//! the same way.
//!
//! Exposes synchronous polled `read(lba, buf)` and `write(lba, buf)`
//! against the first detected virtio-blk device. Reads go through a
//! small in-memory [`cache`] (set-associative, 4 KiB lines) and writes
//! invalidate any overlapping cached page before hitting the driver —
//! write-back is deliberately out of scope (issue #82). Polled I/O,
//! no interrupts.

#[cfg(any(test, target_os = "none"))]
pub mod virtio_blk;

pub mod cache;

/// Size of one disk sector in bytes. The virtio-blk spec fixes this at
/// 512 regardless of the underlying medium's physical block size.
pub const SECTOR_SIZE: usize = 512;

/// Errors surfaced by the block API.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum BlkError {
    /// No block backend was successfully brought up during init.
    NotInitialized,
    /// Buffer length isn't a non-zero multiple of [`SECTOR_SIZE`].
    BadAlign,
    /// Device reported an error completing the request.
    DeviceError,
    /// Bounded spin-wait for request completion elapsed.
    Timeout,
}

/// Probe PCI and bring up the first supported block device. Called once
/// from the main init sequence after `pci::scan()` and `mem::init()`.
#[cfg(target_os = "none")]
pub fn init() {
    virtio_blk::init();
    cache::init();
}

/// Read `buf.len() / 512` sectors starting at `lba` into `buf`.
///
/// `buf.len()` must be a non-zero multiple of [`SECTOR_SIZE`]. Routed
/// through the block [`cache`]: previously-seen pages return without
/// hitting the device. Blocks the calling task on a polled spin-wait
/// on cache miss.
#[cfg(target_os = "none")]
pub fn read(lba: u64, buf: &mut [u8]) -> Result<(), BlkError> {
    cache::read_through(lba, buf)
}

/// Write `buf.len() / 512` sectors from `buf` starting at `lba`.
///
/// Same shape as [`read`]. Invalidates any cached page overlapping the
/// written range, then issues the write through the driver. Blocks on
/// a polled spin-wait until the device reports completion or the poll
/// budget elapses.
#[cfg(target_os = "none")]
pub fn write(lba: u64, buf: &[u8]) -> Result<(), BlkError> {
    cache::write_invalidate(lba, buf)
}

/// `true` once a backend has completed bring-up.
#[cfg(target_os = "none")]
pub fn ready() -> bool {
    virtio_blk::ready()
}

/// Monotonic cache counters (hits/misses/invalidations/fills).
#[cfg(target_os = "none")]
pub fn cache_stats() -> cache::CacheStats {
    cache::stats()
}
