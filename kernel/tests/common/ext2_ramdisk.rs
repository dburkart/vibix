//! Shared `RamDisk` helper for ext2 integration tests.
//!
//! Every ext2 integration test needs a `BlockDevice`-shaped backing
//! store over the 64 KiB golden image. Before this helper, each test
//! file (`ext2_ialloc.rs`, `ext2_dir_ops.rs`, `ext2_unlink.rs`, ...)
//! carried a near-identical ~70-line copy of the same struct. CodeRabbit
//! flagged the duplication on #626 (issue #627).
//!
//! ## Include pattern
//!
//! Integration tests under `kernel/tests/` are each their own
//! `#![no_std] #![no_main]` crate, so a normal `mod common; use common::...;`
//! reference would fail to resolve and would also try to compile the
//! file as its own test binary. Instead, every consumer pulls this in
//! with the per-file `#[path = "..."]` include pattern:
//!
//! ```ignore
//! #[path = "common/ext2_ramdisk.rs"]
//! mod ext2_ramdisk;
//! use ext2_ramdisk::RamDisk;
//! ```
//!
//! That makes the file an inline module of the consumer crate, which
//! keeps it under the `no_std` / `no_main` harness without ever being
//! built as a standalone test binary.
//!
//! ## Surface
//!
//! Kept lean — just the constructors, the read-only latch, the
//! write-count probe, two image-poking accessors, and the
//! `BlockDevice` impl:
//!
//! - [`RamDisk::from_image`] — wrap an in-memory image, asserting the
//!   length is a multiple of `block_size`.
//! - [`RamDisk::zeroed`] — allocate a zero-initialized image of
//!   `block_size * blocks` bytes (used by the block-cache /
//!   writeback tests, which don't seed from a fixture).
//! - [`RamDisk::set_read_only`] — flip the harness-level RO latch so a
//!   forgotten dirty-writeback path surfaces as `BlockError::ReadOnly`
//!   instead of silently mutating the image.
//! - [`RamDisk::writes`] — observe the cumulative write count for
//!   "RO mount must not issue any writes" assertions.
//! - [`RamDisk::read_slot`] / [`RamDisk::patch`] — direct byte-level
//!   peek / poke into the backing storage, used by the `ext2_mount`
//!   tests to surgically corrupt header fields before mount.
//! - `BlockDevice` impl — block-aligned `read_at` / `write_at` over a
//!   `Mutex<Vec<u8>>`.
//!
//! ## Cross-area use
//!
//! The block-cache tests (`block_cache_sync_fs.rs`,
//! `block_writeback.rs`) and the VFS mount-path test
//! (`mount_dev_resolve.rs`) also pull this in even though they aren't
//! ext2-specific. Splitting a second copy under e.g.
//! `tests/common/block_ramdisk.rs` would just re-introduce the
//! duplication this module exists to kill, so the helper lives here
//! and the non-ext2 consumers document the cross-area pull at the
//! include site.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};

// Each integration test pulls this module in via `#[path = ...] mod`,
// which means rustc sees the file fresh in every consumer crate and
// flags any helper that crate doesn't call. The set of methods used
// per consumer varies (some only need `from_image`, the block-cache
// tests need `zeroed`+`writes`, `ext2_mount` needs `patch`+`read_slot`,
// etc.), so suppressing the dead-code warning at the module level is
// simpler than chasing per-call-site allows.
#[allow(dead_code)]
pub struct RamDisk {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    writes: AtomicU32,
    read_only: AtomicBool,
}

#[allow(dead_code)]
impl RamDisk {
    /// Wrap `bytes` as an in-memory block device with the given
    /// `block_size`. The image length must be a multiple of the block
    /// size — otherwise `read_at` / `write_at` would have unreachable
    /// trailing bytes.
    pub fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(
            bytes.len() % block_size as usize == 0,
            "image size {} must be a multiple of block_size {}",
            bytes.len(),
            block_size,
        );
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
            writes: AtomicU32::new(0),
            read_only: AtomicBool::new(false),
        })
    }

    /// Allocate a zero-initialized image of `block_size * blocks`
    /// bytes. Used by the block-cache and writeback tests, which
    /// don't seed from a fixture.
    pub fn zeroed(block_size: u32, blocks: usize) -> Arc<Self> {
        let bytes = (block_size as usize) * blocks;
        Arc::new(Self {
            block_size,
            storage: Mutex::new(vec![0u8; bytes]),
            writes: AtomicU32::new(0),
            read_only: AtomicBool::new(false),
        })
    }

    /// Flip the harness-level RO latch. While set, every `write_at`
    /// returns `BlockError::ReadOnly` so a buggy writeback path surfaces
    /// loudly instead of silently mutating the in-memory image.
    pub fn set_read_only(&self, ro: bool) {
        self.read_only.store(ro, Ordering::Relaxed);
    }

    /// Cumulative count of `write_at` calls that reached storage.
    /// Lets RO tests assert `writes() == 0`.
    pub fn writes(&self) -> u32 {
        self.writes.load(Ordering::Relaxed)
    }

    /// Copy `buf.len()` bytes out of the backing storage starting at
    /// `offset`, with no alignment / block-size requirement. Lets a
    /// test inspect a slice of the image directly (e.g. confirming an
    /// on-disk header reverted after a failed mount).
    pub fn read_slot(&self, offset: usize, buf: &mut [u8]) {
        let storage = self.storage.lock();
        buf.copy_from_slice(&storage[offset..offset + buf.len()]);
    }

    /// Run `f` against an exclusive view of the backing storage. Lets
    /// a test surgically corrupt an on-disk field before mount
    /// without going through the `BlockDevice` write path (so it
    /// doesn't bump the `writes` counter or trip the RO latch).
    pub fn patch<F: FnOnce(&mut [u8])>(&self, f: F) {
        let mut storage = self.storage.lock();
        f(&mut storage);
    }
}

impl BlockDevice for RamDisk {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
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
        // Honor the harness-level RO latch first: a read-only mount
        // must never reach storage with a write. Returning ReadOnly
        // (instead of silently mutating) lets the RO tests assert
        // writes() == 0 and catches regressions where a future
        // dirty-writeback path forgets to gate on MS_RDONLY.
        if self.read_only.load(Ordering::Relaxed) {
            return Err(BlockError::ReadOnly);
        }
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
        self.writes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn capacity(&self) -> u64 {
        self.storage.lock().len() as u64
    }
}
