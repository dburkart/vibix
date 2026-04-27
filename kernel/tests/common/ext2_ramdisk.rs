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
//! Intentionally minimal — just the constructor, the read-only latch,
//! the write-count probe, and the `BlockDevice` impl:
//!
//! - [`RamDisk::from_image`] — wrap an in-memory image, asserting the
//!   length is a multiple of `block_size`.
//! - [`RamDisk::set_read_only`] — flip the harness-level RO latch so a
//!   forgotten dirty-writeback path surfaces as `BlockError::ReadOnly`
//!   instead of silently mutating the image.
//! - [`RamDisk::writes`] — observe the cumulative write count for
//!   "RO mount must not issue any writes" assertions.
//! - `BlockDevice` impl — block-aligned `read_at` / `write_at` over a
//!   `Mutex<Vec<u8>>`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};

pub struct RamDisk {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    writes: AtomicU32,
    read_only: AtomicBool,
}

impl RamDisk {
    /// Wrap `bytes` as an in-memory block device with the given
    /// `block_size`. The image length must be a multiple of the block
    /// size — otherwise `read_at` / `write_at` would have unreachable
    /// trailing bytes.
    pub fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(bytes.len() % block_size as usize == 0);
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
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
