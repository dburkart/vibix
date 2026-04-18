//! Integration test for issue #554: `BlockCache::sync_fs` flushes one
//! mount's dirty buffers to the backing device while leaving a
//! different mount's dirty buffers alone.
//!
//! Runs the real kernel under QEMU. Exercises:
//!
//! - **write + sync_fs + drop cache + "remount"**: dirty a buffer,
//!   flush via `sync_fs`, then drop the cache and reconstruct a fresh
//!   one backed by the same ramdisk. `bread` on the second cache sees
//!   the bytes on disk — proving `sync_fs` persisted them through the
//!   cache teardown.
//! - **cross-mount isolation**: a single `BlockCache` hosts two
//!   `DeviceId`s (two concurrent mounts sharing the same physical
//!   device — the shape RFC 0004 §Buffer cache allows). `sync_fs` on
//!   one must leave the other's dirty buffer untouched.
//!
//! Complements the host-side unit tests in
//! `kernel/src/block/cache.rs::tests`; this integration test
//! re-exercises the same invariants against the live heap /
//! interrupt-enabled kernel environment.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::cache::{BlockCache, STATE_DIRTY};
use vibix::block::{BlockDevice, BlockError};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "sync_fs_persists_across_cache_teardown",
            &(sync_fs_persists_across_cache_teardown as fn()),
        ),
        (
            "sync_fs_does_not_flush_other_mount",
            &(sync_fs_does_not_flush_other_mount as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Shared in-memory ramdisk — lets two sequential `BlockCache` instances
// share the same backing storage so test 1 can observe "remount"
// semantics.
// ---------------------------------------------------------------------------

struct RamDisk {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    writes: AtomicU32,
}

impl RamDisk {
    fn new(block_size: u32, blocks: usize) -> Arc<Self> {
        let bytes = (block_size as usize) * blocks;
        Arc::new(Self {
            block_size,
            storage: Mutex::new(vec![0u8; bytes]),
            writes: AtomicU32::new(0),
        })
    }

    fn writes(&self) -> u32 {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Write a pattern through `BlockCache A`, `sync_fs`, drop the cache
/// (models umount), then build a fresh `BlockCache B` on the same
/// ramdisk (models a second mount) and verify `bread` returns the
/// persisted bytes.
///
/// This is the "write + sync_fs + drop cache + remount; data is
/// present" test from issue #554.
fn sync_fs_persists_across_cache_teardown() {
    let disk = RamDisk::new(512, 16);

    // --- Phase 1: mount 1, dirty block 5, sync_fs, drop cache. ---
    {
        let cache_a = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
        let dev_a = cache_a.register_device();
        let bh = cache_a.bread(dev_a, 5).expect("bread 5");
        {
            let mut data = bh.data.write();
            for (i, slot) in data.iter_mut().enumerate() {
                *slot = 0xc0u8.wrapping_add(i as u8);
            }
        }
        cache_a.mark_dirty(&bh);
        assert!(bh.state_has(STATE_DIRTY));

        let writes_before = disk.writes();
        cache_a.sync_fs(dev_a).expect("sync_fs ok");
        assert_eq!(
            disk.writes(),
            writes_before + 1,
            "sync_fs drove exactly one device write",
        );
        assert!(!bh.state_has(STATE_DIRTY), "DIRTY cleared after sync_fs");

        // Drop explicit handle + the cache Arc. Cache goes away with any
        // resident buffers; only the ramdisk bytes survive.
        drop(bh);
        drop(cache_a);
    }

    // --- Phase 2: fresh cache on the same ramdisk. bread must see the
    //     bytes `sync_fs` committed, because the cache was empty on
    //     construction — the only place the bytes can come from is the
    //     backing device. ---
    let cache_b = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev_b = cache_b.register_device();
    let bh = cache_b.bread(dev_b, 5).expect("bread 5 on fresh cache");
    let data = bh.data.read();
    for (i, byte) in data.iter().enumerate() {
        assert_eq!(
            *byte,
            0xc0u8.wrapping_add(i as u8),
            "byte {} mismatch after remount — sync_fs did not persist",
            i,
        );
    }
}

/// One `BlockCache` hosting two `DeviceId`s (the RFC 0004 §Buffer
/// cache "two concurrent mounts backed by the same ramdisk" shape):
/// `sync_fs(dev_a)` must not touch a dirty buffer owned by `dev_b`.
///
/// This is the "sync_fs does NOT flush buffers belonging to a
/// different mount" test from issue #554.
fn sync_fs_does_not_flush_other_mount() {
    let disk = RamDisk::new(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev_a = cache.register_device();
    let dev_b = cache.register_device();

    // Dirty one buffer under each mount. Use the same block number on
    // purpose — the `(DeviceId, u64)` key shape must keep them distinct.
    let bh_a = cache.bread(dev_a, 3).expect("bread dev_a");
    {
        let mut data = bh_a.data.write();
        for slot in data.iter_mut() {
            *slot = 0xaa;
        }
    }
    cache.mark_dirty(&bh_a);

    let bh_b = cache.bread(dev_b, 3).expect("bread dev_b");
    {
        let mut data = bh_b.data.write();
        for slot in data.iter_mut() {
            *slot = 0x55;
        }
    }
    cache.mark_dirty(&bh_b);

    assert!(bh_a.state_has(STATE_DIRTY));
    assert!(bh_b.state_has(STATE_DIRTY));

    let writes_before = disk.writes();
    cache.sync_fs(dev_a).expect("sync_fs dev_a");

    // Exactly one device write: the dev_a buffer. dev_b is untouched.
    assert_eq!(
        disk.writes(),
        writes_before + 1,
        "sync_fs(dev_a) must drive exactly one write",
    );
    assert!(!bh_a.state_has(STATE_DIRTY), "dev_a flushed");
    assert!(
        bh_b.state_has(STATE_DIRTY),
        "dev_b must remain dirty — sync_fs is scoped",
    );

    // Now flush dev_b to confirm it was still enlisted.
    cache.sync_fs(dev_b).expect("sync_fs dev_b");
    assert_eq!(
        disk.writes(),
        writes_before + 2,
        "sync_fs(dev_b) now flushes the held-back buffer",
    );
    assert!(!bh_b.state_has(STATE_DIRTY));
}
