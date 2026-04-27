//! Integration test for issue #565: block-bitmap allocator.
//!
//! Runs the real kernel under QEMU, in-process: mounts the
//! `balloc_test.img` fixture (see
//! `kernel/src/fs/ext2/fixtures/README.md`) read-write and exercises
//! `alloc_block` / `free_block` against a two-group filesystem.
//!
//! Coverage:
//!
//! - **Round-trip in group 0**: the first `alloc_block` returns block
//!   26 (the first free block on the fixture), counters drop by one,
//!   bitmap bit is persisted on disk. `free_block(26)` restores the
//!   counters and clears the bit.
//! - **Cross-group spill**: simulate group 0 being full by draining it
//!   to exhaustion, then confirm the next `alloc_block` returns a
//!   block from group 1 (`>= 269`).
//! - **Metadata-block free is rejected**: `free_block(1)` (the
//!   superblock) and `free_block(3)` (group 0's block bitmap) both
//!   return `EIO` without touching the counters.
//! - **RO mount refuses alloc**: a second mount of the same image with
//!   `MountFlags::RDONLY` rejects `alloc_block` with `EROFS`.
//!
//! The fixture is loaded into a `RamDisk` (in-memory `BlockDevice`) so
//! each test starts from a clean image copy.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{alloc_block, free_block, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EIO, ENOSPC, EROFS};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const BALLOC_IMG: &[u8; 524_288] = include_bytes!("../src/fs/ext2/fixtures/balloc_test.img");

// Fixture constants pinned to the mkfs.ext2 invocation documented in
// `fixtures/README.md`. A regenerated fixture with different geometry
// would trip these asserts loudly rather than silently mis-testing.
const FIXTURE_BLOCKS_COUNT: u32 = 512;
const FIXTURE_BLOCKS_PER_GROUP: u32 = 256;
const FIXTURE_GROUP0_FIRST_FREE: u32 = 26;
const FIXTURE_GROUP1_FIRST_FREE: u32 = 269;
const FIXTURE_FREE_BLOCKS_AT_MOUNT: u32 = 474;

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
            "alloc_free_round_trip_group0",
            &(alloc_free_round_trip_group0 as fn()),
        ),
        (
            "alloc_spills_to_group1_when_group0_full",
            &(alloc_spills_to_group1_when_group0_full as fn()),
        ),
        (
            "free_rejects_superblock_block",
            &(free_rejects_superblock_block as fn()),
        ),
        (
            "free_rejects_block_bitmap_block",
            &(free_rejects_block_bitmap_block as fn()),
        ),
        (
            "free_rejects_out_of_range",
            &(free_rejects_out_of_range as fn()),
        ),
        (
            "free_rejects_backup_sb_and_bgdt",
            &(free_rejects_backup_sb_and_bgdt as fn()),
        ),
        ("double_free_forces_ro", &(double_free_forces_ro as fn())),
        ("ro_mount_refuses_alloc", &(ro_mount_refuses_alloc as fn())),
        (
            "alloc_exhaustion_returns_enospc",
            &(alloc_exhaustion_returns_enospc as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk copy — same pattern as the sibling ext2 tests.
// ---------------------------------------------------------------------------

struct RamDisk {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    writes: AtomicU32,
}

impl RamDisk {
    fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(bytes.len() % block_size as usize == 0);
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
            writes: AtomicU32::new(0),
        })
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

// ---------------------------------------------------------------------------
// Mount helpers
// ---------------------------------------------------------------------------

fn mount_rw() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>, Arc<RamDisk>) {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let disk_cloned = disk.clone();
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("RW mount must succeed on balloc_test.img");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after successful mount");
    (sb, fs, super_arc, disk_cloned)
}

fn mount_ro() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed on balloc_test.img");
    let super_arc = fs.current_super().expect("current_super");
    (sb, fs, super_arc)
}

/// Sum the BGDT's `bg_free_blocks_count` across every group.
fn bgdt_total_free(super_: &Arc<Ext2Super>) -> u32 {
    super_
        .bgdt
        .lock()
        .iter()
        .map(|bg| bg.bg_free_blocks_count as u32)
        .sum()
}

/// `s_free_blocks_count` at this instant.
fn sb_free(super_: &Arc<Ext2Super>) -> u32 {
    super_.sb_disk.lock().s_free_blocks_count
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn alloc_free_round_trip_group0() {
    let (_sb, _fs, super_arc, _disk) = mount_rw();

    // Sanity: the fixture comes up with the counters we expect. (If
    // these ever drift, the test catches a regenerated-fixture
    // mistake.)
    assert_eq!(
        super_arc.sb_disk.lock().s_blocks_count,
        FIXTURE_BLOCKS_COUNT
    );
    assert_eq!(
        super_arc.sb_disk.lock().s_blocks_per_group,
        FIXTURE_BLOCKS_PER_GROUP
    );
    assert_eq!(sb_free(&super_arc), FIXTURE_FREE_BLOCKS_AT_MOUNT);
    assert_eq!(bgdt_total_free(&super_arc), FIXTURE_FREE_BLOCKS_AT_MOUNT);

    // Allocate with a hint for group 0 → should return the fixture's
    // first free block (26).
    let b = alloc_block(&super_arc, Some(0)).expect("alloc_block must succeed");
    assert_eq!(b, FIXTURE_GROUP0_FIRST_FREE);
    assert_eq!(sb_free(&super_arc), FIXTURE_FREE_BLOCKS_AT_MOUNT - 1);
    assert_eq!(
        bgdt_total_free(&super_arc),
        FIXTURE_FREE_BLOCKS_AT_MOUNT - 1
    );

    // Allocating again must not hand back the same block.
    let b2 = alloc_block(&super_arc, Some(0)).expect("second alloc must succeed");
    assert_ne!(b, b2);
    assert_eq!(b2, FIXTURE_GROUP0_FIRST_FREE + 1);

    // Free both and confirm the counters fully restore.
    free_block(&super_arc, b).expect("free_block(b) must succeed");
    free_block(&super_arc, b2).expect("free_block(b2) must succeed");
    assert_eq!(sb_free(&super_arc), FIXTURE_FREE_BLOCKS_AT_MOUNT);
    assert_eq!(bgdt_total_free(&super_arc), FIXTURE_FREE_BLOCKS_AT_MOUNT);

    // After free, a third alloc should hand the block back again
    // (first-fit).
    let b3 = alloc_block(&super_arc, Some(0)).expect("post-free alloc must succeed");
    assert_eq!(b3, FIXTURE_GROUP0_FIRST_FREE);
}

fn alloc_spills_to_group1_when_group0_full() {
    let (_sb, _fs, super_arc, _disk) = mount_rw();

    // Drain group 0 to exhaustion by allocating the exact number of
    // free blocks it reports at mount. Then the next alloc with
    // hint=0 must spill to group 1.
    let group0_free = super_arc.bgdt.lock()[0].bg_free_blocks_count as u32;
    assert!(
        group0_free > 0,
        "fixture must have at least one free in group 0"
    );
    let mut taken: Vec<u32> = Vec::with_capacity(group0_free as usize);
    for _ in 0..group0_free {
        let b = alloc_block(&super_arc, Some(0)).expect("drain alloc");
        taken.push(b);
    }
    // All drained blocks must belong to group 0.
    for &b in &taken {
        assert!(
            b >= 1 && b < 1 + FIXTURE_BLOCKS_PER_GROUP,
            "drained block {b} must be in group 0's range [1, 257)"
        );
    }
    // Group 0 is now empty.
    assert_eq!(super_arc.bgdt.lock()[0].bg_free_blocks_count, 0);

    // Spill: next alloc with hint=0 must come from group 1.
    let b = alloc_block(&super_arc, Some(0)).expect("spill alloc");
    assert!(
        b >= FIXTURE_GROUP1_FIRST_FREE,
        "spilled block {b} must be >= group 1's first free ({FIXTURE_GROUP1_FIRST_FREE})"
    );
    assert!(
        b < FIXTURE_BLOCKS_COUNT,
        "spilled block {b} must be within the filesystem"
    );
}

fn free_rejects_superblock_block() {
    let (_sb, _fs, super_arc, _disk) = mount_rw();
    let before_sb = sb_free(&super_arc);
    let before_bgdt = bgdt_total_free(&super_arc);
    // Block 1 is the primary superblock on a 1 KiB fs.
    let r = free_block(&super_arc, 1);
    assert_eq!(r, Err(EIO), "free_block(superblock) must be EIO");
    // Counters unchanged.
    assert_eq!(sb_free(&super_arc), before_sb);
    assert_eq!(bgdt_total_free(&super_arc), before_bgdt);
}

fn free_rejects_block_bitmap_block() {
    // A metadata-free attempt now trips the runtime force-RO latch
    // (#617 item 3), so each metadata block needs its own mount —
    // otherwise the second call returns EROFS instead of EIO.
    for &meta in &[3u32, 4, 5] {
        let (_sb, _fs, super_arc, _disk) = mount_rw();
        let before_sb = sb_free(&super_arc);
        let r = free_block(&super_arc, meta);
        assert_eq!(r, Err(EIO), "free_block(metadata block {meta}) must be EIO");
        // Counters unchanged.
        assert_eq!(sb_free(&super_arc), before_sb);
    }
}

fn free_rejects_out_of_range() {
    let (_sb, _fs, super_arc, _disk) = mount_rw();
    // block 0 — reserved prefix.
    assert_eq!(free_block(&super_arc, 0), Err(EIO));
    // Past end of fs.
    assert_eq!(free_block(&super_arc, FIXTURE_BLOCKS_COUNT), Err(EIO));
    assert_eq!(free_block(&super_arc, u32::MAX), Err(EIO));
}

fn free_rejects_backup_sb_and_bgdt() {
    // #617 item 1: backup SB at block 257, backup BGDT at 258 in the
    // 2-group balloc fixture. Both must be rejected with EIO.
    for &meta in &[257u32, 258] {
        let (_sb, _fs, super_arc, _disk) = mount_rw();
        let r = free_block(&super_arc, meta);
        assert_eq!(
            r,
            Err(EIO),
            "free_block(backup metadata {meta}) must be EIO"
        );
    }
}

fn double_free_forces_ro() {
    // #617 item 3: a double-free trips the runtime force-RO latch so
    // subsequent allocator calls refuse with EROFS.
    let (_sb, _fs, super_arc, _disk) = mount_rw();
    // Allocate then free: legit round trip.
    let b = alloc_block(&super_arc, Some(0)).expect("first alloc must succeed");
    free_block(&super_arc, b).expect("first free must succeed");
    // Second free of the same block: double-free → EIO + force-RO.
    assert_eq!(
        free_block(&super_arc, b),
        Err(EIO),
        "double-free must return EIO"
    );
    // Subsequent alloc must now refuse with EROFS because the latch is
    // set even though the mount flags didn't change.
    assert_eq!(
        alloc_block(&super_arc, None),
        Err(EROFS),
        "post-double-free alloc must refuse with EROFS"
    );
    // free_block also refuses.
    assert_eq!(free_block(&super_arc, 27), Err(EROFS));
}

fn ro_mount_refuses_alloc() {
    let (_sb, _fs, super_arc) = mount_ro();
    assert_eq!(
        alloc_block(&super_arc, None),
        Err(EROFS),
        "RO mount must refuse alloc_block"
    );
}

fn alloc_exhaustion_returns_enospc() {
    let (_sb, _fs, super_arc, _disk) = mount_rw();
    // Drain the entire filesystem. The fixture has 474 free blocks at
    // mount; a 475th alloc must return ENOSPC.
    let free = sb_free(&super_arc);
    for _ in 0..free {
        alloc_block(&super_arc, None).expect("drain alloc must succeed while blocks remain");
    }
    assert_eq!(sb_free(&super_arc), 0);
    assert_eq!(bgdt_total_free(&super_arc), 0);
    assert_eq!(alloc_block(&super_arc, None), Err(ENOSPC));
}
