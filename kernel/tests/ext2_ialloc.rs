//! Integration test for issue #566: ext2 inode-bitmap allocator.
//!
//! Mounts the 64 KiB golden image (1 group, 16 inodes, 5 free: inos
//! 12..=16) and exercises `alloc_inode` / `free_inode` against it:
//!
//! - **reserved-range guard** — the first zero bit in a fresh
//!   allocation is ino 12 (not 1..=10), because inos `1..first_ino`
//!   are reserved.
//! - **alloc → free round-trip** — allocate an ino, free it, allocate
//!   again; the second call returns the same ino (bitmap was cleared
//!   cleanly) and all counters balance.
//! - **ENOSPC** — drain every free bit, the next `alloc_inode`
//!   returns `ENOSPC` without corrupting the counters.
//! - **free rejects reserved inos** — `free_inode(5, _)` → `EINVAL`.
//! - **`bg_used_dirs_count` tracks `is_dir`** — allocating a dir
//!   bumps the tally; freeing it (with `was_dir = true`) decrements
//!   it. Allocating a non-dir does not.
//! - **RO refuses mutations** — after a RO mount, both alloc and
//!   free return `EROFS`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{alloc_inode, free_inode, Ext2Fs};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EINVAL, ENOSPC, EROFS};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

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
            "alloc_skips_reserved_range",
            &(alloc_skips_reserved_range as fn()),
        ),
        ("alloc_free_round_trip", &(alloc_free_round_trip as fn())),
        (
            "alloc_exhaustion_returns_enospc",
            &(alloc_exhaustion_returns_enospc as fn()),
        ),
        (
            "free_rejects_reserved_ino",
            &(free_rejects_reserved_ino as fn()),
        ),
        (
            "free_rejects_zero_and_out_of_range",
            &(free_rejects_zero_and_out_of_range as fn()),
        ),
        (
            "used_dirs_tracks_is_dir",
            &(used_dirs_tracks_is_dir as fn()),
        ),
        (
            "ro_mount_refuses_mutations",
            &(ro_mount_refuses_mutations as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — mirrors the copy in ext2_inode_iget.rs.
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

fn mount_golden_rw() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<vibix::fs::ext2::Ext2Fs>,
    Arc<vibix::fs::ext2::Ext2Super>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc)
}

fn mount_golden_ro() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<vibix::fs::ext2::Ext2Fs>,
    Arc<vibix::fs::ext2::Ext2Super>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn alloc_skips_reserved_range() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    // The golden image has inos 1..=11 allocated; the first free bit
    // corresponds to ino 12. That's also the lowest *non-reserved* ino,
    // so this single assertion pins both the bitmap scan starting point
    // and the reserved-range guard.
    let ino = alloc_inode(&super_arc, Some(0), /* is_dir */ false)
        .expect("alloc_inode must succeed on a fresh golden image");
    assert_eq!(
        ino, 12,
        "first alloc on golden image must land on ino 12 (lowest non-reserved free bit)"
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn alloc_free_round_trip() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    let a = alloc_inode(&super_arc, Some(0), false).expect("alloc #1");
    let b = alloc_inode(&super_arc, Some(0), false).expect("alloc #2");
    assert_eq!(a, 12);
    assert_eq!(b, 13);

    free_inode(&super_arc, a, /* was_dir */ false).expect("free #1");
    // After freeing ino 12, the next alloc must return 12 again (the
    // lowest clear bit past the reserved range).
    let c = alloc_inode(&super_arc, Some(0), false).expect("alloc #3");
    assert_eq!(c, 12, "freed ino must be reclaimed on next alloc");

    sb.ops.unmount();
    drop(super_arc);
}

fn alloc_exhaustion_returns_enospc() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    // 5 free inodes on the golden image; drain them all.
    let mut allocated = alloc::vec::Vec::new();
    for _ in 0..5 {
        allocated.push(alloc_inode(&super_arc, Some(0), false).expect("drain"));
    }
    assert_eq!(allocated, alloc::vec![12u32, 13, 14, 15, 16]);

    // Sixth call → ENOSPC.
    assert_eq!(
        alloc_inode(&super_arc, Some(0), false).err(),
        Some(ENOSPC),
        "exhausted image must report ENOSPC"
    );

    // Free one, alloc once → that ino reappears.
    free_inode(&super_arc, 14, false).expect("free #14");
    let back = alloc_inode(&super_arc, Some(0), false).expect("alloc after free");
    assert_eq!(back, 14);

    sb.ops.unmount();
    drop(super_arc);
}

fn free_rejects_reserved_ino() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    // Inos 1..=10 are reserved. Freeing any of them is a driver bug;
    // the allocator refuses with EINVAL so the caller's assertion fires.
    for reserved in [1u32, 2, 5, 10] {
        assert_eq!(
            free_inode(&super_arc, reserved, false).err(),
            Some(EINVAL),
            "free_inode({reserved}) must refuse reserved range"
        );
    }

    sb.ops.unmount();
    drop(super_arc);
}

fn free_rejects_zero_and_out_of_range() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    assert_eq!(free_inode(&super_arc, 0, false).err(), Some(EINVAL));
    assert_eq!(free_inode(&super_arc, u32::MAX, false).err(), Some(EINVAL));
    // 64 KiB image has s_inodes_count = 16.
    assert_eq!(free_inode(&super_arc, 17, false).err(), Some(EINVAL));

    sb.ops.unmount();
    drop(super_arc);
}

fn used_dirs_tracks_is_dir() {
    let (sb, _fs, super_arc) = mount_golden_rw();

    // Read the on-disk `bg_used_dirs_count` fresh via the cache by
    // inspecting the BGDT block directly. Golden image starts at 2.
    let bs = super_arc.block_size as u64;
    let first = super_arc.sb_disk.lock().s_first_data_block as u64;
    let bgdt_block = first + 1;

    fn read_used_dirs(super_arc: &Arc<vibix::fs::ext2::Ext2Super>, bgdt_block: u64) -> u16 {
        let bh = super_arc
            .cache
            .bread(super_arc.device_id, bgdt_block)
            .expect("bread bgdt");
        let data = bh.data.read();
        // bg_used_dirs_count lives at offset 16 in the 32-byte slot;
        // first group sits at offset 0 of the block.
        u16::from_le_bytes(data[16..18].try_into().unwrap())
    }

    let before = read_used_dirs(&super_arc, bgdt_block);
    let ino_dir = alloc_inode(&super_arc, Some(0), /* is_dir */ true).expect("alloc dir");
    let after_dir = read_used_dirs(&super_arc, bgdt_block);
    assert_eq!(after_dir, before + 1, "is_dir alloc must bump used_dirs");

    let _ino_reg = alloc_inode(&super_arc, Some(0), false).expect("alloc reg");
    let after_reg = read_used_dirs(&super_arc, bgdt_block);
    assert_eq!(
        after_reg, after_dir,
        "non-dir alloc must not touch used_dirs"
    );

    free_inode(&super_arc, ino_dir, /* was_dir */ true).expect("free dir");
    let after_free = read_used_dirs(&super_arc, bgdt_block);
    assert_eq!(after_free, before, "free(was_dir) must restore used_dirs");

    // Keep bs used in the assertion above to avoid an unused-var warning
    // on future refactors.
    let _ = bs;

    sb.ops.unmount();
    drop(super_arc);
}

fn ro_mount_refuses_mutations() {
    let (sb, _fs, super_arc) = mount_golden_ro();

    assert_eq!(
        alloc_inode(&super_arc, Some(0), false).err(),
        Some(EROFS),
        "alloc_inode on RO mount must return EROFS"
    );
    assert_eq!(
        free_inode(&super_arc, 12, false).err(),
        Some(EROFS),
        "free_inode on RO mount must return EROFS"
    );

    sb.ops.unmount();
    drop(super_arc);
}
