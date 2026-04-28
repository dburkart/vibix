//! Integration test for issue #678: mount-time BGDT / bitmap
//! consistency checks.
//!
//! Runs the real kernel under QEMU, in-process: starts from the 64 KiB
//! `golden.img` mkfs.ext2 fixture (16 inodes, 1024 blocks, 1 KiB
//! blocks, one block group, block bitmap at block 3, inode bitmap at
//! block 4), patches the on-disk bitmap / counter bytes to simulate
//! each mismatch class, then mounts through [`Ext2Fs`] and asserts
//! that:
//!
//! - **Healthy fixture** — mounts RW cleanly, `SbFlags::RDONLY` is not
//!   set; the validator agreed with the BGDT.
//! - **Block-bitmap clear-bit count != bg_free_blocks_count** — mount
//!   succeeds but is demoted to RO (`SbFlags::RDONLY` set) and the
//!   ramdisk records zero writes (the `s_state := ERROR_FS` stamp is
//!   gated behind `effective_rdonly`).
//! - **Inode-bitmap clear-bit count != bg_free_inodes_count** — same
//!   demote-to-RO behaviour.
//! - **Reserved ino bit unset (root ino 2 marked free)** — mount
//!   demoted to RO.
//! - **`s_free_blocks_count` lies (sum of BGDT counters disagrees)**
//!   — mount demoted to RO.
//! - **`s_free_inodes_count` lies** — same.
//!
//! The fixture image is the same `golden.img` `ext2_mount.rs` and
//! `ext2_orphan_chain.rs` use; see `kernel/src/fs/ext2/fixtures/README.md`
//! for how it is generated.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::Ext2Fs;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SbFlags;
use vibix::fs::vfs::MountFlags;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// 64 KiB `mkfs.ext2` image. See `kernel/src/fs/ext2/fixtures/README.md`.
const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

// On-disk byte offsets we need. The fixture is 1 KiB-block ext2,
// `s_first_data_block == 1`, so:
//   - superblock lives at byte 1024 (block 1)
//   - BGDT lives at byte 2048 (block 2)
//   - block bitmap at byte 3072 (block 3)
//   - inode bitmap at byte 4096 (block 4)
const SB_BYTE_OFFSET: usize = 1024;
const SB_OFF_FREE_BLOCKS_COUNT: usize = 12;
const SB_OFF_FREE_INODES_COUNT: usize = 16;

const BGDT_BYTE_OFFSET_1K: usize = 2048;
const BGD_OFF_FREE_BLOCKS_COUNT: usize = 12;
const BGD_OFF_FREE_INODES_COUNT: usize = 14;

const INODE_BITMAP_BYTE_OFFSET_1K: usize = 4096;

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
            "healthy_fixture_mounts_rw",
            &(healthy_fixture_mounts_rw as fn()),
        ),
        (
            "block_bitmap_count_mismatch_forces_ro",
            &(block_bitmap_count_mismatch_forces_ro as fn()),
        ),
        (
            "inode_bitmap_count_mismatch_forces_ro",
            &(inode_bitmap_count_mismatch_forces_ro as fn()),
        ),
        (
            "reserved_ino_unallocated_forces_ro",
            &(reserved_ino_unallocated_forces_ro as fn()),
        ),
        (
            "sb_free_blocks_lies_forces_ro",
            &(sb_free_blocks_lies_forces_ro as fn()),
        ),
        (
            "sb_free_inodes_lies_forces_ro",
            &(sb_free_inodes_lies_forces_ro as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Construct a `RamDisk` from `bytes`, exposing 512-byte sectors so
/// the `read_at` alignment matches a real virtio-blk.
fn disk_from_bytes(bytes: &[u8]) -> Arc<RamDisk> {
    RamDisk::from_image(bytes, 512)
}

/// Patch a 16-bit little-endian field at byte `offset` in `image`.
fn patch_u16_le(image: &mut [u8], offset: usize, value: u16) {
    image[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Patch a 32-bit little-endian field at byte `offset` in `image`.
fn patch_u32_le(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Mount through `Ext2Fs::new_with_device` with the requested
/// `MountFlags`. Returns the resulting `SbFlags::RDONLY` bit and the
/// number of writes the disk recorded over the mount call. The
/// `SuperBlock` is unmounted before return so a subsequent test can
/// reuse the factory pattern cleanly.
fn mount_and_observe(disk: Arc<RamDisk>, flags: MountFlags) -> (bool, u32) {
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();
    let sb = fs
        .mount(MountSource::None, flags)
        .expect("mount must succeed");
    let rdonly = sb.flags.contains(SbFlags::RDONLY);
    let writes_after = disk.writes();
    sb.ops.unmount();
    (rdonly, writes_after - writes_before)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The unmodified golden image must mount RW cleanly: every BGDT
/// counter agrees with its bitmap, the reserved-inode range is
/// allocated, and the superblock totals match the BGDT sums. If this
/// regresses, every other test in this file is invalid (they all
/// start by validating that the un-patched fixture is healthy).
fn healthy_fixture_mounts_rw() {
    let disk = disk_from_bytes(GOLDEN_IMG.as_slice());
    let (rdonly, _writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        !rdonly,
        "healthy fixture must mount RW (not forced to RDONLY)",
    );
}

/// Lie about the block-bitmap free count: bump
/// `bg_free_blocks_count` by 1 without changing the bitmap. The
/// validator should observe the discrepancy and force RO.
fn block_bitmap_count_mismatch_forces_ro() {
    let mut image = GOLDEN_IMG.to_vec();
    let off = BGDT_BYTE_OFFSET_1K + BGD_OFF_FREE_BLOCKS_COUNT;
    let cur = u16::from_le_bytes([image[off], image[off + 1]]);
    let bumped = cur.wrapping_add(1);
    patch_u16_le(&mut image, off, bumped);
    // Also bump `s_free_blocks_count` in lockstep so the per-group
    // counter check trips first (without this the sb-vs-sum check
    // would also trip; either way we'd force RO, but pinning the
    // primary cause makes the test specific to the bitmap path).
    let sb_off = SB_BYTE_OFFSET + SB_OFF_FREE_BLOCKS_COUNT;
    let sb_cur = u32::from_le_bytes([
        image[sb_off],
        image[sb_off + 1],
        image[sb_off + 2],
        image[sb_off + 3],
    ]);
    patch_u32_le(&mut image, sb_off, sb_cur.wrapping_add(1));

    let disk = disk_from_bytes(&image);
    let (rdonly, writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        rdonly,
        "block-bitmap counter mismatch must demote mount to RDONLY",
    );
    assert_eq!(
        writes, 0,
        "RO-demoted mount must not write to device (got {writes} writes)",
    );
}

/// Lie about the inode-bitmap free count.
fn inode_bitmap_count_mismatch_forces_ro() {
    let mut image = GOLDEN_IMG.to_vec();
    let off = BGDT_BYTE_OFFSET_1K + BGD_OFF_FREE_INODES_COUNT;
    let cur = u16::from_le_bytes([image[off], image[off + 1]]);
    patch_u16_le(&mut image, off, cur.wrapping_add(1));
    // Lockstep on the sb so the per-group check is the primary trip.
    let sb_off = SB_BYTE_OFFSET + SB_OFF_FREE_INODES_COUNT;
    let sb_cur = u32::from_le_bytes([
        image[sb_off],
        image[sb_off + 1],
        image[sb_off + 2],
        image[sb_off + 3],
    ]);
    patch_u32_le(&mut image, sb_off, sb_cur.wrapping_add(1));

    let disk = disk_from_bytes(&image);
    let (rdonly, writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        rdonly,
        "inode-bitmap counter mismatch must demote mount to RDONLY",
    );
    assert_eq!(
        writes, 0,
        "RO-demoted mount must not write to device (got {writes} writes)",
    );
}

/// Clear bit 1 of the inode bitmap (= ino 2 = `EXT2_ROOT_INO`). The
/// reserved-range check must catch this: ino 2 is in the reserved
/// range (inos 1..first_ino=11) and MUST be marked allocated.
///
/// We also bump `bg_free_inodes_count` and `s_free_inodes_count` by 1
/// so the per-group bitmap-vs-counter check passes (otherwise that
/// check trips first). The test then attributes the force-RO verdict
/// specifically to the reserved-range check.
fn reserved_ino_unallocated_forces_ro() {
    let mut image = GOLDEN_IMG.to_vec();

    // Clear bit 1 of byte 0 of the inode bitmap (ino 2).
    let bm_byte = INODE_BITMAP_BYTE_OFFSET_1K;
    image[bm_byte] &= !(1u8 << 1);

    // Bump the free-inode counters in BGDT + SB so the bitmap
    // clear-bit count still matches the BGDT.
    let bg_off = BGDT_BYTE_OFFSET_1K + BGD_OFF_FREE_INODES_COUNT;
    let bg_cur = u16::from_le_bytes([image[bg_off], image[bg_off + 1]]);
    patch_u16_le(&mut image, bg_off, bg_cur + 1);
    let sb_off = SB_BYTE_OFFSET + SB_OFF_FREE_INODES_COUNT;
    let sb_cur = u32::from_le_bytes([
        image[sb_off],
        image[sb_off + 1],
        image[sb_off + 2],
        image[sb_off + 3],
    ]);
    patch_u32_le(&mut image, sb_off, sb_cur + 1);

    let disk = disk_from_bytes(&image);
    let (rdonly, writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        rdonly,
        "unallocated reserved ino must demote mount to RDONLY",
    );
    assert_eq!(
        writes, 0,
        "RO-demoted mount must not write to device (got {writes} writes)",
    );
}

/// Lie only about `s_free_blocks_count` (in the superblock) without
/// touching the BGDT. The sum-of-BGDT-counters cross-check must catch
/// the discrepancy.
fn sb_free_blocks_lies_forces_ro() {
    let mut image = GOLDEN_IMG.to_vec();
    let sb_off = SB_BYTE_OFFSET + SB_OFF_FREE_BLOCKS_COUNT;
    let cur = u32::from_le_bytes([
        image[sb_off],
        image[sb_off + 1],
        image[sb_off + 2],
        image[sb_off + 3],
    ]);
    // Bump by something that won't underflow on a u32 and is
    // unambiguously different from the BGDT sum.
    patch_u32_le(&mut image, sb_off, cur.wrapping_add(7));

    let disk = disk_from_bytes(&image);
    let (rdonly, writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        rdonly,
        "s_free_blocks_count != sum(bg_free_blocks_count) must demote to RDONLY",
    );
    assert_eq!(writes, 0);
}

/// Lie about `s_free_inodes_count`.
fn sb_free_inodes_lies_forces_ro() {
    let mut image = GOLDEN_IMG.to_vec();
    let sb_off = SB_BYTE_OFFSET + SB_OFF_FREE_INODES_COUNT;
    let cur = u32::from_le_bytes([
        image[sb_off],
        image[sb_off + 1],
        image[sb_off + 2],
        image[sb_off + 3],
    ]);
    patch_u32_le(&mut image, sb_off, cur.wrapping_add(3));

    let disk = disk_from_bytes(&image);
    let (rdonly, writes) = mount_and_observe(disk, MountFlags::default());
    assert!(
        rdonly,
        "s_free_inodes_count != sum(bg_free_inodes_count) must demote to RDONLY",
    );
    assert_eq!(writes, 0);
}
