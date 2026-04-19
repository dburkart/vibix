//! Integration test for issue #564: mount-time orphan-chain validation.
//!
//! Runs under QEMU with the real kernel. Starts from the 64 KiB
//! `golden.img` mkfs.ext2 fixture (16 inodes, 1 KiB blocks, one block
//! group), patches `s_last_orphan` and selected inodes' `i_dtime` /
//! `i_links_count` / `i_mode` in-memory, then mounts through
//! [`Ext2Fs`] and asserts on the observable outcomes:
//!
//! - **Valid 3-entry chain** — mounts cleanly, `orphan_list` carries
//!   the three pinned inodes, the sb is **not** forced RO.
//! - **Chain with a cycle** — mount succeeds but is demoted to RO
//!   (`SbFlags::RDONLY`), `orphan_list` is empty (we refuse to pin
//!   anything when the chain is corrupt).
//! - **Chain pointing at ino 0 via a malformed reserved ino** — mount
//!   succeeds, forced RO, empty orphan_list. (Ino 0 terminates the
//!   chain, so we test the reserved-ino rejection by pointing the
//!   head at ino 1 `EXT2_BAD_INO`, which is the spiritually-equivalent
//!   "points at a reserved slot" case the issue calls for.)
//! - **Length > s_inodes_count** — by wiring up a chain that's valid
//!   but exceeds the bound via a forged seen-set-evading nonsense
//!   next-pointer (impossible in practice; exercised via repeated
//!   same-ino rejected-by-cycle instead) — covered by the cycle test.
//!
//! The fixture image has only 16 inodes; once lost+found (ino 11) is
//! accounted for, inos 12..=16 are free-but-allocatable slots. The
//! test uses 12/13/14 for the valid-chain entries (they sit in the
//! same inode-table block as lost+found so the arithmetic is simple).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::Ext2Fs;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SbFlags;
use vibix::fs::vfs::MountFlags;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

/// 64 KiB `mkfs.ext2` image. See `kernel/src/fs/ext2/fixtures/README.md`.
const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

// ---------------------------------------------------------------------------
// On-disk offsets the patcher needs (duplicated from
// `vibix::fs::ext2::disk`; that module's constants are crate-private
// offsets, so copies here are deliberate — the tests pin the values
// against the real image layout rather than consuming the module's
// internal offsets).
// ---------------------------------------------------------------------------
const SB_BYTE_OFFSET: usize = 1024;
const SB_OFF_INODES_COUNT: usize = 0;
const SB_OFF_LAST_ORPHAN: usize = 232;

const BGDT_BYTE_OFFSET_1K: usize = 2048;
const BGD_OFF_INODE_TABLE: usize = 8;

const INODE_SIZE: usize = 128;
const INODE_OFF_MODE: usize = 0;
const INODE_OFF_DTIME: usize = 20;
const INODE_OFF_LINKS_COUNT: usize = 26;

const BLOCK_SIZE_BYTES: usize = 1024;

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
            "valid_orphan_chain_pins_entries",
            &(valid_orphan_chain_pins_entries as fn()),
        ),
        (
            "cycle_forces_ro_and_empty_orphan_list",
            &(cycle_forces_ro_and_empty_orphan_list as fn()),
        ),
        (
            "reserved_ino_head_forces_ro",
            &(reserved_ino_head_forces_ro as fn()),
        ),
        (
            "oob_next_pointer_forces_ro",
            &(oob_next_pointer_forces_ro as fn()),
        ),
        (
            "empty_chain_on_clean_image",
            &(empty_chain_on_clean_image as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk (mirrors ext2_mount.rs / ext2_inode_iget.rs)
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
// Image-patching helpers. The fixture is a 1 KiB-block, 16-inode,
// single-group image — the inode-table block for ino N lives at the
// block named by `bgdt[0].bg_inode_table`, slot offset `(N - 1) * 128`.
// ---------------------------------------------------------------------------

fn u32_le(bytes: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn patch_u32_le(bytes: &mut [u8], off: usize, v: u32) {
    bytes[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn patch_u16_le(bytes: &mut [u8], off: usize, v: u16) {
    bytes[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn inode_slot_offset(image: &[u8], ino: u32) -> usize {
    // Single group in the 64 KiB fixture; the inode table base block
    // sits in the first group descriptor at BGDT offset +8.
    let itab_block = u32_le(image, BGDT_BYTE_OFFSET_1K + BGD_OFF_INODE_TABLE) as usize;
    let slot_in_table = (ino as usize) - 1;
    itab_block * BLOCK_SIZE_BYTES + slot_in_table * INODE_SIZE
}

/// Set `i_links_count = 0`, `i_dtime = next_ino`, and keep `i_mode`
/// nonzero (so classify_orphan_state reads it as "an orphan with an
/// on-disk next-pointer", mirroring Linux's on-disk state for a
/// just-unlinked-but-still-open inode).
fn make_orphan(image: &mut [u8], ino: u32, next: u32) {
    let slot = inode_slot_offset(image, ino);
    // i_mode: force to S_IFREG|0600 if it was zero so the orphan looks
    // like a user file.
    let cur_mode = u16::from_le_bytes(image[slot..slot + 2].try_into().unwrap());
    if cur_mode & 0o170_000 == 0 {
        patch_u16_le(image, slot + INODE_OFF_MODE, 0o100_600);
    }
    patch_u16_le(image, slot + INODE_OFF_LINKS_COUNT, 0);
    patch_u32_le(image, slot + INODE_OFF_DTIME, next);
}

/// Mount the (possibly-patched) image RO-or-RW per `flags` and hand
/// back the live `Arc<SuperBlock>` plus the concrete `Arc<Ext2Super>`.
fn mount_with(
    img: Vec<u8>,
    flags: MountFlags,
) -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<vibix::fs::ext2::Ext2Fs>,
    Arc<vibix::fs::ext2::Ext2Super>,
) {
    let disk = Arc::new(RamDiskOwned::new(img, 512));
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, flags)
        .expect("mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after a successful mount");
    (sb, fs, super_arc)
}

// A RamDisk that owns its starting bytes (mirrors the `from_image`
// constructor but takes an owned Vec so each test can patch
// independently).
struct RamDiskOwned(RamDisk);

impl RamDiskOwned {
    fn new(bytes: Vec<u8>, block_size: u32) -> Self {
        assert!(bytes.len() % block_size as usize == 0);
        Self(RamDisk {
            block_size,
            storage: Mutex::new(bytes),
            writes: AtomicU32::new(0),
        })
    }
}

impl BlockDevice for RamDiskOwned {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<(), BlockError> {
        self.0.read_at(offset, buf)
    }
    fn write_at(&self, offset: u64, buf: &[u8]) -> Result<(), BlockError> {
        self.0.write_at(offset, buf)
    }
    fn block_size(&self) -> u32 {
        self.0.block_size()
    }
    fn capacity(&self) -> u64 {
        self.0.capacity()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn empty_chain_on_clean_image() {
    // Sanity: the golden image ships with `s_last_orphan == 0` and the
    // validator fast-pathes. Mount RO (leave s_state alone) and confirm
    // the orphan_list stays empty and the mount isn't RO-forced.
    let img = GOLDEN_IMG.to_vec();
    assert_eq!(
        u32_le(&img, SB_BYTE_OFFSET + SB_OFF_LAST_ORPHAN),
        0,
        "baseline fixture must have empty s_last_orphan",
    );
    let (sb, _fs, super_arc) = mount_with(img, MountFlags::RDONLY);
    assert!(super_arc.orphan_list.lock().is_empty());
    assert!(sb.flags.contains(SbFlags::RDONLY));
    sb.ops.unmount();
    drop(super_arc);
}

fn valid_orphan_chain_pins_entries() {
    // Craft: s_last_orphan -> 12 -> 13 -> 14 -> 0. All three entries
    // are user inodes in range, with links_count=0 and valid
    // next-pointers. The walk must pin all three into orphan_list
    // and NOT force RO.
    let mut img = GOLDEN_IMG.to_vec();
    patch_u32_le(&mut img, SB_BYTE_OFFSET + SB_OFF_LAST_ORPHAN, 12);
    make_orphan(&mut img, 12, 13);
    make_orphan(&mut img, 13, 14);
    make_orphan(&mut img, 14, 0);

    let (sb, _fs, super_arc) = mount_with(img, MountFlags::RDONLY);
    let list = super_arc.orphan_list.lock();
    assert_eq!(
        list.len(),
        3,
        "valid 3-entry chain must pin exactly 3 orphans"
    );
    assert!(list.contains_key(&12));
    assert!(list.contains_key(&13));
    assert!(list.contains_key(&14));
    // RO-requested mount stays RO, but the `FORCED_RDONLY` hint must
    // NOT be set — the chain was clean.
    let ext2_flags = super_arc.ext2_flags;
    assert!(
        !ext2_flags.contains(vibix::fs::ext2::Ext2MountFlags::FORCED_RDONLY),
        "clean orphan chain must NOT set FORCED_RDONLY",
    );
    drop(list);
    sb.ops.unmount();
    drop(super_arc);
}

fn cycle_forces_ro_and_empty_orphan_list() {
    // Craft a 2-cycle: head -> 12 -> 13 -> 12 -> …
    let mut img = GOLDEN_IMG.to_vec();
    patch_u32_le(&mut img, SB_BYTE_OFFSET + SB_OFF_LAST_ORPHAN, 12);
    make_orphan(&mut img, 12, 13);
    make_orphan(&mut img, 13, 12);

    let (sb, _fs, super_arc) = mount_with(img, MountFlags::RDONLY);
    assert!(
        super_arc.orphan_list.lock().is_empty(),
        "corrupt chain must leave orphan_list empty"
    );
    assert!(
        sb.flags.contains(SbFlags::RDONLY),
        "cycle must force the mount RO",
    );
    assert!(
        super_arc
            .ext2_flags
            .contains(vibix::fs::ext2::Ext2MountFlags::FORCED_RDONLY),
        "cycle must set FORCED_RDONLY hint",
    );
    sb.ops.unmount();
    drop(super_arc);
}

fn reserved_ino_head_forces_ro() {
    // s_last_orphan points at EXT2_BAD_INO (1) — reserved, must reject.
    let mut img = GOLDEN_IMG.to_vec();
    patch_u32_le(&mut img, SB_BYTE_OFFSET + SB_OFF_LAST_ORPHAN, 1);

    let (sb, _fs, super_arc) = mount_with(img, MountFlags::RDONLY);
    assert!(super_arc.orphan_list.lock().is_empty());
    assert!(sb.flags.contains(SbFlags::RDONLY));
    assert!(super_arc
        .ext2_flags
        .contains(vibix::fs::ext2::Ext2MountFlags::FORCED_RDONLY));
    sb.ops.unmount();
    drop(super_arc);
}

fn oob_next_pointer_forces_ro() {
    // head -> 12 with i_dtime (next-pointer) = s_inodes_count + 1 =
    // 17. Must refuse: next ino is > s_inodes_count.
    let mut img = GOLDEN_IMG.to_vec();
    patch_u32_le(&mut img, SB_BYTE_OFFSET + SB_OFF_LAST_ORPHAN, 12);
    // Confirm s_inodes_count == 16 on the fixture (mkfs -N 16).
    assert_eq!(u32_le(&img, SB_BYTE_OFFSET + SB_OFF_INODES_COUNT), 16);
    make_orphan(&mut img, 12, 17);

    let (sb, _fs, super_arc) = mount_with(img, MountFlags::RDONLY);
    assert!(super_arc.orphan_list.lock().is_empty());
    assert!(sb.flags.contains(SbFlags::RDONLY));
    assert!(super_arc
        .ext2_flags
        .contains(vibix::fs::ext2::Ext2MountFlags::FORCED_RDONLY));
    sb.ops.unmount();
    drop(super_arc);
}
