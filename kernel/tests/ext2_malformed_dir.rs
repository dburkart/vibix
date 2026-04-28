//! Integration test for issue #682: `getdents64` over a directory whose
//! first data block carries a structurally-corrupt record must surface
//! `EIO` cleanly without panicking, and the rest of the filesystem must
//! remain usable.
//!
//! Iterator-level coverage of the same `rec_len` defects already exists
//! at `kernel/src/fs/ext2/dir.rs:633-660`. This test exercises the
//! higher-level integration: mount a real ext2 image whose root
//! directory block has been surgically corrupted, then drive
//! `dir::getdents64` against it and assert
//!
//! 1. the syscall path returns `EIO` (no panic, no OOB read);
//! 2. an unrelated live inode (the on-disk `lost+found` at ino 11) is
//!    still readable through `iget` — corruption in the root dir does
//!    not poison sibling inodes.
//!
//! The three variants cover the rec_len defects called out in the
//! `DirEntryIter` host tests, lifted to the syscall surface:
//!
//! - **Overrun**: `rec_len` exceeds the remaining bytes in the block.
//! - **Unaligned**: `rec_len` is not a multiple of 4.
//! - **Zero**: `rec_len == 0` (a self-loop the iterator must reject
//!   instead of spinning forever).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32};

use vibix::block::BlockDevice;
use vibix::fs::ext2::dir;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Inode, Ext2InodeMeta, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::EIO;
use vibix::sync::BlockingRwLock;
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
            "rec_len_overrun_surfaces_eio",
            &(rec_len_overrun_surfaces_eio as fn()),
        ),
        (
            "rec_len_unaligned_surfaces_eio",
            &(rec_len_unaligned_surfaces_eio as fn()),
        ),
        (
            "rec_len_zero_surfaces_eio",
            &(rec_len_zero_surfaces_eio as fn()),
        ),
        (
            "sibling_inode_still_readable_after_root_corruption",
            &(sibling_inode_still_readable_after_root_corruption as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs (issue #627).
// ---------------------------------------------------------------------------

#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Mount the (possibly already-patched) `image` and return the
/// `(SuperBlock, Ext2Fs, Ext2Super, RamDisk)` tuple. Each call gets its
/// own fresh `Ext2Fs` and therefore its own buffer cache, so a patch
/// applied to `image` before this call is what the mount actually sees
/// — there is no stale-cache hazard between variants.
fn mount_image(
    image: &[u8],
) -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(image, 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc, disk)
}

/// Pull the concrete `Ext2Inode`'s decoded fields out of a mounted
/// image — same pattern as `kernel/tests/ext2_dir_ops.rs`.
fn make_ext2_inode_from_stat(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Ext2Inode {
    let _ = iget(super_arc, sb, ino).expect("iget should succeed for a live ino");

    let inodes_per_group = {
        let sb = super_arc.sb_disk.lock();
        sb.s_inodes_per_group
    };
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
    let bg_inode_table = {
        let bgdt = super_arc.bgdt.lock();
        bgdt[group as usize].bg_inode_table
    };
    let byte_offset = (index_in_group as u64) * (super_arc.inode_size as u64);
    let block_in_table = byte_offset / (super_arc.block_size as u64);
    let offset_in_block = (byte_offset % (super_arc.block_size as u64)) as usize;
    let absolute_block = bg_inode_table as u64 + block_in_table;

    let bh = super_arc
        .cache
        .bread(super_arc.device_id, absolute_block)
        .expect("bread inode table");
    let data = bh.data.read();
    let mut slot = [0u8; 128];
    slot.copy_from_slice(&data[offset_in_block..offset_in_block + 128]);
    drop(data);
    let disk_inode = vibix::fs::ext2::disk::Ext2Inode::decode(&slot);

    let meta = Ext2InodeMeta {
        mode: disk_inode.i_mode,
        uid: disk_inode.uid(),
        gid: disk_inode.gid(),
        size: disk_inode.i_size as u64,
        atime: disk_inode.i_atime,
        ctime: disk_inode.i_ctime,
        mtime: disk_inode.i_mtime,
        dtime: disk_inode.i_dtime,
        links_count: disk_inode.i_links_count,
        i_blocks: disk_inode.i_blocks,
        flags: disk_inode.i_flags,
        i_block: disk_inode.i_block,
    };

    Ext2Inode {
        super_ref: Arc::downgrade(super_arc),
        ino,
        meta: BlockingRwLock::new(meta),
        block_map: BlockingRwLock::new(None),
        unlinked: AtomicBool::new(false),
        open_count: AtomicU32::new(0),
    }
}

/// Discover the absolute byte offset of the root directory's first
/// data block and the filesystem's block size from a clean mount of
/// `GOLDEN_IMG`. These are deterministic for the fixture but reading
/// them out programmatically keeps this test from baking in offsets
/// that would silently rot if the fixture is ever regenerated.
fn root_dir_block_offset() -> (usize, usize) {
    let image: Vec<u8> = GOLDEN_IMG.to_vec();
    let (sb, _fs, super_arc, _disk) = mount_image(&image);
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);
    let meta = root.meta.read();
    let i_block0 = meta.i_block[0];
    drop(meta);
    let block_size = super_arc.block_size as usize;
    sb.ops.unmount();
    drop(super_arc);
    assert!(i_block0 != 0, "root dir must have a direct first block");
    let byte_off = i_block0 as usize * block_size;
    (byte_off, block_size)
}

/// Apply a function to a fresh copy of `GOLDEN_IMG` and return it.
/// Used to stamp a corrupt directory record over the root block before
/// mount.
fn corrupted_image<F: FnOnce(&mut [u8])>(f: F) -> Vec<u8> {
    let mut image = GOLDEN_IMG.to_vec();
    f(&mut image);
    image
}

/// Stamp a single directory record at `block_off` in `image` with the
/// given `(ino, rec_len, name_len, file_type, name)`. The caller picks
/// `rec_len` to control which validation rule the record violates;
/// nothing else here enforces correctness so each variant gets exactly
/// the byte pattern it asks for.
fn stamp_record(
    image: &mut [u8],
    block_off: usize,
    ino: u32,
    rec_len: u16,
    name_len: u8,
    file_type: u8,
    name: &[u8],
    block_size: usize,
) {
    // Wipe the whole block first so trailing bytes from the original
    // record can't accidentally form a follow-up record that the
    // iterator might walk past the corrupt one.
    for b in &mut image[block_off..block_off + block_size] {
        *b = 0;
    }
    image[block_off..block_off + 4].copy_from_slice(&ino.to_le_bytes());
    image[block_off + 4..block_off + 6].copy_from_slice(&rec_len.to_le_bytes());
    image[block_off + 6] = name_len;
    image[block_off + 7] = file_type;
    image[block_off + 8..block_off + 8 + name.len()].copy_from_slice(name);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Drive `getdents64` against the (corrupt) root directory and assert
/// the call returns `EIO` without panicking.
fn assert_getdents_eio(image: &[u8]) {
    let (sb, _fs, super_arc, _disk) = mount_image(image);
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);
    let mut buf = vec![0u8; 1024];
    let mut cookie = 0u64;
    let res = dir::getdents64(&super_arc, &root, &mut buf, &mut cookie);
    match res {
        Err(e) => assert_eq!(e, EIO, "corrupt directory must surface EIO, got {e}"),
        Ok(n) => panic!("getdents64 over corrupt dir returned Ok({n}), expected EIO"),
    }
    sb.ops.unmount();
    drop(super_arc);
}

fn rec_len_overrun_surfaces_eio() {
    let (block_off, block_size) = root_dir_block_offset();
    // rec_len declares a record longer than the block — the iterator
    // must reject before reading past the block end.
    let bad_rec_len = (block_size + 4) as u16;
    let image = corrupted_image(|img| {
        stamp_record(
            img,
            block_off,
            2,
            bad_rec_len,
            1,
            vibix::fs::ext2::disk::EXT2_FT_DIR,
            b".",
            block_size,
        );
    });
    assert_getdents_eio(&image);
}

fn rec_len_unaligned_surfaces_eio() {
    let (block_off, block_size) = root_dir_block_offset();
    // rec_len = 13 is not 4-byte aligned. Still fits in the block, so
    // this isolates the alignment check from the overrun check.
    let image = corrupted_image(|img| {
        stamp_record(
            img,
            block_off,
            2,
            13,
            1,
            vibix::fs::ext2::disk::EXT2_FT_DIR,
            b".",
            block_size,
        );
    });
    assert_getdents_eio(&image);
}

fn rec_len_zero_surfaces_eio() {
    let (block_off, block_size) = root_dir_block_offset();
    // rec_len = 0 is a self-loop. The iterator must surface corruption
    // rather than spin or advance by 0 forever.
    let image = corrupted_image(|img| {
        stamp_record(
            img,
            block_off,
            2,
            0,
            1,
            vibix::fs::ext2::disk::EXT2_FT_DIR,
            b".",
            block_size,
        );
    });
    assert_getdents_eio(&image);
}

/// Corrupting the root directory must not make the rest of the
/// filesystem unreadable — `iget` for a sibling live inode (the
/// on-disk `lost+found` at ino 11) still has to succeed. This is the
/// "fs remains usable for siblings of the bad directory" assertion
/// from issue #682.
fn sibling_inode_still_readable_after_root_corruption() {
    let (block_off, block_size) = root_dir_block_offset();
    let image = corrupted_image(|img| {
        stamp_record(
            img,
            block_off,
            2,
            0,
            1,
            vibix::fs::ext2::disk::EXT2_FT_DIR,
            b".",
            block_size,
        );
    });
    let (sb, _fs, super_arc, _disk) = mount_image(&image);
    // Reading the sibling inode still works even though the root dir
    // is poisoned — the inode table is independent of the root dir
    // data block.
    let lf = iget(&super_arc, &sb, 11).expect("sibling iget must still succeed");
    assert_eq!(lf.ino, 11, "iget should return the requested ino");
    sb.ops.unmount();
    drop(super_arc);
}

// Sanity: the imports above ensure the harness links even when tests
// don't touch them directly.
fn _unused() {
    let _ = Weak::<Ext2Super>::new();
}
