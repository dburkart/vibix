//! Integration test for issue #568: ext2 `create` / `mkdir` / `mknod`.
//!
//! Mounts the 64 KiB golden image RW and exercises the
//! `InodeOps`-shaped helpers that land an inode-bitmap bit, stamp a
//! fresh inode-table slot, and splice a new dirent into the parent
//! directory block — in the RFC 0004 §Write Ordering sequence.
//!
//! Coverage:
//!
//! - `create_file` stamps a regular-file inode and inserts a dirent.
//!   A follow-up `dir::lookup` finds the new ino.
//! - `create_dir` allocates a data block for the new dir, stamps
//!   `.` / `..`, and bumps the parent's `i_links_count`.
//! - `mknod` (FIFO) creates a pipe-backed dirent with `i_block[0] == 0`.
//! - `create_file` with an existing name returns `EEXIST`.
//! - `create_file` with a bad name (empty, `.`, `..`, contains `/`)
//!   returns `EINVAL` (or `ENAMETOOLONG` for oversize).
//! - RO mount refuses any create → `EROFS` and no disk writes.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32};

use vibix::block::BlockDevice;
use vibix::fs::ext2::{
    create_dir, create_file, dir, iget, mknod, Ext2Fs, Ext2Inode, Ext2InodeMeta, Ext2Super,
};
use vibix::fs::vfs::inode::InodeKind;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EEXIST, EINVAL, ENAMETOOLONG, EROFS};
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
        ("create_file_lookup", &(create_file_lookup as fn())),
        (
            "create_file_rejects_duplicate",
            &(create_file_rejects_duplicate as fn()),
        ),
        (
            "create_file_rejects_bad_names",
            &(create_file_rejects_bad_names as fn()),
        ),
        (
            "create_dir_stamps_dot_dotdot",
            &(create_dir_stamps_dot_dotdot as fn()),
        ),
        ("mknod_fifo_lookup", &(mknod_fifo_lookup as fn())),
        (
            "ro_mount_refuses_create",
            &(ro_mount_refuses_create as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs (issues
// #627, #658).
#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

fn mount_golden_rw() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc, disk)
}

fn mount_golden_ro() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");
    disk.set_read_only(true);
    let super_arc = fs
        .current_super()
        .expect("Ext2Fs::current_super must upgrade after a successful mount");
    (sb, fs, super_arc, disk)
}

/// Re-hydrate a driver-level `Ext2Inode` from the on-disk inode slot,
/// matching the pattern in `ext2_dir_ops.rs`. We need a concrete
/// `Ext2Inode` to pass to the `create_*` / `mknod` free functions; the
/// trait-level dispatch via `InodeOps::create` is exercised through the
/// `Ext2Inode` type's impl, which forwards to these same helpers.
fn make_ext2_inode_from_disk(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Ext2Inode {
    // Force the VFS-level inode through the cache so a parallel
    // subsystem (buffer cache readback) has already populated block 8
    // for the root inode. We don't keep the returned `Arc<Inode>` — the
    // helpers below operate on the concrete `Ext2Inode` we re-build.
    let _ = iget(super_arc, sb, ino).expect("iget must succeed for a live ino");

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn create_file_lookup() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let new_inode = create_file(&super_arc, &parent, &parent_vfs, &sb, b"hello", 0o644)
        .expect("create_file must succeed");
    let new_ino = new_inode.ino as u32;
    assert!(
        new_ino >= 12,
        "new ino ({new_ino}) must be past the reserved range"
    );
    assert_eq!(new_inode.kind, InodeKind::Reg);

    // Rebuild parent from disk — its i_block[0] (dir block) hasn't changed,
    // but we want the freshest snapshot in case add_link grew it.
    let parent_after = make_ext2_inode_from_disk(&super_arc, &sb, 2);
    let found = dir::lookup(&super_arc, &parent_after, b"hello").expect("lookup new file");
    assert_eq!(found, new_ino);

    sb.ops.unmount();
    drop(super_arc);
}

fn create_file_rejects_duplicate() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // `lost+found` already exists on the golden image at ino 11.
    let err = create_file(&super_arc, &parent, &parent_vfs, &sb, b"lost+found", 0o644)
        .err()
        .expect("duplicate name must fail");
    assert_eq!(err, EEXIST);

    sb.ops.unmount();
    drop(super_arc);
}

fn create_file_rejects_bad_names() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Empty name → EINVAL.
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"", 0o644).err(),
        Some(EINVAL),
    );
    // `.` and `..` reserved — they always collide with the implicit
    // self/parent dirents, so the right error is EEXIST.
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, b".", 0o644).err(),
        Some(EEXIST),
    );
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"..", 0o644).err(),
        Some(EEXIST),
    );
    // Name containing `/` is illegal.
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"a/b", 0o644).err(),
        Some(EINVAL),
    );
    // Name containing NUL is illegal.
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"a\0b", 0o644).err(),
        Some(EINVAL),
    );
    // 256-byte name → ENAMETOOLONG (ext2 cap is 255).
    let too_long = [b'x'; 256];
    assert_eq!(
        create_file(&super_arc, &parent, &parent_vfs, &sb, &too_long, 0o644).err(),
        Some(ENAMETOOLONG),
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn create_dir_stamps_dot_dotdot() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let root_nlink_before = parent.meta.read().links_count;

    let new_dir = create_dir(&super_arc, &parent, &parent_vfs, &sb, b"subdir", 0o755)
        .expect("create_dir must succeed");
    let new_ino = new_dir.ino as u32;
    assert_eq!(new_dir.kind, InodeKind::Dir);

    // The new directory should contain `.` and `..`.
    let new_dir_ext2 = make_ext2_inode_from_disk(&super_arc, &sb, new_ino);
    let dot = dir::lookup(&super_arc, &new_dir_ext2, b".").expect("lookup .");
    assert_eq!(dot, new_ino);
    let dotdot = dir::lookup(&super_arc, &new_dir_ext2, b"..").expect("lookup ..");
    assert_eq!(dotdot, 2, ".. in subdir points at parent (root=2)");

    // Parent's nlink should have gone up by 1 (the new subdir's `..`
    // back-link). Read the fresh meta off-disk.
    let parent_after = make_ext2_inode_from_disk(&super_arc, &sb, 2);
    assert_eq!(
        parent_after.meta.read().links_count,
        root_nlink_before + 1,
        "parent nlink must bump by 1 on mkdir"
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn mknod_fifo_lookup() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let new_fifo = mknod(
        &super_arc,
        &parent,
        &parent_vfs,
        &sb,
        b"fifo",
        InodeKind::Fifo,
        0o644,
        0,
    )
    .expect("mknod(fifo) must succeed");
    let new_ino = new_fifo.ino as u32;
    assert_eq!(new_fifo.kind, InodeKind::Fifo);

    let parent_after = make_ext2_inode_from_disk(&super_arc, &sb, 2);
    let found = dir::lookup(&super_arc, &parent_after, b"fifo").expect("lookup fifo");
    assert_eq!(found, new_ino);

    // FIFOs carry no device number; a non-zero rdev must be refused.
    let err = mknod(
        &super_arc,
        &parent,
        &parent_vfs,
        &sb,
        b"fifo2",
        InodeKind::Fifo,
        0o644,
        42,
    )
    .err()
    .expect("non-zero rdev on FIFO must fail");
    assert_eq!(err, EINVAL);

    sb.ops.unmount();
    drop(super_arc);
}

fn ro_mount_refuses_create() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // RO mount: creating anything must fail with EROFS and issue zero
    // writes against the backing store.
    let writes_before = disk.writes();
    let err = create_file(&super_arc, &parent, &parent_vfs, &sb, b"nope", 0o644)
        .err()
        .expect("RO mount must refuse create");
    assert_eq!(err, EROFS);
    let err2 = create_dir(&super_arc, &parent, &parent_vfs, &sb, b"dirnope", 0o755)
        .err()
        .expect("RO mount must refuse mkdir");
    assert_eq!(err2, EROFS);
    let err3 = mknod(
        &super_arc,
        &parent,
        &parent_vfs,
        &sb,
        b"fifonope",
        InodeKind::Fifo,
        0o644,
        0,
    )
    .err()
    .expect("RO mount must refuse mknod");
    assert_eq!(err3, EROFS);
    assert_eq!(
        disk.writes(),
        writes_before,
        "RO mount must not issue any writes on refused create"
    );

    sb.ops.unmount();
    drop(super_arc);
}
