//! Integration test for issue #570: ext2 `InodeOps::link` +
//! `InodeOps::symlink`.
//!
//! Mounts the 64 KiB golden image RW and exercises the two write-side
//! entry points on `Ext2Inode`:
//!
//! - `link`: bumps target's `i_links_count`, inserts a dirent in the
//!   parent, refuses directory targets with `EPERM`, refuses
//!   `u16::MAX` link counts with `EMLINK`.
//! - `symlink`: fast-path (≤ 60 bytes, inline in `i_block[]`, zero
//!   `i_blocks`) and slow-path (> 60 bytes, single data block). Verify
//!   the target reads back byte-for-byte through the existing
//!   `read_symlink` helper.
//!
//! Shares the RamDisk / mount plumbing with `ext2_create.rs`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::symlink::{is_fast_symlink, is_symlink, read_symlink, EXT2_FAST_SYMLINK_MAX};
use vibix::fs::ext2::{
    create_dir, create_file, dir, iget, link as ext2_link, symlink as ext2_symlink, Ext2Fs,
    Ext2Inode, Ext2InodeMeta, Ext2Super,
};
use vibix::fs::vfs::inode::InodeKind;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EEXIST, ENAMETOOLONG, ENOTDIR, EPERM, EROFS};
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
            "link_bumps_nlink_and_inserts_dirent",
            &(link_bumps_nlink_and_inserts_dirent as fn()),
        ),
        (
            "link_refuses_directory_target",
            &(link_refuses_directory_target as fn()),
        ),
        (
            "link_refuses_duplicate_name",
            &(link_refuses_duplicate_name as fn()),
        ),
        ("link_ro_mount_refuses", &(link_ro_mount_refuses as fn())),
        (
            "symlink_fast_inline_60_bytes",
            &(symlink_fast_inline_60_bytes as fn()),
        ),
        ("symlink_slow_61_bytes", &(symlink_slow_61_bytes as fn())),
        (
            "symlink_boundary_60_vs_61",
            &(symlink_boundary_60_vs_61 as fn()),
        ),
        (
            "symlink_rejects_oversize",
            &(symlink_rejects_oversize as fn()),
        ),
        (
            "symlink_rejects_bad_name",
            &(symlink_rejects_bad_name as fn()),
        ),
        (
            "symlink_ro_mount_refuses",
            &(symlink_ro_mount_refuses as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — identical shape to ext2_create.rs / ext2_unlink.rs.
// ---------------------------------------------------------------------------

struct RamDisk {
    block_size: u32,
    storage: Mutex<Vec<u8>>,
    writes: AtomicU32,
    read_only: AtomicBool,
}

impl RamDisk {
    fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(bytes.len() % block_size as usize == 0);
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
            writes: AtomicU32::new(0),
            read_only: AtomicBool::new(false),
        })
    }
    fn set_read_only(&self, ro: bool) {
        self.read_only.store(ro, Ordering::Relaxed);
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
    let super_arc = fs.current_super().expect("current_super must upgrade");
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
    let super_arc = fs.current_super().expect("current_super must upgrade");
    (sb, fs, super_arc, disk)
}

fn make_ext2_inode_from_disk(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Ext2Inode {
    let _ = iget(super_arc, sb, ino).expect("iget live ino");

    let inodes_per_group = super_arc.sb_disk.lock().s_inodes_per_group;
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
    }
}

/// Re-decode the raw on-disk inode (`disk::Ext2Inode`) for a given
/// ino. The `read_symlink` helper needs this shape, not the driver-
/// level `Ext2Inode`.
fn read_disk_inode(super_arc: &Arc<Ext2Super>, ino: u32) -> vibix::fs::ext2::disk::Ext2Inode {
    let inodes_per_group = super_arc.sb_disk.lock().s_inodes_per_group;
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
    vibix::fs::ext2::disk::Ext2Inode::decode(&slot)
}

// ---------------------------------------------------------------------------
// Tests — hard link
// ---------------------------------------------------------------------------

fn link_bumps_nlink_and_inserts_dirent() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // First create a regular file we'll hard-link.
    let src = create_file(&super_arc, &parent, &parent_vfs, &sb, b"target", 0o644)
        .expect("create_file target");
    let src_ino = src.ino as u32;
    let nlink_before = {
        let d = read_disk_inode(&super_arc, src_ino);
        d.i_links_count
    };

    // Re-read parent meta — add_link may have extended the dir.
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    ext2_link(&super_arc, &parent, &parent_vfs, &src, b"alias").expect("link must succeed");

    // On-disk nlink must have bumped by 1.
    let d_after = read_disk_inode(&super_arc, src_ino);
    assert_eq!(
        d_after.i_links_count,
        nlink_before + 1,
        "target i_links_count must bump by 1"
    );

    // Fresh dirent `alias` resolves to the same ino.
    let parent_after = make_ext2_inode_from_disk(&super_arc, &sb, 2);
    let found = dir::lookup(&super_arc, &parent_after, b"alias").expect("lookup alias");
    assert_eq!(found, src_ino, "alias must resolve to src ino");
    let found_orig = dir::lookup(&super_arc, &parent_after, b"target").expect("lookup target");
    assert_eq!(found_orig, src_ino);

    // In-memory VFS nlink also bumped.
    assert_eq!(
        src.meta.read().nlink as u16,
        nlink_before + 1,
        "VFS meta nlink mirrors on-disk bump"
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn link_refuses_directory_target() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Create a subdir.
    let subdir =
        create_dir(&super_arc, &parent, &parent_vfs, &sb, b"subd", 0o755).expect("create_dir");

    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Linking a directory must fail with EPERM.
    let err = ext2_link(&super_arc, &parent, &parent_vfs, &subdir, b"dalias")
        .err()
        .expect("link to dir must fail");
    assert_eq!(err, EPERM);

    sb.ops.unmount();
    drop(super_arc);
}

fn link_refuses_duplicate_name() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let src =
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"src", 0o644).expect("create_file src");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // `lost+found` already exists on the golden image; linking to that
    // name must surface EEXIST.
    let err = ext2_link(&super_arc, &parent, &parent_vfs, &src, b"lost+found")
        .err()
        .expect("duplicate name must fail");
    assert_eq!(err, EEXIST);

    sb.ops.unmount();
    drop(super_arc);
}

fn link_ro_mount_refuses() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Use the root inode itself (dir) as the "target" — the RO check
    // fires before the directory-target refusal, so EROFS wins. We
    // pass `parent_vfs` as the target too (it happens to be the only
    // Arc<Inode> in hand, and the check is ordered correctly).
    let err = ext2_link(&super_arc, &parent, &parent_vfs, &parent_vfs, b"nope")
        .err()
        .expect("RO mount must refuse link");
    assert_eq!(err, EROFS);
    assert_eq!(disk.writes(), 0, "no writes on a refused RO link");

    sb.ops.unmount();
    drop(super_arc);
}

// ---------------------------------------------------------------------------
// Tests — symbolic link
// ---------------------------------------------------------------------------

fn symlink_fast_inline_60_bytes() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let target: &[u8] = b"/bin/sh";
    let sl =
        ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"sh", target).expect("symlink fast");
    let sl_ino = sl.ino as u32;
    assert_eq!(sl.kind, InodeKind::Link);

    let d = read_disk_inode(&super_arc, sl_ino);
    assert!(is_symlink(&d));
    assert!(
        is_fast_symlink(&d),
        "target ≤ 60 bytes must land in the inline fast path"
    );
    assert_eq!(d.i_size as usize, target.len());
    assert_eq!(d.i_blocks, 0, "fast symlink has zero allocated blocks");

    // Target reads back byte-for-byte via the existing readlink helper.
    let mut buf = [0xffu8; 128];
    let n = read_symlink(&d, &super_arc, &mut buf).expect("read back fast symlink");
    assert_eq!(n, target.len());
    assert_eq!(&buf[..n], target);

    // Dirent resolves to the symlink ino.
    let parent_after = make_ext2_inode_from_disk(&super_arc, &sb, 2);
    let found = dir::lookup(&super_arc, &parent_after, b"sh").expect("lookup sh");
    assert_eq!(found, sl_ino);

    sb.ops.unmount();
    drop(super_arc);
}

fn symlink_slow_61_bytes() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // 64-byte target is > 60, forcing the slow path.
    let target: [u8; 64] = core::array::from_fn(|i| b'a' + (i % 26) as u8);
    let sl = ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"long", &target)
        .expect("symlink slow");
    let sl_ino = sl.ino as u32;

    let d = read_disk_inode(&super_arc, sl_ino);
    assert!(is_symlink(&d));
    assert!(
        !is_fast_symlink(&d),
        "target > 60 bytes must land in the slow path"
    );
    assert_eq!(d.i_size as usize, target.len());
    assert_ne!(d.i_blocks, 0, "slow symlink allocates a data block");
    assert_ne!(
        d.i_block[0], 0,
        "slow symlink i_block[0] is the target block"
    );

    let mut buf = [0u8; 128];
    let n = read_symlink(&d, &super_arc, &mut buf).expect("read back slow symlink");
    assert_eq!(n, target.len());
    assert_eq!(&buf[..n], &target);

    sb.ops.unmount();
    drop(super_arc);
}

fn symlink_boundary_60_vs_61() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Exactly 60 bytes must still be inline.
    let t60: [u8; 60] = core::array::from_fn(|i| b'0' + (i % 10) as u8);
    assert_eq!(EXT2_FAST_SYMLINK_MAX as usize, 60);
    let sl60 =
        ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"s60", &t60).expect("60-byte symlink");
    let d60 = read_disk_inode(&super_arc, sl60.ino as u32);
    assert!(is_fast_symlink(&d60), "60 bytes is the inline boundary");
    let mut buf = [0u8; 64];
    let n = read_symlink(&d60, &super_arc, &mut buf).expect("readback 60");
    assert_eq!(n, 60);
    assert_eq!(&buf[..60], &t60);

    // Re-read parent between calls to pick up freshly-added dirents /
    // possibly-grown block pointer.
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // 61 bytes flips to the slow path.
    let t61: [u8; 61] = core::array::from_fn(|i| b'A' + (i % 26) as u8);
    let sl61 =
        ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"s61", &t61).expect("61-byte symlink");
    let d61 = read_disk_inode(&super_arc, sl61.ino as u32);
    assert!(
        !is_fast_symlink(&d61),
        "61 bytes is one past the inline boundary"
    );
    let mut buf = [0u8; 128];
    let n = read_symlink(&d61, &super_arc, &mut buf).expect("readback 61");
    assert_eq!(n, 61);
    assert_eq!(&buf[..61], &t61);

    sb.ops.unmount();
    drop(super_arc);
}

fn symlink_rejects_oversize() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // 4096-byte target — one past PATH_MAX-minus-NUL. Must fail
    // ENAMETOOLONG before any allocation.
    let huge = [b'x'; 4096];
    let err = ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"huge", &huge)
        .err()
        .expect("oversize target must fail");
    assert_eq!(err, ENAMETOOLONG);

    sb.ops.unmount();
    drop(super_arc);
}

fn symlink_rejects_bad_name() {
    let (sb, _fs, super_arc, _disk) = mount_golden_rw();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    // Reserved names surface as EEXIST (same reason as create_common's
    // validate_name path).
    let err = ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b".", b"/bin")
        .err()
        .expect("`.` name must fail");
    assert_eq!(err, EEXIST);

    // Parent inode must actually be a dir.
    let reg =
        create_file(&super_arc, &parent, &parent_vfs, &sb, b"reg", 0o644).expect("create reg");
    let reg_ext2 = make_ext2_inode_from_disk(&super_arc, &sb, reg.ino as u32);
    let err = ext2_symlink(&super_arc, &reg_ext2, &reg, &sb, b"bad", b"/bin")
        .err()
        .expect("non-dir parent must fail");
    assert_eq!(err, ENOTDIR);

    sb.ops.unmount();
    drop(super_arc);
}

fn symlink_ro_mount_refuses() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let parent_vfs = iget(&super_arc, &sb, 2).expect("iget root");
    let parent = make_ext2_inode_from_disk(&super_arc, &sb, 2);

    let err = ext2_symlink(&super_arc, &parent, &parent_vfs, &sb, b"sl", b"/bin/sh")
        .err()
        .expect("RO mount must refuse symlink");
    assert_eq!(err, EROFS);
    assert_eq!(disk.writes(), 0, "no writes on a refused RO symlink");

    sb.ops.unmount();
    drop(super_arc);
}
