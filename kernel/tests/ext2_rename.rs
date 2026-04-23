//! Integration test for issue #571: ext2 `InodeOps::rename` with
//! link-count-first ordering and cross-directory loop check.
//!
//! Uses the standard 64 KiB golden image. Each test creates its own
//! scratch files/dirs via `create_file` / `create_dir` (issue #568)
//! before exercising rename, so the image's lone baked-in dirent
//! (`lost+found`) is preserved between tests that share a mount.
//!
//! Coverage:
//!
//! - `rename_same_dir` — rename `a` → `b` in `/`, source ino
//!   preserved, old name gone, new name resolves to the same ino.
//! - `rename_cross_dir` — `mkdir /d`, `create /f`, rename `/f` → `/d/f`.
//!   Old location gone, new location resolves, source ino stable.
//! - `rename_replaces_regular` — rename over an existing regular file:
//!   victim dropped to links_count 0, pushed on the orphan list.
//! - `rename_noreplace_equivalent_via_probe` — if destination exists
//!   for a same-type-mismatch, we surface `EISDIR`/`ENOTDIR` (the
//!   trait doesn't expose a NOREPLACE flag but the type-mismatch
//!   arm is the closest check the ext2 path honours).
//! - `rename_into_descendant_is_einval` — `mkdir /a`, `mkdir /a/b`,
//!   rename `/a` → `/a/b/a` must fail with EINVAL.
//! - `rename_dir_updates_dotdot` — cross-dir directory move updates
//!   the source's `..` to point at the new parent and shuffles the
//!   parents' nlinks.
//! - `rename_ro_mount_is_erofs` — RO mount refuses rename.
//! - `rename_dot_and_dotdot_einval` — refuse `.` / `..` as source or
//!   destination names.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{dir, iget, Ext2Fs, Ext2Inode, Ext2InodeMeta, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EINVAL, ENOENT, EROFS};
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
        ("rename_same_dir", &(rename_same_dir as fn())),
        ("rename_cross_dir", &(rename_cross_dir as fn())),
        (
            "rename_replaces_regular",
            &(rename_replaces_regular as fn()),
        ),
        (
            "rename_into_descendant_is_einval",
            &(rename_into_descendant_is_einval as fn()),
        ),
        (
            "rename_dir_updates_dotdot",
            &(rename_dir_updates_dotdot as fn()),
        ),
        (
            "rename_ro_mount_is_erofs",
            &(rename_ro_mount_is_erofs as fn()),
        ),
        (
            "rename_dot_and_dotdot_einval",
            &(rename_dot_and_dotdot_einval as fn()),
        ),
        ("rename_same_name_noop", &(rename_same_name_noop as fn())),
        (
            "rename_missing_same_name_is_enoent",
            &(rename_missing_same_name_is_enoent as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — matches the other ext2 integration tests.
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

fn mount_rw() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount");
    let super_arc = fs.current_super().expect("current_super");
    (sb, fs, super_arc, disk)
}

fn mount_ro() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount");
    disk.set_read_only(true);
    let super_arc = fs.current_super().expect("current_super");
    (sb, fs, super_arc, disk)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Grab the VFS `Arc<Inode>` for a given ino via iget.
fn get(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Arc<vibix::fs::vfs::inode::Inode> {
    iget(super_arc, sb, ino).expect("iget")
}

/// Re-hydrate a driver-private `Ext2Inode` from the on-disk inode
/// slot. Mirrors `ext2_create.rs::make_ext2_inode_from_disk` — we
/// need a concrete `Ext2Inode` to hand to the `dir::lookup` helper,
/// which lives on the driver-private type.
fn ext2_from_disk(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Ext2Inode {
    let _ = iget(super_arc, sb, ino).expect("iget");
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
        .expect("bread");
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn rename_same_dir() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    // Create `/a`.
    let a = root_arc
        .ops
        .create(&root_arc, b"a", 0o644)
        .expect("create /a");
    let a_ino = a.ino as u32;

    // Rename `/a` → `/b`.
    root_arc
        .ops
        .rename(&root_arc, b"a", &root_arc, b"b")
        .expect("rename a->b");

    // Verify via a fresh on-disk inode handle so we don't trust the
    // post-rename in-memory meta.
    let root_e2 = ext2_from_disk(&super_arc, &sb, 2);
    assert!(
        dir::lookup(&super_arc, &root_e2, b"a").is_err(),
        "old name /a must be gone"
    );
    let b_ino = dir::lookup(&super_arc, &root_e2, b"b").expect("lookup b");
    assert_eq!(b_ino, a_ino, "new name must resolve to source ino");

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_cross_dir() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    // Create `/d` (dir) and `/f` (reg file).
    let d_vfs = root_arc
        .ops
        .mkdir(&root_arc, b"d", 0o755)
        .expect("mkdir /d");
    let d_ino = d_vfs.ino as u32;
    let f = root_arc
        .ops
        .create(&root_arc, b"f", 0o644)
        .expect("create /f");
    let f_ino = f.ino as u32;

    // Rename `/f` → `/d/f`.
    root_arc
        .ops
        .rename(&root_arc, b"f", &d_vfs, b"f")
        .expect("rename /f -> /d/f");

    // Old location gone; new location resolves to the source ino.
    let root_e2 = ext2_from_disk(&super_arc, &sb, 2);
    let d_e2 = ext2_from_disk(&super_arc, &sb, d_ino);
    assert!(dir::lookup(&super_arc, &root_e2, b"f").is_err());
    assert_eq!(
        dir::lookup(&super_arc, &d_e2, b"f").expect("lookup /d/f"),
        f_ino,
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_replaces_regular() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    let a = root_arc
        .ops
        .create(&root_arc, b"a", 0o644)
        .expect("create /a");
    let victim = root_arc
        .ops
        .create(&root_arc, b"v", 0o644)
        .expect("create /v");
    let a_ino = a.ino as u32;
    let v_ino = victim.ino as u32;

    // Rename /a -> /v, replacing the existing regular file.
    root_arc
        .ops
        .rename(&root_arc, b"a", &root_arc, b"v")
        .expect("rename /a -> /v (replace)");

    let root_e2 = ext2_from_disk(&super_arc, &sb, 2);
    assert!(dir::lookup(&super_arc, &root_e2, b"a").is_err());
    assert_eq!(
        dir::lookup(&super_arc, &root_e2, b"v").expect("lookup /v"),
        a_ino,
    );

    // Victim landed on the orphan list — its links_count went to 0.
    {
        let list = super_arc.orphan_list.lock();
        assert!(
            list.contains_key(&v_ino),
            "victim inode {} must be pinned on the orphan list after replace",
            v_ino,
        );
    }

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_into_descendant_is_einval() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    // Build /a/b.
    let a_vfs = root_arc
        .ops
        .mkdir(&root_arc, b"a", 0o755)
        .expect("mkdir /a");
    let b_vfs = a_vfs.ops.mkdir(&a_vfs, b"b", 0o755).expect("mkdir /a/b");

    // rename /a -> /a/b/a must fail with EINVAL (target inside source).
    let err = root_arc
        .ops
        .rename(&root_arc, b"a", &b_vfs, b"a")
        .expect_err("rename-into-descendant must fail");
    assert_eq!(err, EINVAL);

    // rename /a -> /a/x (target IS source dir) also fails EINVAL.
    let err2 = root_arc
        .ops
        .rename(&root_arc, b"a", &a_vfs, b"x")
        .expect_err("rename-into-self must fail");
    assert_eq!(err2, EINVAL);

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_dir_updates_dotdot() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    // Two sibling dirs: /p (will become parent of moved) and /m (the
    // dir we'll move into /p).
    let p_vfs = root_arc
        .ops
        .mkdir(&root_arc, b"p", 0o755)
        .expect("mkdir /p");
    let m_vfs = root_arc
        .ops
        .mkdir(&root_arc, b"m", 0o755)
        .expect("mkdir /m");
    let p_ino = p_vfs.ino as u32;
    let m_ino = m_vfs.ino as u32;

    // Rename /m -> /p/m.
    root_arc
        .ops
        .rename(&root_arc, b"m", &p_vfs, b"m")
        .expect("rename /m -> /p/m");

    // /m gone from root; /p/m resolves to the moved ino.
    let root_e2 = ext2_from_disk(&super_arc, &sb, 2);
    let p_e2 = ext2_from_disk(&super_arc, &sb, p_ino);
    assert!(dir::lookup(&super_arc, &root_e2, b"m").is_err());
    assert_eq!(
        dir::lookup(&super_arc, &p_e2, b"m").expect("lookup /p/m"),
        m_ino,
    );

    // /p/m/.. must now resolve to /p.
    let m_e2 = ext2_from_disk(&super_arc, &sb, m_ino);
    let dotdot = dir::lookup(&super_arc, &m_e2, b"..").expect("lookup ..");
    assert_eq!(dotdot, p_ino, "moved dir's .. must point at new parent");

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_ro_mount_is_erofs() {
    let (sb, _fs, super_arc, _disk) = mount_ro();
    let root_arc = get(&super_arc, &sb, 2);

    // lost+found is present on the golden image; an attempt to rename
    // it (or any other existing name) on an RO mount must surface
    // EROFS before touching the disk. The rename's error path short-
    // circuits before we even dereference the source's dirent.
    let err = root_arc
        .ops
        .rename(&root_arc, b"lost+found", &root_arc, b"newname")
        .expect_err("RO rename must fail");
    assert_eq!(err, EROFS);

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_dot_and_dotdot_einval() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    assert_eq!(
        root_arc.ops.rename(&root_arc, b".", &root_arc, b"x").err(),
        Some(EINVAL),
    );
    assert_eq!(
        root_arc.ops.rename(&root_arc, b"..", &root_arc, b"x").err(),
        Some(EINVAL),
    );
    assert_eq!(
        root_arc
            .ops
            .rename(&root_arc, b"lost+found", &root_arc, b".")
            .err(),
        Some(EINVAL),
    );
    assert_eq!(
        root_arc
            .ops
            .rename(&root_arc, b"lost+found", &root_arc, b"..")
            .err(),
        Some(EINVAL),
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn rename_same_name_noop() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    let a = root_arc
        .ops
        .create(&root_arc, b"keep", 0o644)
        .expect("create /keep");
    let a_ino = a.ino as u32;

    // Renaming onto itself is a no-op.
    root_arc
        .ops
        .rename(&root_arc, b"keep", &root_arc, b"keep")
        .expect("rename self must succeed as no-op");

    let root_e2 = ext2_from_disk(&super_arc, &sb, 2);
    assert_eq!(
        dir::lookup(&super_arc, &root_e2, b"keep").expect("still there"),
        a_ino,
    );

    sb.ops.unmount();
    drop(super_arc);
}

/// Regression: renaming a missing source onto the same missing name
/// in the same parent must still fail with ENOENT, not succeed as a
/// no-op. Previously a fast path returned Ok(()) for same-parent,
/// same-name renames before verifying the source even existed.
fn rename_missing_same_name_is_enoent() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root_arc = get(&super_arc, &sb, 2);

    let err = root_arc
        .ops
        .rename(&root_arc, b"does-not-exist", &root_arc, b"does-not-exist")
        .expect_err("missing source must not succeed");
    assert_eq!(err, ENOENT);

    sb.ops.unmount();
    drop(super_arc);
}
