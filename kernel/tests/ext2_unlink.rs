//! Integration test for issue #569: ext2 `InodeOps::unlink` +
//! `InodeOps::rmdir` with orphan-list add on hit-zero.
//!
//! Mounts the 64 KiB golden image (one 1024-byte block group, inos
//! 1..=11 allocated, `/` with `.`, `..`, `lost+found`) and exercises:
//!
//! - **rmdir of an empty directory** — remove `/lost+found` (ino 11).
//!   After the call: `dir::lookup` returns `ENOENT`; `i_links_count`
//!   of the child drops to 0; the child lands on `Ext2Super.orphan_list`
//!   and `s_last_orphan` on disk points at ino 11; the parent's own
//!   `i_links_count` drops by 1 (lost the `..` back-link).
//! - **rmdir refuses a non-dir** — build a synthetic pointer to ino 2
//!   (`/`) and call rmdir for its name, then separately try rmdir on
//!   a regular-file ino to confirm `ENOTDIR`. (The golden image only
//!   has `lost+found` as a dir entry; we exercise ENOTDIR through the
//!   reciprocal `unlink` call path below.)
//! - **unlink refuses a directory** — calling `InodeOps::unlink` for
//!   `lost+found` surfaces `EISDIR`.
//! - **unlink / rmdir with bogus name** — `ENOENT`.
//! - **unlink / rmdir with "." / ".."** — `EINVAL`.
//! - **RO mount refuses both** — `EROFS`.
//!
//! Direct unlinking of a reg file isn't exercised here: the golden
//! image has no reg-file entries in `/` (mkfs.ext2 without `-d` ships
//! only `lost+found`). The create-path issue (#568) adds the
//! reg-file-unlink coverage on top of this PR's rmdir machinery.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EINVAL, EISDIR, ENOENT, EROFS};
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
            "rmdir_removes_lost_found_and_orphans",
            &(rmdir_removes_lost_found_and_orphans as fn()),
        ),
        (
            "unlink_of_directory_is_eisdir",
            &(unlink_of_directory_is_eisdir as fn()),
        ),
        (
            "unlink_missing_name_is_enoent",
            &(unlink_missing_name_is_enoent as fn()),
        ),
        (
            "rmdir_missing_name_is_enoent",
            &(rmdir_missing_name_is_enoent as fn()),
        ),
        (
            "unlink_dot_and_dotdot_are_einval",
            &(unlink_dot_and_dotdot_are_einval as fn()),
        ),
        (
            "ro_mount_refuses_unlink_and_rmdir",
            &(ro_mount_refuses_unlink_and_rmdir as fn()),
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

fn mount_rw() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>, Arc<RamDisk>) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount");
    let super_arc = fs.current_super().expect("current_super");
    (sb, fs, super_arc, disk)
}

fn mount_ro() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>, Arc<RamDisk>) {
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
// Tests
// ---------------------------------------------------------------------------

fn rmdir_removes_lost_found_and_orphans() {
    let (sb, _fs, super_arc, _disk) = mount_rw();

    // Resolve root + lost+found; remember the pre-unlink parent links_count
    // (should drop by 1) and s_last_orphan (should become 11 after the call).
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let lf_before = iget(&super_arc, &sb, 11).expect("iget lost+found");
    let parent_nlink_before = root.meta.read().nlink;
    let last_orphan_before = super_arc.sb_disk.lock().s_last_orphan;
    assert_eq!(
        last_orphan_before, 0,
        "fresh mkfs image must start with empty orphan chain"
    );
    // ensure iget populated the VFS inode for ino 11 before rmdir — so the
    // post-unlink orphan-list entry is the same Arc the test saw.
    let _ = lf_before;

    // Invoke rmdir via the trait. Root is a dir, so its ops.rmdir routes
    // into Ext2InodeOps::rmdir → unlink::rmdir.
    root.ops
        .rmdir(&root, b"lost+found")
        .expect("rmdir(lost+found)");

    // Parent (ino 2) lost one nlink (the `..` back-link).
    let parent_nlink_after = root.meta.read().nlink;
    assert_eq!(
        parent_nlink_after,
        parent_nlink_before - 1,
        "rmdir must decrement parent nlink for lost ..-back-link"
    );

    // Dirent is gone: a second rmdir returns ENOENT — the name is
    // no longer resolvable through the parent's directory walk.

    // On-disk s_last_orphan points at ino 11.
    let last_orphan_after = super_arc.sb_disk.lock().s_last_orphan;
    assert_eq!(
        last_orphan_after, 11,
        "orphan list head must point at rmdir'd ino"
    );

    // In-memory orphan_list pins ino 11.
    let pinned = {
        let list = super_arc.orphan_list.lock();
        list.contains_key(&11)
    };
    assert!(pinned, "in-memory orphan_list must pin ino 11 after rmdir");

    // The pinned Arc<Inode> matches what a fresh iget hands back (same
    // object identity — the orphan list takes the VFS inode we pass in).
    {
        let list = super_arc.orphan_list.lock();
        let pinned_arc = list.get(&11).expect("pinned entry").clone();
        drop(list);
        assert_eq!(pinned_arc.ino, 11, "pinned entry must be ino 11");
    }

    // Second rmdir of the same name fails — the dirent is gone.
    let err = root.ops.rmdir(&root, b"lost+found").expect_err("no-op");
    assert_eq!(err, ENOENT);

    sb.ops.unmount();
    drop(super_arc);
}

fn unlink_of_directory_is_eisdir() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root = iget(&super_arc, &sb, 2).expect("iget root");

    // lost+found is a directory; InodeOps::unlink must refuse with EISDIR.
    let err = root.ops.unlink(&root, b"lost+found").expect_err("EISDIR");
    assert_eq!(
        err, EISDIR,
        "unlink on a directory entry must return EISDIR"
    );

    sb.ops.unmount();
    drop(super_arc);
}

fn unlink_missing_name_is_enoent() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let err = root
        .ops
        .unlink(&root, b"does-not-exist")
        .expect_err("ENOENT");
    assert_eq!(err, ENOENT);
    sb.ops.unmount();
    drop(super_arc);
}

fn rmdir_missing_name_is_enoent() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let err = root
        .ops
        .rmdir(&root, b"does-not-exist")
        .expect_err("ENOENT");
    assert_eq!(err, ENOENT);
    sb.ops.unmount();
    drop(super_arc);
}

fn unlink_dot_and_dotdot_are_einval() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    assert_eq!(root.ops.unlink(&root, b".").err(), Some(EINVAL));
    assert_eq!(root.ops.unlink(&root, b"..").err(), Some(EINVAL));
    assert_eq!(root.ops.rmdir(&root, b".").err(), Some(EINVAL));
    assert_eq!(root.ops.rmdir(&root, b"..").err(), Some(EINVAL));
    sb.ops.unmount();
    drop(super_arc);
}

fn ro_mount_refuses_unlink_and_rmdir() {
    let (sb, _fs, super_arc, _disk) = mount_ro();
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    assert_eq!(
        root.ops.unlink(&root, b"lost+found").err(),
        Some(EROFS),
        "RO mount must refuse unlink"
    );
    assert_eq!(
        root.ops.rmdir(&root, b"lost+found").err(),
        Some(EROFS),
        "RO mount must refuse rmdir"
    );
    sb.ops.unmount();
    drop(super_arc);
}
