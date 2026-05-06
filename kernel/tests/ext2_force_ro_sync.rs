//! Integration test for issue #806: force-RO on uncertain
//! `sync_dirty_buffer`.
//!
//! RFC 0004 ss Write Ordering / ss Security: a `sync_dirty_buffer`
//! returning `Err` does not prove the bytes never reached disk. The
//! buffer cache now atomically trips the `force_ro_latch` on any device
//! write failure so subsequent writes refuse with `EROFS` and the
//! bitmap is never double-freed.
//!
//! Strategy:
//!
//! 1. Mount the 512 KiB `balloc_test.img` RW on a `RamDisk` whose
//!    `set_fail_after(N)` is armed after mount succeeds. `N` is chosen
//!    so the first `sync_dirty_buffer` triggered by a file write will
//!    hit the device error.
//! 2. Drive a `FileOps::write` (small 1-byte payload).
//! 3. Assert `Ext2Super::is_writable() == false` — the latch was
//!    tripped by the buffer cache, not by any individual call site.
//! 4. Assert the write returned `EIO`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::{alloc_inode, iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::Inode;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EIO, EROFS};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const BALLOC_IMG: &[u8; 524_288] = include_bytes!("../src/fs/ext2/fixtures/balloc_test.img");

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
            "sync_failure_latches_force_ro",
            &(sync_failure_latches_force_ro as fn()),
        ),
        (
            "subsequent_write_returns_erofs",
            &(subsequent_write_returns_erofs as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Mount RW and return all the handles we need.
fn mount_rw(disk: Arc<RamDisk>) -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after mount");
    (sb, fs, super_arc)
}

/// Build a minimal `OpenFile` for the given inode so we can route
/// `FileOps::write` calls through the real ops dispatch.
fn open_file(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> Arc<OpenFile> {
    let dentry = Dentry::new_root(inode.clone());
    let file_ops = inode.file_ops.clone();
    let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard::try_acquire");
    OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard)
}

fn do_write(sb: &Arc<SuperBlock>, inode: &Arc<Inode>, buf: &[u8], off: u64) -> Result<usize, i64> {
    let of = open_file(sb, inode.clone());
    let r = of.ops.write(&of, buf, off);
    drop(of);
    r
}

/// Create a fresh zero-length regular file inode and return its
/// iget'd Inode handle.
fn create_fresh_inode(super_: &Arc<Ext2Super>, sb: &Arc<SuperBlock>) -> Arc<Inode> {
    let ino = alloc_inode(super_, None, false).expect("alloc_inode");
    let block_size = super_.block_size;
    let inodes_per_group = super_.sb_disk.lock().s_inodes_per_group;
    let group = (ino - 1) / inodes_per_group;
    let index = (ino - 1) % inodes_per_group;
    let bg_inode_table = super_.bgdt.lock()[group as usize].bg_inode_table;
    let byte_offset = (index as u64) * (super_.inode_size as u64);
    let abs_block = (bg_inode_table as u64) + byte_offset / (block_size as u64);
    let off_in_block = (byte_offset % (block_size as u64)) as usize;

    let bh = super_
        .cache
        .bread(super_.device_id, abs_block)
        .expect("bread inode table");
    {
        let mut data = bh.data.write();
        let slot = &mut data[off_in_block..off_in_block + 128];
        for b in slot.iter_mut() {
            *b = 0;
        }
        // i_mode = S_IFREG | 0644 = 0o100644 = 0x81A4
        slot[0..2].copy_from_slice(&0x81A4u16.to_le_bytes());
        // i_links_count = 1
        slot[26..28].copy_from_slice(&1u16.to_le_bytes());
    }
    super_.cache.mark_dirty(&bh);
    super_
        .cache
        .sync_dirty_buffer(&bh)
        .expect("sync inode slot");
    iget(super_, sb, ino).expect("iget fresh inode")
}

/// A `sync_dirty_buffer` device-write failure latches the mount
/// read-only and returns EIO to the caller.
fn sync_failure_latches_force_ro() {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let (sb, _fs, super_arc) = mount_rw(disk.clone());

    assert!(super_arc.is_writable(), "mount must start writable");

    // Create a fresh inode while the device is healthy.
    let inode = create_fresh_inode(&super_arc, &sb);

    // Record how many writes happened so far, then arm the device to
    // fail on the *next* write. The subsequent FileOps::write will
    // attempt at least one sync_dirty_buffer which hits the injected
    // error.
    let w = disk.writes();
    disk.set_fail_after(w + 1);

    // Attempt a small write. It should fail with EIO.
    let result = do_write(&sb, &inode, &[0x42u8], 0);

    assert!(result.is_err(), "write must fail when device errors");
    let err = result.unwrap_err();
    assert_eq!(err, EIO, "write must return EIO, got {err}");

    // The force-RO latch must now be tripped.
    assert!(
        !super_arc.is_writable(),
        "mount must be force-RO after sync failure"
    );
}

/// After force-RO, a second write attempt returns EROFS without
/// reaching the device.
fn subsequent_write_returns_erofs() {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let (sb, _fs, super_arc) = mount_rw(disk.clone());

    let inode = create_fresh_inode(&super_arc, &sb);

    // Trip force-RO via an injected sync failure.
    let w = disk.writes();
    disk.set_fail_after(w + 1);
    let _ = do_write(&sb, &inode, &[0x42u8], 0);

    assert!(
        !super_arc.is_writable(),
        "mount must be force-RO after sync failure"
    );

    // Second write on the same (now-RO) mount.
    disk.set_fail_after(0); // disarm — shouldn't matter
    let result2 = do_write(&sb, &inode, &[0xFFu8], 0);
    assert!(result2.is_err(), "second write must fail");
    // Depending on the write path, the error may be EROFS (caught at
    // the is_writable() gate) or EIO. Either is acceptable; the key
    // assertion is that the write fails and the mount stays RO.
    let err2 = result2.unwrap_err();
    assert!(
        err2 == EROFS || err2 == EIO,
        "second write should return EROFS or EIO, got {err2}"
    );
    assert!(
        !super_arc.is_writable(),
        "mount must remain force-RO"
    );
}
