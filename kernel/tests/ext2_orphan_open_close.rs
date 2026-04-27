//! Integration test for issue #638: ext2 orphan-finalize **production
//! trigger** (last `OpenFile::Drop` on an unlinked inode runs the
//! RFC 0004 §Final-close sequence in-line, without unmount/remount).
//!
//! This test exercises the chain:
//!
//!   `iget` -> `OpenFile::new` (open_count = 1) -> `rmdir` (unlinked = true,
//!   orphan_list pin installed) -> `drop(OpenFile)` (release hook -> finalize)
//!
//! and checks the postconditions:
//!
//! 1. With the OpenFile alive, the orphan_list pin survives across rmdir
//!    (the inode is `unlinked` but blocks/inode are still reserved).
//! 2. Dropping the OpenFile causes `release` to observe the
//!    open_count → 0 transition with `unlinked == true` and call
//!    `finalize_orphan` directly. After the drop:
//!    - orphan_list is empty,
//!    - `s_last_orphan` reverts to 0 (single-entry chain),
//!    - the on-disk inode slot is fully tombstoned (`i_links_count == 0`,
//!      `i_dtime != 0`),
//!    - the `s_free_inodes_count` and `s_free_blocks_count` counters
//!      both moved.
//! 3. With **no** open files at unlink time, `rmdir` (which runs an
//!    internal `iget` that releases its strong ref on return) leaves the
//!    orphan pinned by the `orphan_list` itself — the open_count from
//!    the internal iget never went above zero (no `OpenFile` was built),
//!    so there's no automatic finalize. The mount-time replay path
//!    (#564) and `evict_inode` remain the safety nets, both unchanged.
//!
//! Together these prove the production trigger fires when (and only
//! when) a real `OpenFile` was outstanding.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
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
            "open_unlink_close_finalizes_orphan",
            &(open_unlink_close_finalizes_orphan as fn()),
        ),
        (
            "rmdir_with_no_openers_keeps_orphan_pinned",
            &(rmdir_with_no_openers_keeps_orphan_pinned as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — same shape as the other ext2 integration tests.
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

fn mount_rw() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>, Arc<RamDisk>) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount");
    let super_arc = fs.current_super().expect("current_super");
    (sb, fs, super_arc, disk)
}

// On-disk offsets for tombstone-state assertions. Duplicated from
// ext2_orphan_finalize.rs so the test stays self-contained against the
// golden image's mkfs.ext2 layout.
const BGDT_BYTE_OFFSET_1K: usize = 2048;
const BGD_OFF_INODE_TABLE: usize = 8;
const INODE_SIZE: usize = 128;
const INODE_OFF_DTIME: usize = 20;
const INODE_OFF_LINKS_COUNT: usize = 26;
const BLOCK_SIZE_BYTES: usize = 1024;

fn u32_le(image: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(image[off..off + 4].try_into().unwrap())
}
fn u16_le(image: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(image[off..off + 2].try_into().unwrap())
}
fn inode_slot_offset(image: &[u8], ino: u32) -> usize {
    let itab_block = u32_le(image, BGDT_BYTE_OFFSET_1K + BGD_OFF_INODE_TABLE) as usize;
    let slot_in_table = (ino as usize) - 1;
    itab_block * BLOCK_SIZE_BYTES + slot_in_table * INODE_SIZE
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Exercise the full open → unlink → close → in-line-finalize chain.
fn open_unlink_close_finalizes_orphan() {
    let (sb, _fs, super_arc, disk) = mount_rw();

    let (free_inodes_before, free_blocks_before) = {
        let d = super_arc.sb_disk.lock();
        (d.s_free_inodes_count, d.s_free_blocks_count)
    };

    // Resolve the orphan-target inode (lost+found, ino 11) and build a
    // real `OpenFile` against it. `OpenFile::new` invokes the FileOps
    // `open` hook, which bumps `Ext2Inode::open_count` to 1.
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let lf_inode = iget(&super_arc, &sb, 11).expect("iget lost+found");
    let dentry = Dentry::new_root(lf_inode.clone());
    let guard = SbActiveGuard::try_acquire(&sb).expect("SbActiveGuard");
    let of = OpenFile::new(
        dentry,
        lf_inode.clone(),
        lf_inode.file_ops.clone(),
        sb.clone(),
        0,
        guard,
    );

    // Now rmdir lost+found through the InodeOps surface. The unlink
    // path sets `unlinked = true` (after `push_on_orphan_list`) — the
    // ordering matters for the release-trigger race; see the matching
    // note in `unlink::unlink_common`.
    root.ops
        .rmdir(&root, b"lost+found")
        .expect("rmdir(lost+found)");

    // With the OpenFile still live the orphan_list pin is preserved
    // and finalize has not yet fired.
    assert!(
        super_arc.orphan_list.lock().contains_key(&11),
        "open holds the orphan pin until OpenFile::Drop"
    );
    assert_eq!(
        super_arc.sb_disk.lock().s_last_orphan,
        11,
        "rmdir leaves chain head at ino 11"
    );

    // The user-facing inode Arc held by the test is also still live —
    // drop it so the `OpenFile`'s `Arc<Inode>` is the only non-orphan
    // pin remaining. (Even with this drop, `orphan_list` keeps
    // `lf_inode`'s allocation alive via its own Arc — the drop here
    // just confirms the trigger doesn't depend on a user-side strong
    // ref hanging around.)
    drop(lf_inode);

    // Drop the OpenFile. `OpenFile::Drop` runs the FileOps `release`
    // hook **before** releasing the SB pin; for ext2 that decrements
    // open_count from 1 → 0 and, observing `unlinked == true`, calls
    // `orphan_finalize::finalize` synchronously.
    drop(of);

    // Finalize postconditions.
    assert!(
        super_arc.orphan_list.lock().is_empty(),
        "release-hook finalize must drop the in-memory pin"
    );
    assert_eq!(
        super_arc.sb_disk.lock().s_last_orphan,
        0,
        "release-hook finalize must clear the on-disk chain head"
    );

    let free_inodes_after = super_arc.sb_disk.lock().s_free_inodes_count;
    assert_eq!(
        free_inodes_after,
        free_inodes_before + 1,
        "release-hook finalize must bump s_free_inodes_count"
    );
    let free_blocks_after = super_arc.sb_disk.lock().s_free_blocks_count;
    assert!(
        free_blocks_after > free_blocks_before,
        "release-hook finalize must free lost+found's data block (before={free_blocks_before}, after={free_blocks_after})"
    );

    // Tombstone state on the raw RamDisk image (bypasses any cache).
    {
        let storage = disk.storage.lock();
        let slot_off = inode_slot_offset(&storage, 11);
        let links = u16_le(&storage, slot_off + INODE_OFF_LINKS_COUNT);
        let dtime = u32_le(&storage, slot_off + INODE_OFF_DTIME);
        assert_eq!(
            links, 0,
            "release-hook finalize must preserve i_links_count == 0"
        );
        assert_ne!(
            dtime, 0,
            "release-hook finalize must stamp a nonzero i_dtime tombstone"
        );
    }

    sb.ops.unmount();
    drop(super_arc);
}

/// When no `OpenFile` was ever built for the to-be-orphaned inode, the
/// release-hook trigger naturally never fires (open_count never reached
/// >0 from a real open), so the orphan pin sticks around — the
/// existing `evict_inode` and mount-replay paths remain the recovery
/// sites. This pins the boundary so a future change can't accidentally
/// finalize on an `iget` round-trip with no opener.
fn rmdir_with_no_openers_keeps_orphan_pinned() {
    let (sb, _fs, super_arc, _disk) = mount_rw();

    let root = iget(&super_arc, &sb, 2).expect("iget root");
    // Pre-load ino 11 into the cache so it has an Arc<Ext2Inode>
    // visible to the orphan-list bookkeeping; do NOT build an
    // OpenFile.
    let _lf = iget(&super_arc, &sb, 11).expect("iget lost+found");

    root.ops
        .rmdir(&root, b"lost+found")
        .expect("rmdir(lost+found)");

    // No OpenFile was ever constructed → open_count stayed at zero
    // → no release-hook finalize fired. The orphan_list still pins
    // ino 11 and the on-disk chain head is still 11.
    assert!(
        super_arc.orphan_list.lock().contains_key(&11),
        "without any opener, orphan_list pin must persist past rmdir"
    );
    assert_eq!(
        super_arc.sb_disk.lock().s_last_orphan,
        11,
        "without any opener, on-disk chain head must remain at ino 11"
    );

    // Drop the lf Arc to simulate cache eviction; orphan_list still
    // holds its own strong ref so the inode allocation stays live.
    drop(_lf);
    assert!(
        super_arc.orphan_list.lock().contains_key(&11),
        "orphan_list strong ref keeps the inode resident across user-Arc drop"
    );

    sb.ops.unmount();
    drop(super_arc);
}
