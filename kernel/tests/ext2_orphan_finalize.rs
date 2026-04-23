//! Integration test for issue #573: ext2 orphan-list final-close
//! sequence — truncate-to-zero, free inode, unchain from the on-disk
//! orphan list.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Orphan list
//! and §Final-close sequence are the normative spec. This test drives
//! the sequence in two entry configurations:
//!
//! 1. **Single-entry chain**: rmdir `lost+found` → orphan_list + chain
//!    head both carry ino 11. Call [`finalize_orphan`] → blocks freed,
//!    inode freed in the bitmap, `s_last_orphan` reverts to 0, in-memory
//!    orphan_list empty.
//! 2. **RO mount rejects**: mounting RO and invoking the finalize
//!    free function returns `EROFS`, preserving the pin.
//! 3. **No-op on non-orphan**: calling finalize for a ino that isn't
//!    in orphan_list returns `ENOENT`.
//!
//! A "mid-sequence crash and replay" test isn't wired here because the
//! replay path (mount-time orphan-chain validator, #564) already has
//! independent coverage in `kernel/tests/ext2_orphan_chain.rs`; the
//! interesting property for *this* PR is that finalize itself is the
//! round-trip the replay path eventually drives.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{finalize_orphan, iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::fs::{ENOENT, EROFS};
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
            "finalize_rmdir_orphan_frees_blocks_and_chain_head",
            &(finalize_rmdir_orphan_frees_blocks_and_chain_head as fn()),
        ),
        (
            "finalize_on_non_orphan_is_enoent",
            &(finalize_on_non_orphan_is_enoent as fn()),
        ),
        (
            "finalize_ro_mount_is_erofs",
            &(finalize_ro_mount_is_erofs as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — matches ext2_unlink.rs.
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

// On-disk offsets for the tombstone-state assertion. Duplicated from
// the ext2_orphan_chain test — the offsets are pinned against the real
// mkfs.ext2 layout rather than consuming crate-private constants.
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

fn finalize_rmdir_orphan_frees_blocks_and_chain_head() {
    let (sb, _fs, super_arc, _disk) = mount_rw();

    // Snapshot baselines.
    let (free_inodes_before, free_blocks_before) = {
        let d = super_arc.sb_disk.lock();
        (d.s_free_inodes_count, d.s_free_blocks_count)
    };
    let used_dirs_before_mount = super_arc.bgdt.lock()[0].bg_used_dirs_count;

    // Drive the rmdir half: this populates orphan_list + s_last_orphan.
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    // Pre-load ino 11 into the ext2-inode cache so finalize can upgrade
    // its Weak<Ext2Inode>. rmdir itself already performs the iget, but
    // binding a local here makes the ext2_inode_cache insertion visible
    // for the rest of this test even after rmdir returns.
    let _lf = iget(&super_arc, &sb, 11).expect("iget lost+found");
    root.ops
        .rmdir(&root, b"lost+found")
        .expect("rmdir(lost+found)");

    // Confirm rmdir's postconditions (mirror ext2_unlink.rs expectations).
    assert_eq!(
        super_arc.sb_disk.lock().s_last_orphan,
        11,
        "rmdir must leave chain head at ino 11"
    );
    assert!(
        super_arc.orphan_list.lock().contains_key(&11),
        "rmdir must pin ino 11 in the orphan_list"
    );

    // Drop the explicit Arc<Inode> so only the orphan_list pin +
    // inode-cache Weak remain live for ino 11. `finalize` should still
    // succeed — it reaches the Ext2Inode via the parallel ext2 inode
    // cache, which shares the pinned Arc through `inode.ops`.
    drop(_lf);

    // Now run the final-close sequence.
    finalize_orphan(&super_arc, 11).expect("finalize");

    // Postconditions.
    // 1. Orphan chain head reverts to 0 (we were the sole entry).
    assert_eq!(
        super_arc.sb_disk.lock().s_last_orphan,
        0,
        "finalize must clear the on-disk chain head for the last entry"
    );
    // 2. Orphan list is empty.
    assert!(
        super_arc.orphan_list.lock().is_empty(),
        "finalize must drop the in-memory pin"
    );
    // 3. Free-inode counter incremented by 1.
    let free_inodes_after = super_arc.sb_disk.lock().s_free_inodes_count;
    assert_eq!(
        free_inodes_after,
        free_inodes_before + 1,
        "free_inode must bump s_free_inodes_count"
    );
    // 4. `bg_used_dirs_count` was already decremented by `rmdir` (#569
    //    `decrement_used_dirs`) before the inode reached the orphan
    //    list. Finalize's `free_inode` call therefore passes
    //    `was_dir=false` to avoid a double-decrement. Confirm the
    //    counter is exactly one less than at mount and did NOT drop
    //    again across finalize.
    let used_dirs_after = super_arc.bgdt.lock()[0].bg_used_dirs_count;
    assert_eq!(
        used_dirs_after,
        used_dirs_before_mount - 1,
        "rmdir owns the bg_used_dirs_count decrement; finalize must not double-decrement"
    );
    // 5. Free-blocks counter: lost+found owns its own dir data block
    //    (1 × 1 KiB block). A zero-size directory after finalize means
    //    that block is back in the allocator. `truncate_free` returns
    //    >= 1 freed block for lost+found; assert the counter rose.
    let free_blocks_after = super_arc.sb_disk.lock().s_free_blocks_count;
    assert!(
        free_blocks_after > free_blocks_before,
        "finalize must free lost+found's dir data block back to the allocator (before={free_blocks_before}, after={free_blocks_after})",
    );
    // 6. Tombstone state. The on-disk inode slot for ino 11 must show
    //    `i_links_count == 0 && i_dtime != 0` — the canonical "fully
    //    deleted" signature mount-replay (#564) uses to distinguish
    //    finalized inodes from still-orphan ones. Read the block
    //    directly off the RamDisk storage so we bypass any in-memory
    //    cache of the Ext2Inode.
    {
        let storage = _disk.storage.lock();
        let slot_off = inode_slot_offset(&storage, 11);
        let links = u16_le(&storage, slot_off + INODE_OFF_LINKS_COUNT);
        let dtime = u32_le(&storage, slot_off + INODE_OFF_DTIME);
        assert_eq!(
            links, 0,
            "finalize must leave i_links_count == 0 (orphan invariant preserved)"
        );
        assert_ne!(
            dtime, 0,
            "finalize must stamp a nonzero i_dtime — mount-replay uses i_dtime != 0 as the 'fully deleted' marker"
        );
    }

    sb.ops.unmount();
    drop(super_arc);
}

fn finalize_on_non_orphan_is_enoent() {
    let (sb, _fs, super_arc, _disk) = mount_rw();
    // Ino 2 is the root — never on the orphan list.
    let err = finalize_orphan(&super_arc, 2).expect_err("ENOENT");
    assert_eq!(
        err, ENOENT,
        "finalize on a non-orphan ino must return ENOENT"
    );

    // Ino 11 (lost+found) is a live dirent, not on the orphan list
    // until someone rmdir's it.
    let err11 = finalize_orphan(&super_arc, 11).expect_err("ENOENT");
    assert_eq!(err11, ENOENT);

    sb.ops.unmount();
    drop(super_arc);
}

fn finalize_ro_mount_is_erofs() {
    let (sb, _fs, super_arc, _disk) = mount_ro();
    // RO mount refuses finalize before it ever consults the orphan list
    // — the RO gate is the first check in the sequence.
    let err = finalize_orphan(&super_arc, 11).expect_err("EROFS");
    assert_eq!(
        err, EROFS,
        "finalize on a RO mount must return EROFS before touching any on-disk state"
    );

    sb.ops.unmount();
    drop(super_arc);
}
