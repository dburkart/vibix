//! Integration test for issue #558: `Ext2Fs::mount` end-to-end.
//!
//! Runs the real kernel under QEMU, in-process: builds an in-memory
//! `BlockDevice` (a `RamDisk` wrapping a `mkfs.ext2`-produced image),
//! hands it to `Ext2Fs::new_with_device`, drives
//! `FileSystem::mount(...)` with each of the flag/feature scenarios,
//! and asserts on the observable outcomes:
//!
//! - **RO mount**: `SuperBlock::flags` carries `SbFlags::RDONLY`; the
//!   backing ramdisk records zero writes (RO mount never writes).
//! - **RW mount**: `s_state` on the ramdisk is `EXT2_ERROR_FS` after
//!   mount returned (proof the driver stamped ERROR_FS + flushed it);
//!   `SuperBlock::flags` does NOT carry `SbFlags::RDONLY`.
//! - **Bogus INCOMPAT**: mount returns `Err(EINVAL)` and the ramdisk
//!   was not written (feature-gate rejection leaves the device alone).
//! - **Bogus RO_COMPAT**: caller asked for RW but the driver demoted
//!   to RO (`SbFlags::RDONLY` set); no bytes written.
//! - **Bad magic**: mount returns `Err(EINVAL)`, factory's mount-latch
//!   is *not* burned (a subsequent valid mount attempt succeeds).
//! - **Single-mount latch**: a second mount attempt on an already-mounted
//!   factory returns `Err(EBUSY)`; `unmount` releases it.
//!
//! See `kernel/src/fs/ext2/fixtures/README.md` for how the fixture
//! image is generated. The test uses the 64 KiB `golden.img` variant
//! and patches feature-flag bits in-memory before mount to exercise
//! the rejection paths.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::disk::{
    Ext2SuperBlock, EXT2_ERROR_FS, EXT2_MAGIC, EXT2_SB_OFF_MAGIC, EXT2_SUPERBLOCK_SIZE,
    EXT2_VALID_FS,
};
use vibix::fs::ext2::Ext2Fs;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbFlags, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EBUSY, EINVAL, ENODEV};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

/// 64 KiB `mkfs.ext2` image used as the backing bytes for the RamDisk.
/// Checked in; see `kernel/src/fs/ext2/fixtures/README.md`.
const GOLDEN_IMG: &[u8; 65_536] = include_bytes!("../src/fs/ext2/fixtures/golden.img");

// Superblock field offsets (duplicated so the test can patch fields
// on the in-memory copy without re-decoding / re-encoding the whole
// slot; the driver itself uses `disk::Ext2SuperBlock::{decode, encode_to_slot}`).
const SB_OFF_STATE: usize = 58;
const SB_OFF_FEATURE_INCOMPAT: usize = 96;
const SB_OFF_FEATURE_RO_COMPAT: usize = 100;
const SB_OFF_MNT_COUNT: usize = 52;

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
            "ro_mount_leaves_device_untouched",
            &(ro_mount_leaves_device_untouched as fn()),
        ),
        (
            "rw_mount_stamps_error_fs",
            &(rw_mount_stamps_error_fs as fn()),
        ),
        (
            "bogus_incompat_refuses_mount",
            &(bogus_incompat_refuses_mount as fn()),
        ),
        (
            "bogus_ro_compat_forces_readonly",
            &(bogus_ro_compat_forces_readonly as fn()),
        ),
        (
            "bad_magic_returns_einval",
            &(bad_magic_returns_einval as fn()),
        ),
        (
            "single_mount_latch_rejects_double_mount",
            &(single_mount_latch_rejects_double_mount as fn()),
        ),
        (
            "rw_mount_bumps_mnt_count",
            &(rw_mount_bumps_mnt_count as fn()),
        ),
        (
            "clean_unmount_restores_valid_fs",
            &(clean_unmount_restores_valid_fs as fn()),
        ),
        (
            "dirty_mount_proceeds_with_warning",
            &(dirty_mount_proceeds_with_warning as fn()),
        ),
        (
            "ro_mount_does_not_rewrite_valid_fs",
            &(ro_mount_does_not_rewrite_valid_fs as fn()),
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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Construct a `RamDisk` backed by the golden 64 KiB `mkfs.ext2` image.
/// 512-byte sectors so the `read_at` alignment checks match what a
/// real virtio-blk presents.
fn fresh_disk() -> Arc<RamDisk> {
    RamDisk::from_image(GOLDEN_IMG.as_slice(), 512)
}

/// Destructure `Result<Arc<SuperBlock>, i64>` into the error side,
/// panicking with `msg` if it was `Ok`. Needed because `SuperBlock`
/// doesn't implement `Debug` (no need in production code) and
/// `.expect_err(...)` requires `T: Debug`.
fn expect_mount_err(r: Result<Arc<SuperBlock>, i64>, msg: &str) -> i64 {
    match r {
        Ok(_) => panic!("{}", msg),
        Err(e) => e,
    }
}

/// Read the on-disk `s_state` straight out of the ramdisk (bypassing
/// the cache). Used by assertions that want to see what actually
/// landed on the device, not what the cache thinks.
fn read_sb_state(disk: &RamDisk) -> u16 {
    let mut slot = [0u8; EXT2_SUPERBLOCK_SIZE];
    disk.read_slot(1024, &mut slot);
    u16::from_le_bytes([slot[SB_OFF_STATE], slot[SB_OFF_STATE + 1]])
}

/// Read the on-disk `s_mnt_count`.
fn read_sb_mnt_count(disk: &RamDisk) -> u16 {
    let mut slot = [0u8; EXT2_SUPERBLOCK_SIZE];
    disk.read_slot(1024, &mut slot);
    u16::from_le_bytes([slot[SB_OFF_MNT_COUNT], slot[SB_OFF_MNT_COUNT + 1]])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// RO mount never writes through to the backing device — the driver
/// must skip the ERROR_FS stamp when `MountFlags::RDONLY` is set, and
/// the returned `SuperBlock` must carry `SbFlags::RDONLY`.
fn ro_mount_leaves_device_untouched() {
    let disk = fresh_disk();

    // Pre-condition: the fixture image is clean (`s_state ==
    // EXT2_VALID_FS`). If this ever fires, the fixture was regenerated
    // incorrectly — guard against a silent bit-rotted binary.
    assert_eq!(
        read_sb_state(&disk),
        EXT2_VALID_FS,
        "fixture pre-condition: golden image has clean s_state",
    );

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");

    // No writes drove through to the device.
    assert_eq!(
        disk.writes(),
        writes_before,
        "RO mount drove {} writes; expected 0",
        disk.writes() - writes_before,
    );

    // RDONLY flag is set on the SuperBlock.
    assert!(
        sb.flags.contains(SbFlags::RDONLY),
        "RO mount must stamp SbFlags::RDONLY",
    );
    // s_state on disk is still VALID_FS — the RW stamp is RW-only.
    assert_eq!(
        read_sb_state(&disk),
        EXT2_VALID_FS,
        "RO mount must not touch s_state",
    );

    // fs_type label is the canonical driver name.
    assert_eq!(sb.fs_type, "ext2");

    // Release the mount so Ext2Fs can be dropped cleanly.
    sb.ops.unmount();
}

/// RW mount stamps `s_state := EXT2_ERROR_FS` and writes it through
/// to the device. A subsequent `bread` of the superblock block (by
/// the test directly from the ramdisk) observes the new state.
fn rw_mount_stamps_error_fs() {
    let disk = fresh_disk();
    assert_eq!(read_sb_state(&disk), EXT2_VALID_FS);

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("RW mount must succeed");

    // At least one device write happened (the ERROR_FS stamp).
    assert!(
        disk.writes() > writes_before,
        "RW mount must drive at least one device write",
    );

    // RDONLY is NOT set on the SuperBlock.
    assert!(
        !sb.flags.contains(SbFlags::RDONLY),
        "RW mount must not stamp SbFlags::RDONLY",
    );

    // `s_state` on disk is now ERROR_FS — proves the RMW + flush hit.
    assert_eq!(
        read_sb_state(&disk),
        EXT2_ERROR_FS,
        "RW mount must stamp s_state = EXT2_ERROR_FS",
    );

    sb.ops.unmount();
}

/// An unknown `s_feature_incompat` bit must refuse the mount with
/// `EINVAL` and leave the device untouched — the driver can't safely
/// interpret the filesystem structure in that case.
fn bogus_incompat_refuses_mount() {
    let disk = fresh_disk();

    // Set the high bit of s_feature_incompat. 1 << 31 is definitely
    // not in our SUPPORTED_INCOMPAT set (which is just
    // INCOMPAT_FILETYPE = 0x2) and won't be any time soon.
    disk.patch(|storage| {
        let off = 1024 + SB_OFF_FEATURE_INCOMPAT;
        let old = u32::from_le_bytes([
            storage[off],
            storage[off + 1],
            storage[off + 2],
            storage[off + 3],
        ]);
        let patched = old | (1u32 << 31);
        storage[off..off + 4].copy_from_slice(&patched.to_le_bytes());
    });

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();
    let err = expect_mount_err(
        fs.mount(MountSource::None, MountFlags::default()),
        "bogus INCOMPAT must refuse mount",
    );
    assert_eq!(err, EINVAL, "bogus INCOMPAT must return EINVAL");
    assert_eq!(
        disk.writes(),
        writes_before,
        "failed mount must not write to device",
    );

    // The factory's latch must also be clear: a subsequent mount with
    // the feature-flag patch still in place must still fail EINVAL
    // (not EBUSY — the first mount never latched).
    let err2 = expect_mount_err(
        fs.mount(MountSource::None, MountFlags::default()),
        "subsequent mount still fails",
    );
    assert_eq!(err2, EINVAL);
}

/// An unknown `s_feature_ro_compat` bit must *demote* the mount to RO,
/// not reject it. The caller can read; the kernel just can't write
/// through a feature it doesn't model.
fn bogus_ro_compat_forces_readonly() {
    let disk = fresh_disk();

    // Set bit 31 of s_feature_ro_compat — not in SUPPORTED_RO_COMPAT.
    disk.patch(|storage| {
        let off = 1024 + SB_OFF_FEATURE_RO_COMPAT;
        let old = u32::from_le_bytes([
            storage[off],
            storage[off + 1],
            storage[off + 2],
            storage[off + 3],
        ]);
        let patched = old | (1u32 << 31);
        storage[off..off + 4].copy_from_slice(&patched.to_le_bytes());
    });

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();

    // Caller asked for RW.
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("unknown RO_COMPAT must succeed in RO mode");

    // But the driver demoted to RO — s_state unchanged, no writes.
    assert!(
        sb.flags.contains(SbFlags::RDONLY),
        "unknown RO_COMPAT must force SbFlags::RDONLY",
    );
    assert_eq!(
        disk.writes(),
        writes_before,
        "RO-demoted mount must not write",
    );
    assert_eq!(
        read_sb_state(&disk),
        EXT2_VALID_FS,
        "RO-demoted mount must not stamp ERROR_FS",
    );

    sb.ops.unmount();
}

/// A bad superblock magic returns `EINVAL`, and the factory's
/// single-mount latch is not consumed — a subsequent mount attempt
/// (with a good image) would succeed. Verified here by pointing the
/// factory at a disk whose first 1024+2 bytes are zeroed.
fn bad_magic_returns_einval() {
    let disk = fresh_disk();
    // Zero out the magic word.
    disk.patch(|storage| {
        let off = 1024 + EXT2_SB_OFF_MAGIC;
        storage[off] = 0;
        storage[off + 1] = 0;
    });

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let writes_before = disk.writes();
    let err = expect_mount_err(
        fs.mount(MountSource::None, MountFlags::RDONLY),
        "bad magic must refuse mount",
    );
    assert!(
        err == EINVAL || err == ENODEV,
        "bad magic must return EINVAL or ENODEV; got {err}",
    );
    assert_eq!(
        disk.writes(),
        writes_before,
        "failed mount must not write to device",
    );

    // Prove the latch is still clear by patching the magic back and
    // re-mounting successfully.
    disk.patch(|storage| {
        let off = 1024 + EXT2_SB_OFF_MAGIC;
        storage[off..off + 2].copy_from_slice(&EXT2_MAGIC.to_le_bytes());
    });
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("retry on a repaired image must succeed");
    sb.ops.unmount();
}

/// The single-mount latch on `Ext2Fs` rejects a second `mount` while
/// the first is still live; `unmount` releases the latch so a
/// subsequent mount succeeds.
fn single_mount_latch_rejects_double_mount() {
    let disk = fresh_disk();
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);

    let sb1 = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("first RO mount");

    let err = expect_mount_err(
        fs.mount(MountSource::None, MountFlags::RDONLY),
        "second mount must fail",
    );
    assert_eq!(err, EBUSY, "second mount must return EBUSY");

    // Release the latch and confirm a fresh mount succeeds.
    sb1.ops.unmount();

    let sb2 = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("post-unmount mount must succeed");
    sb2.ops.unmount();
}

/// RW mount increments `s_mnt_count` on disk — the counter that an
/// `e2fsck -p` uses (together with `s_max_mnt_count`) to decide when a
/// periodic check is due. Also exercises that the in-memory `sb_disk`
/// mirror reflects the stamped state: if it didn't, a follow-up
/// allocator flush would clobber ERROR_FS with the stale pre-mount
/// VALID_FS (#617 item 5).
fn rw_mount_bumps_mnt_count() {
    let disk = fresh_disk();
    let before = read_sb_mnt_count(&disk);

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("RW mount must succeed");

    let after = read_sb_mnt_count(&disk);
    assert_eq!(
        after,
        before + 1,
        "RW mount must increment s_mnt_count ({} -> {})",
        before,
        after,
    );
    assert_eq!(read_sb_state(&disk), EXT2_ERROR_FS);

    sb.ops.unmount();
}

/// Clean unmount must rewrite `s_state = EXT2_VALID_FS`. A subsequent
/// mount of the same image then sees a clean filesystem.
fn clean_unmount_restores_valid_fs() {
    let disk = fresh_disk();
    assert_eq!(read_sb_state(&disk), EXT2_VALID_FS);

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("RW mount must succeed");

    // During the mount, disk state is ERROR_FS.
    assert_eq!(
        read_sb_state(&disk),
        EXT2_ERROR_FS,
        "RW mount stamped ERROR_FS",
    );

    // Clean unmount restores VALID_FS.
    sb.ops.unmount();
    assert_eq!(
        read_sb_state(&disk),
        EXT2_VALID_FS,
        "clean unmount must write EXT2_VALID_FS back",
    );

    // A second mount of the same factory (same disk) must see a clean
    // state at mount-time entry — proving the re-mount cycle works.
    let sb2 = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("re-mount after clean unmount must succeed");
    // Again stamped ERROR_FS during the mount body.
    assert_eq!(read_sb_state(&disk), EXT2_ERROR_FS);
    sb2.ops.unmount();
    assert_eq!(read_sb_state(&disk), EXT2_VALID_FS);
}

/// A mount that finds `s_state != VALID_FS` (simulating an unclean
/// crash) must still succeed — we log a warning but proceed. The new
/// mount then re-stamps ERROR_FS (so the counter is consistent) and a
/// clean unmount closes the cycle back to VALID_FS.
fn dirty_mount_proceeds_with_warning() {
    let disk = fresh_disk();
    // Pretend the last mount crashed: zero out `s_state` on disk. This
    // is NOT the same as ERROR_FS (0x2) nor VALID_FS (0x1); it exercises
    // the "not clean" branch without pre-staining ERROR_FS.
    disk.patch(|storage| {
        let off = 1024 + SB_OFF_STATE;
        storage[off] = 0;
        storage[off + 1] = 0;
    });
    assert_eq!(read_sb_state(&disk), 0);

    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::default())
        .expect("dirty mount must still succeed");

    // ERROR_FS stamp landed.
    assert_eq!(read_sb_state(&disk), EXT2_ERROR_FS);

    sb.ops.unmount();
    assert_eq!(
        read_sb_state(&disk),
        EXT2_VALID_FS,
        "clean unmount writes VALID_FS even if prior mount found dirty fs",
    );
}

/// RO mount's unmount path must not touch `s_state` — it never stamped
/// ERROR_FS at mount, so rewriting VALID_FS would be a spurious device
/// write. Verified by write-counter on the ramdisk.
fn ro_mount_does_not_rewrite_valid_fs() {
    let disk = fresh_disk();
    let fs = Ext2Fs::new_with_device(disk.clone() as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount succeeds");

    let writes_before_unmount = disk.writes();
    sb.ops.unmount();
    assert_eq!(
        disk.writes(),
        writes_before_unmount,
        "RO mount's unmount must not drive any writes",
    );
    assert_eq!(read_sb_state(&disk), EXT2_VALID_FS);
}

/// Quiet an unused-import warning when `alloc::vec!` and friends are
/// compiled in but not every test uses them.
#[allow(dead_code)]
fn _unused_sanity() {
    let _ = vec![0u8; 1];
    // Exercise `Ext2SuperBlock::decode` so a stale re-export of the
    // struct path is caught at compile time.
    let slot = [0u8; EXT2_SUPERBLOCK_SIZE];
    let _sb = Ext2SuperBlock::decode(&slot);
}
