//! Integration test for issue #562: `dir::lookup` +
//! `dir::getdents64` over the golden mkfs.ext2 image.
//!
//! Runs the real kernel under QEMU: mounts the 64 KiB fixture RO,
//! reads the root directory's `Ext2Inode` through `iget`, materialises
//! a driver-level `Ext2Inode` from its public fields (we need the
//! concrete type to call into `dir::lookup` / `dir::getdents64` —
//! a follow-up PR wires the trait objects on `InodeOps` / `FileOps`
//! to call these helpers without the explicit `&Ext2Inode` hop),
//! then exercises:
//!
//! - `lookup(root, "lost+found")` → ino 11 (the only other live entry
//!   on a fresh mkfs image).
//! - `lookup(root, "nonexistent")` → `ENOENT`.
//! - `lookup(root, "")` → `ENOENT` (empty name never matches).
//! - `getdents64(root)` — fill a big-enough buffer in one call,
//!   assert the emitted records contain `.`, `..`, and `lost+found`
//!   with the correct `d_ino` values.
//! - `getdents64(root)` — drive with a small buffer that forces
//!   multiple calls; confirm the cookie advances correctly and no
//!   record is duplicated or skipped.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::AtomicBool;

use vibix::block::BlockDevice;
use vibix::fs::ext2::dir;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Inode, Ext2InodeMeta, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::MountFlags;
use vibix::fs::ENOENT;
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
            "lookup_finds_lost_found",
            &(lookup_finds_lost_found as fn()),
        ),
        (
            "lookup_missing_name_is_enoent",
            &(lookup_missing_name_is_enoent as fn()),
        ),
        (
            "lookup_empty_name_is_enoent",
            &(lookup_empty_name_is_enoent as fn()),
        ),
        (
            "getdents_returns_dot_dotdot_and_lost_found",
            &(getdents_returns_dot_dotdot_and_lost_found as fn()),
        ),
        (
            "getdents_small_buffer_advances_cookie",
            &(getdents_small_buffer_advances_cookie as fn()),
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

fn mount_golden_ro() -> (
    Arc<vibix::fs::vfs::super_block::SuperBlock>,
    Arc<Ext2Fs>,
    Arc<Ext2Super>,
    Arc<RamDisk>,
) {
    let disk = RamDisk::from_image(GOLDEN_IMG.as_slice(), 512);
    // Latch the RO flag *after* the mount has completed. The mount
    // itself only reads, but pinning RO on the disk now means any
    // subsequent write (a forgotten dirty-inode flush, a buggy
    // metadata update) will surface as BlockError::ReadOnly instead
    // of silently mutating the in-memory image.
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

/// Pull the concrete `Ext2Inode`'s decoded fields out of a mounted
/// image by calling `iget` for the `Stat`, then re-reading the
/// `Ext2InodeMeta` through the same cached trait object. Because
/// `inode.ops` hides the concrete type, we reconstruct an equivalent
/// `Ext2Inode` by copying the pub fields we need — the `dir` helpers
/// only touch `meta.size` and `meta.i_block`. See #562 for why the
/// trait-surface wiring is a follow-up.
fn make_ext2_inode_from_stat(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<vibix::fs::vfs::super_block::SuperBlock>,
    ino: u32,
) -> Ext2Inode {
    // Refresh the VFS inode so its `getattr` populates `Stat` — we use
    // only `st_size` and the inode's decoded `i_block`. Re-read the
    // raw on-disk slot through the inode-table math rather than poking
    // the now-stashed `Arc<dyn InodeOps>`.
    let _ = iget(super_arc, sb, ino).expect("iget should succeed for a live ino");

    // Compute the slot address.
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
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn lookup_finds_lost_found() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);
    let ino = dir::lookup(&super_arc, &root, b"lost+found").expect("lookup lost+found");
    assert_eq!(ino, 11, "mkfs.ext2 places lost+found at ino 11");
    sb.ops.unmount();
    drop(super_arc);
    assert_eq!(disk.writes(), 0, "RO mount must not issue any writes");
}

fn lookup_missing_name_is_enoent() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);
    let err = dir::lookup(&super_arc, &root, b"does-not-exist").unwrap_err();
    assert_eq!(err, ENOENT);
    sb.ops.unmount();
    drop(super_arc);
    assert_eq!(disk.writes(), 0, "RO mount must not issue any writes");
}

fn lookup_empty_name_is_enoent() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);
    let err = dir::lookup(&super_arc, &root, b"").unwrap_err();
    assert_eq!(err, ENOENT);
    sb.ops.unmount();
    drop(super_arc);
    assert_eq!(disk.writes(), 0, "RO mount must not issue any writes");
}

fn parse_names(buf: &[u8], n: usize) -> Vec<(Vec<u8>, u64)> {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + 19 <= n {
        let reclen = u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]) as usize;
        if reclen == 0 {
            break;
        }
        let d_ino = u64::from_ne_bytes(buf[pos..pos + 8].try_into().expect("d_ino"));
        let name_raw = &buf[pos + 19..pos + reclen];
        let nul = name_raw
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_raw.len());
        out.push((name_raw[..nul].to_vec(), d_ino));
        pos += reclen;
    }
    out
}

fn getdents_returns_dot_dotdot_and_lost_found() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);

    let mut buf = vec![0u8; 1024];
    let mut cookie = 0u64;
    let n = dir::getdents64(&super_arc, &root, &mut buf, &mut cookie).expect("getdents64");
    assert!(n > 0);
    let entries = parse_names(&buf, n);

    let dot = entries.iter().find(|(n, _)| n == b".").expect("missing .");
    assert_eq!(dot.1, 2, ". points at root ino");
    let dotdot = entries
        .iter()
        .find(|(n, _)| n == b"..")
        .expect("missing ..");
    assert_eq!(dotdot.1, 2, ".. on root points at root");
    let lf = entries
        .iter()
        .find(|(n, _)| n == b"lost+found")
        .expect("missing lost+found");
    assert_eq!(lf.1, 11);

    // A follow-up call with the cookie at end-of-dir returns 0 bytes.
    let mut buf2 = vec![0u8; 1024];
    let n2 = dir::getdents64(&super_arc, &root, &mut buf2, &mut cookie).expect("getdents EOD");
    assert_eq!(n2, 0, "subsequent call after EOD returns 0");

    sb.ops.unmount();
    drop(super_arc);
    assert_eq!(disk.writes(), 0, "RO mount must not issue any writes");
}

fn getdents_small_buffer_advances_cookie() {
    let (sb, _fs, super_arc, disk) = mount_golden_ro();
    let root = make_ext2_inode_from_stat(&super_arc, &sb, 2);

    // Size the buffer so at most one record fits per call: the ".",
    // "..", "lost+found" records encode to dirent64 lengths 24, 24,
    // and 32 bytes respectively. Use 32 so the largest record just
    // fits; each getdents64 call will return exactly one record.
    let mut all_names: Vec<Vec<u8>> = Vec::new();
    let mut cookie = 0u64;
    let mut buf = [0u8; 32];
    loop {
        let n = dir::getdents64(&super_arc, &root, &mut buf, &mut cookie).expect("getdents");
        if n == 0 {
            break;
        }
        for (name, _ino) in parse_names(&buf, n) {
            all_names.push(name);
        }
        // Guard against a runaway loop on a broken cookie.
        assert!(
            all_names.len() <= 4,
            "too many records — cookie not advancing"
        );
    }
    assert!(all_names.iter().any(|n| n == b"."));
    assert!(all_names.iter().any(|n| n == b".."));
    assert!(all_names.iter().any(|n| n == b"lost+found"));
    // Each live record must appear exactly once across the whole
    // small-buffer walk; any dup means the cookie either reset or
    // failed to advance past an emitted record.
    let dot_count = all_names.iter().filter(|n| n.as_slice() == b".").count();
    assert_eq!(dot_count, 1, "`.` must appear exactly once");
    let dotdot_count = all_names.iter().filter(|n| n.as_slice() == b"..").count();
    assert_eq!(dotdot_count, 1, "`..` must appear exactly once");
    let lost_found_count = all_names
        .iter()
        .filter(|n| n.as_slice() == b"lost+found")
        .count();
    assert_eq!(lost_found_count, 1, "`lost+found` must appear exactly once");

    sb.ops.unmount();
    drop(super_arc);
    assert_eq!(disk.writes(), 0, "RO mount must not issue any writes");
}

// Sanity: the imports above ensure the harness links even when tests
// don't touch them directly.
fn _unused() {
    let _ = Weak::<Ext2Super>::new();
}
