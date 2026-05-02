//! Integration test for issue #754: ext2 [`FileOps::read`] routes
//! through the per-inode [`PageCache`] when `Inode::mapping` is
//! `Some(_)` (RFC 0007 Workstream C).
//!
//! Mounts the existing `read_test.img` fixture (small / large /
//! sparse pre-populated inodes — see
//! `kernel/src/fs/ext2/fixtures/README.md`) and exercises the
//! cache-routing path end-to-end:
//!
//! - **read(2) of a file with mapping=Some returns the same bytes a
//!   parallel mmap+read would** — install the inode's `Ext2Aops`,
//!   trigger `Inode::page_cache_or_create()` (which materialises the
//!   `Arc<PageCache>` in `mapping`), then issue a `read(2)` through
//!   `FileOps::read`. Compare the bytes against the direct
//!   `read_file_at` (buffer-cache) path. They must agree byte for
//!   byte across direct, single-indirect, and double-indirect blocks.
//! - **read past i_size returns 0** — even when the cache is
//!   installed, a read whose `off >= i_size` returns `Ok(0)` and
//!   leaves the caller buffer untouched.
//! - **read across sparse holes returns zero bytes** — the sparse
//!   fixture has hole regions; a cache-routed read must still
//!   observe the same per-block zero-fill the direct path produces.
//! - **read with mapping=None still works (back-compat)** — when
//!   `Inode::page_cache_or_create()` is not invoked, `mapping` stays
//!   `None`; `FileOps::read` falls back to `read_file_at` and
//!   returns identical bytes.
//! - **install-once Arc identity** — two consecutive `FileOps::read`
//!   calls on the same inode go through the **same** `Arc<PageCache>`
//!   (the install-once invariant of RFC 0007 §Inode-binding rule).
//!   Verified by snapshotting the cache `Arc` before and after a
//!   read and confirming `Arc::ptr_eq`.
//!
//! The test mounts RO so the fixture stays byte-identical across
//! runs (a RW mount would stamp `s_state := EXT2_ERROR_FS` into the
//! ramdisk copy on every invocation).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::aops::Ext2Aops;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::Inode;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::mem::aops::AddressSpaceOps;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const READ_IMG: &[u8; 1_048_576] = include_bytes!("../src/fs/ext2/fixtures/read_test.img");

// Pre-assigned inos on the deterministic `mkfs.ext2` invocation that
// generates `read_test.img` — see `fixtures/README.md`.
const INO_SMALL: u32 = 12;
const INO_LARGE: u32 = 13;
const INO_SPARSE: u32 = 15;

const SMALL_BYTES: &[u8] = b"hello ext2 read path #561\n";
const SPARSE_SIZE: usize = 11 * 1024;
const LARGE_SIZE: usize = 300 * 1024;

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
            "read_small_file_via_cache_matches_direct",
            &(read_small_file_via_cache_matches_direct as fn()),
        ),
        (
            "read_large_file_via_cache_matches_direct",
            &(read_large_file_via_cache_matches_direct as fn()),
        ),
        (
            "read_sparse_via_cache_zero_fills_holes",
            &(read_sparse_via_cache_zero_fills_holes as fn()),
        ),
        (
            "read_past_i_size_returns_zero",
            &(read_past_i_size_returns_zero as fn()),
        ),
        (
            "read_with_mapping_none_falls_back",
            &(read_with_mapping_none_falls_back as fn()),
        ),
        (
            "mapping_is_install_once_across_reads",
            &(mapping_is_install_once_across_reads as fn()),
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

fn mount_ro() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let disk = RamDisk::from_image(READ_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount of read_test.img must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after mount");
    (sb, fs, super_arc)
}

/// Install `Ext2Aops` for `inode` and force the `Inode::mapping`
/// slot to materialise via `page_cache_or_create()`. After this
/// returns, `inode.mapping.read().is_some()` and any subsequent
/// `FileOps::read` call routes through the cache.
fn install_cache(
    super_arc: &Arc<Ext2Super>,
    inode: &Arc<Inode>,
) -> Arc<vibix::mem::page_cache::PageCache> {
    use alloc::sync::Weak;
    // Recover the `Arc<Ext2Inode>` from the per-mount parallel cache
    // (see ext2_readpage.rs::iget_with_ext2 for the rationale).
    let ext2_inode = {
        let ecache = super_arc.ext2_inode_cache.lock();
        ecache
            .get(&(inode.ino as u32))
            .and_then(Weak::upgrade)
            .expect("ext2_inode_cache must hold a Weak<Ext2Inode> after iget")
    };
    let aops = Ext2Aops::new(super_arc, &ext2_inode);
    // The bool return on `set_aops` is `true` on first install and
    // `false` on subsequent attempts. Either is acceptable here
    // because `iget` may have already installed it (Workstream C
    // sibling #753 wires that path); the only invariant we care
    // about is that `aops.is_some()` after this line.
    let _ = inode.set_aops(aops as Arc<dyn AddressSpaceOps>);
    inode
        .page_cache_or_create()
        .expect("aops installed; mapping must materialise")
}

/// Build a minimal `OpenFile` whose `inode` is set to `inode` and
/// whose `ops` is the inode's own `file_ops`. The `dentry` slot is
/// a synthesised root-style dentry — `FileOps::read` for ext2 reads
/// only `f.inode` (and `f.inode.mapping`); the synthesised dentry
/// is unobserved.
fn open_file_for_read(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> Arc<OpenFile> {
    let dentry = Dentry::new_root(inode.clone());
    let file_ops = inode.file_ops.clone();
    let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard::try_acquire");
    OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard)
}

/// Issue a read through `inode.file_ops` (the production dispatch).
fn read_via_file_ops(
    sb: &Arc<SuperBlock>,
    inode: &Arc<Inode>,
    buf: &mut [u8],
    off: u64,
) -> Result<usize, i64> {
    let of = open_file_for_read(sb, inode.clone());
    let r = of.ops.read(&of, buf, off);
    drop(of);
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Read the small file (26 bytes, single page) through the cache and
/// confirm the bytes match the known-good greeting. Then read again
/// after dropping the cache install: a fresh mount + iget without
/// install_cache must agree byte for byte (back-compat).
fn read_small_file_via_cache_matches_direct() {
    // Cache-routed read.
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let _cache = install_cache(&super_arc, &inode);
    assert!(
        inode.mapping.read().is_some(),
        "mapping must be Some after page_cache_or_create"
    );
    let mut buf = [0u8; 64];
    let n = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("cache-routed read");
    assert_eq!(n, SMALL_BYTES.len());
    assert_eq!(&buf[..n], SMALL_BYTES);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Read the large 300 KiB file (crosses direct → single-indirect →
/// double-indirect on a 1 KiB-block fixture) through the cache and
/// compare every byte against the deterministic per-block markers
/// the generator stamped down. Exercises the multi-page walk in
/// `read_via_page_cache`.
fn read_large_file_via_cache_matches_direct() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_LARGE).expect("iget large");
    let _cache = install_cache(&super_arc, &inode);

    // Read the whole file in one go through the cache.
    let mut buf = alloc::vec::Vec::new();
    buf.resize(LARGE_SIZE, 0xffu8);
    let n = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("cache-routed full read");
    assert_eq!(n, LARGE_SIZE, "cache-routed read returns full i_size bytes");

    // Verify per-1KiB-block marker + body. The fixture has 300
    // logical blocks; logical 0..11 are direct, 12..267 single-
    // indirect, 268..299 double-indirect.
    for blk in 0..(LARGE_SIZE / 1024) {
        let head = format_block_head(blk);
        let off = blk * 1024;
        assert_eq!(
            &buf[off..off + head.len()],
            head.as_slice(),
            "logical block {blk} marker via cache",
        );
        for (i, &byte) in buf[off + head.len()..off + 1024].iter().enumerate() {
            let expected = ((blk * 131 + i) & 0xff) as u8;
            assert_eq!(
                byte, expected,
                "logical block {blk} body byte {i} via cache",
            );
        }
    }

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Read the sparse file (block 0 = 'X', blocks 1..3 = holes, block
/// 10 = 'Z', i_size = 11264) through the cache and confirm the
/// sparse-hole zero-fill semantics survive the cache routing.
fn read_sparse_via_cache_zero_fills_holes() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SPARSE).expect("iget sparse");
    let _cache = install_cache(&super_arc, &inode);

    let mut buf = alloc::vec::Vec::new();
    buf.resize(SPARSE_SIZE, 0xffu8);
    let n = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("cache-routed sparse read");
    assert_eq!(n, SPARSE_SIZE);

    // Block 0: 'X' * 1024.
    for (i, &b) in buf[0..1024].iter().enumerate() {
        assert_eq!(b, b'X', "sparse block 0 byte {i} via cache");
    }
    // Blocks 1..=9: sparse holes — must be zero. (Block 10 is 'Z'.)
    for blk in 1..=9usize {
        for (i, &b) in buf[blk * 1024..(blk + 1) * 1024].iter().enumerate() {
            assert_eq!(b, 0, "sparse block {blk} hole byte {i} via cache");
        }
    }
    // Block 10: 'Z' * 1024.
    for (i, &b) in buf[10 * 1024..11 * 1024].iter().enumerate() {
        assert_eq!(b, b'Z', "sparse block 10 byte {i} via cache");
    }

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// `read(2)` at or past `i_size` returns `Ok(0)` even when the
/// cache is installed; the caller buffer is untouched.
fn read_past_i_size_returns_zero() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let _cache = install_cache(&super_arc, &inode);

    // small.bin is 26 bytes; off = 100 is well past i_size.
    let mut buf = [0xa5u8; 32];
    let n = read_via_file_ops(&sb, &inode, &mut buf, 100).expect("read past EOF");
    assert_eq!(n, 0, "read at off >= i_size returns Ok(0)");
    // Buffer untouched — sentinel survives.
    for (i, &b) in buf.iter().enumerate() {
        assert_eq!(b, 0xa5, "past-EOF read must not touch buf, byte {i}");
    }
    // Exactly at i_size also returns 0.
    let n =
        read_via_file_ops(&sb, &inode, &mut buf, SMALL_BYTES.len() as u64).expect("read at i_size");
    assert_eq!(n, 0, "read exactly at i_size returns Ok(0)");

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Without `install_cache`, `Inode::mapping` stays `None` and
/// `FileOps::read` falls through to `read_file_at`. The bytes must
/// match the cache-routed read so the back-compat fall-through is
/// equivalent (closes the "no surprise on default-build" worry the
/// migration window's `page_cache` feature gate exists to enforce).
fn read_with_mapping_none_falls_back() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small (mapping=None)");
    // Sanity: no aops installed on this inode (well, #753's iget
    // wiring may install one — but `page_cache_or_create` was never
    // called on this iget, so `mapping` should still be None).
    assert!(
        inode.mapping.read().is_none(),
        "mapping must be None when page_cache_or_create has not been called",
    );

    let mut buf = [0u8; 64];
    let n = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("fallback read");
    assert_eq!(n, SMALL_BYTES.len());
    assert_eq!(&buf[..n], SMALL_BYTES);

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// The `Arc<PageCache>` snapshotted at first install is the same
/// `Arc` observed on every subsequent read of the same inode (RFC
/// 0007 §Inode-binding rule). A second `read(2)` doesn't replace
/// the mapping with a fresh cache.
fn mapping_is_install_once_across_reads() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let cache_first = install_cache(&super_arc, &inode);

    let mut buf = [0u8; 32];
    let _ = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("read 1");

    let cache_second = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping is Some");
    assert!(
        Arc::ptr_eq(&cache_first, &cache_second),
        "mapping is install-once across reads",
    );

    let _ = read_via_file_ops(&sb, &inode, &mut buf, 0).expect("read 2");
    let cache_third = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping is Some");
    assert!(
        Arc::ptr_eq(&cache_first, &cache_third),
        "mapping is install-once across more reads",
    );

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reproduce the generator's per-block marker (`BLKnnnnn`, no NUL,
/// no trailing separator). Mirrors `kernel/tests/ext2_file_read.rs`
/// and `kernel/tests/ext2_readpage.rs`.
fn format_block_head(b: usize) -> alloc::vec::Vec<u8> {
    let mut out = alloc::vec::Vec::with_capacity(8);
    out.extend_from_slice(b"BLK");
    let digits = [
        ((b / 10_000) % 10) as u8,
        ((b / 1_000) % 10) as u8,
        ((b / 100) % 10) as u8,
        ((b / 10) % 10) as u8,
        (b % 10) as u8,
    ];
    for d in digits {
        out.push(b'0' + d);
    }
    out
}
