//! Integration test for issue #749: ext2 [`AddressSpaceOps::readpage`]
//! through the indirect-block walker + buffer cache.
//!
//! Mounts the existing `read_test.img` fixture (small / large / sparse
//! pre-populated inodes — see `fixtures/README.md`) and calls
//! `Ext2Aops::readpage` directly to validate:
//!
//! - **Dense file readpage** — page 0 of `large.bin` (300 KiB, crosses
//!   the 12-direct → single-indirect boundary at logical block 12)
//!   must match the per-block markers the generator stamped down. Page
//!   3 covers logical blocks 12..15 entirely on the indirect path —
//!   exercises a 4-KiB page made of four 1-KiB indirect-block reads.
//! - **Sparse-hole readpage** — page 0 of `sparse.bin` (block 0 is
//!   `'X'`, blocks 1..3 are sparse holes) must yield 1 KiB of `'X'`
//!   followed by 3 KiB of zeros. Page 1 (blocks 4..7, all holes) must
//!   be all-zero. Page 2 (blocks 8..11, blocks 8/9 holes, block 10 is
//!   `'Z'`, block 11 is past `i_size`) must yield 2 KiB of zero, 1 KiB
//!   of `'Z'`, then 1 KiB of tail-zero past EOF.
//! - **Tail-page zero** — page 0 of `small.bin` (26 bytes) must yield
//!   the 26-byte greeting followed by 4070 bytes of zero. The page-end
//!   bytes specifically are the [tail-page zeroing] surface (RFC 0007
//!   §Tail-page zeroing).
//! - **Past-EOF readpage** — page 5 of `small.bin` (well past `i_size
//!   = 26`) must return `Ok(0)` and leave `buf` at its caller-provided
//!   sentinel (the trait contract: pages past EOF are pre-zeroed by
//!   the caller, not by the impl).
//! - **Errno propagation** — readpage on a torn-down (post-`unmount`)
//!   `Ext2Aops` must surface `EIO` rather than panic. Exercised by
//!   dropping the `Arc<Ext2Super>` and calling readpage on the same
//!   `Ext2Aops` whose `super_ref` is now stale.
//!
//! The test mounts RO so the fixture stays byte-identical across runs
//! (a RW mount would stamp `s_state := EXT2_ERROR_FS` into the ramdisk
//! copy on every invocation).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::aops::Ext2Aops;
use vibix::fs::ext2::inode::Ext2Inode;
use vibix::fs::ext2::{iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::fs::EIO;
use vibix::mem::aops::AddressSpaceOps;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const READ_IMG: &[u8; 1_048_576] = include_bytes!("../src/fs/ext2/fixtures/read_test.img");

// Pre-assigned inos on the deterministic `mkfs.ext2` invocation that
// generates `read_test.img` — see `fixtures/README.md`. Pinning them
// here catches an accidental fixture re-generation that shifts inode
// allocation order.
const INO_SMALL: u32 = 12;
const INO_LARGE: u32 = 13;
const INO_SPARSE: u32 = 15;

const SMALL_BYTES: &[u8] = b"hello ext2 read path #561\n";
const SPARSE_SIZE: usize = 11 * 1024;

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
            "readpage_dense_file_page_zero",
            &(readpage_dense_file_page_zero as fn()),
        ),
        (
            "readpage_dense_file_indirect_page",
            &(readpage_dense_file_indirect_page as fn()),
        ),
        (
            "readpage_sparse_hole_zero_fills",
            &(readpage_sparse_hole_zero_fills as fn()),
        ),
        (
            "readpage_sparse_all_holes_page",
            &(readpage_sparse_all_holes_page as fn()),
        ),
        (
            "readpage_partial_page_tail_zeroes_past_eof",
            &(readpage_partial_page_tail_zeroes_past_eof as fn()),
        ),
        (
            "readpage_small_file_tail_zero",
            &(readpage_small_file_tail_zero as fn()),
        ),
        (
            "readpage_past_eof_returns_zero_and_buf_untouched",
            &(readpage_past_eof_returns_zero_and_buf_untouched as fn()),
        ),
        (
            "readpage_after_super_torn_down_returns_eio",
            &(readpage_after_super_torn_down_returns_eio as fn()),
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

/// Mount `read_test.img` RO. Returns the `SuperBlock`, the `Ext2Fs`
/// factory (kept alive so the per-mount state isn't torn down between
/// the mount and the test body), and the per-mount `Ext2Super`.
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

/// `iget(ino)` and recover the parallel `Arc<Ext2Inode>` from the
/// per-mount `ext2_inode_cache` so we can construct an `Ext2Aops`.
fn iget_with_ext2(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<SuperBlock>,
    ino: u32,
) -> (Arc<vibix::fs::vfs::inode::Inode>, Arc<Ext2Inode>) {
    let inode = iget(super_arc, sb, ino).expect("iget");
    // The driver-private cache is populated by `iget` at the same
    // moment it publishes the VFS-cache `Weak<Inode>`. Upgrading the
    // weak here is the canonical recovery path used by the unlink /
    // setattr / orphan-finalize call sites.
    let ext2_inode = {
        let ecache = super_arc.ext2_inode_cache.lock();
        ecache
            .get(&ino)
            .and_then(Weak::upgrade)
            .expect("ext2_inode_cache must hold a Weak<Ext2Inode> after iget")
    };
    (inode, ext2_inode)
}

fn readpage(aops: &Ext2Aops, pgoff: u64, buf: &mut [u8; 4096]) -> Result<usize, i64> {
    AddressSpaceOps::readpage(aops, pgoff, buf)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Page 0 of `large.bin` covers logical blocks 0..3 entirely on the
/// direct path. Each 1-KiB block carries the generator's marker
/// (`BLK00000` … `BLK00003`) followed by a deterministic body.
fn readpage_dense_file_page_zero() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 0, &mut buf).expect("readpage page 0");
    assert_eq!(n, 4096, "dense in-file page returns full 4 KiB");

    for b in 0..4usize {
        let head = format_block_head(b);
        let off = b * 1024;
        assert_eq!(
            &buf[off..off + head.len()],
            head.as_slice(),
            "logical block {b} marker"
        );
        for (i, &byte) in buf[off + head.len()..off + 1024].iter().enumerate() {
            let expected = ((b * 131 + i) & 0xff) as u8;
            assert_eq!(byte, expected, "logical block {b} body byte {i}");
        }
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 3 of `large.bin` covers logical blocks 12..15 — entirely
/// reached through the single-indirect block (the direct slots stop
/// at logical 11). Page 67 of the same file covers logical blocks
/// 268..271 — entirely on the **double-indirect** path
/// (single-indirect runs out at logical 267 on this 1 KiB-block
/// fixture: `12 + ptrs_per_block(256) = 268`). The two together
/// confirm both indirect levels of the RFC 0004 walker light up
/// end-to-end inside `readpage` and the per-block markers line up.
fn readpage_dense_file_indirect_page() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    // --- single-indirect: page 3 → logical blocks 12..15 ---
    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 3, &mut buf).expect("readpage page 3");
    assert_eq!(n, 4096);

    for b in 0..4usize {
        let logical = 12 + b;
        let head = format_block_head(logical);
        let off = b * 1024;
        assert_eq!(
            &buf[off..off + head.len()],
            head.as_slice(),
            "indirect logical block {logical} marker"
        );
        for (i, &byte) in buf[off + head.len()..off + 1024].iter().enumerate() {
            let expected = ((logical * 131 + i) & 0xff) as u8;
            assert_eq!(
                byte, expected,
                "indirect logical block {logical} body byte {i}"
            );
        }
    }

    // --- double-indirect: page 67 → logical blocks 268..271 ---
    // 1 KiB-block ext2: ptrs_per_block = 256, so the single-indirect
    // range spans logical [12, 268). Page byte-offset 67 * 4096 =
    // 274432 = logical 268 on a 1024-byte block — first page entirely
    // past the single-indirect boundary.
    let mut buf2 = [0xffu8; 4096];
    let n = readpage(&aops, 67, &mut buf2).expect("readpage page 67 (double-indirect)");
    assert_eq!(n, 4096);

    for b in 0..4usize {
        let logical = 268 + b;
        let head = format_block_head(logical);
        let off = b * 1024;
        assert_eq!(
            &buf2[off..off + head.len()],
            head.as_slice(),
            "double-indirect logical block {logical} marker"
        );
        for (i, &byte) in buf2[off + head.len()..off + 1024].iter().enumerate() {
            let expected = ((logical * 131 + i) & 0xff) as u8;
            assert_eq!(
                byte, expected,
                "double-indirect logical block {logical} body byte {i}"
            );
        }
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 0 of `sparse.bin`: logical block 0 is `'X' * 1024`, blocks 1..3
/// are sparse holes (zero direct slot, no on-disk allocation). The
/// readpage impl must zero-fill the holes inline — the trait caller
/// only pre-zeroes on `Ok(0)`, not on `Ok(4096)` with sparse interior
/// chunks.
fn readpage_sparse_hole_zero_fills() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SPARSE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 0, &mut buf).expect("readpage sparse page 0");
    assert_eq!(n, 4096);

    // Block 0: 'X' * 1024.
    for (i, &b) in buf[0..1024].iter().enumerate() {
        assert_eq!(b, b'X', "sparse page 0 block 0 byte {i}");
    }
    // Blocks 1..=3: sparse holes — must be zero.
    for blk in 1..=3usize {
        for (i, &b) in buf[blk * 1024..(blk + 1) * 1024].iter().enumerate() {
            assert_eq!(b, 0, "sparse page 0 hole block {blk} byte {i}");
        }
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 1 of `sparse.bin`: logical blocks 4..7, all sparse holes.
/// Every byte of the page must be zero.
fn readpage_sparse_all_holes_page() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SPARSE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 1, &mut buf).expect("readpage sparse page 1");
    assert_eq!(n, 4096);

    for (i, &b) in buf.iter().enumerate() {
        assert_eq!(b, 0, "sparse page 1 (all holes) byte {i}");
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 2 of `sparse.bin`: logical blocks 8..11. Blocks 8/9 are sparse
/// holes; block 10 is `'Z' * 1024`; block 11 is past `i_size = 11264`
/// — it must be tail-zeroed (RFC 0007 §Tail-page zeroing).
fn readpage_partial_page_tail_zeroes_past_eof() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SPARSE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 2, &mut buf).expect("readpage sparse page 2");
    assert_eq!(
        n, 4096,
        "partial-tail page returns full 4096 (tail zero-fill is part of the populate contract)"
    );

    // Block 8: hole.
    for (i, &b) in buf[0..1024].iter().enumerate() {
        assert_eq!(b, 0, "sparse page 2 block 8 hole byte {i}");
    }
    // Block 9: hole.
    for (i, &b) in buf[1024..2048].iter().enumerate() {
        assert_eq!(b, 0, "sparse page 2 block 9 hole byte {i}");
    }
    // Block 10: 'Z' * 1024.
    for (i, &b) in buf[2048..3072].iter().enumerate() {
        assert_eq!(b, b'Z', "sparse page 2 block 10 byte {i}");
    }
    // Block 11 is past i_size = SPARSE_SIZE = 11264 = 11 KiB → tail zero.
    let tail_off = SPARSE_SIZE - 2 * 4096; // 11264 - 8192 = 3072
    assert_eq!(tail_off, 3072);
    for (i, &b) in buf[tail_off..].iter().enumerate() {
        assert_eq!(
            b, 0,
            "sparse page 2 tail (past EOF) byte {i} (offset {tail_off})"
        );
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// `small.bin` is 26 bytes — all in page 0. Bytes 0..26 must match the
/// greeting; bytes 26..4096 are tail-zero (RFC 0007 §Tail-page zeroing).
fn readpage_small_file_tail_zero() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SMALL);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xffu8; 4096];
    let n = readpage(&aops, 0, &mut buf).expect("readpage small page 0");
    assert_eq!(n, 4096);

    assert_eq!(&buf[..SMALL_BYTES.len()], SMALL_BYTES);
    for (i, &b) in buf[SMALL_BYTES.len()..].iter().enumerate() {
        assert_eq!(
            b,
            0,
            "small file tail zero byte {} (page offset {})",
            i,
            SMALL_BYTES.len() + i,
        );
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 5 of `small.bin` (page byte offset 20480) is well past
/// `i_size = 26`. The trait contract (RFC 0007 §`AddressSpaceOps`)
/// says past-EOF pages return `Ok(0)` and the impl leaves `buf`
/// untouched — the caller pre-zeroes.
fn readpage_past_eof_returns_zero_and_buf_untouched() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SMALL);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut buf = [0xa5u8; 4096];
    let n = readpage(&aops, 5, &mut buf).expect("readpage past EOF");
    assert_eq!(n, 0, "past-EOF readpage returns Ok(0)");
    // Buf untouched — the sentinel survives.
    for (i, &b) in buf.iter().enumerate() {
        assert_eq!(b, 0xa5, "past-EOF readpage must not touch buf, byte {i}");
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// After the mount tears down, the `Ext2Aops`' `Weak<Ext2Super>`
/// upgrade fails. The trait contract requires a faithful errno —
/// `EIO` is the correct surface for "the backing storage is gone".
fn readpage_after_super_torn_down_returns_eio() {
    let (sb, _fs, super_arc) = mount_ro();
    let (inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SMALL);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    // Drop the strong refs that pin the mount.
    sb.ops.unmount();
    drop(inode);
    drop(ext2_inode);
    drop(super_arc);
    drop(_fs);
    drop(sb);

    // Now the aops' Weak refs no longer upgrade. readpage must return
    // EIO rather than panic.
    let mut buf = [0xffu8; 4096];
    let r = readpage(&aops, 0, &mut buf);
    assert_eq!(
        r,
        Err(EIO),
        "readpage after mount teardown must surface EIO"
    );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reproduce the generator's per-block marker (`BLKnnnnn`, no NUL, no
/// trailing separator). Mirrors `kernel/tests/ext2_file_read.rs`.
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
