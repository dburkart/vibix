//! Integration test for issue #561: ext2 `FileOps::read` through the
//! buffer cache.
//!
//! Runs the real kernel under QEMU, in-process: mounts the
//! `read_test.img` fixture (generator documented in
//! `kernel/src/fs/ext2/fixtures/README.md`) and exercises the read
//! path across four pre-populated inodes:
//!
//! - **`small.bin` (ino 12, 26 bytes)** — single-direct read, partial
//!   tail, EOF short-read behaviour, read past EOF returns `Ok(0)`.
//! - **`large.bin` (ino 13, 300 KiB)** — crosses the 12-direct →
//!   single-indirect boundary at logical block 12. Validates that the
//!   indirect-walker path lights up end-to-end and the per-block
//!   markers line up with what the generator laid down on disk.
//!   Triple-indirect coverage is left for a dedicated fixture in a
//!   follow-up (300 × 1 KiB doesn't reach triple on a 1 KiB-block fs).
//! - **`sparse.bin` (ino 15, 11 KiB with logical blocks 1..=9 hole-
//!   punched via `debugfs set_inode_field block[n] 0`)** — validates
//!   sparse-hole zero-fill. Block 0 has 'X' data, blocks 1..=9 are
//!   holes (zero pointer in `i_block`), block 10 has 'Z' data.
//! - **Root dir (ino 2)** — `FileOps::read` on a directory returns
//!   `EISDIR`, not a silent misread of the directory-entry stream.
//!
//! The test mounts RO so the fixture stays byte-identical across
//! runs (a RW mount would stamp `s_state := EXT2_ERROR_FS` into the
//! ramdisk copy on every invocation, wastefully).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::{BlockDevice, BlockError};
use vibix::fs::ext2::{iget, Ext2Fs};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::Inode;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::fs::EISDIR;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const READ_IMG: &[u8; 1_048_576] = include_bytes!("../src/fs/ext2/fixtures/read_test.img");

// Pre-assigned inos on the deterministic `mkfs.ext2` invocation that
// generates `read_test.img`. Documented alongside the generator in
// `fixtures/README.md`. Pinning them here catches an accidental
// fixture re-generation that shifts inode allocation order.
const INO_SMALL: u32 = 12;
const INO_LARGE: u32 = 13;
const INO_SPARSE: u32 = 15;

const SMALL_BYTES: &[u8] = b"hello ext2 read path #561\n";
const LARGE_BLOCKS: usize = 300;
const LARGE_SIZE: usize = LARGE_BLOCKS * 1024;
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
        ("read_small_file_exact", &(read_small_file_exact as fn())),
        (
            "read_small_file_partial",
            &(read_small_file_partial as fn()),
        ),
        (
            "read_small_file_past_eof",
            &(read_small_file_past_eof as fn()),
        ),
        (
            "read_small_file_tail_short_read",
            &(read_small_file_tail_short_read as fn()),
        ),
        (
            "read_large_file_crosses_indirect",
            &(read_large_file_crosses_indirect as fn()),
        ),
        (
            "read_sparse_file_fills_hole_with_zeros",
            &(read_sparse_file_fills_hole_with_zeros as fn()),
        ),
        (
            "read_on_directory_returns_eisdir",
            &(read_on_directory_returns_eisdir as fn()),
        ),
        (
            "read_empty_buffer_is_ok_zero",
            &(read_empty_buffer_is_ok_zero as fn()),
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
}

impl RamDisk {
    fn from_image(bytes: &[u8], block_size: u32) -> Arc<Self> {
        assert!(bytes.len() % block_size as usize == 0);
        Arc::new(Self {
            block_size,
            storage: Mutex::new(bytes.to_vec()),
            writes: AtomicU32::new(0),
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

/// Mount `read_test.img` RO.
fn mount_ro() -> (
    Arc<SuperBlock>,
    Arc<Ext2Fs>,
    Arc<vibix::fs::ext2::Ext2Super>,
) {
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

/// Build a minimal `OpenFile` whose `inode` field is set to `inode`
/// and whose `ops` is the inode's own `file_ops`. The `dentry` slot
/// is a synthesised root-style dentry — `FileOps::read` for ext2
/// reads only `f.inode` (the offset is passed explicitly), so the
/// synthesised dentry is unobserved.
fn open_file_for_read(sb: &Arc<SuperBlock>, inode: Arc<Inode>) -> Arc<OpenFile> {
    let dentry = Dentry::new_root(inode.clone());
    let file_ops = inode.file_ops.clone();
    let guard = SbActiveGuard::try_acquire(sb).expect("SbActiveGuard::try_acquire");
    OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard)
}

/// Issue a read against `inode.file_ops` through a synthesised
/// `OpenFile`. Mirrors the production call path (`sys_read` →
/// `OpenFile::ops.read`).
fn read_at(
    sb: &Arc<SuperBlock>,
    inode: &Arc<Inode>,
    buf: &mut [u8],
    off: u64,
) -> Result<usize, i64> {
    let of = open_file_for_read(sb, inode.clone());
    let r = of.ops.read(&of, buf, off);
    // Drop the OpenFile explicitly so the SbActiveGuard's
    // fetch_sub fires before the test exits (avoids leaving the
    // SB pinned across test boundaries).
    drop(of);
    r
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn read_small_file_exact() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let mut buf = [0u8; 64];
    let n = read_at(&sb, &inode, &mut buf, 0).expect("read");
    assert_eq!(n, SMALL_BYTES.len(), "read returns exactly i_size bytes");
    assert_eq!(&buf[..n], SMALL_BYTES);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_small_file_partial() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let mut buf = [0u8; 5];
    let n = read_at(&sb, &inode, &mut buf, 0).expect("read");
    assert_eq!(n, 5);
    assert_eq!(&buf, &SMALL_BYTES[..5]);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_small_file_tail_short_read() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let mut buf = [0xffu8; 64];
    let n = read_at(&sb, &inode, &mut buf, 20).expect("read");
    assert_eq!(n, SMALL_BYTES.len() - 20);
    assert_eq!(&buf[..n], &SMALL_BYTES[20..]);
    // Bytes past the short read stay at the sentinel.
    assert_eq!(buf[n], 0xff);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_small_file_past_eof() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let mut buf = [0u8; 16];
    let n = read_at(&sb, &inode, &mut buf, SMALL_BYTES.len() as u64).expect("read at EOF");
    assert_eq!(n, 0);
    let n = read_at(&sb, &inode, &mut buf, 1_000_000).expect("read past EOF");
    assert_eq!(n, 0);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_large_file_crosses_indirect() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_LARGE).expect("iget large");

    let mut whole = vec![0u8; LARGE_SIZE];
    let n = read_at(&sb, &inode, &mut whole, 0).expect("read whole");
    assert_eq!(n, LARGE_SIZE);

    for b in 0..LARGE_BLOCKS {
        let head = format_block_head(b);
        let block = &whole[b * 1024..(b + 1) * 1024];
        assert_eq!(
            &block[..head.len()],
            head.as_slice(),
            "logical block {b} head marker mismatch",
        );
        for (i, &byte) in block[head.len()..].iter().enumerate() {
            let expected = ((b * 131 + i) & 0xff) as u8;
            assert_eq!(
                byte, expected,
                "logical block {b} body mismatch at byte {i}",
            );
        }
    }

    // Cross-block read at the direct → single-indirect boundary.
    let mut mid = [0u8; 20];
    let n = read_at(&sb, &inode, &mut mid, 12 * 1024 - 10).expect("read boundary");
    assert_eq!(n, 20);
    let head12 = format_block_head(12);
    assert_eq!(&mid[10..10 + head12.len()], head12.as_slice());

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_sparse_file_fills_hole_with_zeros() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SPARSE).expect("iget sparse");

    let mut whole = vec![0xffu8; SPARSE_SIZE];
    let n = read_at(&sb, &inode, &mut whole, 0).expect("read sparse");
    assert_eq!(n, SPARSE_SIZE);

    for &b in &whole[..1024] {
        assert_eq!(b, b'X', "block 0 must be 'X'");
    }
    for blk in 1..=9usize {
        let slice = &whole[blk * 1024..(blk + 1) * 1024];
        for (i, &b) in slice.iter().enumerate() {
            assert_eq!(
                b, 0,
                "sparse hole block {blk} byte {i} must be zero, got {b:#x}",
            );
        }
    }
    for &b in &whole[10 * 1024..11 * 1024] {
        assert_eq!(b, b'Z', "block 10 must be 'Z'");
    }

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_on_directory_returns_eisdir() {
    let (sb, _fs, super_arc) = mount_ro();
    let root = sb.root.get().expect("root populated at mount").clone();
    let mut buf = [0u8; 64];
    let err = read_at(&sb, &root, &mut buf, 0).expect_err("EISDIR");
    assert_eq!(err, EISDIR);
    drop(root);
    sb.ops.unmount();
    drop(super_arc);
}

fn read_empty_buffer_is_ok_zero() {
    let (sb, _fs, super_arc) = mount_ro();
    let inode = iget(&super_arc, &sb, INO_SMALL).expect("iget small");
    let mut buf: [u8; 0] = [];
    let n = read_at(&sb, &inode, &mut buf, 0).expect("empty buf read");
    assert_eq!(n, 0);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Reproduce the generator's per-block marker (`BLKnnnnn`, no NUL, no
/// trailing separator).
fn format_block_head(b: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
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
