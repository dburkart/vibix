//! Integration test for issue #567: ext2 `FileOps::write` extend path
//! with lazy indirect-block allocation.
//!
//! RFC 0004 §Write extend + §Write Ordering. Mounts the 512 KiB
//! `balloc_test.img` (two block groups of 256 blocks, 128 inodes, 1 KiB
//! blocks) read-write, `alloc_inode`s a fresh inode, initialises its
//! on-disk slot as a zero-length regular file, `iget`s it, then drives
//! `FileOps::write` through a synthesised `OpenFile` against several
//! extend patterns:
//!
//! - **Direct-only write (1 KiB)** — single direct slot, no indirect
//!   allocation. Verifies `i_size` bumps, `i_blocks` bumps, data round-
//!   trips through `FileOps::read`.
//! - **Crosses direct→single-indirect (13 KiB)** — writes past the
//!   12-direct boundary. Single-indirect pointer block is lazily
//!   allocated and zeroed before link; the 13th logical block shows up
//!   at a freshly-allocated data block.
//! - **Sparse write past EOF** — writes one byte at offset 12 KiB on a
//!   fresh inode; the bytes in `[0, 12 KiB)` read back as zeros (POSIX
//!   sparse-file semantics), the byte at 12 KiB reads back as the
//!   written value, and `i_size` reflects the offset + length.
//! - **Append-style multi-call** — two successive writes grow the file
//!   monotonically; the second write doesn't clobber the first.
//! - **EROFS on RO mount** — `FileOps::write` on a read-only mount
//!   returns `EROFS` without allocating anything.
//! - **EISDIR on the root directory** — `FileOps::write` on the
//!   directory inode rejects with `EISDIR`.
//! - **ENOSPC propagates** — drain every free block, the next write
//!   returns a short count (or `ENOSPC` when zero bytes committed).
//!
//! Each test starts from a fresh RamDisk copy of the fixture so
//! mutations don't bleed between tests.

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
use vibix::fs::ext2::{alloc_block, alloc_inode, iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::dentry::Dentry;
use vibix::fs::vfs::inode::Inode;
use vibix::fs::vfs::open_file::OpenFile;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use vibix::fs::vfs::MountFlags;
use vibix::fs::{EISDIR, ENOSPC, EROFS};
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
        ("write_small_direct", &(write_small_direct as fn())),
        (
            "write_crosses_single_indirect",
            &(write_crosses_single_indirect as fn()),
        ),
        (
            "write_sparse_past_eof_reads_zero_prefix",
            &(write_sparse_past_eof_reads_zero_prefix as fn()),
        ),
        (
            "write_append_grows_monotonically",
            &(write_append_grows_monotonically as fn()),
        ),
        ("write_ro_mount_eros", &(write_ro_mount_eros as fn())),
        (
            "write_on_directory_returns_eisdir",
            &(write_on_directory_returns_eisdir as fn()),
        ),
        (
            "write_enospc_on_bitmap_exhaustion",
            &(write_enospc_on_bitmap_exhaustion as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// RamDisk — mirrors the copy in the other ext2 integration tests.
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

fn mount_rw() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags(0))
        .expect("RW mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after mount");
    (sb, fs, super_arc)
}

fn mount_ro() -> (Arc<SuperBlock>, Arc<Ext2Fs>, Arc<Ext2Super>) {
    let disk = RamDisk::from_image(BALLOC_IMG.as_slice(), 512);
    let fs = Ext2Fs::new_with_device(disk as Arc<dyn BlockDevice>);
    let sb = fs
        .mount(MountSource::None, MountFlags::RDONLY)
        .expect("RO mount must succeed");
    let super_arc = fs
        .current_super()
        .expect("current_super must upgrade after mount");
    (sb, fs, super_arc)
}

/// Stamp a freshly-allocated `ino`'s on-disk inode slot with a minimal
/// regular-file layout: `i_mode = 0o100644`, `i_size = 0`, everything
/// else zero. Flushes synchronously so a subsequent `iget` reads the
/// new mode bits instead of whatever garbage the freed-file-or-zeroed
/// slot previously held.
fn init_reg_inode(super_arc: &Arc<Ext2Super>, ino: u32) {
    use vibix::fs::ext2::disk::Ext2Inode as DiskInode;
    let inodes_per_group = super_arc.sb_disk.lock().s_inodes_per_group;
    let bg_inode_table =
        super_arc.bgdt.lock()[((ino - 1) / inodes_per_group) as usize].bg_inode_table;
    let block_size = super_arc.block_size;
    let inode_size = super_arc.inode_size;
    let index_in_group = (ino - 1) % inodes_per_group;
    let byte_offset = (index_in_group as u64) * (inode_size as u64);
    let block_in_table = byte_offset / (block_size as u64);
    let offset_in_block = (byte_offset % (block_size as u64)) as usize;
    let bh = super_arc
        .cache
        .bread(super_arc.device_id, bg_inode_table as u64 + block_in_table)
        .expect("bread inode table");
    {
        let mut data = bh.data.write();
        let slot_end = offset_in_block + 128;
        // Zero the 128-byte prefix first so no garbage carries over.
        for b in &mut data[offset_in_block..slot_end] {
            *b = 0;
        }
        // Build a minimal disk inode: regular file, mode 0o644, zero
        // size / blocks / links. `encode_to_slot` preserves the
        // un-owned bytes after offset 100 verbatim from the zero fill.
        let mut di = DiskInode::decode(&data[offset_in_block..slot_end]);
        di.i_mode = 0o100644;
        di.i_links_count = 1;
        di.i_size = 0;
        di.i_blocks = 0;
        di.i_block = [0u32; 15];
        di.encode_to_slot(&mut data[offset_in_block..slot_end]);
    }
    super_arc.cache.mark_dirty(&bh);
    super_arc
        .cache
        .sync_dirty_buffer(&bh)
        .expect("sync inode slot");
}

/// Build a minimal `OpenFile` for the given inode so we can route
/// `FileOps::write` / `FileOps::read` calls through the real ops
/// dispatch (matches the production `sys_write` / `sys_read` path).
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

fn do_read(
    sb: &Arc<SuperBlock>,
    inode: &Arc<Inode>,
    buf: &mut [u8],
    off: u64,
) -> Result<usize, i64> {
    let of = open_file(sb, inode.clone());
    let r = of.ops.read(&of, buf, off);
    drop(of);
    r
}

/// Allocate a fresh inode on the mount and return an `Arc<Inode>`
/// ready for `FileOps::write`. Stamps the on-disk slot so the mode
/// bits parse as a regular file.
fn fresh_regular(sb: &Arc<SuperBlock>, super_arc: &Arc<Ext2Super>) -> (u32, Arc<Inode>) {
    let ino = alloc_inode(super_arc, Some(0), false).expect("alloc_inode");
    init_reg_inode(super_arc, ino);
    let inode = iget(super_arc, sb, ino).expect("iget fresh inode");
    (ino, inode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn write_small_direct() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode) = fresh_regular(&sb, &super_arc);

    let data = b"hello ext2 write path #567\n";
    let n = do_write(&sb, &inode, data, 0).expect("write");
    assert_eq!(n, data.len());

    // i_size bumped.
    {
        let m = inode.meta.read();
        assert_eq!(m.size, data.len() as u64);
        // One 1 KiB block allocated = 2 × 512-byte units.
        assert_eq!(m.blocks, 2);
    }

    // Round-trip through read.
    let mut buf = [0u8; 64];
    let r = do_read(&sb, &inode, &mut buf, 0).expect("read back");
    assert_eq!(r, data.len());
    assert_eq!(&buf[..r], data);

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_crosses_single_indirect() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode) = fresh_regular(&sb, &super_arc);

    // Block size is 1 KiB → direct slots cover logical blocks 0..=11
    // (12 KiB). Write exactly 13 KiB so the 13th block (logical index
    // 12) lands on the single-indirect chain.
    let total = 13 * 1024usize;
    let mut payload = vec![0u8; total];
    for (i, b) in payload.iter_mut().enumerate() {
        *b = (i & 0xff) as u8;
    }
    let n = do_write(&sb, &inode, &payload, 0).expect("write 13 KiB");
    assert_eq!(n, total);

    {
        let m = inode.meta.read();
        assert_eq!(m.size, total as u64);
        // 13 data blocks + 1 single-indirect pointer block = 14 × 2 =
        // 28 512-byte units.
        assert_eq!(m.blocks, 28);
    }

    let mut buf = vec![0u8; total];
    let r = do_read(&sb, &inode, &mut buf, 0).expect("read back 13 KiB");
    assert_eq!(r, total);
    assert_eq!(buf, payload);

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_sparse_past_eof_reads_zero_prefix() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode) = fresh_regular(&sb, &super_arc);

    // Write 3 bytes at offset 8 KiB (logical block 8). Blocks 0..=7
    // remain unallocated holes; a read of them returns zeros.
    let payload = b"END";
    let off = 8 * 1024u64;
    let n = do_write(&sb, &inode, payload, off).expect("sparse write");
    assert_eq!(n, payload.len());

    {
        let m = inode.meta.read();
        assert_eq!(m.size, off + payload.len() as u64);
        // Only one data block allocated (logical block 8), even
        // though logical 0..=7 are addressable. 1 × 2 = 2 units.
        assert_eq!(m.blocks, 2);
    }

    // Read [0, 8 KiB) — all zeros (holes).
    let mut buf = vec![0xaau8; 8 * 1024];
    let r = do_read(&sb, &inode, &mut buf, 0).expect("read hole");
    assert_eq!(r, 8 * 1024);
    assert!(buf.iter().all(|&b| b == 0), "sparse read must zero-fill");

    // Read the live tail.
    let mut tail = [0u8; 3];
    let r = do_read(&sb, &inode, &mut tail, off).expect("read tail");
    assert_eq!(r, 3);
    assert_eq!(&tail, payload);

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_append_grows_monotonically() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode) = fresh_regular(&sb, &super_arc);

    let first = b"first chunk of bytes ";
    let second = b"second follows";
    let n1 = do_write(&sb, &inode, first, 0).expect("write #1");
    assert_eq!(n1, first.len());
    let n2 = do_write(&sb, &inode, second, first.len() as u64).expect("write #2");
    assert_eq!(n2, second.len());

    let total = first.len() + second.len();
    {
        let m = inode.meta.read();
        assert_eq!(m.size, total as u64);
    }

    let mut buf = vec![0u8; total];
    let r = do_read(&sb, &inode, &mut buf, 0).expect("read back");
    assert_eq!(r, total);
    assert_eq!(&buf[..first.len()], first);
    assert_eq!(&buf[first.len()..], second);

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_ro_mount_eros() {
    // Mount RO, stamp a regular-file inode via the buffer cache (which
    // doesn't itself honor RDONLY — it writes straight to the backing
    // device), `iget` it, and verify `FileOps::write` short-circuits on
    // `EROFS` before touching any allocator.
    let (sb, _fs, super_arc) = mount_ro();
    init_reg_inode(&super_arc, 12);
    let inode = iget(&super_arc, &sb, 12).expect("iget fabricated reg");
    let r = do_write(&sb, &inode, b"nope", 0);
    assert_eq!(
        r,
        Err(EROFS),
        "FileOps::write on RO mount must return EROFS"
    );

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_on_directory_returns_eisdir() {
    let (sb, _fs, super_arc) = mount_rw();
    let root = iget(&super_arc, &sb, 2).expect("iget root");
    let r = do_write(&sb, &root, b"nope", 0);
    assert_eq!(r, Err(EISDIR));

    drop(root);
    sb.ops.unmount();
    drop(super_arc);
}

fn write_enospc_on_bitmap_exhaustion() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode) = fresh_regular(&sb, &super_arc);

    // Drain every free block by calling alloc_block directly. Leaves
    // the bitmap fully used so the next write from FileOps will fail
    // its first allocation attempt.
    loop {
        match alloc_block(&super_arc, None) {
            Ok(_) => {}
            Err(ENOSPC) => break,
            Err(e) => panic!("unexpected balloc error: {e}"),
        }
    }

    // First write must fail outright — zero bytes committed means the
    // caller gets the error directly rather than a partial count.
    let r = do_write(&sb, &inode, b"no room at the inn", 0);
    assert_eq!(r, Err(ENOSPC));

    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}
