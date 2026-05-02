//! Integration test for issue #750: ext2
//! [`AddressSpaceOps::writepage`] with allocate-on-extend.
//!
//! RFC 0007 §`AddressSpaceOps` and RFC 0004 §Write Ordering are the
//! normative spec. Mounts the 512 KiB `balloc_test.img` fixture (two
//! block groups of 256 blocks, 128 inodes, 1 KiB blocks) read-write,
//! `alloc_inode`s a fresh inode, initialises its on-disk slot as a
//! zero-length regular file, builds an [`Ext2Aops`] over it, and
//! exercises three writepage scenarios:
//!
//! - **Dense writepage** — the first page (4 KiB) of a fresh inode.
//!   On a 1 KiB-block fs the page splits into four direct-block
//!   fragments; every fragment is allocated, written, and synced.
//!   `i_size` and `i_blocks` reflect the full page after the call. A
//!   subsequent `read_file_at` round-trips the bytes.
//! - **Sparse-then-extend writepage** — writepage at page index 5 of
//!   a fresh inode. `i_size` jumps from 0 to `6 * 4096`; pages
//!   `[0, 5)` remain unallocated holes, and `read_file_at` over the
//!   `[0, 20480)` window returns POSIX-zero. Page 5 itself round-
//!   trips the user bytes.
//! - **Allocator-failure rollback** — drain every free block, then
//!   call writepage. The allocator returns `ENOSPC` partway through
//!   the four-fragment page; rollback frees any fragments allocated
//!   so far, and `i_size` / `i_blocks` are *unchanged* from the pre-
//!   call state. The mount-wide free-block counter is identical
//!   before and after.
//!
//! All tests use the same `balloc_test.img` fixture as
//! `kernel/tests/ext2_file_write.rs` so the per-mount state is
//! battle-tested.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use core::panic::PanicInfo;

use vibix::block::BlockDevice;
use vibix::fs::ext2::aops::Ext2Aops;
use vibix::fs::ext2::inode::Ext2Inode;
use vibix::fs::ext2::{alloc_block, alloc_inode, iget, read_file_at, Ext2Fs, Ext2Super};
use vibix::fs::vfs::ops::{FileSystem as _, MountSource};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::fs::{ENOSPC, EROFS};
use vibix::mem::aops::AddressSpaceOps;
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
            "writepage_dense_first_page",
            &(writepage_dense_first_page as fn()),
        ),
        (
            "writepage_sparse_then_extend",
            &(writepage_sparse_then_extend as fn()),
        ),
        (
            "writepage_allocator_failure_rolls_back",
            &(writepage_allocator_failure_rolls_back as fn()),
        ),
        (
            "writepage_ro_mount_returns_erofs",
            &(writepage_ro_mount_returns_erofs as fn()),
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

/// Allocate a fresh inode on the mount and return both its `Arc<Inode>`
/// (kept alive so the inode-cache `Weak` upgrade succeeds) and the
/// parallel `Arc<Ext2Inode>` (the writepage hook needs the latter).
fn fresh_regular(
    sb: &Arc<SuperBlock>,
    super_arc: &Arc<Ext2Super>,
) -> (u32, Arc<vibix::fs::vfs::inode::Inode>, Arc<Ext2Inode>) {
    use alloc::sync::Weak;
    let ino = alloc_inode(super_arc, Some(0), false).expect("alloc_inode");
    init_reg_inode(super_arc, ino);
    let inode = iget(super_arc, sb, ino).expect("iget fresh inode");
    let ext2_inode = {
        let ecache = super_arc.ext2_inode_cache.lock();
        ecache
            .get(&ino)
            .and_then(Weak::upgrade)
            .expect("ext2_inode_cache must hold a Weak<Ext2Inode>")
    };
    (ino, inode, ext2_inode)
}

/// Stamp `ino`'s on-disk inode slot with a minimal regular-file
/// layout. Mirrors the helper in `ext2_file_write.rs`.
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
        for b in &mut data[offset_in_block..slot_end] {
            *b = 0;
        }
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

fn s_free_blocks(super_arc: &Arc<Ext2Super>) -> u32 {
    super_arc.sb_disk.lock().s_free_blocks_count
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Dense writepage: a fresh inode, page 0 (`pgoff = 0`). On a 1 KiB-
/// block fs the 4 KiB page splits into four direct fragments. Every
/// fragment is allocated through the bitmap, written via the buffer
/// cache, and synced. `i_size` and `i_blocks` reflect the complete
/// page; a subsequent `read_file_at` round-trips the user bytes.
fn writepage_dense_first_page() {
    let (sb, _fs, super_arc) = mount_rw();
    let (ino, inode, ext2_inode) = fresh_regular(&sb, &super_arc);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    // Build a deterministic 4 KiB payload — one byte-per-position with
    // a marker per 1 KiB sub-fragment so we can prove each fragment
    // reached its target block.
    let mut payload = [0u8; 4096];
    for (i, slot) in payload.iter_mut().enumerate() {
        *slot = ((i * 17 + 1) & 0xff) as u8;
    }
    payload[0] = b'A';
    payload[1024] = b'B';
    payload[2048] = b'C';
    payload[3072] = b'D';

    let free_before = s_free_blocks(&super_arc);

    AddressSpaceOps::writepage(&*aops, 0, &payload).expect("dense writepage page 0");

    {
        let m = ext2_inode.meta.read();
        assert_eq!(m.size, 4096, "i_size must reflect full page");
        // Four 1 KiB blocks × 2 (512-byte units per block) = 8.
        assert_eq!(m.i_blocks, 8, "i_blocks must reflect 4 fragments");
        // Every direct slot 0..=3 holds a non-zero data block.
        for i in 0..4 {
            assert!(
                m.i_block[i] != 0,
                "i_block[{i}] must be allocated by writepage"
            );
        }
        // Slots 4..15 are still unallocated.
        for i in 4..15 {
            assert_eq!(m.i_block[i], 0, "i_block[{i}] untouched");
        }
    }

    // Free-block counter dropped by exactly 4 (no indirect-pointer
    // allocations needed at this offset).
    assert_eq!(
        s_free_blocks(&super_arc),
        free_before - 4,
        "exactly 4 data blocks consumed"
    );

    // Round-trip the bytes via `read_file_at`.
    let mut readback = [0u8; 4096];
    let n =
        read_file_at(&inode, &ext2_inode, &mut readback, 0).expect("read_file_at after writepage");
    assert_eq!(n, 4096);
    assert_eq!(readback, payload, "writepage data must round-trip");

    // Persistence check (CodeRabbit #803 nit): drop every strong ref
    // to the inode so the cache's `Weak` decays, then re-`iget` the
    // same `ino`. The fresh `Ext2Inode` is constructed straight from
    // the on-disk slot, so an `i_size` / `i_blocks` mismatch here
    // would prove `flush_inode_slot` never landed.
    drop(aops);
    drop(ext2_inode);
    drop(inode);

    let inode2 = iget(&super_arc, &sb, ino).expect("iget after writepage");
    {
        use alloc::sync::Weak;
        let ext2_inode2 = {
            let ecache = super_arc.ext2_inode_cache.lock();
            ecache
                .get(&ino)
                .and_then(Weak::upgrade)
                .expect("ext2_inode_cache repopulated by iget")
        };
        let m = ext2_inode2.meta.read();
        assert_eq!(m.size, 4096, "i_size persisted across iget");
        assert_eq!(m.i_blocks, 8, "i_blocks persisted across iget");
        for i in 0..4 {
            assert!(m.i_block[i] != 0, "i_block[{i}] persisted across iget");
        }
    }
    drop(inode2);
    sb.ops.unmount();
    drop(super_arc);
}

/// Sparse-then-extend writepage: writepage at page 5 of a fresh
/// inode. `i_size` jumps to `6 * 4096`; pages `[0, 5)` remain
/// unallocated holes and read back as zero. Page 5 itself round-trips
/// the user bytes.
fn writepage_sparse_then_extend() {
    let (sb, _fs, super_arc) = mount_rw();
    let (ino, inode, ext2_inode) = fresh_regular(&sb, &super_arc);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let mut payload = [0u8; 4096];
    for (i, slot) in payload.iter_mut().enumerate() {
        *slot = ((i * 31 + 7) & 0xff) as u8;
    }
    payload[0] = b'X';
    payload[4095] = b'Y';

    let free_before = s_free_blocks(&super_arc);

    let pgoff: u64 = 5;
    AddressSpaceOps::writepage(&*aops, pgoff, &payload).expect("sparse writepage at pgoff 5");

    let page_lo = pgoff * 4096;
    let page_hi = page_lo + 4096;

    {
        let m = ext2_inode.meta.read();
        assert_eq!(m.size, page_hi, "i_size grew to end-of-written-page");
        // Page 5 spans logical blocks 20..=23 (1 KiB blocks). All four
        // are direct slots (12 directs cover logical 0..=11) so logical
        // 20..=23 land in the *single-indirect* range — the
        // single-indirect pointer block plus four data blocks = 5
        // blocks × 2 = 10 × 512-byte units.
        assert_eq!(
            m.i_blocks, 10,
            "i_blocks must reflect 4 data + 1 indirect block"
        );
        // Direct slots 0..=11 must remain unallocated holes.
        for i in 0..12 {
            assert_eq!(m.i_block[i], 0, "direct slot {i} must be a hole");
        }
        // Single-indirect slot must be populated.
        assert!(
            m.i_block[12] != 0,
            "single-indirect slot must hold pointer block"
        );
    }

    // Free-block counter dropped by exactly 5 (4 data + 1 indirect
    // pointer).
    assert_eq!(
        s_free_blocks(&super_arc),
        free_before - 5,
        "5 blocks consumed: 4 data + 1 indirect pointer"
    );

    // Pages [0, 5) read back as POSIX zero.
    let mut hole = vec![0xaau8; page_lo as usize];
    let r = read_file_at(&inode, &ext2_inode, &mut hole, 0).expect("read hole prefix");
    assert_eq!(r, page_lo as usize, "full hole prefix must read");
    assert!(
        hole.iter().all(|&b| b == 0),
        "sparse hole must read as POSIX zero"
    );

    // Page 5 round-trips the user bytes.
    let mut readback = [0u8; 4096];
    let r = read_file_at(&inode, &ext2_inode, &mut readback, page_lo).expect("read live page");
    assert_eq!(r, 4096);
    assert_eq!(readback, payload, "sparse writepage data must round-trip");

    // Persistence check (CodeRabbit #803 nit): drop strong refs and
    // re-`iget`. The single-indirect pointer block + size +
    // i_blocks must all be reflected in the freshly-decoded slot.
    drop(aops);
    drop(ext2_inode);
    drop(inode);

    let inode2 = iget(&super_arc, &sb, ino).expect("iget after sparse writepage");
    {
        use alloc::sync::Weak;
        let ext2_inode2 = {
            let ecache = super_arc.ext2_inode_cache.lock();
            ecache
                .get(&ino)
                .and_then(Weak::upgrade)
                .expect("ext2_inode_cache repopulated by iget")
        };
        let m = ext2_inode2.meta.read();
        assert_eq!(m.size, page_hi, "sparse i_size persisted across iget");
        assert_eq!(m.i_blocks, 10, "sparse i_blocks persisted across iget");
        for i in 0..12 {
            assert_eq!(m.i_block[i], 0, "direct slot {i} hole persisted");
        }
        assert!(
            m.i_block[12] != 0,
            "single-indirect slot persisted across iget"
        );
    }
    drop(inode2);
    sb.ops.unmount();
    drop(super_arc);
}

/// Allocator-failure rollback: drain every free block, then call
/// writepage. The first fragment's allocation fails with `ENOSPC`;
/// rollback (a no-op since nothing landed yet) is exercised, and the
/// inode metadata is unchanged from the fresh state.
///
/// Cross-checks the rollback path with a *second* scenario: pre-fill
/// some direct slots so the allocator has free space for the first
/// few fragments but not the last one. Drain bitmap to `n - 3` free
/// blocks before the writepage, so fragments 0..=2 succeed and
/// fragment 3 fails. The metadata + bitmap counter must end identical
/// to their pre-writepage values.
fn writepage_allocator_failure_rolls_back() {
    // ---------- Sub-test 1: ENOSPC on the very first fragment ----------
    {
        let (sb, _fs, super_arc) = mount_rw();
        let (_ino, _inode, ext2_inode) = fresh_regular(&sb, &super_arc);
        let aops = Ext2Aops::new(&super_arc, &ext2_inode);

        // Drain the bitmap to zero free blocks.
        loop {
            match alloc_block(&super_arc, None) {
                Ok(_) => {}
                Err(ENOSPC) => break,
                Err(e) => panic!("unexpected balloc error: {e}"),
            }
        }
        let free_before = s_free_blocks(&super_arc);
        assert_eq!(free_before, 0, "drain leaves zero free blocks");

        let payload = [b'Z'; 4096];

        // Snapshot pre-call state.
        let (size_before, blocks_before, iblock_before) = {
            let m = ext2_inode.meta.read();
            (m.size, m.i_blocks, m.i_block)
        };

        let r = AddressSpaceOps::writepage(&*aops, 0, &payload);
        assert_eq!(r, Err(ENOSPC), "writepage with no free blocks → ENOSPC");

        // Metadata must be unchanged. Read in a tight scope so the
        // RwLock guard is dropped before we move `ext2_inode` below.
        {
            let m = ext2_inode.meta.read();
            assert_eq!(m.size, size_before, "i_size must not change on rollback");
            assert_eq!(
                m.i_blocks, blocks_before,
                "i_blocks must not change on rollback"
            );
            assert_eq!(
                m.i_block, iblock_before,
                "i_block[] must not change on rollback"
            );
        }
        // Bitmap counter must be unchanged.
        assert_eq!(
            s_free_blocks(&super_arc),
            free_before,
            "free-blocks counter must not change on rollback"
        );

        drop(aops);
        drop(ext2_inode);
        drop(_inode);
        sb.ops.unmount();
        drop(super_arc);
    }

    // ---------- Sub-test 2: ENOSPC mid-page after partial allocation ----------
    {
        let (sb, _fs, super_arc) = mount_rw();
        let (_ino, _inode, ext2_inode) = fresh_regular(&sb, &super_arc);
        let aops = Ext2Aops::new(&super_arc, &ext2_inode);

        // Drain the bitmap leaving exactly 2 free blocks. The 4 KiB
        // page on a 1 KiB-block fs needs 4 fragments → fragment 2
        // (third call) will fail.
        loop {
            let free = s_free_blocks(&super_arc);
            if free <= 2 {
                break;
            }
            alloc_block(&super_arc, None).expect("drain alloc");
        }
        let free_before = s_free_blocks(&super_arc);
        assert!(free_before <= 2 && free_before > 0, "drain to ≤2 free");

        let payload = [b'P'; 4096];

        let (size_before, blocks_before, iblock_before) = {
            let m = ext2_inode.meta.read();
            (m.size, m.i_blocks, m.i_block)
        };

        let r = AddressSpaceOps::writepage(&*aops, 0, &payload);
        assert_eq!(
            r,
            Err(ENOSPC),
            "writepage with partial allocator capacity → ENOSPC"
        );

        // After rollback: every direct slot still zero, i_size and
        // i_blocks unchanged, bitmap counter restored. Tight scope so
        // the RwLock guard drops before we move `ext2_inode` below.
        {
            let m = ext2_inode.meta.read();
            assert_eq!(m.size, size_before, "i_size unchanged after rollback");
            assert_eq!(
                m.i_blocks, blocks_before,
                "i_blocks unchanged after rollback"
            );
            assert_eq!(
                m.i_block, iblock_before,
                "i_block[] unchanged after rollback"
            );
        }
        assert_eq!(
            s_free_blocks(&super_arc),
            free_before,
            "free-blocks counter must be restored"
        );

        drop(aops);
        drop(ext2_inode);
        drop(_inode);
        sb.ops.unmount();
        drop(super_arc);
    }
}

/// RO mount: writepage must surface `EROFS` without touching any
/// allocator or buffer cache. Mirrors the `FileOps::write` RO test.
fn writepage_ro_mount_returns_erofs() {
    use alloc::sync::Weak;
    let (sb, _fs, super_arc) = mount_ro();
    init_reg_inode(&super_arc, 12);
    let inode = iget(&super_arc, &sb, 12).expect("iget fabricated reg");
    let ext2_inode = {
        let ecache = super_arc.ext2_inode_cache.lock();
        ecache
            .get(&12)
            .and_then(Weak::upgrade)
            .expect("ext2_inode_cache populated")
    };
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let payload = [0u8; 4096];
    let r = AddressSpaceOps::writepage(&*aops, 0, &payload);
    assert_eq!(r, Err(EROFS), "writepage on RO mount must return EROFS");

    drop(aops);
    drop(ext2_inode);
    drop(inode);
    sb.ops.unmount();
    drop(super_arc);
}
