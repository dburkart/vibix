//! Integration test for issue #752: ext2
//! [`AddressSpaceOps::readahead`] driven by the page cache's
//! per-inode `ra_state` heuristic (#741).
//!
//! Mounts the existing `read_test.img` fixture (small / large / sparse
//! pre-populated inodes — see `fixtures/README.md`) and exercises:
//!
//! - **Sequential prefetch warms the buffer cache** — call
//!   `readahead(start=1, nr_pages=4)` on a fresh `Ext2Aops` over
//!   `large.bin` and assert that the underlying fs-blocks for those
//!   pages are now resident in the buffer cache (per `BlockCache::contains`).
//! - **`nr_pages == 0` is a no-op** — the cache state is unchanged
//!   across the call, even on an inode whose blocks aren't yet warm.
//! - **Past-EOF window is a no-op** — `readahead` over a window that
//!   begins past `i_size` doesn't warm anything (and doesn't read
//!   metadata blocks past the file).
//! - **Sparse-hole window doesn't warm phantom blocks** — `readahead`
//!   over the all-holes range of `sparse.bin` page 1 doesn't warm any
//!   blocks (the impl skips `Ok(None)` on `resolve_block`). The data
//!   block of `sparse.bin` page 0 (`'X' * 1024`) does get warmed when
//!   `readahead(start=0, nr_pages=1)` runs.
//! - **End-to-end heuristic ramp** — drive `PageCache::note_miss`
//!   on the same `Ext2Aops`-backed cache and observe that a sequential
//!   miss stream (`1, 2, 3, …`) returns growing windows that, when
//!   passed into `readahead`, warm the next blocks; whereas a
//!   random/non-sequential miss stream returns 0-page windows so
//!   `readahead(_, 0)` is a no-op (cache stays cold).
//!
//! All assertions go through public `BlockCache` API (`contains` /
//! `len`) so a future refactor of the cache's internal residency
//! tracking doesn't have to update this test.

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
use vibix::mem::aops::AddressSpaceOps;
use vibix::mem::page_cache::{InodeId, PageCache};
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const READ_IMG: &[u8; 1_048_576] = include_bytes!("../src/fs/ext2/fixtures/read_test.img");

// Pre-assigned inos on the deterministic `mkfs.ext2` invocation that
// generates `read_test.img` — see `fixtures/README.md`.
const INO_LARGE: u32 = 13;
const INO_SPARSE: u32 = 15;

// `large.bin` is 300 KiB (300 logical 1 KiB-blocks). The fixture
// allocates them densely starting at logical block 0 — block-pointer
// layout drops out of the indirect walker. We assert against
// per-page block-pointer resolutions rather than hard-coding absolute
// disk-block numbers, so a future fixture re-generation that shifts
// the on-disk layout doesn't break the test.

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
            "readahead_zero_pages_is_noop",
            &(readahead_zero_pages_is_noop as fn()),
        ),
        (
            "readahead_past_eof_is_noop",
            &(readahead_past_eof_is_noop as fn()),
        ),
        (
            "readahead_sequential_warms_buffer_cache",
            &(readahead_sequential_warms_buffer_cache as fn()),
        ),
        (
            "readahead_sparse_holes_dont_warm_phantom_blocks",
            &(readahead_sparse_holes_dont_warm_phantom_blocks as fn()),
        ),
        (
            "readahead_after_super_torn_down_is_silent",
            &(readahead_after_super_torn_down_is_silent as fn()),
        ),
        (
            "ra_state_sequential_stream_drives_readahead_progressively",
            &(ra_state_sequential_stream_drives_readahead_progressively as fn()),
        ),
        (
            "ra_state_random_stream_does_not_drive_readahead",
            &(ra_state_random_stream_does_not_drive_readahead as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// Shared `RamDisk` — see kernel/tests/common/ext2_ramdisk.rs.
#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Mount `read_test.img` RO. Mirrors `ext2_readpage.rs::mount_ro`.
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

fn iget_with_ext2(
    super_arc: &Arc<Ext2Super>,
    sb: &Arc<SuperBlock>,
    ino: u32,
) -> (Arc<vibix::fs::vfs::inode::Inode>, Arc<Ext2Inode>) {
    let inode = iget(super_arc, sb, ino).expect("iget");
    let ext2_inode = {
        let ecache = super_arc.ext2_inode_cache.lock();
        ecache
            .get(&ino)
            .and_then(Weak::upgrade)
            .expect("ext2_inode_cache must hold a Weak<Ext2Inode> after iget")
    };
    (inode, ext2_inode)
}

/// `nr_pages == 0` short-circuits before the inode-metadata snapshot —
/// the cache state must be byte-identical before and after.
fn readahead_zero_pages_is_noop() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    let len_before = super_arc.cache.len();
    aops.readahead(0, 0);
    let len_after = super_arc.cache.len();
    assert_eq!(
        len_before, len_after,
        "readahead with nr_pages == 0 must not perform any I/O"
    );

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// A `start` past `i_size` makes the entire window past EOF — the
/// impl bails after the size snapshot. No new blocks resident.
fn readahead_past_eof_is_noop() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    // `large.bin` is 300 KiB. Page 100 is at byte 409600, well past
    // the end of the file.
    let len_before = super_arc.cache.len();
    aops.readahead(100, 8);
    let len_after = super_arc.cache.len();
    assert_eq!(
        len_before, len_after,
        "readahead starting past i_size must not warm any blocks"
    );

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// On a 1 KiB-block / 4 KiB-page fs, page `pgoff` covers logical
/// blocks `[pgoff*4, pgoff*4 + 4)`. `readahead(start=1, nr_pages=2)`
/// over `large.bin` must warm logical blocks 4..12. We probe through
/// the indirect walker to convert each logical block to its absolute
/// disk block and assert the buffer cache holds it after the call.
fn readahead_sequential_warms_buffer_cache() {
    use vibix::fs::ext2::indirect::{resolve_block, Geometry};

    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);

    // Build the geometry / forbidden map the same way `Ext2Aops`
    // does, so the test resolves blocks against the same fixture.
    let (s_first_data_block, s_blocks_count) = {
        let sb_disk = super_arc.sb_disk.lock();
        (sb_disk.s_first_data_block, sb_disk.s_blocks_count)
    };
    let geom =
        Geometry::new(super_arc.block_size, s_first_data_block, s_blocks_count).expect("geometry");
    // The integration test resolves logical→absolute block numbers
    // independently to set up its `cache.contains` assertions. An
    // empty metadata-forbidden map is sufficient for the regular-file
    // inodes (`large.bin`, `sparse.bin`) the test uses — their data
    // blocks live in regular allocator-issued data regions, well
    // outside any metadata range that `validate_pointer` would
    // reject. The driver itself uses the real map (built by
    // `Ext2Aops::readahead`), but for the *probe* in this test the
    // empty map produces identical results on legal data blocks.
    let md = vibix::fs::ext2::indirect::MetadataMap::empty();

    let i_block = ext2_inode.meta.read().i_block;

    // Pre-resolve the absolute blocks for logical 4..=11 (pages 1..=2).
    // Each page holds four logical blocks on this 1 KiB-block fs.
    //
    // The `resolve_block` calls above also warm the cache as a side
    // effect (an indirect-walker that reads the indirect block calls
    // `bread` internally). To assert that *readahead specifically*
    // populated the leaf data blocks we'd have to either (a) know the
    // forbidden-map / metadata bread pattern in advance, or (b)
    // verify that *after* readahead the data blocks are resident,
    // which is the actual user-visible contract: a subsequent
    // `readpage` will hit the cache.
    //
    // We pick (b). The probe is robust against the cache also holding
    // metadata blocks the indirect walker bread'd along the way.
    let mut absolute_blocks_to_warm = alloc::vec::Vec::new();
    for logical in 4u32..12 {
        match resolve_block(
            &super_arc.cache,
            super_arc.device_id,
            &geom,
            &md,
            &i_block,
            logical,
            None,
        )
        .expect("resolve_block on dense file")
        {
            Some(abs) => absolute_blocks_to_warm.push(abs),
            None => panic!("large.bin logical block {logical} unexpectedly sparse"),
        }
    }

    let aops = Ext2Aops::new(&super_arc, &ext2_inode);
    aops.readahead(1, 2);

    for &abs in &absolute_blocks_to_warm {
        assert!(
            super_arc.cache.contains(super_arc.device_id, abs as u64),
            "readahead(1, 2) must warm absolute block {abs}"
        );
    }

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Page 1 of `sparse.bin` covers logical blocks 4..7 — all sparse
/// holes. `readahead(start=1, nr_pages=1)` must not warm any block,
/// because there are no on-disk blocks to warm. Page 0 of `sparse.bin`
/// has block 0 = `'X' * 1024` — the data block — and blocks 1..=3
/// holes; `readahead(start=0, nr_pages=1)` must warm block 0's
/// absolute disk block.
fn readahead_sparse_holes_dont_warm_phantom_blocks() {
    use vibix::fs::ext2::indirect::{resolve_block, Geometry};

    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_SPARSE);

    let (s_first_data_block, s_blocks_count) = {
        let sb_disk = super_arc.sb_disk.lock();
        (sb_disk.s_first_data_block, sb_disk.s_blocks_count)
    };
    let geom =
        Geometry::new(super_arc.block_size, s_first_data_block, s_blocks_count).expect("geometry");
    // The integration test resolves logical→absolute block numbers
    // independently to set up its `cache.contains` assertions. An
    // empty metadata-forbidden map is sufficient for the regular-file
    // inodes (`large.bin`, `sparse.bin`) the test uses — their data
    // blocks live in regular allocator-issued data regions, well
    // outside any metadata range that `validate_pointer` would
    // reject. The driver itself uses the real map (built by
    // `Ext2Aops::readahead`), but for the *probe* in this test the
    // empty map produces identical results on legal data blocks.
    let md = vibix::fs::ext2::indirect::MetadataMap::empty();
    let i_block = ext2_inode.meta.read().i_block;

    // Resolve sparse.bin block 0 — must be `Some`.
    let block0_abs = match resolve_block(
        &super_arc.cache,
        super_arc.device_id,
        &geom,
        &md,
        &i_block,
        0,
        None,
    )
    .expect("resolve_block sparse 0")
    {
        Some(abs) => abs,
        None => panic!("sparse.bin block 0 unexpectedly sparse"),
    };

    // Resolve a hole — must be `None`.
    for logical in 4u32..=7 {
        let r = resolve_block(
            &super_arc.cache,
            super_arc.device_id,
            &geom,
            &md,
            &i_block,
            logical,
            None,
        )
        .expect("resolve_block sparse hole");
        assert!(r.is_none(), "sparse.bin logical {logical} must be a hole");
    }

    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    // Page 0: should warm block 0's absolute block.
    aops.readahead(0, 1);
    assert!(
        super_arc
            .cache
            .contains(super_arc.device_id, block0_abs as u64),
        "readahead(0, 1) must warm sparse block 0 (abs {block0_abs})"
    );

    // Page 1: all holes — readahead must complete without panicking
    // and without bread'ing any phantom block. By this point the
    // setup has already walked `resolve_block` over logical 4..=7
    // (which warmed the indirect-pointer block servicing those
    // logical indices) plus `aops.readahead(0, 1)` (which warmed
    // the indirect block again — same `bread` cache hit — and
    // installed the page-0 data block). So the indirect block
    // covering page 1's logicals is already resident; an
    // `Ok(None)`-only walk over those holes performs no further
    // `bread` and the cache size must be stable across the call.
    //
    // This is the external observable that catches a regression
    // where a future `Ok(None)` arm accidentally tries to `bread`
    // a phantom block.
    let len_before = super_arc.cache.len();
    aops.readahead(1, 1);
    assert_eq!(
        len_before,
        super_arc.cache.len(),
        "sparse-hole readahead must not warm any new buffer-cache blocks"
    );

    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// After the mount tears down, `readahead` must not panic — the
/// `Weak<Ext2Super>` upgrade fails and the impl returns silently.
/// Best-effort: a torn-down inode's prefetch is no longer useful.
fn readahead_after_super_torn_down_is_silent() {
    let (sb, _fs, super_arc) = mount_ro();
    let (inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);
    let aops = Ext2Aops::new(&super_arc, &ext2_inode);

    sb.ops.unmount();
    drop(inode);
    drop(ext2_inode);
    drop(super_arc);
    drop(_fs);
    drop(sb);

    // Now `aops`' Weak refs no longer upgrade. readahead must be a
    // silent no-op.
    aops.readahead(0, 8);
    aops.readahead(0, 0);
    aops.readahead(u64::MAX, 1);
}

/// Wire `Ext2Aops` into a `PageCache`, drive a sequential miss
/// stream through `note_miss`, and verify each non-zero window the
/// heuristic returns produces a real prefetch (warmed buffer-cache
/// blocks).
fn ra_state_sequential_stream_drives_readahead_progressively() {
    use vibix::fs::ext2::indirect::{resolve_block, Geometry};

    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);

    let (s_first_data_block, s_blocks_count) = {
        let sb_disk = super_arc.sb_disk.lock();
        (sb_disk.s_first_data_block, sb_disk.s_blocks_count)
    };
    let geom =
        Geometry::new(super_arc.block_size, s_first_data_block, s_blocks_count).expect("geometry");
    // The integration test resolves logical→absolute block numbers
    // independently to set up its `cache.contains` assertions. An
    // empty metadata-forbidden map is sufficient for the regular-file
    // inodes (`large.bin`, `sparse.bin`) the test uses — their data
    // blocks live in regular allocator-issued data regions, well
    // outside any metadata range that `validate_pointer` would
    // reject. The driver itself uses the real map (built by
    // `Ext2Aops::readahead`), but for the *probe* in this test the
    // empty map produces identical results on legal data blocks.
    let md = vibix::fs::ext2::indirect::MetadataMap::empty();
    let i_block = ext2_inode.meta.read().i_block;

    let aops_arc = Ext2Aops::new(&super_arc, &ext2_inode);
    let cache = PageCache::new(
        InodeId::new(0xfeed_face_dead_beef, INO_LARGE as u64),
        ext2_inode.meta.read().size,
        aops_arc.clone() as Arc<dyn AddressSpaceOps>,
    );

    // Sequential miss stream starting at pgoff 0. The third miss
    // (pgoff 2) is the first one to return a non-zero window
    // (`hit_streak == 2 ⇒ window = 4`).
    let mut last_window = 0u32;
    let mut saw_nonzero_window = false;
    for pgoff in 0..6u64 {
        let window = cache.note_miss(pgoff);
        if pgoff >= 2 {
            assert!(
                window >= last_window,
                "sequential stream window must be non-decreasing: prev {last_window}, now {window} at pgoff {pgoff}"
            );
        }
        if window > 0 {
            saw_nonzero_window = true;
            // Issue the readahead the cache says we should. The pages
            // it covers are `[pgoff + 1, pgoff + 1 + window)`.
            cache.ops().readahead(pgoff + 1, window);

            // Confirm the data blocks for the *first* readahead page
            // are warm. (We only check the leading edge so the assert
            // stays robust against a window that runs past the file's
            // 300 KiB / 75-page tail.)
            let lead_pgoff = pgoff + 1;
            let lead_byte = lead_pgoff * 4096;
            if lead_byte < ext2_inode.meta.read().size {
                let leading_logical = (lead_byte / 1024) as u32;
                if let Some(abs) = resolve_block(
                    &super_arc.cache,
                    super_arc.device_id,
                    &geom,
                    &md,
                    &i_block,
                    leading_logical,
                    None,
                )
                .expect("resolve_block")
                {
                    assert!(
                        super_arc.cache.contains(super_arc.device_id, abs as u64),
                        "readahead from pgoff {pgoff} (window {window}) must warm \
                         logical {leading_logical} (abs {abs})"
                    );
                }
            }
        }
        last_window = window;
    }
    assert!(
        saw_nonzero_window,
        "a sequential stream of >= 3 misses must yield a non-zero readahead window"
    );

    drop(aops_arc);
    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// A non-sequential miss stream returns a zero window from
/// `note_miss` on every miss — `readahead(_, 0)` is a no-op so no
/// blocks are warmed beyond what `note_miss` itself observes.
fn ra_state_random_stream_does_not_drive_readahead() {
    let (sb, _fs, super_arc) = mount_ro();
    let (_inode, ext2_inode) = iget_with_ext2(&super_arc, &sb, INO_LARGE);

    let aops_arc = Ext2Aops::new(&super_arc, &ext2_inode);
    let cache = PageCache::new(
        InodeId::new(0xfeed_face_dead_beef, INO_LARGE as u64),
        ext2_inode.meta.read().size,
        aops_arc.clone() as Arc<dyn AddressSpaceOps>,
    );

    // Hop pattern: 10, 20, 30, 5, 50 — every miss is non-adjacent
    // to the previous, so `hit_streak` resets to 1 on each miss and
    // `note_miss` returns 0.
    let cache_len_before = super_arc.cache.len();
    for &pgoff in &[10u64, 20, 30, 5, 50] {
        let window = cache.note_miss(pgoff);
        assert_eq!(
            window, 0,
            "non-sequential miss at pgoff {pgoff} must yield a zero readahead window"
        );
        // The contract: the heuristic returns 0, so the caller would
        // pass 0 into readahead. nr_pages == 0 is a fast no-op in
        // the impl.
        cache.ops().readahead(pgoff + 1, window);
    }
    let cache_len_after = super_arc.cache.len();
    assert_eq!(
        cache_len_before, cache_len_after,
        "random-access stream must not warm any new buffer-cache blocks via readahead \
         (cache size: before {cache_len_before}, after {cache_len_after})"
    );

    drop(aops_arc);
    drop(ext2_inode);
    drop(_inode);
    sb.ops.unmount();
    drop(super_arc);
}
