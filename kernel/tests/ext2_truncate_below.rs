//! Integration test for issue #751: ext2
//! [`AddressSpaceOps::truncate_below`] — drops cached pages above the
//! new size, parks on `PG_WRITEBACK` for any in-flight `writepage`,
//! then returns so `setattr` can drive the on-disk block free.
//!
//! RFC 0007 §Truncate, unmap, MADV_DONTNEED is the normative spec.
//! Closes the on-disk UAF surface where the writeback daemon's
//! `writepage` could otherwise commit stale bytes into blocks the FS
//! is concurrently freeing.
//!
//! Coverage:
//!
//! - **`shrink_truncate_drops_cached_pages_above_new_size`** — install
//!   four cached pages over a fresh inode's mapping at `pgoff = 0..=3`,
//!   `setattr(SIZE)` to 8192 bytes (= start of page 2), and verify
//!   pages `[2, 3]` are evicted from the index while `[0, 1]` survive.
//!
//! - **`shrink_truncate_below_zero_drops_every_cached_page`** — same
//!   setup, truncate to zero. Every cached page is gone from the
//!   index and the page cache reports `i_size == 0`.
//!
//! - **`shrink_truncate_with_writeback_in_flight_is_awaited`** —
//!   synthesize an in-flight writeback by hand-setting `PG_WRITEBACK`
//!   on a cached page above the cut, then spawn a kernel task that
//!   calls `end_writeback` after a short delay. The main task
//!   `setattr`s and must block on the WB-clear handshake until the
//!   spawn fires, after which `setattr` returns and the page is
//!   evicted.
//!
//! The existing setattr-size correctness (free-block accounting,
//! sparse-grow, EISDIR / EINVAL gates) lives in
//! `ext2_setattr.rs`; this file adds the page-cache-side coverage.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::{Arc, Weak};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use vibix::block::BlockDevice;
use vibix::fs::ext2::aops::Ext2Aops;
use vibix::fs::ext2::inode::Ext2Inode;
use vibix::fs::ext2::{alloc_inode, iget, Ext2Fs, Ext2Super};
use vibix::fs::vfs::inode::Inode;
use vibix::fs::vfs::ops::{FileSystem as _, MountSource, SetAttr, SetAttrMask};
use vibix::fs::vfs::super_block::SuperBlock;
use vibix::fs::vfs::MountFlags;
use vibix::mem::page_cache::CachePage;
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

const BALLOC_IMG: &[u8; 524_288] = include_bytes!("../src/fs/ext2/fixtures/balloc_test.img");

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    // The writeback-wait test below spawns a kernel task and depends
    // on cooperative wake-up via `WaitQueue::notify_all` reaching the
    // parked main task; both require the scheduler to be live.
    task::init();
    x86_64::instructions::interrupts::enable();
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
            "shrink_truncate_drops_cached_pages_above_new_size",
            &(shrink_truncate_drops_cached_pages_above_new_size as fn()),
        ),
        (
            "shrink_truncate_below_zero_drops_every_cached_page",
            &(shrink_truncate_below_zero_drops_every_cached_page as fn()),
        ),
        (
            "shrink_truncate_with_writeback_in_flight_is_awaited",
            &(shrink_truncate_with_writeback_in_flight_is_awaited as fn()),
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

/// Allocate a fresh regular-file inode on the mount and stamp its
/// on-disk slot to a minimal regular layout. Returns the ino, the VFS
/// `Arc<Inode>`, and the parallel `Arc<Ext2Inode>` (the latter is what
/// `Ext2Aops` needs as its inode-side weak handle).
fn fresh_regular(
    sb: &Arc<SuperBlock>,
    super_arc: &Arc<Ext2Super>,
) -> (u32, Arc<Inode>, Arc<Ext2Inode>) {
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
/// layout. Mirrors the helper in `ext2_writepage.rs`.
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

/// Install + publish a stub cache page at `pgoff` against `inode`'s
/// page cache. Returns the resulting `Arc<CachePage>` so the test can
/// inspect / mutate state bits directly. The stub is published
/// `PG_UPTODATE`-and-unlocked so it looks like a "real" cached page
/// to the truncate driver.
fn install_published_page(inode: &Arc<Inode>, pgoff: u64) -> Arc<CachePage> {
    use vibix::mem::page_cache::{InstallOutcome, PageCache};
    let pc: Arc<PageCache> = inode
        .page_cache_or_create()
        .expect("inode mapping must construct after set_aops");
    // Install via the same install_or_get path the fault path uses.
    // The `phys` value here is a fictional non-zero page-aligned u64
    // — `truncate_below` never dereferences it.
    let stub = match pc.install_or_get(pgoff, || {
        CachePage::new_locked(0x1_0000_0000 + pgoff * 4096, pgoff)
    }) {
        InstallOutcome::InstalledNew(p) => p,
        InstallOutcome::AlreadyPresent(p) => p,
    };
    stub.publish_uptodate_and_unlock();
    stub
}

/// Build + install an [`Ext2Aops`] on `inode`. Required so the
/// page-cache mapping is reachable from `inode.aops` and so the
/// `setattr` shrink path picks up the truncate hook.
fn install_aops(super_arc: &Arc<Ext2Super>, inode: &Arc<Inode>, ext2_inode: &Arc<Ext2Inode>) {
    let aops = Ext2Aops::new(super_arc, ext2_inode);
    let installed = inode.set_aops(aops);
    assert!(installed, "set_aops must install on a fresh inode");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Shrinking truncate drops every cached page strictly above the new
/// size; the page that holds the boundary byte (and any below) stays
/// cached. The page-cache `i_size` cap is bumped to the new size as a
/// side-effect of the truncate driver.
fn shrink_truncate_drops_cached_pages_above_new_size() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode, ext2_inode) = fresh_regular(&sb, &super_arc);
    install_aops(&super_arc, &inode, &ext2_inode);

    // Pretend the file is 4 pages worth of data (16 KiB) so the
    // truncate has both kept and dropped pages to walk. We update
    // both the in-memory ext2 meta and the VFS meta directly because
    // the page-cache truncate path is independent of any `writepage`
    // having actually populated disk blocks.
    {
        let mut m = ext2_inode.meta.write();
        m.size = 16 * 1024;
    }
    {
        let mut m = inode.meta.write();
        m.size = 16 * 1024;
    }

    // Install four cached pages.
    let pages: alloc::vec::Vec<Arc<CachePage>> = (0..4u64)
        .map(|p| install_published_page(&inode, p))
        .collect();
    assert!(pages.iter().all(|p| p.is_uptodate()));

    // setattr to 8192 bytes (= page 2 start). Pages 2 and 3 must be
    // dropped from the cache index; pages 0 and 1 must survive.
    let attr = SetAttr {
        mask: SetAttrMask::SIZE,
        size: 8 * 1024,
        ..SetAttr::default()
    };
    inode.ops.setattr(&inode, &attr).expect("setattr shrink");

    let pc = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("mapping installed by install_published_page");
    assert!(pc.lookup(0).is_some(), "page 0 must survive shrink to 8192");
    assert!(pc.lookup(1).is_some(), "page 1 must survive shrink to 8192");
    assert!(
        pc.lookup(2).is_none(),
        "page 2 must be dropped (starts exactly at new_size)"
    );
    assert!(pc.lookup(3).is_none(), "page 3 must be dropped");
    assert_eq!(pc.i_size(), 8 * 1024, "page cache i_size cap bumped");

    drop(pages);
    drop(inode);
    drop(ext2_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// `setattr(size = 0)` against an inode whose mapping holds several
/// cached pages drops every cached page from the index. The on-disk
/// block-free path runs as before — tested in `ext2_setattr.rs`; here
/// we only assert the cache half.
fn shrink_truncate_below_zero_drops_every_cached_page() {
    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode, ext2_inode) = fresh_regular(&sb, &super_arc);
    install_aops(&super_arc, &inode, &ext2_inode);

    {
        let mut m = ext2_inode.meta.write();
        m.size = 12 * 1024;
    }
    {
        let mut m = inode.meta.write();
        m.size = 12 * 1024;
    }

    let pages: alloc::vec::Vec<Arc<CachePage>> = (0..3u64)
        .map(|p| install_published_page(&inode, p))
        .collect();
    assert_eq!(pages.len(), 3);

    let attr = SetAttr {
        mask: SetAttrMask::SIZE,
        size: 0,
        ..SetAttr::default()
    };
    inode.ops.setattr(&inode, &attr).expect("setattr to 0");

    let pc = inode.mapping.read().as_ref().map(Arc::clone).unwrap();
    for pgoff in 0..3u64 {
        assert!(
            pc.lookup(pgoff).is_none(),
            "page {pgoff} must be dropped on truncate to 0"
        );
    }
    assert_eq!(pc.i_size(), 0);

    drop(pages);
    drop(inode);
    drop(ext2_inode);
    sb.ops.unmount();
    drop(super_arc);
}

/// Synthesize an in-flight writeback over a page above the truncate
/// cut. The main task calls `setattr(SIZE)` and must park on
/// `PG_WRITEBACK` until a spawned kernel task fires `end_writeback`.
/// After the wake the truncate completes and the page is evicted.
///
/// The test pins (a) that `truncate_below` does observe `PG_WRITEBACK`
/// and parks rather than tearing the writeback in flight, and
/// (b) that `end_writeback`'s `notify_all` reaches the parked
/// truncate caller and unblocks it. RFC 0007 §Truncate, unmap,
/// MADV_DONTNEED.

// Statics used by the spawned writeback-completion task. The
// integration-test stub harness routes spawned tasks through
// `extern "C" fn() -> !`; the task can't take owned state by closure,
// so we publish the page Arc + a kick / acknowledge handshake via
// statics.
//
// The race we need to close: if `end_writeback` runs before the main
// task has reached `wait_until_writeback_clear`, the bare-metal
// `WaitQueue::wait_while` re-checks `is_writeback()` under the queue
// lock, sees the bit clear, and returns immediately — no deadlock,
// but also no real "park-then-wake" exercise. To force a real park,
// the spawned task spins on `MAIN_PARKED == true` (set by the main
// task right before it calls into setattr) plus a fixed extra
// `hlt_loop` to give the main task time to actually descend into the
// waitqueue.
static MAIN_PARKED: AtomicBool = AtomicBool::new(false);
static WORKER_FINISHED: AtomicBool = AtomicBool::new(false);
// Strong ref to the page the worker will end writeback on. Held in a
// `spin::Once`-style slot the worker reads on entry. We use a
// `spin::Mutex` instead of `Once` because the cleanup between tests
// resets the slot.
static WORKER_PAGE: spin::Mutex<Option<Arc<CachePage>>> = spin::Mutex::new(None);

fn writeback_completion_worker() -> ! {
    // Wait until the main task has at least *entered* setattr — the
    // `MAIN_PARKED` flag is set immediately before that descent. A
    // few extra hlts give the main task time to traverse setattr,
    // call `Ext2Aops::truncate_below`, snapshot the index, drop the
    // inner lock, and reach the `wait_while` body so its enqueue
    // happens before our `notify_all`.
    while !MAIN_PARKED.load(Ordering::Acquire) {
        x86_64::instructions::hlt();
    }
    for _ in 0..32 {
        x86_64::instructions::hlt();
    }
    let page = WORKER_PAGE
        .lock()
        .take()
        .expect("test must publish the page before spawn");
    page.end_writeback();
    WORKER_FINISHED.store(true, Ordering::Release);
    loop {
        x86_64::instructions::hlt();
    }
}

fn shrink_truncate_with_writeback_in_flight_is_awaited() {
    // Reset cross-test statics so a previous test in this file does
    // not leak its handshake state into ours.
    MAIN_PARKED.store(false, Ordering::Release);
    WORKER_FINISHED.store(false, Ordering::Release);
    *WORKER_PAGE.lock() = None;

    let (sb, _fs, super_arc) = mount_rw();
    let (_ino, inode, ext2_inode) = fresh_regular(&sb, &super_arc);
    install_aops(&super_arc, &inode, &ext2_inode);

    {
        let mut m = ext2_inode.meta.write();
        m.size = 8 * 1024;
    }
    {
        let mut m = inode.meta.write();
        m.size = 8 * 1024;
    }

    // Two pages: page 0 survives, page 1 is the writeback-in-flight
    // victim. Set PG_WRITEBACK on page 1 BEFORE we hand it to the
    // worker — `truncate_below` must observe the bit and park.
    let _page0 = install_published_page(&inode, 0);
    let page1 = install_published_page(&inode, 1);
    page1.begin_writeback();
    assert!(page1.is_writeback());
    *WORKER_PAGE.lock() = Some(Arc::clone(&page1));

    // Spawn the worker. From this point the worker is spinning on
    // MAIN_PARKED.
    task::spawn(writeback_completion_worker);

    // Tell the worker we're about to park, then descend into setattr.
    // The setattr → Ext2Aops::truncate_below path will:
    //   1. snapshot pages 1.. into a Vec<Arc<CachePage>>
    //   2. drop the cache mutex
    //   3. for each, wait_until_writeback_clear → wait_while
    //
    // Step 3 is where the worker's `end_writeback` reaches us. The
    // worker's hlt-loop delay gives us time to actually enter wait_while
    // and enqueue ourselves before the wake fires.
    MAIN_PARKED.store(true, Ordering::Release);
    let attr = SetAttr {
        mask: SetAttrMask::SIZE,
        size: 4 * 1024,
        ..SetAttr::default()
    };
    inode
        .ops
        .setattr(&inode, &attr)
        .expect("setattr must complete after writeback wake");

    // The worker must have ended writeback (otherwise the main task
    // would still be parked and we wouldn't have reached here). The
    // PG_WRITEBACK bit is cleared, and page 1 has been evicted from
    // the cache index.
    assert!(!page1.is_writeback(), "PG_WRITEBACK cleared by worker");
    let pc = inode.mapping.read().as_ref().map(Arc::clone).unwrap();
    assert!(pc.lookup(0).is_some(), "page 0 survives shrink to 4096");
    assert!(
        pc.lookup(1).is_none(),
        "page 1 must be evicted after the writeback wake"
    );
    assert_eq!(pc.i_size(), 4 * 1024);
    // Sanity: the worker actually ran end_writeback before the assert
    // above; the WORKER_FINISHED flag confirms it (it's set after the
    // wake).
    assert!(
        WORKER_FINISHED.load(Ordering::Acquire),
        "writeback worker must have completed"
    );

    drop(page1);
    drop(_page0);
    drop(inode);
    drop(ext2_inode);
    sb.ops.unmount();
    drop(super_arc);
}
