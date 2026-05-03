//! Integration test for issue #755: writeback daemon walks every
//! superblock-mounted inode's `mapping` and calls `writepage` on every
//! dirty `pgoff`.
//!
//! Builds a synthesized `SuperOps` that owns a stable list of
//! `Arc<Inode>`s and exposes them via the `for_each_mapped_inode`
//! trait hook (RFC 0007 §MAP_SHARED writeback, Workstream D).
//! Every inode carries an in-memory [`AddressSpaceOps`] impl
//! (`RecordOps`) whose `writepage` does nothing but record the
//! `(pgoff)` it was called with — the test then asserts the daemon
//! visited every dirty page on every inode after one sweep.
//!
//! Why this shape: ext2's concrete `AddressSpaceOps::writepage` impl
//! is sibling issue #750 and has not landed. The daemon under test
//! calls the trait method; the in-test recorder lets us verify
//! dispatch went through the trait without depending on #750. The
//! daemon's existing buffer-cache flush is unrelated to this walk —
//! it runs first, on an empty cache, and contributes no writepage
//! calls.
//!
//! Coverage:
//!
//! - **Many-inode workload.** 8 inodes × 4 dirty pages each = 32
//!   distinct `writepage` calls, all expected to fire in the first
//!   sweep. Demonstrates the daemon iterates the full inode set
//!   surfaced by `for_each_mapped_inode`, not just the first.
//! - **Snapshot-then-writepage discipline.** The recorder doesn't
//!   need this directly, but the assertion that **every** page lands
//!   per-inode shows the snapshot collected the dirty set under
//!   `cache.inner` and the writepage ran outside the lock without
//!   skipping entries.
//! - **Skip-on-shutdown via `SbActiveGuard`.** A second test sets
//!   `sb.draining = true` before the first sweep and confirms the
//!   daemon exits cleanly without any writepage dispatch — the
//!   `SbActiveGuard::try_acquire` path returns `ENOENT` and the
//!   sweep is skipped (issue #755 bare hook; #760 hardens it).

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use spin::Mutex;

use vibix::block::cache::BlockCache;
use vibix::block::writeback::{self, reset_configured_for_tests};
use vibix::block::BlockDevice;
use vibix::fs::vfs::ops::{StatFs, SuperOps};
use vibix::fs::vfs::super_block::{SbFlags, SuperBlock};
use vibix::fs::vfs::{FsId, Inode, InodeKind, InodeMeta};
use vibix::mem::aops::AddressSpaceOps;
use vibix::mem::page_cache::{InodeId, PageCache, PG_DIRTY};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
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
            "writeback_walks_every_dirty_page_on_every_inode",
            &(walks_every_inode as fn()),
        ),
        (
            "draining_sb_skips_inode_walk",
            &(draining_skips_walk as fn()),
        ),
        (
            "umount_mid_loop_drains_and_joins",
            &(umount_mid_loop_drains_and_joins as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- Helpers --------------------------------------------------------------

#[path = "common/ext2_ramdisk.rs"]
mod ext2_ramdisk;
use ext2_ramdisk::RamDisk;

/// Test stand-in for a real FS-backed `AddressSpaceOps`. Records every
/// `writepage(pgoff, _)` invocation so the assertions below can
/// observe which pages the daemon flushed.
///
/// `readpage` returns zero-fill (the writeback daemon never calls it),
/// `readahead` and `truncate_below` keep the trait defaults — they
/// also never fire on this path.
struct RecordOps {
    writepage_log: Mutex<Vec<u64>>,
    writepage_calls: AtomicU32,
}

impl RecordOps {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            writepage_log: Mutex::new(Vec::new()),
            writepage_calls: AtomicU32::new(0),
        })
    }

    fn calls(&self) -> u32 {
        self.writepage_calls.load(Ordering::Relaxed)
    }

    /// Snapshot of the recorded `pgoff` list, sorted ascending so the
    /// assertions below don't depend on iteration order. The daemon
    /// iterates `cache.dirty` (a `BTreeSet`) so the order *is* sorted
    /// in practice; the explicit sort here documents the contract.
    fn pgoffs_sorted(&self) -> Vec<u64> {
        let mut v = self.writepage_log.lock().clone();
        v.sort();
        v
    }
}

impl AddressSpaceOps for RecordOps {
    fn readpage(&self, _pgoff: u64, _buf: &mut [u8; 4096]) -> Result<usize, i64> {
        // The writeback daemon never calls readpage; treat as
        // unreachable from the surface this test exercises. Returning
        // Ok(0) keeps the test resilient if a future readahead path
        // accidentally fires.
        Ok(0)
    }

    fn writepage(&self, pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
        self.writepage_calls.fetch_add(1, Ordering::Relaxed);
        self.writepage_log.lock().push(pgoff);
        Ok(())
    }
}

/// Synthesized `SuperOps` that owns a stable inode list and surfaces
/// it via [`SuperOps::for_each_mapped_inode`]. Every inode is held by
/// strong `Arc` so the test crate keeps them alive across the sweep
/// without depending on a real FS driver's icache pinning.
struct InodeWalkSuper {
    inodes: Mutex<Vec<Arc<Inode>>>,
}

impl InodeWalkSuper {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inodes: Mutex::new(Vec::new()),
        })
    }

    fn push(&self, inode: Arc<Inode>) {
        self.inodes.lock().push(inode);
    }
}

impl SuperOps for InodeWalkSuper {
    fn root_inode(&self) -> Arc<Inode> {
        unreachable!("InodeWalkSuper::root_inode unused by the writeback daemon")
    }
    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs::default())
    }
    fn unmount(&self) {}
    fn for_each_mapped_inode(&self, cb: &mut dyn FnMut(&Arc<Inode>)) {
        // Snapshot under our own lock, drop the lock, then dispatch
        // the callback. RFC 0007 §Lock-order ladder: the writeback
        // daemon's `cb` will take the per-inode `mapping` mutex, so
        // we must not still be holding any spinlock when it runs.
        let snap: Vec<Arc<Inode>> = {
            let g = self.inodes.lock();
            g.iter().cloned().collect()
        };
        for inode in &snap {
            cb(inode);
        }
    }
}

fn make_sb(ops: Arc<dyn SuperOps>, flags: SbFlags) -> Arc<SuperBlock> {
    Arc::new(SuperBlock::new(
        FsId(0xc0de),
        ops,
        "writeback_inode_walk_test",
        4096,
        flags,
    ))
}

/// Stub `InodeOps` — the inode walk only consults
/// `inode.mapping`; the inode-ops virtual table is irrelevant.
struct StubInodeOps;
impl vibix::fs::vfs::ops::InodeOps for StubInodeOps {
    fn getattr(&self, _inode: &Inode, _out: &mut vibix::fs::vfs::ops::Stat) -> Result<(), i64> {
        Ok(())
    }
}

struct StubFileOps;
impl vibix::fs::vfs::ops::FileOps for StubFileOps {}

/// Build a regular-file inode owned by `sb` with `aops` installed.
/// The inode's `mapping` slot stays empty — the test seeds it
/// explicitly per pgoff via `mark_page_dirty` after constructing a
/// `PageCache` directly so we can put `PG_UPTODATE`-set entries into
/// the index without going through the fault path.
fn make_inode(sb: &Arc<SuperBlock>, ino: u64, aops: Arc<dyn AddressSpaceOps>) -> Arc<Inode> {
    let inode = Arc::new(Inode::new(
        ino,
        Arc::downgrade(sb),
        Arc::new(StubInodeOps),
        Arc::new(StubFileOps),
        InodeKind::Reg,
        InodeMeta {
            mode: 0o644,
            nlink: 1,
            size: 16 * 4096,
            ..Default::default()
        },
    ));
    // Install aops so `page_cache_or_create` returns Some(..). Even
    // though we install the page cache directly below, the install
    // path checks `aops.is_some()` as a precondition for the wave-2
    // mapping API.
    let _ = inode.set_aops(aops.clone());
    // Construct the per-inode PageCache and pre-seed `mapping` with
    // it so the daemon's `inode.mapping.read().as_ref()` snapshot
    // resolves. We do this manually instead of via
    // `page_cache_or_create` because the test populates the cache
    // index directly.
    let pc = Arc::new(PageCache::new(InodeId::new(0xc0de, ino), 16 * 4096, aops));
    *inode.mapping.write() = Some(pc);
    inode
}

/// Allocate a real frame, zero it through the HHDM window so the
/// daemon's HHDM read of `phys` is reading defined bytes (not freshly
/// uninitialised memory), and return the physical address.
fn fresh_frame() -> u64 {
    let phys = vibix::mem::frame::alloc().expect("frame::alloc");
    // SAFETY: `phys` was just handed back by the bitmap allocator
    // with refcount 1; no other task observes it. The HHDM window
    // is RW kernel memory.
    unsafe {
        let hhdm = vibix::mem::paging::hhdm_offset();
        let dst = (hhdm.as_u64() + phys) as *mut u8;
        core::ptr::write_bytes(dst, 0u8, 4096);
    }
    phys
}

/// Insert a page-cache entry at `pgoff` whose backing frame is real
/// HHDM-mapped memory and whose state bits are `PG_UPTODATE`. Calls
/// `mark_page_dirty` so the entry is enrolled in the dirty index.
fn seed_dirty_page(pc: &Arc<PageCache>, pgoff: u64) {
    use vibix::mem::page_cache::CachePage;
    let phys = fresh_frame();
    let page = CachePage::new_locked(phys, pgoff);
    // `new_locked` returns a stub with PG_LOCKED set. Use the public
    // `publish_uptodate_and_unlock` helper to set PG_UPTODATE and
    // clear PG_LOCKED with the correct Release ordering — the same
    // transition the page-fault path's "fill complete" publish does.
    // Direct `state.fetch_*` is `pub(crate)` and not reachable from
    // the integration-test crate.
    page.publish_uptodate_and_unlock();
    {
        let mut inner = pc.inner.lock();
        inner.pages.insert(pgoff, page);
    }
    // Mark dirty *after* the index insert so the dirty-set entry
    // resolves to the page we just inserted.
    assert!(
        pc.mark_page_dirty(pgoff),
        "mark_page_dirty must observe the freshly-inserted entry"
    );
    // Sanity: the per-page bit is set too.
    let p = pc.lookup(pgoff).expect("seeded page must be in index");
    assert!(p.state() & PG_DIRTY != 0, "page must be PG_DIRTY post-mark");
}

// --- Tests ----------------------------------------------------------------

const NUM_INODES: usize = 8;
const PAGES_PER_INODE: u64 = 4;

/// Many-inode workload: every inode's every dirty page must be
/// flushed on the first sweep.
fn walks_every_inode() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);

    // Buffer cache + ramdisk are required for daemon construction
    // even though this test doesn't dirty any block-cache buffers.
    let disk = RamDisk::zeroed(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev = cache.register_device();

    let super_ops = InodeWalkSuper::new();
    let sb = make_sb(super_ops.clone() as Arc<dyn SuperOps>, SbFlags::default());

    // Build NUM_INODES inodes, each with PAGES_PER_INODE dirty pages.
    // Stash each inode's `RecordOps` so the assertions can read its
    // counters.
    let mut recorders: Vec<Arc<RecordOps>> = Vec::with_capacity(NUM_INODES);
    for i in 0..NUM_INODES {
        let rec = RecordOps::new();
        let aops: Arc<dyn AddressSpaceOps> = rec.clone();
        let inode = make_inode(&sb, 100 + i as u64, aops);
        // Seed PAGES_PER_INODE dirty pages.
        let pc = inode
            .mapping
            .read()
            .as_ref()
            .map(Arc::clone)
            .expect("seeded mapping must be Some");
        for pg in 0..PAGES_PER_INODE {
            seed_dirty_page(&pc, pg);
        }
        super_ops.push(inode);
        recorders.push(rec);
    }

    let handle = writeback::start(sb.clone(), cache.clone(), dev)
        .expect("writeback daemon must start for a RW mount");

    // Wait up to ~3 s for at least one sweep to land. Route through
    // the scheduler/IRQ seam (RFC 0005); production resolves to the
    // same `time::ticks()` source.
    let (clock, _irq) = vibix::task::env::env();
    let start_ticks = clock.now().raw();
    let deadline = start_ticks + 300; // 3 s at 100 Hz
    while clock.now().raw() < deadline {
        if handle.sweeps() >= 1 {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert!(
        handle.sweeps() >= 1,
        "writeback daemon never swept — sweeps={} after {} ticks",
        handle.sweeps(),
        clock.now().raw() - start_ticks,
    );

    // Every inode's recorder must have observed every pgoff
    // exactly once. (One sweep, no concurrent dirtiers — the daemon
    // visits each pgoff exactly once and clear_page_dirty empties
    // the set so the second sweep wouldn't re-fire even if the test
    // racers it.)
    let expected: Vec<u64> = (0..PAGES_PER_INODE).collect();
    for (i, rec) in recorders.iter().enumerate() {
        assert!(
            rec.calls() >= PAGES_PER_INODE as u32,
            "inode #{i}: writepage_calls={} < expected {}",
            rec.calls(),
            PAGES_PER_INODE,
        );
        let pgoffs = rec.pgoffs_sorted();
        assert!(
            pgoffs.len() >= expected.len(),
            "inode #{i}: pgoffs={pgoffs:?}, expected at least {expected:?}",
        );
        // The first PAGES_PER_INODE entries must cover [0, PAGES_PER_INODE).
        for (idx, want) in expected.iter().enumerate() {
            assert_eq!(
                pgoffs[idx], *want,
                "inode #{i}: pgoff[{idx}]={} != {want}",
                pgoffs[idx],
            );
        }
    }

    // Post-sweep, the dirty index is empty on every mapping. (The
    // daemon may run additional sweeps in the test window before
    // `join` returns; on each one the dirty set is already empty
    // and the recorder count stays put.)
    let inodes = super_ops.inodes.lock().clone();
    for (i, inode) in inodes.iter().enumerate() {
        let pc = inode
            .mapping
            .read()
            .as_ref()
            .map(Arc::clone)
            .expect("mapping installed");
        let snap = pc.snapshot_dirty();
        assert!(
            snap.is_empty(),
            "inode #{i}: dirty set non-empty after sweep: {} entries",
            snap.len(),
        );
    }

    handle.join();
}

/// `sb.draining = true` set *before* the daemon's first sweep starts
/// must short-circuit: `SbActiveGuard::try_acquire` returns `ENOENT`,
/// the daemon exits cleanly, and no writepage dispatches happen.
fn draining_skips_walk() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);

    let disk = RamDisk::zeroed(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev = cache.register_device();

    let super_ops = InodeWalkSuper::new();
    let sb = make_sb(super_ops.clone() as Arc<dyn SuperOps>, SbFlags::default());

    // One inode, one dirty page — we only need to verify the count
    // stays at zero, not exhaustive-coverage.
    let rec = RecordOps::new();
    let aops: Arc<dyn AddressSpaceOps> = rec.clone();
    let inode = make_inode(&sb, 200, aops);
    let pc = inode
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("seeded mapping must be Some");
    seed_dirty_page(&pc, 0);
    super_ops.push(inode);

    // Set draining *before* `start` so the daemon's first
    // `SbActiveGuard::try_acquire` fails. The daemon then exits
    // cleanly without ever entering the inode walk.
    sb.draining.store(true, Ordering::SeqCst);

    let handle = writeback::start(sb.clone(), cache.clone(), dev)
        .expect("daemon spawn does not consult `draining`");

    // Wait long enough for one cadence interval to pass; the daemon
    // wakes, fails `try_acquire`, exits. We can't assert on
    // `sweeps()` because the daemon never gets to bump it (the
    // increment is after the inode walk, which is gated by the SB
    // guard). Instead, assert that recorder.calls() stays 0.
    let (clock, _irq) = vibix::task::env::env();
    let deadline = clock.now().raw() + 200; // 2 s at 100 Hz
    while clock.now().raw() < deadline {
        x86_64::instructions::hlt();
    }

    assert_eq!(
        rec.calls(),
        0,
        "draining SB must skip inode-walk: writepage_calls={}",
        rec.calls(),
    );

    // The daemon's `try_acquire` failure path returns from
    // `writeback_loop` and `writeback_entry` then publishes
    // `done = true`. `join` is therefore a no-op observer here —
    // call it for symmetry with the other tests.
    handle.join();
}

// --- Issue #760 test ---------------------------------------------------------

/// A `writepage` implementation that sets `sb.draining = true` on its
/// first invocation — simulating `sys_umount` racing the page-cache
/// sweep. Also records call counts so the assertion can verify partial
/// progress.
struct DrainOnFirstWriteOps {
    sb: Arc<SuperBlock>,
    drained: AtomicBool,
    writepage_calls: AtomicU32,
}

impl DrainOnFirstWriteOps {
    fn new(sb: Arc<SuperBlock>) -> Arc<Self> {
        Arc::new(Self {
            sb,
            drained: AtomicBool::new(false),
            writepage_calls: AtomicU32::new(0),
        })
    }

    fn calls(&self) -> u32 {
        self.writepage_calls.load(Ordering::Relaxed)
    }
}

impl AddressSpaceOps for DrainOnFirstWriteOps {
    fn readpage(&self, _pgoff: u64, _buf: &mut [u8; 4096]) -> Result<usize, i64> {
        Ok(0)
    }

    fn writepage(&self, _pgoff: u64, _buf: &[u8; 4096]) -> Result<(), i64> {
        self.writepage_calls.fetch_add(1, Ordering::Relaxed);
        // On the very first call, set draining — the daemon's next
        // per-inode `SbActiveGuard::try_acquire` (issue #760) will
        // observe `ENOENT` and exit the inner loop cleanly.
        if !self.drained.swap(true, Ordering::SeqCst) {
            self.sb.draining.store(true, Ordering::SeqCst);
        }
        Ok(())
    }
}

/// Issue #760: `sb.draining` set *mid-sweep* (via a `writepage` side-
/// effect on inode 0) causes the daemon to exit the inner loop between
/// inodes — the per-inode `SbActiveGuard::try_acquire` returns `ENOENT`
/// and no further `writepage` calls are issued for subsequent inodes.
/// After `join`, the daemon has exited cleanly and the handle is safe
/// to drop.
///
/// The test builds 4 inodes each with 1 dirty page; inode 0 uses
/// `DrainOnFirstWriteOps` which sets `draining` on first writepage.
/// Inodes 1..3 use plain `RecordOps`. The assertion: inode 0's
/// writepage fires (it ran before draining was set); at least one of
/// inodes 1..3 must see zero writepage calls (the daemon exited before
/// reaching it).
const DRAIN_NUM_INODES: usize = 4;

fn umount_mid_loop_drains_and_joins() {
    reset_configured_for_tests();
    writeback::set_configured_secs(1);

    let disk = RamDisk::zeroed(512, 16);
    let cache = BlockCache::new(disk.clone() as Arc<dyn BlockDevice>, 512, 8);
    let dev = cache.register_device();

    let super_ops = InodeWalkSuper::new();
    let sb = make_sb(super_ops.clone() as Arc<dyn SuperOps>, SbFlags::default());

    // Inode 0: sets draining on first writepage.
    let drain_ops = DrainOnFirstWriteOps::new(sb.clone());
    let drain_aops: Arc<dyn AddressSpaceOps> = drain_ops.clone();
    let inode0 = make_inode(&sb, 300, drain_aops);
    let pc0 = inode0
        .mapping
        .read()
        .as_ref()
        .map(Arc::clone)
        .expect("seeded mapping");
    seed_dirty_page(&pc0, 0);
    super_ops.push(inode0);

    // Inodes 1..3: plain recorders.
    let mut recorders: Vec<Arc<RecordOps>> = Vec::with_capacity(DRAIN_NUM_INODES - 1);
    for i in 1..DRAIN_NUM_INODES {
        let rec = RecordOps::new();
        let aops: Arc<dyn AddressSpaceOps> = rec.clone();
        let inode = make_inode(&sb, 300 + i as u64, aops);
        let pc = inode
            .mapping
            .read()
            .as_ref()
            .map(Arc::clone)
            .expect("seeded mapping");
        seed_dirty_page(&pc, 0);
        super_ops.push(inode);
        recorders.push(rec);
    }

    let handle =
        writeback::start(sb.clone(), cache.clone(), dev).expect("daemon must start for RW mount");

    // Wait for the daemon to run; it will process inode 0 (setting
    // draining), then exit the inner loop when the next per-inode
    // SbActiveGuard::try_acquire fails.
    let (clock, _irq) = vibix::task::env::env();
    let deadline = clock.now().raw() + 300; // 3 s at 100 Hz
    while clock.now().raw() < deadline {
        if drain_ops.drained.load(Ordering::SeqCst) {
            break;
        }
        x86_64::instructions::hlt();
    }

    // Inode 0's writepage must have fired (the drain trigger ran
    // from within writepage).
    assert!(
        drain_ops.calls() >= 1,
        "inode 0 writepage must have fired to set draining: calls={}",
        drain_ops.calls(),
    );

    // At least one of the subsequent inodes must NOT have been
    // visited — the per-inode SbActiveGuard::try_acquire returned
    // ENOENT and the daemon exited the inner loop.
    let any_skipped = recorders.iter().any(|r| r.calls() == 0);
    assert!(
        any_skipped,
        "at least one inode after the drain trigger must be skipped; \
         calls: {:?}",
        recorders.iter().map(|r| r.calls()).collect::<Vec<_>>(),
    );

    // The total writepage calls across all inodes must be strictly
    // less than DRAIN_NUM_INODES (one page each). If all fired, the
    // per-inode guard check didn't abort the loop.
    let total: u32 = drain_ops.calls() + recorders.iter().map(|r| r.calls()).sum::<u32>();
    assert!(
        (total as usize) < DRAIN_NUM_INODES,
        "total writepage calls ({total}) must be < {DRAIN_NUM_INODES} \
         (daemon should have exited mid-loop)",
    );

    // `join` must complete — the daemon exited cleanly after
    // `try_acquire` returned ENOENT and `writeback_loop` returned.
    handle.join();
}
