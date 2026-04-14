//! Deferred-eviction GC queue (RFC 0002 item 3/15).
//!
//! `Drop for Inode` enqueues `(sb, ino)` rather than calling
//! `evict_inode` inline. Eviction runs at well-defined drain points
//! (syscall-return, idle task, `sys_umount` Phase B) with no VFS locks
//! held. This closes [OS-B3]: an inline `evict_inode` invoked from
//! `Drop` could re-enter sibling locks (e.g. the parent dentry's
//! `children` rwlock that triggered the Arc replacement).
//!
//! ## Single global queue
//!
//! RFC 0002 calls for a per-CPU ring; v1 uses one global
//! [`spin::Mutex`]-protected queue. The kernel has no per-CPU
//! infrastructure today and building it for GC alone is scope creep.
//! Follow-up issue captures the per-CPU upgrade.
//!
//! ## Why `spin::Mutex` (not `BlockingMutex`)
//!
//! `Inode::drop` may run while sibling [`crate::sync::BlockingRwLock`]s
//! are held; a sleeping primitive would risk re-entry into the
//! scheduler with locks held. The queue lock is held only across O(1)
//! push/pop, never across `evict_inode`.

use alloc::collections::VecDeque;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use spin::Mutex;

use super::super_block::SuperBlock;

/// Soft cap on the inline ring portion of the queue. Past this we
/// spill into a heap `VecDeque` rather than panic or leak — the cost
/// of a transient allocation is preferable to losing eviction work.
const GC_RING_CAP: usize = 256;

/// One pending eviction. `sb` is `Weak` so a queued entry doesn't keep
/// the SuperBlock alive past its own teardown; the drainer treats a
/// failed upgrade as "already gone, skip."
struct GcEntry {
    sb: Weak<SuperBlock>,
    ino: u64,
}

/// Backing storage. `VecDeque` because we want FIFO semantics with
/// O(1) push/pop on both ends.
struct GcRing {
    entries: VecDeque<GcEntry>,
}

impl GcRing {
    const fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }
}

static GC_QUEUE: Mutex<GcRing> = Mutex::new(GcRing::new());

/// Diagnostic counter: bumped each time a push grew the queue past
/// [`GC_RING_CAP`]. Useful for spotting drain-pressure regressions.
static GC_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

/// Set while the global drainer is running. New `enqueue` calls (from
/// `evict_inode` itself dropping more inodes) still succeed, and the
/// drainer re-checks the queue after each eviction.
static DRAINING: AtomicBool = AtomicBool::new(false);

/// Enqueue an inode for deferred eviction. Called from `Drop for
/// Inode`; must not block, must not re-enter VFS locks, must not
/// allocate beyond the spill `VecDeque` push.
pub(crate) fn enqueue(sb: Weak<SuperBlock>, ino: u64) {
    let mut q = GC_QUEUE.lock();
    if q.entries.len() >= GC_RING_CAP {
        GC_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
    q.entries.push_back(GcEntry { sb, ino });
}

/// Pop one entry, releasing the queue lock before the caller touches
/// it. Separate from [`gc_drain`] so the drainer never holds the
/// queue lock across `evict_inode`.
fn pop_one() -> Option<GcEntry> {
    GC_QUEUE.lock().entries.pop_front()
}

/// Drain all pending evictions. Safe to call from any task-context
/// site that holds no VFS locks. Re-entrant: an eviction that itself
/// drops more inodes adds to the queue, and the loop picks them up on
/// the next iteration.
pub fn gc_drain() {
    DRAINING.store(true, Ordering::Release);
    while let Some(entry) = pop_one() {
        if let Some(sb) = entry.sb.upgrade() {
            // Errors from evict_inode are advisory — there's no
            // sensible fallback this late in the lifecycle.
            let _ = sb.ops.evict_inode(entry.ino);
        }
    }
    DRAINING.store(false, Ordering::Release);
}

/// Drain only entries whose SuperBlock matches `sb`. Used by
/// `sys_umount` Phase B before calling `ops.unmount` so the FS sees
/// no pending evictions.
///
/// Walks the queue once, partitioning matched entries out. Unmatched
/// entries are written back in original order.
pub fn gc_drain_for(sb: &Arc<SuperBlock>) {
    let target = sb.fs_id;
    let mut to_evict: VecDeque<GcEntry> = VecDeque::new();
    {
        let mut q = GC_QUEUE.lock();
        let mut keep: VecDeque<GcEntry> = VecDeque::with_capacity(q.entries.len());
        while let Some(entry) = q.entries.pop_front() {
            match entry.sb.upgrade() {
                Some(entry_sb) if entry_sb.fs_id == target => to_evict.push_back(entry),
                _ => keep.push_back(entry),
            }
        }
        q.entries = keep;
    }
    for entry in to_evict {
        let _ = sb.ops.evict_inode(entry.ino);
    }
}

/// Number of pending entries. For tests and metrics; not for control
/// flow (the count can change between observation and use).
pub fn gc_pending_count() -> usize {
    GC_QUEUE.lock().entries.len()
}

/// Total number of pushes that found the queue at or above
/// [`GC_RING_CAP`]. Monotonic.
pub fn gc_overflow_count() -> u64 {
    GC_OVERFLOWS.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::{DString, Dentry, FsId};
    use core::sync::atomic::AtomicUsize;

    /// SuperOps stub that records evict_inode calls. Tests share the
    /// queue (it's static), so each test drains at start and end to
    /// stay isolated.
    struct CountingSuper {
        evicted: AtomicUsize,
    }
    impl SuperOps for CountingSuper {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) -> Result<(), i64> {
            Ok(())
        }
        fn evict_inode(&self, _ino: u64) -> Result<(), i64> {
            self.evicted.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct StubInode;
    impl InodeOps for StubInode {
        fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
        fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
            Ok(())
        }
    }
    struct StubFile;
    impl FileOps for StubFile {}

    fn drain_static_queue() {
        gc_drain();
    }

    fn make_sb(fs_id: u64) -> (Arc<SuperBlock>, Arc<CountingSuper>) {
        let ops = Arc::new(CountingSuper {
            evicted: AtomicUsize::new(0),
        });
        let sb = Arc::new(SuperBlock::new(
            FsId(fs_id),
            ops.clone(),
            "stub",
            512,
            SbFlags::default(),
        ));
        (sb, ops)
    }

    fn make_inode(sb: &Arc<SuperBlock>, ino: u64) -> Arc<Inode> {
        Arc::new(Inode::new(
            ino,
            Arc::downgrade(sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta {
                mode: 0o644,
                nlink: 1,
                ..Default::default()
            },
        ))
    }

    #[test]
    fn enqueue_push_pop_fifo() {
        drain_static_queue();
        let (sb, _ops) = make_sb(101);
        enqueue(Arc::downgrade(&sb), 1);
        enqueue(Arc::downgrade(&sb), 2);
        enqueue(Arc::downgrade(&sb), 3);
        assert_eq!(gc_pending_count(), 3);
        let a = pop_one().unwrap();
        let b = pop_one().unwrap();
        let c = pop_one().unwrap();
        assert_eq!((a.ino, b.ino, c.ino), (1, 2, 3));
        assert!(pop_one().is_none());
    }

    #[test]
    fn drop_inode_enqueues_not_inline() {
        drain_static_queue();
        let (sb, ops) = make_sb(102);
        let ino = make_inode(&sb, 42);
        let pending_before = gc_pending_count();
        drop(ino);
        // evict_inode must not have run yet — push only.
        assert_eq!(ops.evicted.load(Ordering::SeqCst), 0);
        assert_eq!(gc_pending_count(), pending_before + 1);
        gc_drain();
        assert_eq!(ops.evicted.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn nested_drop_under_parent_children_lock() {
        drain_static_queue();
        let (sb, _ops) = make_sb(103);
        let parent_ino = make_inode(&sb, 1);
        let parent = Dentry::new_root(parent_ino);
        let child_ino = make_inode(&sb, 2);
        // Hold the parent's children rwlock — would have deadlocked
        // if Inode::drop tried to call evict_inode inline (which can
        // grab sibling locks via the FS implementation).
        let _children_guard = parent.children.write();
        let pending_before = gc_pending_count();
        drop(child_ino);
        assert_eq!(gc_pending_count(), pending_before + 1);
        // Lock still held; no deadlock proves the deferral.
        drop(_children_guard);
        gc_drain();
    }

    #[test]
    fn gc_drain_for_filters_by_fs_id() {
        drain_static_queue();
        let (sb_a, ops_a) = make_sb(200);
        let (sb_b, ops_b) = make_sb(201);
        enqueue(Arc::downgrade(&sb_a), 10);
        enqueue(Arc::downgrade(&sb_b), 20);
        enqueue(Arc::downgrade(&sb_a), 11);
        enqueue(Arc::downgrade(&sb_b), 21);
        gc_drain_for(&sb_a);
        assert_eq!(ops_a.evicted.load(Ordering::SeqCst), 2);
        assert_eq!(ops_b.evicted.load(Ordering::SeqCst), 0);
        assert_eq!(gc_pending_count(), 2);
        gc_drain_for(&sb_b);
        assert_eq!(ops_b.evicted.load(Ordering::SeqCst), 2);
        assert_eq!(gc_pending_count(), 0);
    }

    #[test]
    fn overflow_counter_increments_past_cap() {
        drain_static_queue();
        let baseline = gc_overflow_count();
        let (sb, ops) = make_sb(300);
        for i in 0..(GC_RING_CAP + 5) {
            enqueue(Arc::downgrade(&sb), i as u64);
        }
        let after = gc_overflow_count();
        assert!(after >= baseline + 5, "overflow counter must rise past cap");
        gc_drain();
        // Every enqueued entry must have been evicted; nothing was lost.
        assert_eq!(
            ops.evicted.load(Ordering::SeqCst),
            GC_RING_CAP + 5,
            "spill path must not lose entries"
        );
    }

    #[test]
    fn weak_sb_dropped_entries_are_discarded() {
        drain_static_queue();
        let (sb, ops) = make_sb(400);
        let weak = Arc::downgrade(&sb);
        enqueue(weak, 99);
        // Drop the SB; the queue still holds a Weak which now upgrades to None.
        drop(sb);
        // No panic, no eviction call (ops Arc kept alive through the
        // SuperOps Arc inside SuperBlock — but SB is gone).
        gc_drain();
        // ops Arc was kept alive by our own clone; assert no spurious call.
        assert_eq!(ops.evicted.load(Ordering::SeqCst), 0);
        assert_eq!(gc_pending_count(), 0);
    }

    /// `DString` is unused in this file outside this dummy referent;
    /// silence the unused-import lint that would otherwise fire when
    /// the `Dentry` API changes shape.
    #[allow(dead_code)]
    fn _touch_dstring(_d: DString) {}
}
