//! `OpenFile` — one per successful `sys_open`.
//!
//! Holds strong references to its dentry, inode, and super-block; the
//! `sb` strong ref is the anchor that closes OS-B6 — an `Inode`
//! cannot outlive its `SuperBlock` while any `OpenFile` on that SB is
//! still live.
//!
//! Separate from the existing `kernel::fs::FileDescription` for now;
//! the bridge between the two lands with RFC 0002 item 14 (fd-table
//! integration).

use alloc::sync::Arc;
use core::mem;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::sync::BlockingMutex;

use super::dentry::Dentry;
use super::inode::Inode;
use super::mount_table::finalize_pending_detach;
use super::ops::FileOps;
use super::super_block::{SbActiveGuard, SuperBlock};

/// Per-open-file state.
pub struct OpenFile {
    pub dentry: Arc<Dentry>,
    pub inode: Arc<Inode>,
    /// Serialises `read`/`write`/`lseek` offset mutation — matches
    /// POSIX "one offset per open file description" semantics.
    pub offset: BlockingMutex<u64>,
    /// Open-file status flags. Interior-mutable so `fcntl(F_SETFL)` can
    /// flip `O_APPEND`/`O_NONBLOCK`/`O_ASYNC` and have the change become
    /// visible to every dup'd fd that shares this `Arc<OpenFile>` — POSIX
    /// requires it. Read on every `write` (for the `O_APPEND` snap-to-EOF
    /// check) with `Relaxed` ordering; the write-path offset mutex already
    /// serialises writers through the same open-file description.
    pub flags: AtomicU32,
    pub ops: Arc<dyn FileOps>,
    pub sb: Arc<SuperBlock>,
    /// errseq snapshot of the inode's page-cache `wb_err` counter,
    /// captured at `open(2)` and re-read by every `fsync(2)` /
    /// `fdatasync(2)` on this `OpenFile`. RFC 0007 §`wb_err` errseq
    /// counter: a sticky `EIO` is surfaced when the cache's counter
    /// has advanced since this snapshot, after which the snapshot is
    /// caught up so subsequent `fsync` calls observe a clean state
    /// (the standard errseq "consume once per witness" semantics).
    ///
    /// Today the `Inode::mapping` field is not yet wired (issue
    /// #745), so [`Inode::wb_err`] returns 0 universally and this
    /// snapshot is always 0. The seam is in place so that when #745
    /// lands, snapshotting the inode's mapping at `open` and
    /// comparing against it on `fsync` becomes a one-line change to
    /// [`Inode::wb_err`] without touching syscall plumbing.
    pub wb_err_snapshot: AtomicU32,
}

impl OpenFile {
    /// Construct an `OpenFile`, converting the syscall-scope
    /// [`SbActiveGuard`] into a long-lived `dentry_pin_count` bump.
    ///
    /// `guard`'s `fetch_add` on `sb_active` would normally be undone
    /// by its `Drop`; `mem::forget`ting it here instead hands ownership
    /// of that pin to this `OpenFile`. To keep `sb_active` honest — it
    /// should only count in-flight syscalls, never long-lived
    /// storage — the constructor immediately `fetch_sub`s it and in the
    /// same motion `fetch_add`s `dentry_pin_count`, which is the
    /// counter that `umount2`'s default busy-check and the
    /// `MNT_DETACH` finalize-gate consult for open files.
    ///
    /// The net effect on `sb_active` is zero, which is correct: the
    /// in-flight syscall that called `open(2)` is about to return to
    /// userspace (its guard scope ends) and there is no further
    /// in-flight work on this SB for this open. The SB stays pinned
    /// by `dentry_pin_count` for the file's lifetime instead.
    /// Implementation of `fsync(2)` / `fdatasync(2)` for this open
    /// file. RFC 0007 §Ordering vs fsync/fdatasync defines the
    /// two-stage flush: page cache first, then the per-mount buffer
    /// cache via `SuperOps::sync_fs`. The `data_only` flag selects
    /// `fdatasync` (today the metadata flush is conservatively kept
    /// as a superset; splitting requires a `sync_fs(data_only)` seam
    /// which is tracked as a follow-up).
    ///
    /// On success, the caller's per-`OpenFile` `wb_err_snapshot` is
    /// caught up to the inode's current `wb_err` value before
    /// returning so the next `fsync` only surfaces failures that
    /// happen *after* this call (errseq "consume once per witness").
    /// On `EIO` from a stale `wb_err`, the snapshot is *also* caught
    /// up — Linux semantics: `fsync` reports the error exactly once
    /// per file description.
    pub fn do_fsync(&self, data_only: bool) -> Result<(), i64> {
        // 1. Driver hook. Concrete filesystems may override
        //    FileOps::fsync to flush their inode metadata or to
        //    invoke an inode-private writeback path; the default
        //    body is `Ok(())`. Filler errors here propagate first so
        //    the buffer-cache fence below isn't issued against a
        //    cache that the driver knows is in an inconsistent
        //    state.
        self.ops.fsync(self, data_only)?;

        // 2. Per-mount BlockCache::sync_fs (or whatever the FS
        //    layered on top of it). For an in-memory filesystem
        //    (ramfs, tarfs, devfs) the default `SuperOps::sync_fs`
        //    body is `Ok(())`; for a block-backed FS the driver
        //    forwards to its `BlockCache::sync_fs(device_id)`.
        //
        //    For `data_only=true` (fdatasync), the RFC calls for
        //    skipping the inode-table flush. We do not currently
        //    have a `sync_fs(data_only)` variant on `SuperOps`;
        //    flushing the full sb is a conservative POSIX-compatible
        //    superset (fdatasync is permitted to flush more than
        //    necessary). Splitting is tracked as a follow-up; see
        //    the issue auto-engineer files for the seam shape.
        self.sb.ops.sync_fs(&self.sb)?;

        // 3. errseq EIO surfacing. Compare the per-file-description
        //    snapshot against the inode's current wb_err counter; if
        //    the counter advanced since `open` (or since the last
        //    fsync that consumed an error), some writeback in the
        //    interval failed. Catch the snapshot up so the next
        //    fsync only sees *new* errors.
        let current = self.inode.wb_err();
        let snapshot = self.wb_err_snapshot.load(Ordering::Acquire);
        if current != snapshot {
            self.wb_err_snapshot.store(current, Ordering::Release);
            return Err(crate::fs::EIO);
        }
        Ok(())
    }

    pub fn new(
        dentry: Arc<Dentry>,
        inode: Arc<Inode>,
        ops: Arc<dyn FileOps>,
        sb: Arc<SuperBlock>,
        flags: u32,
        guard: SbActiveGuard<'_>,
    ) -> Arc<Self> {
        debug_assert!(
            core::ptr::eq(guard.sb() as *const SuperBlock, Arc::as_ptr(&sb)),
            "OpenFile::new: SbActiveGuard must pin the same SuperBlock"
        );
        mem::forget(guard);
        // Hand the guard's pin off to `dentry_pin_count` before any
        // other code observes a zero edge on `sb_active`. Use a single
        // SeqCst fence-ordered pair: bump dentry_pin_count first so
        // any racing umount that reads sb_active==0 also sees a
        // nonzero dentry_pin_count.
        sb.dentry_pin_count.fetch_add(1, Ordering::SeqCst);
        let old = sb.sb_active.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(old > 0, "OpenFile::new: sb_active underflow");
        if old == 1 {
            // The sub drove sb_active to zero; if a lazy-detach was
            // waiting only on us and the new dentry_pin is invisible
            // to its check, the finalize-gate would fire prematurely.
            // finalize_pending_detach re-reads both counters under
            // the PENDING_DETACH mutex and will see dentry_pin_count
            // > 0, so we stay pending. Calling it is still the right
            // thing: it's a no-op when the SB isn't in the pending
            // list.
            finalize_pending_detach(&sb);
        }
        // Snapshot the inode's page-cache wb_err counter at open
        // time. This is what `fsync(2)` will compare against later to
        // surface a sticky EIO; if the counter advanced between open
        // and fsync, some intervening writeback failed and the next
        // fsync caller is the one that learns about it (RFC 0007
        // §`wb_err` errseq counter).
        let wb_err_at_open = inode.wb_err();
        let of = Arc::new(Self {
            dentry,
            inode,
            offset: BlockingMutex::new(0),
            flags: AtomicU32::new(flags),
            ops,
            sb,
            wb_err_snapshot: AtomicU32::new(wb_err_at_open),
        });
        // Fire the driver `open` hook now that the `OpenFile` is fully
        // constructed and the SB pin has been migrated to
        // `dentry_pin_count`. Drivers (ext2) use this to bump a
        // per-open refcount that pairs with the `release` hook below.
        of.ops.open(&of);
        of
    }
}

/// Releases the `dentry_pin_count` pin transferred into
/// [`OpenFile::new`]. If this drops the count to zero, any lazily
/// -detached SB waiting on the pin has its finalizer fire here.
impl Drop for OpenFile {
    fn drop(&mut self) {
        // Driver `release` hook runs BEFORE the SB pin release. ext2's
        // orphan-finalize trigger needs the inode + super still
        // structurally pinned so it can call `finalize_orphan` (which
        // touches the buffer cache, sb_disk, BGDT) without racing the
        // mount teardown. The hook is infallible by trait contract.
        self.ops.release(self);

        let old = self.sb.dentry_pin_count.fetch_sub(1, Ordering::SeqCst);
        debug_assert!(old > 0, "OpenFile::drop: dentry_pin_count underflow");
        if old == 1 {
            finalize_pending_detach(&self.sb);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::Dentry;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::FsId;

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
    struct StubSuper;
    impl SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) {}
    }

    #[test]
    fn open_file_pins_super_block() {
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let inode = Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta::default(),
        ));
        let dentry = Dentry::new_root(inode.clone());
        let file_ops: Arc<dyn FileOps> = Arc::new(StubFile);
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        let of = OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard);
        assert_eq!(sb.sb_active.load(Ordering::SeqCst), 0);
        assert_eq!(sb.dentry_pin_count.load(Ordering::SeqCst), 1);

        // Drop the local strong ref; the OpenFile still pins the SB.
        let weak = Arc::downgrade(&sb);
        drop(sb);
        assert!(weak.upgrade().is_some(), "OpenFile must pin SuperBlock");
        assert_eq!(*of.offset.lock(), 0);
    }

    #[test]
    fn open_file_drop_releases_dentry_pin() {
        let sb = Arc::new(SuperBlock::new(
            FsId(2),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let inode = Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta::default(),
        ));
        let dentry = Dentry::new_root(inode.clone());
        let file_ops: Arc<dyn FileOps> = Arc::new(StubFile);
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        let of = OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard);
        assert_eq!(sb.sb_active.load(Ordering::SeqCst), 0);
        assert_eq!(sb.dentry_pin_count.load(Ordering::SeqCst), 1);
        drop(of);
        assert_eq!(sb.sb_active.load(Ordering::SeqCst), 0);
        assert_eq!(sb.dentry_pin_count.load(Ordering::SeqCst), 0);
    }

    fn build_open_file(sb: Arc<SuperBlock>) -> Arc<OpenFile> {
        let inode = Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta::default(),
        ));
        let dentry = Dentry::new_root(inode.clone());
        let file_ops: Arc<dyn FileOps> = Arc::new(StubFile);
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        OpenFile::new(dentry, inode, file_ops, sb, 0, guard)
    }

    #[test]
    fn do_fsync_default_impl_returns_ok() {
        // RFC 0007: with the default `FileOps::fsync` (Ok) and the
        // default `SuperOps::sync_fs` (Ok), and an inode whose
        // `wb_err()` is universally zero (Inode::mapping not yet
        // wired — issue #745), `do_fsync` is a clean Ok(()) path.
        let sb = Arc::new(SuperBlock::new(
            FsId(3),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let of = build_open_file(sb);
        assert_eq!(of.do_fsync(false), Ok(()));
        assert_eq!(of.do_fsync(true), Ok(()));
    }

    #[test]
    fn do_fsync_repeated_calls_remain_clean() {
        // Stable wb_err snapshot ⇒ no false-positive EIO.
        let sb = Arc::new(SuperBlock::new(
            FsId(4),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let of = build_open_file(sb);
        for _ in 0..10 {
            assert_eq!(of.do_fsync(false), Ok(()));
            assert_eq!(of.do_fsync(true), Ok(()));
        }
    }

    #[test]
    fn wb_err_snapshot_initialised_from_inode() {
        // Forward-compat seam: `OpenFile::new` snapshots
        // `inode.wb_err()` at construction. Today that helper always
        // returns 0; the assertion pins the wiring so a future #745
        // can update `Inode::wb_err` and immediately observe a
        // non-zero snapshot here without having to re-thread anything
        // through OpenFile.
        let sb = Arc::new(SuperBlock::new(
            FsId(5),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let of = build_open_file(sb);
        assert_eq!(of.wb_err_snapshot.load(Ordering::Acquire), 0);
    }

    /// Stub SuperOps whose `sync_fs` simulates a writeback error and
    /// can simulate a `wb_err` advance via a per-instance counter on
    /// the inode. We can't yet reach into a real `PageCache`
    /// (Inode::mapping is #745), so this exercises the syscall-side
    /// errseq logic by overriding `Inode::wb_err` indirectly through
    /// a wrapper SuperOps. Today's `Inode::wb_err()` is hardcoded to
    /// 0, so this test is a placeholder pinning the seam — it will
    /// be filled out by the test added when the mapping field lands.
    #[test]
    fn fsync_propagates_sb_sync_fs_error() {
        struct FailingSuper;
        impl SuperOps for FailingSuper {
            fn root_inode(&self) -> Arc<Inode> {
                unreachable!()
            }
            fn statfs(&self) -> Result<StatFs, i64> {
                Ok(StatFs::default())
            }
            fn sync_fs(&self, _sb: &SuperBlock) -> Result<(), i64> {
                Err(crate::fs::EIO)
            }
            fn unmount(&self) {}
        }
        let sb = Arc::new(SuperBlock::new(
            FsId(6),
            Arc::new(FailingSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let of = build_open_file(sb);
        assert_eq!(of.do_fsync(false), Err(crate::fs::EIO));
        // Same path for fdatasync.
        assert_eq!(of.do_fsync(true), Err(crate::fs::EIO));
    }
}
