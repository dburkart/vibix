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
        Arc::new(Self {
            dentry,
            inode,
            offset: BlockingMutex::new(0),
            flags: AtomicU32::new(flags),
            ops,
            sb,
        })
    }
}

/// Releases the `dentry_pin_count` pin transferred into
/// [`OpenFile::new`]. If this drops the count to zero, any lazily
/// -detached SB waiting on the pin has its finalizer fire here.
impl Drop for OpenFile {
    fn drop(&mut self) {
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
}
