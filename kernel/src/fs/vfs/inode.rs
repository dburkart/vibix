//! `Inode` — one object per unique file on a mounted filesystem.
//!
//! Identity is `(sb.fs_id, ino)`. The `sb` back-reference is `Weak`
//! to break the SB → Inode → SB reference cycle; every path that
//! needs the SB upgrades the weak and fails with `ENOENT` if the SB
//! has already been torn down.

use alloc::sync::{Arc, Weak};

use crate::sync::{BlockingMutex, BlockingRwLock};

#[cfg(feature = "page_cache")]
use crate::mem::aops::AddressSpaceOps;
#[cfg(feature = "page_cache")]
use crate::mem::page_cache::PageCache;

use super::ops::{FileOps, InodeOps};
use super::super_block::SuperBlock;
use super::Timespec;

/// Enumerated file kind. Packs into `S_IFMT` bits of `st_mode` at
/// `getattr` time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InodeKind {
    Reg,
    Dir,
    Link,
    Chr,
    Blk,
    Fifo,
    Sock,
}

/// Mutable metadata. Separated from the dir-mutation rwsem so that
/// `stat(2)` doesn't serialise against directory modifications.
#[derive(Clone, Copy, Debug, Default)]
pub struct InodeMeta {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub nlink: u32,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub rdev: u64,
    pub blksize: u32,
    pub blocks: u64,
}

/// Lifecycle bookkeeping for an inode. Short-lived lock; no
/// scheduling point is held while inspecting these.
#[derive(Clone, Copy, Debug, Default)]
pub struct InodeState {
    /// `true` once the last link has been removed but the inode still
    /// has open references — POSIX "unlinked but open".
    pub unlinked: bool,
    /// Set when any `setattr`/write path has dirtied the inode since
    /// the last `sync`.
    pub dirty: bool,
    /// Number of `OpenFile` + `path_walk` pins outstanding.
    pub pin_count: u32,
}

/// In-memory representation of a single FS object.
///
/// Constructed by `InodeOps::lookup` / `create` / `mkdir` and
/// published via a [`super::dentry::Dentry`]. Immutable fields live on
/// the struct; mutable state is behind `BlockingRwLock` / `BlockingMutex`.
pub struct Inode {
    pub ino: u64,
    pub sb: Weak<SuperBlock>,
    pub ops: Arc<dyn InodeOps>,
    pub file_ops: Arc<dyn FileOps>,
    /// `i_rwsem` analogue: write-locked by directory mutations,
    /// read-locked by lookup + permission checks during path walk.
    /// Non-directory inodes never acquire it.
    pub dir_rwsem: BlockingRwLock<()>,
    pub meta: BlockingRwLock<InodeMeta>,
    pub state: BlockingMutex<InodeState>,
    pub kind: InodeKind,
    /// Per-inode page cache slot (RFC 0007 §Inode-binding rule).
    ///
    /// Populated lazily on first mmap or first read-via-cache by
    /// [`Inode::page_cache_or_create`]. Once installed, the
    /// `Arc<PageCache>` never changes — the slot is "install-once" for
    /// the inode's lifetime, which is what closes the execve-rename
    /// TOCTOU on `FileObject.cache`: a `FileObject` snapshots this Arc
    /// at open and never re-resolves it, so a rename underneath cannot
    /// silently swap the underlying cache.
    ///
    /// Gated by `feature = "page_cache"` for the migration window
    /// (RFC 0007 §`PageCache`). The field is the only on-Inode owner;
    /// when the inode is dropped, the cache's strong ref drops with
    /// it. The writeback daemon owns weak refs, so the daemon never
    /// pins an inode past its last user-visible reference.
    #[cfg(feature = "page_cache")]
    pub mapping: BlockingRwLock<Option<Arc<PageCache>>>,
    /// Per-FS address-space hook captured at inode publication.
    ///
    /// Backing filesystems that participate in the page cache install
    /// their `AddressSpaceOps` via [`Inode::set_aops`] before the inode
    /// is reachable from userspace. Filesystems that do not yet
    /// participate (e.g. `devfs`, synthetic stubs) leave it `None`;
    /// for those inodes, [`Inode::page_cache_or_create`] returns
    /// `None` and the caller falls back to its non-cache I/O path.
    ///
    /// Once set, the Arc is **never replaced** — this is the
    /// `inode-binding rule` (RFC 0007). The field is wrapped in
    /// `BlockingMutex` solely to make `set_aops` install-once-safe;
    /// reads after install go through the inner `Option` clone with
    /// no locking concern (the discriminant is set once and the Arc
    /// pointee is stable for the inode's lifetime).
    #[cfg(feature = "page_cache")]
    pub aops: BlockingMutex<Option<Arc<dyn AddressSpaceOps>>>,
}

impl Inode {
    pub fn new(
        ino: u64,
        sb: Weak<SuperBlock>,
        ops: Arc<dyn InodeOps>,
        file_ops: Arc<dyn FileOps>,
        kind: InodeKind,
        meta: InodeMeta,
    ) -> Self {
        Self {
            ino,
            sb,
            ops,
            file_ops,
            dir_rwsem: BlockingRwLock::new(()),
            meta: BlockingRwLock::new(meta),
            state: BlockingMutex::new(InodeState::default()),
            kind,
            #[cfg(feature = "page_cache")]
            mapping: BlockingRwLock::new(None),
            #[cfg(feature = "page_cache")]
            aops: BlockingMutex::new(None),
        }
    }

    /// Install the per-FS [`AddressSpaceOps`] hook **once**, before
    /// the inode becomes reachable from userspace. Subsequent calls
    /// are silently ignored — the inode-binding rule (RFC 0007
    /// §Inode-binding rule) forbids rebinding a published inode's
    /// address-space hook.
    ///
    /// Returns `true` if the install happened, `false` if the slot
    /// was already populated. Callers in tests and FS publication
    /// paths can ignore the bool; the only reason to inspect it is
    /// to assert install-once during debug builds.
    #[cfg(feature = "page_cache")]
    pub fn set_aops(&self, ops: Arc<dyn AddressSpaceOps>) -> bool {
        let mut slot = self.aops.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(ops);
        true
    }

    /// Return the inode's page cache, constructing it on first call.
    ///
    /// Implements the install-once discipline of RFC 0007
    /// §Inode-binding rule: every caller observes the *same*
    /// `Arc<PageCache>` for the rest of the inode's life. Concurrent
    /// first-callers race on the write lock; the loser drops its
    /// freshly-built `PageCache` and returns the winner's.
    ///
    /// Returns `None` if the inode has no [`AddressSpaceOps`]
    /// installed via [`Inode::set_aops`] — for such inodes the page
    /// cache is not applicable and the caller (typically the wave-2
    /// `sys_mmap` / `FileOps::mmap` consumers, #746 / #753) must fall
    /// back to a non-cache path.
    ///
    /// Implementation:
    ///
    /// 1. Optimistic read-lock fast path: if `mapping` is already
    ///    `Some`, clone the `Arc` and return.
    /// 2. Otherwise re-check under the write lock (another task may
    ///    have installed it between dropping the read lock and taking
    ///    the write lock); if still `None`, build a fresh `PageCache`
    ///    seeded with the current `i_size` snapshot, the inode's
    ///    `(fs_id, ino)` identity, and a clone of the per-inode
    ///    `Arc<dyn AddressSpaceOps>`. Install it and return the
    ///    clone.
    ///
    /// The cache is bound to the inode's identity at construction
    /// time and is never rebound. If the inode's superblock has
    /// already been torn down (`sb.upgrade()` returns `None`) we use
    /// `fs_id = 0` for the bound identity — the inode is on its way
    /// out via `gc_queue` and the cache will not outlive this Arc.
    ///
    /// Lock order: takes [`Self::mapping`] (level matches the page
    /// cache's level-4 mutex) and, on the install path, briefly takes
    /// [`Self::aops`] inside it to clone the ops Arc. Both locks are
    /// released before any caller-driven I/O.
    #[cfg(feature = "page_cache")]
    pub fn page_cache_or_create(&self) -> Option<Arc<PageCache>> {
        use crate::mem::page_cache::InodeId;

        if let Some(pc) = self.mapping.read().as_ref() {
            return Some(Arc::clone(pc));
        }
        let ops = self.aops.lock().as_ref().map(Arc::clone)?;
        let mut slot = self.mapping.write();
        if let Some(pc) = slot.as_ref() {
            return Some(Arc::clone(pc));
        }
        let fs_id = self.sb.upgrade().map(|sb| sb.fs_id.0).unwrap_or(0);
        let i_size = self.meta.read().size;
        let pc = Arc::new(PageCache::new(InodeId::new(fs_id, self.ino), i_size, ops));
        *slot = Some(Arc::clone(&pc));
        Some(pc)
    }
}

/// Defer eviction so we never call `evict_inode` from inside another
/// VFS lock. The drop fires from contexts like a parent dentry's
/// children-map mutation, where calling back into the FS could
/// re-enter sibling locks. See `super::gc_queue` for the drain sites.
impl Drop for Inode {
    fn drop(&mut self) {
        super::gc_queue::enqueue(self.sb.clone(), self.ino);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::ops::{SetAttr, Stat, StatFs};
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::{FsId, InodeKind};
    use alloc::sync::Arc;

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
    impl super::super::ops::SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) {}
    }

    #[test]
    fn inode_construction_roundtrip() {
        let sb = Arc::new(SuperBlock::new(
            FsId(7),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let ino = Inode::new(
            42,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta {
                mode: 0o644,
                nlink: 1,
                size: 100,
                ..Default::default()
            },
        );
        assert_eq!(ino.ino, 42);
        assert_eq!(ino.meta.read().size, 100);
        assert!(!ino.state.lock().unlinked);
    }

    #[cfg(feature = "page_cache")]
    fn fresh_inode() -> Arc<Inode> {
        let sb = Arc::new(SuperBlock::new(
            FsId(9),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        Arc::new(Inode::new(
            123,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Reg,
            InodeMeta {
                mode: 0o644,
                nlink: 1,
                size: 4096,
                ..Default::default()
            },
        ))
    }

    #[cfg(feature = "page_cache")]
    #[test]
    fn page_cache_or_create_returns_none_without_aops() {
        let inode = fresh_inode();
        assert!(inode.page_cache_or_create().is_none());
        assert!(inode.mapping.read().is_none());
    }

    #[cfg(feature = "page_cache")]
    #[test]
    fn page_cache_or_create_installs_once() {
        let inode = fresh_inode();
        inode.set_aops(crate::mem::aops::tests::fresh_ops());
        let a = inode.page_cache_or_create().expect("aops installed");
        let b = inode.page_cache_or_create().expect("aops installed");
        // Same Arc both calls — not a fresh PageCache on second call.
        assert!(Arc::ptr_eq(&a, &b));
    }

    #[cfg(feature = "page_cache")]
    #[test]
    fn page_cache_starts_empty() {
        let inode = fresh_inode();
        inode.set_aops(crate::mem::aops::tests::fresh_ops());
        assert!(inode.mapping.read().is_none());
        let _ = inode.page_cache_or_create();
        assert!(inode.mapping.read().is_some());
    }

    #[cfg(feature = "page_cache")]
    #[test]
    fn page_cache_seeds_identity_and_size() {
        use core::sync::atomic::Ordering;
        let inode = fresh_inode();
        inode.set_aops(crate::mem::aops::tests::fresh_ops());
        let pc = inode.page_cache_or_create().expect("aops installed");
        assert_eq!(pc.inode_id.fs_id, 9);
        assert_eq!(pc.inode_id.ino, 123);
        assert_eq!(pc.i_size.load(Ordering::Relaxed), 4096);
    }

    #[cfg(feature = "page_cache")]
    #[test]
    fn set_aops_is_install_once() {
        let inode = fresh_inode();
        assert!(inode.set_aops(crate::mem::aops::tests::fresh_ops()));
        // Second install attempt is rejected — inode-binding rule.
        assert!(!inode.set_aops(crate::mem::aops::tests::fresh_ops()));
    }

    #[test]
    fn weak_sb_does_not_cycle() {
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let weak = Arc::downgrade(&sb);
        // Dropping the strong sb drops inode's only SB reference path.
        drop(sb);
        assert!(weak.upgrade().is_none());
    }
}
