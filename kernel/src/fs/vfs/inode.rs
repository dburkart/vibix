//! `Inode` — one object per unique file on a mounted filesystem.
//!
//! Identity is `(sb.fs_id, ino)`. The `sb` back-reference is `Weak`
//! to break the SB → Inode → SB reference cycle; every path that
//! needs the SB upgrades the weak and fails with `ENOENT` if the SB
//! has already been torn down.

use alloc::sync::{Arc, Weak};

use crate::sync::{BlockingMutex, BlockingRwLock};

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
        }
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
