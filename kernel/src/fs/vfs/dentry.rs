//! `Dentry` — name-to-Inode cache node. Also the mount-edge carrier.
//!
//! A dentry is the entry point for every path lookup: the `children`
//! map caches name→dentry resolutions for its own inode's directory
//! entries, and the `mount` field (`Some` when this dentry itself is a
//! mount point) redirects traversal into another filesystem.
//!
//! Negative dentries (`inode` is `None`) let the VFS cache
//! "definitely does not exist" results so repeated failing lookups
//! don't hammer the underlying FS.
//!
//! Concurrent first-lookup-of-a-name is serialised by
//! [`ChildState::Loading`]: the first walker inserts a `Loading`
//! holding an `Arc<Semaphore>`; later walkers park on that semaphore
//! and retry when released. See RFC 0002 §Path resolution.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};

use crate::sync::{BlockingRwLock, Semaphore};

use super::inode::Inode;
use super::super_block::SuperBlock;
use super::DString;

/// Per-dentry flags (IS_ROOT, DISCONNECTED, ...). Empty for now;
/// filled out by later RFC 0002 items.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct DFlags(pub u32);

impl DFlags {
    pub const IS_ROOT: DFlags = DFlags(1 << 0);
    pub const DISCONNECTED: DFlags = DFlags(1 << 1);

    pub const fn contains(self, other: DFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for DFlags {
    type Output = DFlags;
    fn bitor(self, rhs: Self) -> Self {
        DFlags(self.0 | rhs.0)
    }
}

/// Per-mount flags. Distinct from [`super::SbFlags`]: these decorate
/// the mount edge, not the filesystem itself (e.g. a read-only bind
/// mount of a read-write FS).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct MountFlags(pub u32);

impl MountFlags {
    pub const RDONLY: MountFlags = MountFlags(1 << 0);
    pub const NOEXEC: MountFlags = MountFlags(1 << 1);
    pub const NOSUID: MountFlags = MountFlags(1 << 2);
    pub const NODEV: MountFlags = MountFlags(1 << 3);

    pub const fn contains(self, other: MountFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for MountFlags {
    type Output = MountFlags;
    fn bitor(self, rhs: Self) -> Self {
        MountFlags(self.0 | rhs.0)
    }
}

/// One edge in the mount graph. Installed on the mountpoint dentry's
/// `mount` slot while holding the mount-table write lock.
pub struct MountEdge {
    pub mountpoint: Weak<Dentry>,
    pub super_block: Arc<SuperBlock>,
    pub root_dentry: Arc<Dentry>,
    pub flags: MountFlags,
}

/// State of a name in a parent's children map.
///
/// `Loading` is a transient synchronisation marker: the first walker
/// for a name publishes `Loading(sem)` before calling
/// `InodeOps::lookup`, later walkers park on `sem.acquire`, and the
/// first walker replaces the entry with `Resolved` or `Negative` and
/// calls `sem.release` for every waiter.
pub enum ChildState {
    Loading(Arc<Semaphore>),
    Negative,
    Resolved(Arc<Dentry>),
}

/// Cached path-component node.
///
/// `parent` is a weak back-edge so a child cannot keep its parent
/// alive. The root dentry is self-parenting, installed via
/// [`Arc::new_cyclic`] at mount time.
pub struct Dentry {
    pub name: DString,
    pub parent: Weak<Dentry>,
    pub inode: BlockingRwLock<Option<Arc<Inode>>>,
    pub mount: BlockingRwLock<Option<Arc<MountEdge>>>,
    pub children: BlockingRwLock<BTreeMap<DString, ChildState>>,
    pub flags: DFlags,
}

impl Dentry {
    /// Construct a non-root dentry with an explicit parent.
    pub fn new(name: DString, parent: Weak<Dentry>, inode: Option<Arc<Inode>>) -> Arc<Self> {
        Arc::new(Self {
            name,
            parent,
            inode: BlockingRwLock::new(inode),
            mount: BlockingRwLock::new(None),
            children: BlockingRwLock::new(BTreeMap::new()),
            flags: DFlags::default(),
        })
    }

    /// Construct the root dentry: self-parenting via `Arc::new_cyclic`.
    /// The name is empty (roots don't have a component name).
    pub fn new_root(inode: Arc<Inode>) -> Arc<Self> {
        Arc::new_cyclic(|weak_self| Self {
            name: DString::try_from_bytes(b"/").unwrap_or_else(|_| unreachable!("'/' is valid")),
            parent: weak_self.clone(),
            inode: BlockingRwLock::new(Some(inode)),
            mount: BlockingRwLock::new(None),
            children: BlockingRwLock::new(BTreeMap::new()),
            flags: DFlags::IS_ROOT,
        })
    }

    /// `true` if `inode` is currently populated (positive dentry).
    pub fn is_positive(&self) -> bool {
        self.inode.read().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        fn unmount(&self) -> Result<(), i64> {
            Ok(())
        }
    }

    fn make_inode() -> Arc<Inode> {
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Dir,
            InodeMeta {
                mode: 0o755,
                nlink: 2,
                ..Default::default()
            },
        ))
    }

    #[test]
    fn root_is_self_parenting() {
        let ino = make_inode();
        let root = Dentry::new_root(ino);
        let parent = root.parent.upgrade().expect("weak to self must upgrade");
        assert!(Arc::ptr_eq(&root, &parent));
        assert!(root.flags.contains(DFlags::IS_ROOT));
        assert!(root.is_positive());
    }

    #[test]
    fn non_root_parent_weak() {
        let ino = make_inode();
        let root = Dentry::new_root(ino.clone());
        let child = Dentry::new(
            DString::try_from_bytes(b"child").unwrap(),
            Arc::downgrade(&root),
            Some(ino),
        );
        assert!(Arc::ptr_eq(
            &root,
            &child.parent.upgrade().expect("parent alive")
        ));
    }

    #[test]
    fn negative_dentry() {
        let root = Dentry::new_root(make_inode());
        let neg = Dentry::new(
            DString::try_from_bytes(b"missing").unwrap(),
            Arc::downgrade(&root),
            None,
        );
        assert!(!neg.is_positive());
    }

    #[test]
    fn mountflags_bitor() {
        let f = MountFlags::RDONLY | MountFlags::NOEXEC;
        assert!(f.contains(MountFlags::RDONLY));
        assert!(f.contains(MountFlags::NOEXEC));
        assert!(!f.contains(MountFlags::NOSUID));
    }
}
