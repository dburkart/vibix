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

use crate::sync::BlockingMutex;

use super::dentry::Dentry;
use super::inode::Inode;
use super::ops::FileOps;
use super::super_block::SuperBlock;

/// Per-open-file state.
pub struct OpenFile {
    pub dentry: Arc<Dentry>,
    pub inode: Arc<Inode>,
    /// Serialises `read`/`write`/`lseek` offset mutation — matches
    /// POSIX "one offset per open file description" semantics.
    pub offset: BlockingMutex<u64>,
    pub flags: u32,
    pub ops: Arc<dyn FileOps>,
    pub sb: Arc<SuperBlock>,
}

impl OpenFile {
    pub fn new(
        dentry: Arc<Dentry>,
        inode: Arc<Inode>,
        ops: Arc<dyn FileOps>,
        sb: Arc<SuperBlock>,
        flags: u32,
    ) -> Arc<Self> {
        Arc::new(Self {
            dentry,
            inode,
            offset: BlockingMutex::new(0),
            flags,
            ops,
            sb,
        })
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
        fn unmount(&self) -> Result<(), i64> {
            Ok(())
        }
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
        let of = OpenFile::new(dentry, inode, file_ops, sb.clone(), 0);

        // Drop the local strong ref; the OpenFile still pins the SB.
        let weak = Arc::downgrade(&sb);
        drop(sb);
        assert!(weak.upgrade().is_some(), "OpenFile must pin SuperBlock");
        assert_eq!(*of.offset.lock(), 0);
    }
}
