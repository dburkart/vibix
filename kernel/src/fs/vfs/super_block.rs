//! `SuperBlock` — one instance per mounted filesystem.
//!
//! Owns the root inode and brokers every syscall's access to the FS.
//! The `sb_active` counter plus `draining` flag together close the
//! `sys_umount` TOCTOU: a syscall enters via [`SbActiveGuard`] (commit
//! then validate), and unmount commits `draining = true` before
//! checking `sb_active == 0`.

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use spin::Once;

use crate::sync::BlockingMutex;

use super::inode::Inode;
use super::ops::SuperOps;
use super::FsId;

/// Flags stored on a [`SuperBlock`]; a syscall bounces off them before
/// calling into `*Ops`. Matches the Linux `SB_*` subset we need.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct SbFlags(pub u32);

impl SbFlags {
    pub const RDONLY: SbFlags = SbFlags(1 << 0);
    pub const NOEXEC: SbFlags = SbFlags(1 << 1);
    pub const NOSUID: SbFlags = SbFlags(1 << 2);
    pub const NODEV: SbFlags = SbFlags(1 << 3);

    pub const fn contains(self, other: SbFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for SbFlags {
    type Output = SbFlags;
    fn bitor(self, rhs: Self) -> Self {
        SbFlags(self.0 | rhs.0)
    }
}

/// Per-mount filesystem instance.
///
/// `root` is populated by `FileSystem::mount` via
/// [`Once::call_once`]; before that returns the SuperBlock is not yet
/// visible to the rest of the kernel, so the Once can't race.
pub struct SuperBlock {
    pub fs_id: FsId,
    pub ops: Arc<dyn SuperOps>,
    pub fs_type: &'static str,
    pub root: Once<Arc<Inode>>,
    pub block_size: u32,
    pub flags: SbFlags,
    /// Serialises cross-directory rename (`s_vfs_rename_mutex`): the
    /// global tiebreaker that prevents two renames from deadlocking
    /// when they'd each grab the other's directory rwsem.
    pub rename_mutex: BlockingMutex<()>,
    /// In-flight syscall pin count. Incremented by [`SbActiveGuard`];
    /// `sys_umount` Phase A sets `draining = true` then spins on
    /// `sb_active == 0`.
    pub sb_active: AtomicUsize,
    pub draining: AtomicBool,
}

impl SuperBlock {
    pub fn new(
        fs_id: FsId,
        ops: Arc<dyn SuperOps>,
        fs_type: &'static str,
        block_size: u32,
        flags: SbFlags,
    ) -> Self {
        Self {
            fs_id,
            ops,
            fs_type,
            root: Once::new(),
            block_size,
            flags,
            rename_mutex: BlockingMutex::new(()),
            sb_active: AtomicUsize::new(0),
            draining: AtomicBool::new(false),
        }
    }
}

/// RAII pin that a syscall acquires before touching a [`SuperBlock`].
/// Commit-then-validate: bump `sb_active` first, then check
/// `draining`. If unmount racing won, roll back and return `ENOENT`.
pub struct SbActiveGuard<'a> {
    sb: &'a SuperBlock,
}

impl<'a> SbActiveGuard<'a> {
    pub fn try_acquire(sb: &'a SuperBlock) -> Result<Self, i64> {
        sb.sb_active.fetch_add(1, Ordering::SeqCst);
        if sb.draining.load(Ordering::SeqCst) {
            sb.sb_active.fetch_sub(1, Ordering::SeqCst);
            return Err(super::super::ENOENT);
        }
        Ok(Self { sb })
    }

    pub fn sb(&self) -> &'a SuperBlock {
        self.sb
    }
}

impl Drop for SbActiveGuard<'_> {
    fn drop(&mut self) {
        self.sb.sb_active.fetch_sub(1, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::ops::StatFs;
    use crate::fs::vfs::{Inode, InodeKind, InodeMeta, InodeState};
    use alloc::sync::Arc;

    struct StubSuper;
    impl SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!("test stub")
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) -> Result<(), i64> {
            Ok(())
        }
    }

    fn make_sb() -> Arc<SuperBlock> {
        Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            4096,
            SbFlags::default(),
        ))
    }

    #[test]
    fn guard_acquires_and_releases() {
        let sb = make_sb();
        {
            let _g = SbActiveGuard::try_acquire(&sb).expect("acquire");
            assert_eq!(sb.sb_active.load(Ordering::SeqCst), 1);
        }
        assert_eq!(sb.sb_active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn guard_rejects_when_draining() {
        let sb = make_sb();
        sb.draining.store(true, Ordering::SeqCst);
        let r = SbActiveGuard::try_acquire(&sb);
        assert!(r.is_err());
        assert_eq!(sb.sb_active.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn sbflags_bitor_and_contains() {
        let f = SbFlags::RDONLY | SbFlags::NOEXEC;
        assert!(f.contains(SbFlags::RDONLY));
        assert!(f.contains(SbFlags::NOEXEC));
        assert!(!f.contains(SbFlags::NOSUID));
    }

    // Suppress the InodeMeta/InodeState unused-import warning when
    // compiled without the inode tests.
    #[allow(dead_code)]
    fn _types_exist(_m: InodeMeta, _s: InodeState, _k: InodeKind) {}
}
