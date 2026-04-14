//! Global `MountTable` plus `mount` / `unmount` helpers (RFC 0002
//! item 5/15).
//!
//! Owns the namespace's mount graph: a flat `Vec<Arc<MountEdge>>`
//! protected by a single rwlock. Linear scan is fine — RFC 0002 caps
//! the namespace at ≤ 8 mounts in v1.
//!
//! ## Lifetime / safety contract
//!
//! - `mount` runs `FileSystem::mount` outside the table write lock so
//!   the FS driver can park on its own primitives. The cross-side
//!   publish (`MOUNT_TABLE.push` + `mountpoint.mount.write() = Some(..)`)
//!   happens under one critical section so a concurrent walker either
//!   sees both sides or neither.
//!
//! - `unmount` is two-phase to close the umount/syscall TOCTOU
//!   ([`SbActiveGuard`]):
//!     - Phase A (under `MOUNT_TABLE.write()`): take the edge, set
//!       `draining=true`, observe `sb_active==0` (or honour
//!       `MNT_FORCE`), unlink. If the active count is non-zero and
//!       force is off, restore `draining=false`, reinstate the edge,
//!       return `EBUSY`.
//!     - Phase B (no VFS locks held): `gc_drain_for(&sb)` to flush any
//!       pending evictions, then `sb.ops.unmount()`.
//!
//! - The mount table is the only strong-reference holder for a
//!   mounted SB. Phase A keeps `sb` as a local `Arc` for the duration
//!   of Phase B, so `gc_drain_for` and `ops.unmount` see a live SB
//!   even though it has been unlinked from the global table.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use super::dentry::{Dentry, MountEdge, MountFlags};
use super::gc_queue::gc_drain_for;
use super::inode::InodeKind;
use super::ops::{FileSystem, MountSource};
use super::path_walk::MountResolver;
use super::super_block::SuperBlock;
use super::FsId;
use crate::fs::{EBUSY, EINVAL, ENOTDIR};
use crate::sync::BlockingRwLock;

/// Caller-supplied flags to [`unmount`]. Distinct from
/// [`MountFlags`]: those decorate the persistent edge; these gate
/// just the unmount call.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct UmountFlags(pub u32);

impl UmountFlags {
    /// `MNT_FORCE` analogue: tear the mount down even if syscalls are
    /// still pinning it. The in-flight callers will trip the
    /// `draining` flag on their next [`SbActiveGuard::try_acquire`].
    pub const FORCE: UmountFlags = UmountFlags(1 << 0);

    pub const fn contains(self, other: UmountFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for UmountFlags {
    type Output = UmountFlags;
    fn bitor(self, rhs: Self) -> Self {
        UmountFlags(self.0 | rhs.0)
    }
}

/// Global mount-edge list. Flat vector — RFC 0002 caps namespace
/// size at ≤ 8 in v1, so linear scans cost nothing.
pub static MOUNT_TABLE: BlockingRwLock<Vec<Arc<MountEdge>>> = BlockingRwLock::new(Vec::new());

/// Monotonic source of [`FsId`] values. Bumped on every successful
/// `mount`. Wraps after 2^64 mounts (i.e. never).
static NEXT_FS_ID: AtomicU64 = AtomicU64::new(1);

/// Allocate the next unused [`FsId`]. Drivers call this from their
/// `FileSystem::mount` impl when constructing the [`SuperBlock`].
pub fn alloc_fs_id() -> FsId {
    FsId(NEXT_FS_ID.fetch_add(1, Ordering::Relaxed))
}

/// Mount `fs` at `target`. The target must be a positive directory
/// dentry that doesn't already host a mount.
///
/// Calls `FileSystem::mount` *outside* the table write lock so a
/// driver that wants to park (e.g. tarfs reading its byte slice) can
/// do so without blocking unrelated mounts.
pub fn mount(
    source: MountSource<'_>,
    target: &Arc<Dentry>,
    fs: Arc<dyn FileSystem>,
    flags: MountFlags,
) -> Result<Arc<MountEdge>, i64> {
    {
        let inode_slot = target.inode.read();
        let inode = inode_slot.as_ref().ok_or(ENOTDIR)?;
        if inode.kind != InodeKind::Dir {
            return Err(ENOTDIR);
        }
    }

    let sb: Arc<SuperBlock> = fs.mount(source, flags)?;
    let root_inode = sb
        .root
        .get()
        .cloned()
        .unwrap_or_else(|| sb.ops.root_inode());
    let root_dentry = Dentry::new_root(root_inode);
    let edge = Arc::new(MountEdge {
        mountpoint: Arc::downgrade(target),
        super_block: sb,
        root_dentry,
        flags,
    });

    let mut table = MOUNT_TABLE.write();
    {
        let existing = target.mount.read();
        if existing.is_some() {
            return Err(EBUSY);
        }
    }
    table.push(edge.clone());
    *target.mount.write() = Some(edge.clone());
    Ok(edge)
}

/// Unmount the filesystem rooted at `target` (the mountpoint dentry,
/// not the mount's own root). Returns `EINVAL` if `target` doesn't
/// host a mount; `EBUSY` if syscalls still pin the SB and `FORCE`
/// isn't set.
///
/// Phase A acquires the table write lock; Phase B releases it before
/// touching the FS driver.
pub fn unmount(target: &Arc<Dentry>, flags: UmountFlags) -> Result<(), i64> {
    let force = flags.contains(UmountFlags::FORCE);

    let sb = {
        let mut table = MOUNT_TABLE.write();
        let mut edge_slot = target.mount.write();
        let edge = edge_slot.take().ok_or(EINVAL)?;
        let sb = edge.super_block.clone();
        sb.draining.store(true, Ordering::SeqCst);
        let active = sb.sb_active.load(Ordering::SeqCst);
        if active != 0 && !force {
            sb.draining.store(false, Ordering::SeqCst);
            *edge_slot = Some(edge);
            return Err(EBUSY);
        }
        let edge_ptr = Arc::as_ptr(&edge);
        table.retain(|e| !core::ptr::eq(Arc::as_ptr(e), edge_ptr));
        drop(edge_slot);
        drop(table);
        sb
    };

    gc_drain_for(&sb);
    sb.ops.unmount()
}

/// Production [`MountResolver`] backed by [`MOUNT_TABLE`]. `path_walk`
/// uses this in the live kernel; tests still use `NullMountResolver`
/// or a fake that pre-installs edges directly on `Dentry.mount`.
pub struct GlobalMountResolver;

impl MountResolver for GlobalMountResolver {
    fn mount_below(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        d.mount.read().clone()
    }

    fn mount_above(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        let table = MOUNT_TABLE.read();
        for edge in table.iter() {
            if Arc::ptr_eq(&edge.root_dentry, d) {
                return Some(edge.clone());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbActiveGuard, SbFlags};
    use crate::fs::vfs::DString;
    use core::sync::atomic::AtomicUsize;
    use spin::Mutex;

    /// Tests share `MOUNT_TABLE` and `NEXT_FS_ID`; serialise.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    struct StubInode;
    impl InodeOps for StubInode {
        fn getattr(&self, _i: &Inode, _o: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
        fn setattr(&self, _i: &Inode, _a: &SetAttr) -> Result<(), i64> {
            Ok(())
        }
    }
    struct StubFile;
    impl FileOps for StubFile {}

    struct StubSuper {
        unmount_calls: AtomicUsize,
    }
    impl SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<Inode> {
            // Tests pre-populate `sb.root` so this isn't reached.
            unreachable!("root_inode should not be called when sb.root is pre-populated");
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) -> Result<(), i64> {
            self.unmount_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct StubFs {
        ops: Arc<StubSuper>,
        sb_built: Mutex<Option<Arc<SuperBlock>>>,
    }
    impl FileSystem for StubFs {
        fn name(&self) -> &'static str {
            "stub"
        }
        fn mount(
            &self,
            _source: MountSource<'_>,
            _flags: MountFlags,
        ) -> Result<Arc<SuperBlock>, i64> {
            let sb = Arc::new(SuperBlock::new(
                alloc_fs_id(),
                self.ops.clone(),
                "stub",
                512,
                SbFlags::default(),
            ));
            // Populate sb.root with a dir-kind inode so mount() can build
            // a root dentry without touching root_inode().
            let root_ino = Arc::new(Inode::new(
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
            ));
            sb.root.call_once(|| root_ino);
            *self.sb_built.lock() = Some(sb.clone());
            Ok(sb)
        }
    }

    fn make_fs() -> Arc<StubFs> {
        Arc::new(StubFs {
            ops: Arc::new(StubSuper {
                unmount_calls: AtomicUsize::new(0),
            }),
            sb_built: Mutex::new(None),
        })
    }

    fn make_dir_dentry() -> Arc<Dentry> {
        let sb = Arc::new(SuperBlock::new(
            alloc_fs_id(),
            Arc::new(StubSuper {
                unmount_calls: AtomicUsize::new(0),
            }),
            "host",
            512,
            SbFlags::default(),
        ));
        let inode = Arc::new(Inode::new(
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
        ));
        let root = Dentry::new_root(inode);
        // Keep sb alive for the dentry's weak reference path; leak by
        // returning only the dentry — the parent test holds it long
        // enough that the SB is kept by the inode's Weak reference
        // through the test_lock-protected scope.
        core::mem::forget(sb);
        root
    }

    fn drain_table() {
        let mut t = MOUNT_TABLE.write();
        t.clear();
    }

    #[test]
    fn mount_then_unmount_round_trip() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        let edge = mount(
            MountSource::None,
            &target,
            fs.clone(),
            MountFlags::default(),
        )
        .expect("mount");
        assert!(target.mount.read().is_some());
        assert_eq!(MOUNT_TABLE.read().len(), 1);
        assert!(Arc::ptr_eq(
            &edge.super_block,
            fs.sb_built.lock().as_ref().unwrap()
        ));

        unmount(&target, UmountFlags::default()).expect("unmount");
        assert!(target.mount.read().is_none());
        assert_eq!(MOUNT_TABLE.read().len(), 0);
        assert_eq!(fs.ops.unmount_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn double_mount_returns_ebusy() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs1 = make_fs();
        mount(MountSource::None, &target, fs1, MountFlags::default()).expect("first mount");
        let fs2 = make_fs();
        let r = mount(MountSource::None, &target, fs2, MountFlags::default());
        assert_eq!(r.err(), Some(EBUSY));
    }

    #[test]
    fn unmount_with_active_guard_returns_ebusy_and_restores() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        let edge = mount(
            MountSource::None,
            &target,
            fs.clone(),
            MountFlags::default(),
        )
        .expect("mount");
        // Pin the SB via SbActiveGuard, simulating an in-flight syscall.
        let _guard = SbActiveGuard::try_acquire(&edge.super_block).expect("guard");

        let r = unmount(&target, UmountFlags::default());
        assert_eq!(r.err(), Some(EBUSY));
        // Edge restored, draining cleared, table still has the entry.
        assert!(target.mount.read().is_some());
        assert!(!edge.super_block.draining.load(Ordering::SeqCst));
        assert_eq!(MOUNT_TABLE.read().len(), 1);
    }

    #[test]
    fn unmount_force_bypasses_active_check() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        let edge = mount(
            MountSource::None,
            &target,
            fs.clone(),
            MountFlags::default(),
        )
        .expect("mount");
        let _guard = SbActiveGuard::try_acquire(&edge.super_block).expect("guard");
        unmount(&target, UmountFlags::FORCE).expect("force unmount");
        assert!(target.mount.read().is_none());
        assert_eq!(fs.ops.unmount_calls.load(Ordering::SeqCst), 1);
        // The guard is still held — its Drop will decrement after unmount,
        // but draining is set so any new try_acquire would fail.
        assert!(edge.super_block.draining.load(Ordering::SeqCst));
    }

    #[test]
    fn draining_blocks_new_guards_after_phase_a() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        let edge = mount(MountSource::None, &target, fs, MountFlags::default()).expect("mount");
        let sb = edge.super_block.clone();
        unmount(&target, UmountFlags::default()).expect("unmount");
        let r = SbActiveGuard::try_acquire(&sb);
        assert!(r.is_err(), "guard must fail after unmount sets draining");
    }

    #[test]
    fn unmount_of_unmounted_dentry_returns_einval() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let r = unmount(&target, UmountFlags::default());
        assert_eq!(r.err(), Some(EINVAL));
    }

    #[test]
    fn global_resolver_round_trip() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        let edge = mount(MountSource::None, &target, fs, MountFlags::default()).expect("mount");
        let resolver = GlobalMountResolver;
        // mount_below: from mountpoint dentry to the new mount edge.
        let below = resolver.mount_below(&target).expect("mount_below");
        assert!(Arc::ptr_eq(&below, &edge));
        // mount_above: from the new mount's root dentry back to the edge.
        let above = resolver
            .mount_above(&edge.root_dentry)
            .expect("mount_above");
        assert!(Arc::ptr_eq(&above, &edge));
        // Cleanup so subsequent tests aren't polluted.
        unmount(&target, UmountFlags::default()).expect("unmount");
    }

    #[allow(dead_code)]
    fn _touch(_: DString) {}
}
