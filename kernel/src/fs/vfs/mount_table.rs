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
//!     - Phase A (under `MOUNT_TABLE.write()`): take the edge,
//!       pre-check `sb_active==0` *before* publishing `draining=true`
//!       so racing callers don't see a transient drain we'll roll
//!       back; set `draining=true`; re-check `sb_active==0` (or
//!       honour `MNT_FORCE`/`MNT_DETACH`) to close the zero->one
//!       window; unlink. If either check fails and force/detach are
//!       off, clear `draining` (if set), reinstate the edge, return
//!       `EBUSY`. `MNT_FORCE` additionally refuses if a nested
//!       child mount still pins this SB (EBUSY).
//!     - Phase B (no VFS locks held): `gc_drain_for(&sb)` to flush any
//!       pending evictions, then `sb.ops.sync_fs` + `sb.ops.unmount()`.
//!       For `MNT_DETACH`, Phase B is deferred: the `Arc<SuperBlock>`
//!       is stashed in `PENDING_DETACH` and the finalizer runs from
//!       [`SbActiveGuard::drop`] when the last guard releases.
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
use crate::sync::{BlockingMutex, BlockingRwLock};

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
    ///
    /// Per the umount2(2) contract, `MNT_FORCE` is refused with
    /// `-EBUSY` on mounts that still have nested (child) mounts — the
    /// caller must tear those down first, either by direct umount or
    /// by using [`DETACH`](Self::DETACH) below.
    pub const FORCE: UmountFlags = UmountFlags(1 << 0);

    /// `MNT_DETACH` analogue: lazy unmount. Unlink the mount from the
    /// namespace now so no new syscalls can enter, but defer
    /// `sync_fs` + `SuperOps::unmount` until the last in-flight
    /// [`SbActiveGuard`] drops. In-flight I/O completes normally
    /// instead of being aborted.
    pub const DETACH: UmountFlags = UmountFlags(1 << 1);

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

    let publish_result = {
        let mut table = MOUNT_TABLE.write();
        let existing = target.mount.read();
        if existing.is_some() {
            Err(())
        } else {
            drop(existing);
            table.push(edge.clone());
            *target.mount.write() = Some(edge.clone());
            Ok(())
        }
    };
    match publish_result {
        Ok(()) => Ok(edge),
        Err(()) => {
            // Lost the mountpoint race after fs.mount() already succeeded.
            // Tear down the freshly-built SB so the driver can release any
            // state it allocated; drop happens with no VFS locks held.
            let sb = edge.super_block.clone();
            drop(edge);
            sb.ops.unmount();
            Err(EBUSY)
        }
    }
}

/// Global list of super-blocks whose mount edge has been detached
/// lazily (`MNT_DETACH`) and whose final `sync_fs` + `ops.unmount()`
/// must fire when their last [`SbActiveGuard`] drops. Owning the
/// `Arc<SuperBlock>` here keeps the driver state alive across the
/// interval between detach and the last guard drop, and is the only
/// anchor that holds an `Arc` reference to a detached SB.
///
/// Contention is trivial: entries are pushed at most once per
/// successful umount2 call, and drained inside
/// [`finalize_pending_detach`] which is called by
/// `SbActiveGuard::drop`.
static PENDING_DETACH: BlockingMutex<Vec<Arc<SuperBlock>>> = BlockingMutex::new(Vec::new());

/// Return true if any edge in `MOUNT_TABLE` is mounted on a dentry
/// that belongs to `sb`'s subtree — i.e. `sb` has a nested child
/// mount. Used by the umount2 path to refuse `MNT_FORCE` when a
/// child mount pins the parent (RFC 0004 §Forced unmount).
///
/// Walks the mount table under its read lock and inspects each
/// edge's mountpoint dentry; a dentry whose inode's superblock
/// matches `sb` is, by construction, a path inside `sb`. The
/// candidate edge itself is excluded via pointer identity.
fn has_child_mounts(
    table: &[Arc<MountEdge>],
    self_edge: &Arc<MountEdge>,
    sb: &Arc<SuperBlock>,
) -> bool {
    let self_ptr = Arc::as_ptr(self_edge);
    for edge in table.iter() {
        if core::ptr::eq(Arc::as_ptr(edge), self_ptr) {
            continue;
        }
        let Some(mp) = edge.mountpoint.upgrade() else {
            continue;
        };
        let inode_slot = mp.inode.read();
        if let Some(inode) = inode_slot.as_ref() {
            if let Some(other_sb) = inode.sb.upgrade() {
                if Arc::ptr_eq(&other_sb, sb) {
                    return true;
                }
            }
        }
    }
    false
}

/// Drain the Phase-B work for an SB: `gc_drain_for` + `sync_fs` +
/// `ops.unmount`. Always returns `Ok(())` — driver errors from
/// `sync_fs` are logged and absorbed (matches the
/// `SuperOps::unmount` infallibility contract).
fn finalize_detach(sb: &Arc<SuperBlock>) {
    gc_drain_for(sb);
    if let Err(errno) = sb.ops.sync_fs(sb) {
        crate::serial_println!(
            "vfs: sync_fs failed during unmount ({}): errno={}",
            sb.fs_type,
            errno,
        );
    }
    sb.ops.unmount();
}

/// Run the deferred finalizer for any lazily-detached SB whose last
/// [`SbActiveGuard`] has just dropped. Called from the guard's
/// `Drop` impl after it decrements `sb_active`.
///
/// Lifts entries out of [`PENDING_DETACH`] under the mutex, then
/// drops the lock before calling `ops.unmount` — driver impls must
/// not be run under a VFS-internal lock.
pub(super) fn finalize_pending_detach(sb: &SuperBlock) {
    // Fast path: nothing pending at all.
    let mut ready: Vec<Arc<SuperBlock>> = Vec::new();
    {
        let mut pending = PENDING_DETACH.lock();
        if pending.is_empty() {
            return;
        }
        let sb_ptr: *const SuperBlock = sb;
        let mut i = 0;
        while i < pending.len() {
            let entry_ptr: *const SuperBlock = &*pending[i];
            if core::ptr::eq(entry_ptr, sb_ptr) && pending[i].sb_active.load(Ordering::SeqCst) == 0
            {
                ready.push(pending.swap_remove(i));
            } else {
                i += 1;
            }
        }
    }
    for sb in ready {
        finalize_detach(&sb);
    }
}

/// Unmount the filesystem rooted at `target` (the mountpoint dentry,
/// not the mount's own root).
///
/// Returns:
/// - `EINVAL` if `target` doesn't host a mount.
/// - `EBUSY` (default flags) if any syscall still pins the SB.
/// - `EBUSY` (`MNT_FORCE`) if the mount has a nested child mount —
///   the caller must tear those down first.
///
/// Flag semantics (mirror Linux umount2(2)):
/// - Default (`flags == 0`): strict busy check. EBUSY if `sb_active`
///   is nonzero at phase-A commit.
/// - [`UmountFlags::FORCE`]: bypass the busy check for in-flight
///   syscalls (they observe `draining` and error out), but *refuse*
///   if any nested child mount still pins this SB. `sync_fs` +
///   `ops.unmount` run synchronously.
/// - [`UmountFlags::DETACH`]: always succeeds at detach (no busy
///   check, no nested-mount refusal). Unlinks from the mount table
///   and dentry right away so no new path walk can enter. The
///   Phase-B finalize (`sync_fs` + `ops.unmount`) is deferred until
///   the last active [`SbActiveGuard`] drops, giving in-flight I/O a
///   chance to complete normally.
///
/// Phase A acquires the table write lock; Phase B releases it before
/// touching the FS driver.
pub fn unmount(target: &Arc<Dentry>, flags: UmountFlags) -> Result<(), i64> {
    let force = flags.contains(UmountFlags::FORCE);
    let detach = flags.contains(UmountFlags::DETACH);

    let (sb, defer_finalize) = {
        let mut table = MOUNT_TABLE.write();
        let mut edge_slot = target.mount.write();
        let edge = edge_slot.take().ok_or(EINVAL)?;
        let sb = edge.super_block.clone();

        // Nested-mount refusal for MNT_FORCE: forcing a tear-down
        // with a child mount still pinning the parent would strand
        // the child on top of a torn-down SB. DETACH explicitly
        // opts out of this check — the child mount's own Arc chain
        // keeps its SB alive past the parent's detach.
        if force && !detach && has_child_mounts(&table, &edge, &sb) {
            *edge_slot = Some(edge);
            return Err(EBUSY);
        }

        // Default-flag busy check: a single two-phase commit around
        // the `draining` flag closes the zero->one window.
        if !force && !detach {
            // Pre-check sb_active before publishing `draining=true`,
            // so racing SbActiveGuard::try_acquire callers don't
            // observe a transient drain we'd roll back.
            if sb.sb_active.load(Ordering::SeqCst) != 0 {
                *edge_slot = Some(edge);
                return Err(EBUSY);
            }
            sb.draining.store(true, Ordering::SeqCst);
            if sb.sb_active.load(Ordering::SeqCst) != 0 {
                sb.draining.store(false, Ordering::SeqCst);
                *edge_slot = Some(edge);
                return Err(EBUSY);
            }
        } else {
            // FORCE or DETACH: publish draining unconditionally so
            // no *new* guards enter after we unlink the edge. FORCE
            // relies on in-flight guards erroring out on their
            // next VFS entry; DETACH waits for them to drain.
            sb.draining.store(true, Ordering::SeqCst);
        }

        let edge_ptr = Arc::as_ptr(&edge);
        table.retain(|e| !core::ptr::eq(Arc::as_ptr(e), edge_ptr));
        drop(edge_slot);
        drop(table);

        // Decide finalize path: DETACH defers if any guard still
        // holds the SB; every other path runs Phase B inline.
        let defer = detach && sb.sb_active.load(Ordering::SeqCst) != 0;
        if defer {
            PENDING_DETACH.lock().push(sb.clone());
        }
        (sb, defer)
    };

    if defer_finalize {
        // Race window: a guard may have dropped to zero between our
        // `defer` check and the push above. Re-check and finalize
        // inline if so; otherwise the guard's Drop will run it.
        // `finalize_pending_detach` will pop the entry and run the
        // finalizer exactly once.
        if sb.sb_active.load(Ordering::SeqCst) == 0 {
            finalize_pending_detach(&sb);
        }
    } else {
        finalize_detach(&sb);
    }
    Ok(())
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
        fn unmount(&self) {
            self.unmount_calls.fetch_add(1, Ordering::SeqCst);
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

    /// Verify that `ops.unmount()` is called during Phase B even when the
    /// caller has no way to propagate a driver error — the detach is
    /// unconditional and the VFS always returns `Ok(())` from Phase B.
    #[test]
    fn phase_b_detach_is_unconditional() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        mount(
            MountSource::None,
            &target,
            fs.clone(),
            MountFlags::default(),
        )
        .expect("mount");

        // Unmount must succeed and ops.unmount must have been called once.
        let result = unmount(&target, UmountFlags::default());
        assert_eq!(result, Ok(()), "unmount must return Ok(()) from Phase B");
        assert!(
            target.mount.read().is_none(),
            "mount edge must be gone after unmount"
        );
        assert_eq!(
            MOUNT_TABLE.read().len(),
            0,
            "table must be empty after unmount"
        );
        assert_eq!(
            fs.ops.unmount_calls.load(Ordering::SeqCst),
            1,
            "ops.unmount must be called exactly once"
        );
    }

    #[allow(dead_code)]
    fn _touch(_: DString) {}

    // -----------------------------------------------------------------
    // umount2 flag-surface tests (issue #576).
    // -----------------------------------------------------------------

    /// `MNT_DETACH` with an in-flight guard must succeed at the
    /// detach step (mount table / dentry edge both cleared) but
    /// defer `ops.unmount` until the guard drops.
    #[test]
    fn detach_defers_ops_unmount_until_guard_drops() {
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
        let sb = edge.super_block.clone();
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");

        // DETACH succeeds even with a live guard, and the edge
        // unlinks synchronously. But `ops.unmount` must NOT have
        // been called yet — Phase B is deferred.
        unmount(&target, UmountFlags::DETACH).expect("detach unmount");
        assert!(target.mount.read().is_none(), "edge unlinked synchronously");
        assert_eq!(
            MOUNT_TABLE.read().len(),
            0,
            "table entry removed synchronously"
        );
        assert_eq!(
            fs.ops.unmount_calls.load(Ordering::SeqCst),
            0,
            "ops.unmount must be deferred until guard drops"
        );

        // Dropping the last guard fires the deferred finalize.
        drop(guard);
        assert_eq!(
            fs.ops.unmount_calls.load(Ordering::SeqCst),
            1,
            "guard drop must run deferred finalize exactly once"
        );
    }

    /// `MNT_DETACH` with no guards currently held must finalize
    /// synchronously — there's no future guard-drop to hook.
    #[test]
    fn detach_with_no_guards_finalizes_inline() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let target = make_dir_dentry();
        let fs = make_fs();
        mount(
            MountSource::None,
            &target,
            fs.clone(),
            MountFlags::default(),
        )
        .expect("mount");

        unmount(&target, UmountFlags::DETACH).expect("detach unmount");
        assert_eq!(
            fs.ops.unmount_calls.load(Ordering::SeqCst),
            1,
            "no in-flight guard: ops.unmount runs inline"
        );
    }

    /// `MNT_FORCE` refuses with `EBUSY` when another mount is
    /// nested on top of this one, to avoid stranding the child on a
    /// torn-down parent SB.
    #[test]
    fn force_refuses_nested_child_mount() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let parent_target = make_dir_dentry();
        let parent_fs = make_fs();
        let parent_edge = mount(
            MountSource::None,
            &parent_target,
            parent_fs.clone(),
            MountFlags::default(),
        )
        .expect("parent mount");

        // Build a dentry whose inode belongs to parent's SB — this
        // is the mount-point for a nested child.
        let parent_sb = parent_edge.super_block.clone();
        let child_mp_inode = Arc::new(Inode::new(
            2,
            Arc::downgrade(&parent_sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Dir,
            InodeMeta {
                mode: 0o755,
                nlink: 2,
                ..Default::default()
            },
        ));
        let child_mp = Dentry::new_root(child_mp_inode);
        let child_fs = make_fs();
        mount(
            MountSource::None,
            &child_mp,
            child_fs.clone(),
            MountFlags::default(),
        )
        .expect("child mount");

        // FORCE-unmounting the parent must refuse because a child
        // mount still pins it.
        let r = unmount(&parent_target, UmountFlags::FORCE);
        assert_eq!(r.err(), Some(EBUSY), "FORCE must refuse nested mounts");
        // Parent edge must be restored.
        assert!(parent_target.mount.read().is_some());
        assert!(!parent_sb.draining.load(Ordering::SeqCst));
        // Cleanup: detach both to leave a clean table.
        unmount(&child_mp, UmountFlags::default()).expect("cleanup child");
        unmount(&parent_target, UmountFlags::default()).expect("cleanup parent");
    }

    /// `MNT_DETACH` with a nested child mount still succeeds —
    /// DETACH is the cooperative variant and opts out of the
    /// FORCE nested-mount refusal.
    #[test]
    fn detach_allows_nested_child_mount() {
        let _g = TEST_LOCK.lock();
        drain_table();
        let parent_target = make_dir_dentry();
        let parent_fs = make_fs();
        let parent_edge = mount(
            MountSource::None,
            &parent_target,
            parent_fs.clone(),
            MountFlags::default(),
        )
        .expect("parent mount");
        let parent_sb = parent_edge.super_block.clone();
        let child_mp_inode = Arc::new(Inode::new(
            2,
            Arc::downgrade(&parent_sb),
            Arc::new(StubInode),
            Arc::new(StubFile),
            InodeKind::Dir,
            InodeMeta {
                mode: 0o755,
                nlink: 2,
                ..Default::default()
            },
        ));
        let child_mp = Dentry::new_root(child_mp_inode);
        let child_fs = make_fs();
        mount(
            MountSource::None,
            &child_mp,
            child_fs.clone(),
            MountFlags::default(),
        )
        .expect("child mount");

        unmount(&parent_target, UmountFlags::DETACH).expect("detach parent");
        assert!(parent_target.mount.read().is_none());
        // Cleanup the child.
        unmount(&child_mp, UmountFlags::default()).expect("cleanup child");
    }
}
