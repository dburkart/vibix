//! Integration test for issue #576: `umount2(2)` flag semantics.
//!
//! Runs in-kernel under QEMU and exercises
//! [`vibix::fs::vfs::unmount`] directly (the single code path behind
//! `sys_umount2`), asserting the MNT_FORCE / MNT_DETACH / default
//! behaviour documented in RFC 0004 §umount2:
//!
//! - Default: EBUSY when any [`SbActiveGuard`] still pins the SB.
//! - `MNT_FORCE`: bypasses the active-guard check, but refuses with
//!   EBUSY if a nested child mount still pins the SB.
//! - `MNT_DETACH`: always detaches synchronously; defers `sync_fs`
//!   + `ops.unmount` until the last guard drops.
//!
//! The unit-test stub filesystem from `mount_table.rs` is re-built
//! here so the tests don't depend on any real driver (ext2 / tarfs
//! / ramfs) and don't touch the live `MOUNT_TABLE` from other tests
//! — each test drains the table at entry.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

use vibix::fs::vfs::dentry::{Dentry, MountFlags};
use vibix::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use vibix::fs::vfs::ops::{
    FileOps, FileSystem, InodeOps, MountSource, SetAttr, Stat, StatFs, SuperOps,
};
use vibix::fs::vfs::super_block::{SbActiveGuard, SbFlags, SuperBlock};
use vibix::fs::vfs::{alloc_fs_id, mount, unmount, UmountFlags, MOUNT_TABLE};
use vibix::fs::EBUSY;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "default_unmount_no_pins_succeeds",
            &(default_unmount_no_pins_succeeds as fn()),
        ),
        (
            "default_unmount_with_active_guard_returns_ebusy",
            &(default_unmount_with_active_guard_returns_ebusy as fn()),
        ),
        (
            "force_with_active_guard_tears_down",
            &(force_with_active_guard_tears_down as fn()),
        ),
        (
            "force_refuses_nested_child_mount",
            &(force_refuses_nested_child_mount as fn()),
        ),
        (
            "detach_defers_ops_unmount_until_guard_drops",
            &(detach_defers_ops_unmount_until_guard_drops as fn()),
        ),
        (
            "detach_with_no_guards_finalizes_inline",
            &(detach_with_no_guards_finalizes_inline as fn()),
        ),
        (
            "detach_allows_nested_child_mount",
            &(detach_allows_nested_child_mount as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Stub filesystem. Same shape as `mount_table.rs`'s unit-test stub:
// `StubSuper` counts `unmount` calls so we can assert
// "Phase B ran" / "Phase B deferred".
// ---------------------------------------------------------------------------

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
        unreachable!("root_inode should not be called; sb.root is pre-populated");
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
        "umount2-stub"
    }
    fn mount(&self, _source: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        let sb = Arc::new(SuperBlock::new(
            alloc_fs_id(),
            self.ops.clone(),
            "umount2-stub",
            512,
            SbFlags::default(),
        ));
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

/// Build a fresh dir-kind dentry suitable as a mountpoint. Uses a
/// separate host SB (kept alive via `mem::forget` for the test
/// lifetime, same trick as the unit tests) so the returned dentry
/// has a plausible weak-ref chain.
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
    core::mem::forget(sb);
    root
}

fn drain_table() {
    let mut t = MOUNT_TABLE.write();
    t.clear();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn default_unmount_no_pins_succeeds() {
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
    unmount(&target, UmountFlags::default()).expect("unmount");
    assert!(target.mount.read().is_none(), "edge must unlink");
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        1,
        "Phase B must run inline on default unmount",
    );
}

fn default_unmount_with_active_guard_returns_ebusy() {
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
    // Pin the SB — simulates an in-flight syscall.
    let _guard = SbActiveGuard::try_acquire(&edge.super_block).expect("guard");
    let r = unmount(&target, UmountFlags::default());
    assert_eq!(r.err(), Some(EBUSY), "default umount2 must return EBUSY");
    assert!(target.mount.read().is_some(), "edge must be restored");
    assert!(
        !edge.super_block.draining.load(Ordering::SeqCst),
        "draining flag must be rolled back on EBUSY",
    );
    // Cleanup.
    drop(_guard);
    unmount(&target, UmountFlags::default()).expect("cleanup");
}

fn force_with_active_guard_tears_down() {
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
    unmount(&target, UmountFlags::FORCE).expect("FORCE unmount");
    assert!(target.mount.read().is_none());
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        1,
        "FORCE must run Phase B inline",
    );
    assert!(
        edge.super_block.draining.load(Ordering::SeqCst),
        "draining must remain set so no new guards enter",
    );
}

fn force_refuses_nested_child_mount() {
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

    // Build a dentry whose inode belongs to the parent's SB so a
    // second mount below it looks nested to the `has_child_mounts`
    // walk.
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

    let r = unmount(&parent_target, UmountFlags::FORCE);
    assert_eq!(r.err(), Some(EBUSY), "FORCE must refuse nested mounts");
    assert!(parent_target.mount.read().is_some(), "parent edge restored");
    assert!(
        !parent_sb.draining.load(Ordering::SeqCst),
        "draining flag rolled back on nested-mount refusal",
    );

    // Cleanup child first, then parent, to leave a clean table.
    unmount(&child_mp, UmountFlags::default()).expect("cleanup child");
    unmount(&parent_target, UmountFlags::default()).expect("cleanup parent");
}

fn detach_defers_ops_unmount_until_guard_drops() {
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

    unmount(&target, UmountFlags::DETACH).expect("detach unmount");
    assert!(
        target.mount.read().is_none(),
        "detach unlinks synchronously"
    );
    assert_eq!(
        MOUNT_TABLE.read().len(),
        0,
        "mount table entry removed synchronously",
    );
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        0,
        "Phase B must be deferred while guard is held",
    );

    drop(guard);
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        1,
        "last guard drop runs deferred finalize exactly once",
    );
}

fn detach_with_no_guards_finalizes_inline() {
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
        "detach with no pins must finalize inline",
    );
}

fn detach_allows_nested_child_mount() {
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

    // The child mount's own SB keeps its driver state alive — clean
    // up by unmounting it explicitly.
    unmount(&child_mp, UmountFlags::default()).expect("cleanup child");
}
