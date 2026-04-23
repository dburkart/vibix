//! Integration test for issue #637: `SuperBlock::dentry_pin_count` is
//! honoured by the `umount2` default busy-check and the `MNT_DETACH`
//! finalize-gate.
//!
//! The pre-#637 `umount2` implementation only consulted `sb_active`
//! (the in-flight-syscall guard counter). That missed dentries kept in
//! long-lived storage: `Task::cwd` via `chdir(2)`, `OpenFile.dentry`
//! held by an open fd, and any future `getcwd`-style path cache.
//!
//! This test stands up a stub filesystem, mounts it, constructs a
//! [`PinnedDentry`] on that mount's root (the generic proxy for any of
//! those long-lived storage sites), and verifies:
//!
//! 1. Default `umount2(MNT_NONE)` returns `-EBUSY` while the pin
//!    lives; releasing the pin lets the same call succeed.
//! 2. `umount2(MNT_DETACH)` with a live dentry pin unlinks the mount
//!    edge synchronously but defers `sync_fs` + `ops.unmount` until
//!    the pin drops — mirroring the Linux lazy-umount contract.
//!
//! Stub filesystem is re-built locally (matching `umount2_flags.rs`)
//! so the test doesn't depend on any real driver and drains
//! `MOUNT_TABLE` at entry to stay isolated from neighbour tests.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex;

use vibix::fs::vfs::dentry::{Dentry, MountFlags, PinnedDentry};
use vibix::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use vibix::fs::vfs::ops::{
    FileOps, FileSystem, InodeOps, MountSource, SetAttr, Stat, StatFs, SuperOps,
};
use vibix::fs::vfs::super_block::{SbFlags, SuperBlock};
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
            "default_umount_with_dentry_pin_is_ebusy",
            &(default_umount_with_dentry_pin_is_ebusy as fn()),
        ),
        (
            "dentry_pin_release_unblocks_umount",
            &(dentry_pin_release_unblocks_umount as fn()),
        ),
        (
            "detach_with_dentry_pin_defers_finalize",
            &(detach_with_dentry_pin_defers_finalize as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Stub filesystem (mirrors umount2_flags.rs).
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
        "dentry-pin-stub"
    }
    fn mount(&self, _source: MountSource<'_>, _flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        let sb = Arc::new(SuperBlock::new(
            alloc_fs_id(),
            self.ops.clone(),
            "dentry-pin-stub",
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

/// Build a fresh dir-kind dentry suitable as a mountpoint. Its inode's
/// SB is leaked via `mem::forget` for the test lifetime so the
/// weak-ref chain upgrades.
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

/// Pin a dentry on a mounted FS; default umount2 must fail with EBUSY
/// even though no `SbActiveGuard` is live. This is the #637 regression
/// coverage: the old code only consulted `sb_active` and would have
/// erroneously succeeded here.
fn default_umount_with_dentry_pin_is_ebusy() {
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

    // Simulate `chdir(mount.root)` by pinning the mount's root dentry.
    // `PinnedDentry::new` bumps the SB's `dentry_pin_count`.
    let pin = PinnedDentry::new(edge.root_dentry.clone());
    assert_eq!(
        edge.super_block.dentry_pin_count.load(Ordering::SeqCst),
        1,
        "PinnedDentry must bump dentry_pin_count",
    );
    assert_eq!(
        edge.super_block.sb_active.load(Ordering::SeqCst),
        0,
        "no SbActiveGuard taken — sb_active must stay zero",
    );

    let r = unmount(&target, UmountFlags::default());
    assert_eq!(
        r.err(),
        Some(EBUSY),
        "default umount2 must return EBUSY while dentry_pin_count > 0",
    );
    assert!(
        target.mount.read().is_some(),
        "mount edge must be restored on EBUSY",
    );
    assert!(
        !edge.super_block.draining.load(Ordering::SeqCst),
        "draining flag must be rolled back on EBUSY",
    );
    // Cleanup.
    drop(pin);
    unmount(&target, UmountFlags::default()).expect("cleanup");
}

/// Release the dentry pin and then re-run umount — it must succeed.
/// Mirrors the issue's second scenario: "open a file, chdir out,
/// umount → still EBUSY until the file is closed" (fd-table Arc chain
/// ultimately bottoms out at the same `dentry_pin_count` counter that
/// `PinnedDentry` bumps here).
fn dentry_pin_release_unblocks_umount() {
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

    let pin = PinnedDentry::new(edge.root_dentry.clone());
    assert_eq!(unmount(&target, UmountFlags::default()).err(), Some(EBUSY));
    drop(pin);
    assert_eq!(
        edge.super_block.dentry_pin_count.load(Ordering::SeqCst),
        0,
        "dentry_pin_count must return to zero after Drop",
    );
    unmount(&target, UmountFlags::default()).expect("post-release umount");
    assert!(target.mount.read().is_none());
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        1,
        "Phase B must run inline now that no pins remain",
    );
}

/// `MNT_DETACH` with a dentry pin unlinks the edge synchronously but
/// defers `ops.unmount` until the pin drops — the same lazy contract
/// that `MNT_DETACH` already honoured for in-flight `SbActiveGuard`s.
fn detach_with_dentry_pin_defers_finalize() {
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
    let pin = PinnedDentry::new(edge.root_dentry.clone());

    unmount(&target, UmountFlags::DETACH).expect("detach unmount");
    assert!(
        target.mount.read().is_none(),
        "detach unlinks synchronously even with a dentry pin",
    );
    assert_eq!(
        MOUNT_TABLE.read().len(),
        0,
        "table entry removed synchronously",
    );
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        0,
        "Phase B must be deferred while dentry_pin_count > 0",
    );

    // Dropping the last dentry pin fires the deferred finalize.
    drop(pin);
    assert_eq!(
        sb.dentry_pin_count.load(Ordering::SeqCst),
        0,
        "pin Drop must decrement the counter",
    );
    assert_eq!(
        fs.ops.unmount_calls.load(Ordering::SeqCst),
        1,
        "pin Drop must trigger the deferred finalize exactly once",
    );
}
