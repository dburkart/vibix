//! Integration test for issue #636: `umount2(2)` target-path
//! canonicalization to the covering mount edge.
//!
//! Exercises [`vibix::arch::x86_64::syscalls::vfs::canonicalize_umount_target`]
//! across the four states the helper picks between:
//!
//! - resolved dentry is itself a mount root → return its mountpoint;
//! - resolved dentry is interior to a mounted FS (e.g. `/mnt/subdir`)
//!   → ascend parent links until a covering edge is found, then
//!   return its mountpoint;
//! - resolved dentry is the namespace root with no covering edge
//!   (i.e. `umount2("/")`) → return `EBUSY`;
//! - covering edge exists but its `mountpoint` weak-ref is dead
//!   (mount racing teardown) → return `EINVAL`.
//!
//! Runs in QEMU so the `target_os = "none"`-gated `arch::x86_64`
//! module is available; mirrors the stub-FS pattern used by
//! `umount2_flags.rs`.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::panic::PanicInfo;

use vibix::arch::x86_64::syscalls::vfs::canonicalize_umount_target;
use vibix::fs::vfs::dentry::{Dentry, MountEdge, MountFlags};
use vibix::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use vibix::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
use vibix::fs::vfs::path_walk::MountResolver;
use vibix::fs::vfs::super_block::{SbFlags, SuperBlock};
use vibix::fs::vfs::{alloc_fs_id, DString};
use vibix::fs::{EBUSY, EINVAL};
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
            "canonicalize_returns_mountpoint_when_resolved_is_mount_root",
            &(canonicalize_returns_mountpoint_when_resolved_is_mount_root as fn()),
        ),
        (
            "canonicalize_walks_up_for_interior_dentry",
            &(canonicalize_walks_up_for_interior_dentry as fn()),
        ),
        (
            "canonicalize_namespace_root_returns_ebusy",
            &(canonicalize_namespace_root_returns_ebusy as fn()),
        ),
        (
            "canonicalize_dead_mountpoint_weakref_returns_einval",
            &(canonicalize_dead_mountpoint_weakref_returns_einval as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// ---------------------------------------------------------------------------
// Stub VFS objects.
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

struct StubSuper;
impl SuperOps for StubSuper {
    fn root_inode(&self) -> Arc<Inode> {
        unreachable!("root_inode should not be called; sb.root is pre-populated");
    }
    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs::default())
    }
    fn unmount(&self) {}
}

/// Stub `MountResolver` keyed by `Arc<Dentry>` raw pointer identity.
/// Same shape as the in-tree `path_walk::tests::InoResolver` but
/// without needing the inode-ino plumbing.
struct PtrResolver {
    edges: BTreeMap<usize, Arc<MountEdge>>,
}
impl MountResolver for PtrResolver {
    fn mount_below(&self, _d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        None
    }
    fn mount_above(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        self.edges.get(&(Arc::as_ptr(d) as usize)).cloned()
    }
}

/// Build a fresh dir-kind root dentry. Each one anchors its own SB so
/// the inode's weak SB ref is valid; SBs are kept alive in `keep`
/// for the test's lifetime.
fn make_root(keep: &mut Vec<Arc<SuperBlock>>) -> Arc<Dentry> {
    let sb = Arc::new(SuperBlock::new(
        alloc_fs_id(),
        Arc::new(StubSuper),
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
    let d = Dentry::new_root(inode);
    keep.push(sb);
    d
}

/// Build a non-root child dentry under `parent`. Inode lives on a
/// fresh SB for simplicity; the helper under test only inspects
/// parent links and the resolver-supplied edge, not SB identity.
fn make_child(parent: &Arc<Dentry>, name: &[u8], keep: &mut Vec<Arc<SuperBlock>>) -> Arc<Dentry> {
    let sb = Arc::new(SuperBlock::new(
        alloc_fs_id(),
        Arc::new(StubSuper),
        "host",
        512,
        SbFlags::default(),
    ));
    let inode = Arc::new(Inode::new(
        2,
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
    keep.push(sb);
    Dentry::new(
        DString::try_from_bytes(name).expect("dstring"),
        Arc::downgrade(parent),
        Some(inode),
    )
}

fn make_edge(
    mountpoint: &Arc<Dentry>,
    root: &Arc<Dentry>,
    keep: &mut Vec<Arc<SuperBlock>>,
) -> Arc<MountEdge> {
    let sb = Arc::new(SuperBlock::new(
        alloc_fs_id(),
        Arc::new(StubSuper),
        "edge",
        512,
        SbFlags::default(),
    ));
    keep.push(sb.clone());
    Arc::new(MountEdge {
        mountpoint: Arc::downgrade(mountpoint),
        super_block: sb,
        root_dentry: root.clone(),
        flags: MountFlags::default(),
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

fn canonicalize_returns_mountpoint_when_resolved_is_mount_root() {
    // /mnt is a mountpoint dentry; mnt_root is the mounted FS root.
    // path_walk follows mounts so resolved == mnt_root.
    let mut keep = Vec::new();
    let ns_root = make_root(&mut keep);
    let mountpoint = make_child(&ns_root, b"mnt", &mut keep);
    let mnt_root = make_root(&mut keep);
    let edge = make_edge(&mountpoint, &mnt_root, &mut keep);
    let mut edges = BTreeMap::new();
    edges.insert(Arc::as_ptr(&mnt_root) as usize, edge);
    let resolver = PtrResolver { edges };

    let r = canonicalize_umount_target(mnt_root.clone(), &ns_root, &resolver)
        .expect("must resolve to mountpoint");
    assert!(
        Arc::ptr_eq(&r, &mountpoint),
        "must return the mountpoint dentry"
    );
}

fn canonicalize_walks_up_for_interior_dentry() {
    // /mnt/subdir — resolved is `subdir` inside the mounted FS;
    // helper must ascend to mnt_root and resolve via the edge.
    let mut keep = Vec::new();
    let ns_root = make_root(&mut keep);
    let mountpoint = make_child(&ns_root, b"mnt", &mut keep);
    let mnt_root = make_root(&mut keep);
    let subdir = make_child(&mnt_root, b"subdir", &mut keep);
    let edge = make_edge(&mountpoint, &mnt_root, &mut keep);
    let mut edges = BTreeMap::new();
    edges.insert(Arc::as_ptr(&mnt_root) as usize, edge);
    let resolver = PtrResolver { edges };

    let r = canonicalize_umount_target(subdir, &ns_root, &resolver)
        .expect("must resolve to mountpoint");
    assert!(
        Arc::ptr_eq(&r, &mountpoint),
        "must walk up from subdir to mnt's mountpoint",
    );
}

fn canonicalize_namespace_root_returns_ebusy() {
    // umount2("/") — resolved == ns_root, no covering edge.
    let mut keep = Vec::new();
    let ns_root = make_root(&mut keep);
    let resolver = PtrResolver {
        edges: BTreeMap::new(),
    };
    let r = canonicalize_umount_target(ns_root.clone(), &ns_root, &resolver);
    assert_eq!(r.err(), Some(EBUSY), "umount2(\"/\") must be EBUSY");
}

fn canonicalize_dead_mountpoint_weakref_returns_einval() {
    // Edge present but mountpoint Arc dropped → weak upgrade fails.
    let mut keep = Vec::new();
    let ns_root = make_root(&mut keep);
    let mnt_root = make_root(&mut keep);
    let edge = {
        let mp = make_child(&ns_root, b"mnt", &mut keep);
        let e = make_edge(&mp, &mnt_root, &mut keep);
        // Drop the strong ref so only the edge's Weak survives, then
        // dies on upgrade.
        drop(mp);
        e
    };
    let mut edges = BTreeMap::new();
    edges.insert(Arc::as_ptr(&mnt_root) as usize, edge);
    let resolver = PtrResolver { edges };
    let r = canonicalize_umount_target(mnt_root.clone(), &ns_root, &resolver);
    assert_eq!(
        r.err(),
        Some(EINVAL),
        "dead mountpoint weak-ref must be EINVAL",
    );
}
