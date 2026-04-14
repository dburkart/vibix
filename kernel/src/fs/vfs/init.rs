//! Boot-time VFS initialization (RFC 0002 item 12/15).
//!
//! Populates the namespace with its three initial mounts so that the
//! kernel has a live filesystem before PID 1 runs:
//!
//! | Mountpoint | FS     | Backing                       |
//! |------------|--------|-------------------------------|
//! | `/`        | ramfs  | synthesised                   |
//! | `/dev`     | devfs  | synthesised                   |
//! | `/tmp`     | ramfs  | synthesised                   |
//!
//! On bare-metal, if a `rootfs.tar` module is present in the Limine
//! config, TarFs is mounted at `/` instead of RamFs. `/dev` and `/tmp`
//! are always overlaid with DevFs/RamFs respectively; their mountpoint
//! dentries use synthetic bootstrap inodes when the root FS is read-only.
//!
//! ## Bootstrap: where does the namespace root come from?
//!
//! The mount at `/` needs a target dentry before any FS exists. We
//! build a minimal bootstrap placeholder — a dentry whose inode lives
//! in a throwaway bootstrap superblock — purely so [`mount_table::mount`]
//! has something to hang the first edge on. After mounting ramfs there,
//! the reachable namespace root is `edge.root_dentry`, which is what we
//! expose via [`root`].
//!
//! ## Failure policy
//!
//! All three mounts are fatal pre-PID-1: `init()` panics with a
//! descriptive message if any step fails. A boot where `/dev` can't be
//! mounted is a boot where nothing useful can run next.

use alloc::sync::Arc;
use spin::Once;

use super::dentry::{ChildState, Dentry, MountFlags};
use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::{alloc_fs_id, mount};
use super::ops::{FileOps, InodeOps, MountSource, SetAttr, Stat, StatFs, SuperOps};
use super::super_block::{SbFlags, SuperBlock};
use super::{DevFs, RamFs, TarFs};

/// Global namespace root. Populated by [`init`]; `None` before the
/// kernel has run boot-time VFS setup. Consumers who need to start a
/// [`path_walk`](super::path_walk::path_walk) against `/` call
/// [`root`] to retrieve it.
static ROOT_DENTRY: Once<Arc<Dentry>> = Once::new();

/// Return the namespace root dentry, or `None` if [`init`] has not run
/// yet. Path-based syscalls should fail with `-ENOENT` (or a clearer
/// init-not-ready code) if this returns `None`.
pub fn root() -> Option<Arc<Dentry>> {
    ROOT_DENTRY.get().cloned()
}

/// Mount the three initial filesystems. Panics on any failure — see
/// module doc for why this is the correct policy.
///
/// Called from `vibix::init()` after `mem::init()` so the heap is
/// available for `Arc` / `Vec` allocation done by the FS drivers.
pub fn init() {
    if ROOT_DENTRY.get().is_some() {
        return;
    }

    let bootstrap = bootstrap_target();

    // On the bare-metal target, prefer tarfs-on-ramdisk-module for `/` per
    // RFC 0002. Fall back to ramfs when the module is absent (host tests,
    // early-boot without the ISO, or any future build that omits it).
    #[cfg(target_os = "none")]
    let root_edge = {
        if let Some((ptr, len)) = find_rootfs_module() {
            // SAFETY (inside tarfs): Limine places module payloads in
            // EXECUTABLE_AND_MODULES memory, preserved for the kernel's
            // lifetime. TarFs::mount() converts the raw pointer to a slice
            // with an internal `unsafe` block.
            let source = MountSource::RamdiskModule(ptr, len);
            let edge = mount(
                source,
                &bootstrap,
                TarFs::new_arc() as Arc<dyn super::ops::FileSystem>,
                MountFlags::default(),
            )
            .unwrap_or_else(|e| panic!("vfs::init: mount tarfs / failed: errno={}", e));
            crate::serial_println!("vfs: mounted tarfs at /");
            edge
        } else {
            let edge = mount(
                MountSource::None,
                &bootstrap,
                Arc::new(RamFs) as Arc<dyn super::ops::FileSystem>,
                MountFlags::default(),
            )
            .unwrap_or_else(|e| panic!("vfs::init: mount ramfs / failed: errno={}", e));
            crate::serial_println!("vfs: mounted ramfs at /");
            edge
        }
    };

    #[cfg(not(target_os = "none"))]
    let root_edge = mount(
        MountSource::None,
        &bootstrap,
        Arc::new(RamFs) as Arc<dyn super::ops::FileSystem>,
        MountFlags::default(),
    )
    .unwrap_or_else(|e| panic!("vfs::init: mount ramfs / failed: errno={}", e));

    let root = root_edge.root_dentry.clone();
    ROOT_DENTRY.call_once(|| root.clone());

    mount_child(
        &root,
        b"dev",
        Arc::new(DevFs) as Arc<dyn super::ops::FileSystem>,
    );
    crate::serial_println!("vfs: mounted devfs at /dev");

    mount_child(
        &root,
        b"tmp",
        Arc::new(RamFs) as Arc<dyn super::ops::FileSystem>,
    );
    crate::serial_println!("vfs: mounted ramfs at /tmp");
}

/// Locate the rootfs tarball module from the Limine module response.
/// Returns `(ptr, len)` if found, `None` otherwise.
#[cfg(target_os = "none")]
fn find_rootfs_module() -> Option<(*const u8, usize)> {
    let resp = crate::boot::MODULE_REQUEST.get_response()?;
    let file = resp
        .modules()
        .iter()
        .find(|f| f.path().to_bytes().ends_with(b"/boot/rootfs.tar"))?;
    Some((file.addr(), file.size() as usize))
}

/// Create a subdirectory `name` under `parent`, wrap it in a fresh
/// dentry, and mount `fs` onto it. Panics on any step's failure.
///
/// When the parent filesystem is read-only (EROFS), `mkdir` will fail.
/// In that case a synthetic bootstrap inode is used as the mountpoint —
/// the mounted FS's own root takes over immediately, so the synthetic
/// inode is never visible to callers.
fn mount_child(parent: &Arc<Dentry>, name: &[u8], fs: Arc<dyn super::ops::FileSystem>) {
    let parent_inode = parent
        .inode
        .read()
        .as_ref()
        .cloned()
        .unwrap_or_else(|| panic!("vfs::init: parent dentry is negative"));

    // Attempt to create the directory in the parent FS. Falls back to a
    // synthetic inode when the parent is read-only or doesn't support
    // mkdir (EPERM = -1 default, EROFS = -30). The mounted child FS's
    // root dentry takes over immediately, so the stub is never visible.
    let child_inode = match parent_inode.ops.mkdir(&parent_inode, name, 0o755) {
        Ok(inode) => inode,
        Err(_) => {
            let stub_sb = Arc::new(SuperBlock::new(
                alloc_fs_id(),
                Arc::new(BootstrapSuperOps) as Arc<dyn SuperOps>,
                "mountpoint-stub",
                4096,
                SbFlags::default(),
            ));
            let stub_inode = Arc::new(Inode::new(
                1,
                Arc::downgrade(&stub_sb),
                Arc::new(BootstrapInodeOps) as Arc<dyn InodeOps>,
                Arc::new(BootstrapFileOps) as Arc<dyn FileOps>,
                InodeKind::Dir,
                InodeMeta {
                    mode: 0o755,
                    nlink: 2,
                    ..Default::default()
                },
            ));
            core::mem::forget(stub_sb);
            stub_inode
        }
    };

    let child_dname =
        super::DString::try_from_bytes(name).unwrap_or_else(|_| panic!("vfs::init: invalid dname"));
    let child_dentry = Dentry::new(
        child_dname.clone(),
        Arc::downgrade(parent),
        Some(child_inode),
    );

    // Publish the child into `parent.children` *before* mounting so
    // the parent's strong BTreeMap reference keeps it alive after we
    // return. `mount_table::mount` only holds a `Weak<Dentry>` on the
    // mountpoint; without this insert, `..` traversal out of the
    // mounted FS would fail to upgrade and yield `ENOENT`.
    parent
        .children
        .write()
        .insert(child_dname, ChildState::Resolved(child_dentry.clone()));

    mount(MountSource::None, &child_dentry, fs, MountFlags::default()).unwrap_or_else(|e| {
        panic!(
            "vfs::init: mount {:?} failed: errno={}",
            core::str::from_utf8(name).unwrap_or("<non-utf8>"),
            e
        )
    });
}

/// Build the synthetic directory dentry onto which ramfs mounts for
/// `/`. The bootstrap SB lives for the rest of the kernel's lifetime
/// via the ramfs edge's backlink; we can leak-like-forget it here
/// because mount_table holds the live mount edge strongly.
fn bootstrap_target() -> Arc<Dentry> {
    let bootstrap_sb = Arc::new(SuperBlock::new(
        alloc_fs_id(),
        Arc::new(BootstrapSuperOps) as Arc<dyn SuperOps>,
        "rootfs-bootstrap",
        4096,
        SbFlags::default(),
    ));
    let bootstrap_inode = Arc::new(Inode::new(
        1,
        Arc::downgrade(&bootstrap_sb),
        Arc::new(BootstrapInodeOps) as Arc<dyn InodeOps>,
        Arc::new(BootstrapFileOps) as Arc<dyn FileOps>,
        InodeKind::Dir,
        InodeMeta {
            mode: 0o755,
            nlink: 2,
            ..Default::default()
        },
    ));
    let target = Dentry::new_root(bootstrap_inode);

    // The bootstrap SB is only ever referenced as a Weak back-pointer
    // from the target dentry's inode. `mount_table::mount` produces an
    // edge that holds the new FS's SuperBlock strongly — the bootstrap
    // SB itself has no consumers after that, so forgetting it here is
    // the simplest way to keep its one Inode's Weak backlink
    // upgradeable for the short duration of the first mount.
    core::mem::forget(bootstrap_sb);

    target
}

// ---------------------------------------------------------------------------
// Bootstrap SB/Inode/File ops — deliberately minimal. The bootstrap
// dentry is never the target of a syscall; only `mount_table::mount`
// looks at its kind, then the edge takes over for all future walks.
// ---------------------------------------------------------------------------

struct BootstrapSuperOps;

impl SuperOps for BootstrapSuperOps {
    fn root_inode(&self) -> Arc<Inode> {
        // mount_table::mount doesn't call this (the FS being mounted
        // produces its own root), and nothing else ever resolves
        // through this SB. An unreachable here flags any future
        // regression that widens the bootstrap surface.
        unreachable!("bootstrap SuperOps::root_inode should never be reached")
    }
    fn statfs(&self) -> Result<StatFs, i64> {
        Ok(StatFs::default())
    }
    fn unmount(&self) {}
}

struct BootstrapInodeOps;

impl InodeOps for BootstrapInodeOps {
    fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
        Ok(())
    }
    fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
        Ok(())
    }
}

struct BootstrapFileOps;

impl FileOps for BootstrapFileOps {}

#[cfg(test)]
mod tests {
    use super::*;
    use spin::Mutex;

    // `init()` installs into the global `ROOT_DENTRY` and global
    // `MOUNT_TABLE`. Tests must serialise to avoid cross-test races on
    // those singletons.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn clear_root() {
        // There is no public reset path for Once / MOUNT_TABLE; the
        // init flow is idempotent (early-returns on second entry) so
        // all we need for these tests is serialisation + running
        // against whatever state a prior test left behind.
    }

    #[test]
    fn init_is_idempotent() {
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let first = root().expect("root populated after first init");
        init();
        let second = root().expect("root populated after second init");
        assert!(
            Arc::ptr_eq(&first, &second),
            "idempotent init returns same root dentry"
        );
    }

    #[test]
    fn root_is_positive_directory() {
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let r = root().expect("root populated");
        let inode_slot = r.inode.read();
        let inode = inode_slot.as_ref().expect("root is positive");
        assert_eq!(inode.kind, InodeKind::Dir);
    }

    #[test]
    fn root_is_a_mountpoint_via_lookup_chain() {
        // After init, the ramfs root dentry is the globally-exposed
        // root; the bootstrap dentry it was mounted onto is held alive
        // only by the edge's `mountpoint: Weak`. A walker asking about
        // `root()` should see a positive dir and no further mount on
        // top of it.
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let r = root().expect("root populated");
        assert!(
            r.mount.read().is_none(),
            "namespace root is not a mountpoint itself"
        );
    }

    #[test]
    fn dev_mount_is_present_in_root_children() {
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let r = root().expect("root populated");
        let root_inode = r.inode.read().as_ref().cloned().expect("positive");

        // Look up `dev` through the ramfs InodeOps — should succeed
        // because `mount_child` created the directory in ramfs before
        // mounting devfs on it.
        let dev = root_inode
            .ops
            .lookup(&root_inode, b"dev")
            .expect("ramfs /dev directory exists");
        assert_eq!(dev.kind, InodeKind::Dir);
    }

    #[test]
    fn tmp_mount_is_present_in_root_children() {
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let r = root().expect("root populated");
        let root_inode = r.inode.read().as_ref().cloned().expect("positive");

        let tmp = root_inode
            .ops
            .lookup(&root_inode, b"tmp")
            .expect("ramfs /tmp directory exists");
        assert_eq!(tmp.kind, InodeKind::Dir);
    }

    #[test]
    fn mount_child_dentries_survive_via_parent_children() {
        // Regression: `mount()` stores only a `Weak<Dentry>` on the
        // mountpoint, so the child dentry produced by `mount_child`
        // would be dropped at function exit if the parent didn't hold
        // it strongly. Upgrading the mount edge's `mountpoint` Weak
        // proves the dentry is still alive, i.e. `..` traversal out of
        // `/dev` or `/tmp` will succeed.
        let _g = TEST_LOCK.lock();
        clear_root();
        init();
        let r = root().expect("root populated");

        let children = r.children.read();
        let dev_dname = super::super::DString::try_from_bytes(b"dev").unwrap();
        let tmp_dname = super::super::DString::try_from_bytes(b"tmp").unwrap();
        for (dname, label) in [(&dev_dname, "dev"), (&tmp_dname, "tmp")] {
            let state = children
                .get(dname)
                .unwrap_or_else(|| panic!("/{} should be registered under root.children", label));
            let child = match state {
                ChildState::Resolved(d) => d.clone(),
                _ => panic!("/{} should be Resolved, not Loading/Negative", label),
            };
            let edge = child
                .mount
                .read()
                .as_ref()
                .cloned()
                .unwrap_or_else(|| panic!("/{} dentry should host a mount edge", label));
            let upgraded = edge
                .mountpoint
                .upgrade()
                .unwrap_or_else(|| panic!("mount edge's mountpoint Weak for /{} must upgrade — if it fails the child dentry was dropped", label));
            assert!(
                Arc::ptr_eq(&upgraded, &child),
                "upgraded mountpoint should be the same dentry we registered under root.children"
            );
        }
    }
}
