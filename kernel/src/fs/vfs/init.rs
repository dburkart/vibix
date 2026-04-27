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

use alloc::boxed::Box;

use super::dentry::{ChildState, Dentry, MountFlags};
use super::inode::{Inode, InodeKind, InodeMeta};
use super::mount_table::{alloc_fs_id, mount};
use super::ops::{FileOps, FileSystem, InodeOps, MountSource, SetAttr, Stat, StatFs, SuperOps};
use super::registry::register_filesystem;
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
///
/// Equivalent to [`init_with`] with `RootArgs::auto()` — the default
/// "try ext2-on-virtio-blk, fall back to tarfs module, fall back to
/// ramfs" auto-probe that this path used before #577. Existing
/// callers (integration tests, `lib::init()`) keep working unchanged.
pub fn init() {
    init_with(crate::boot_cmdline::RootArgs::auto());
}

/// Cmdline-aware variant of [`init`]. Selects the root filesystem
/// per the caller-supplied [`RootArgs`] (parsed from the kernel
/// cmdline by [`boot_cmdline::parse`]).
///
/// Fallback policy when the configured source cannot be mounted (e.g.
/// `root=/dev/vda` but the default block device holds no ext2
/// superblock): log and try the next source in preference order
/// (tarfs module → ramfs). A ramfs mount always succeeds so this path
/// never panics pre-PID-1 unless all three are broken simultaneously.
pub fn init_with(args: crate::boot_cmdline::RootArgs) {
    use crate::boot_cmdline::RootSource;

    if ROOT_DENTRY.get().is_some() {
        return;
    }

    // Populate the fstype registry so `mount(2)` can resolve names. The
    // factories here are stateless: ramfs/devfs/tarfs each mint a fresh
    // `Arc<dyn FileSystem>` per mount. ext2 is feature-gated and
    // registered separately below.
    register_builtin_filesystems();

    let bootstrap = bootstrap_target();

    // `rootflags=` already carries the caller's mount-flag intent;
    // `RDONLY` is the default for now until #564's orphan-replay soak
    // has been exercised in CI with RW mounts. Callers that want RW
    // pass `rootflags=rw` (explicit_ro = Some(false)).
    let mut mount_flags: MountFlags = args.mount_flags.into();
    if args.explicit_ro.is_none() && matches!(args.source, RootSource::VirtioBlk) {
        // Default to read-only on ext2 boots until rw is explicitly
        // opted in. The TarFs / RamFs paths below have never honoured
        // a writeable mount flag so their behaviour is unchanged.
        mount_flags = mount_flags | MountFlags::RDONLY;
    }

    // Selection order per RFC 0004 Workstream F (#577):
    //   - RootSource::VirtioBlk  → try ext2 on default_device, else fall through.
    //   - RootSource::TarfsModule → try tarfs module, else fall through.
    //   - RootSource::Ramfs      → mount empty ramfs.
    //   - RootSource::Default    → try ext2 → tarfs → ramfs in order.
    #[cfg(target_os = "none")]
    let root_edge = try_mount_selected_root(&bootstrap, args.source, mount_flags);

    // Host-side tests don't have a block device or a Limine module, so
    // the mount path collapses to "always ramfs" — matches the pre-#577
    // behaviour of this branch and keeps every `#[cfg(test)]` caller
    // green without having to stub up a disk fixture.
    #[cfg(not(target_os = "none"))]
    let root_edge = {
        let _ = args; // silence unused-warning on host
        mount(
            MountSource::None,
            &bootstrap,
            Arc::new(RamFs) as Arc<dyn super::ops::FileSystem>,
            MountFlags::default(),
        )
        .unwrap_or_else(|e| panic!("vfs::init: mount ramfs / failed: errno={}", e))
    };

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

/// Try each root-filesystem candidate in priority order, returning the
/// first successful [`MountEdge`]. Ramfs is always the final fallback
/// and cannot fail, so this function never returns `None`.
#[cfg(target_os = "none")]
fn try_mount_selected_root(
    bootstrap: &Arc<Dentry>,
    source: crate::boot_cmdline::RootSource,
    flags: MountFlags,
) -> Arc<super::dentry::MountEdge> {
    use crate::boot_cmdline::RootSource;

    // Build the ordered attempt list. `Default` walks the full
    // preference chain; explicit sources attempt only themselves, then
    // fall through to the safe-but-empty ramfs floor so a single
    // misconfigured `root=` doesn't wedge the boot.
    let attempts: &[RootSource] = match source {
        RootSource::Default => &[
            RootSource::VirtioBlk,
            RootSource::TarfsModule,
            RootSource::Ramfs,
        ],
        RootSource::VirtioBlk => &[
            RootSource::VirtioBlk,
            RootSource::TarfsModule,
            RootSource::Ramfs,
        ],
        RootSource::TarfsModule => &[RootSource::TarfsModule, RootSource::Ramfs],
        RootSource::Ramfs => &[RootSource::Ramfs],
    };

    for &attempt in attempts {
        match try_mount_one(bootstrap, attempt, flags) {
            Ok(edge) => {
                crate::serial_println!(
                    "vfs: mounted {} at / (requested={:?})",
                    source_label(attempt),
                    source
                );
                return edge;
            }
            Err(errno) => {
                crate::serial_println!(
                    "vfs: mount {} / failed: errno={} (trying next)",
                    source_label(attempt),
                    errno
                );
            }
        }
    }

    // Unreachable in practice: ramfs has no failure mode that isn't a
    // memory-exhaustion panic inside `mount_table::mount`. If we get
    // here every option including the synthesised ramfs floor failed.
    panic!("vfs::init: every root-fs candidate failed to mount");
}

#[cfg(target_os = "none")]
fn source_label(s: crate::boot_cmdline::RootSource) -> &'static str {
    use crate::boot_cmdline::RootSource;
    match s {
        RootSource::Default => "default",
        RootSource::VirtioBlk => "ext2 (virtio-blk)",
        RootSource::TarfsModule => "tarfs (module)",
        RootSource::Ramfs => "ramfs",
    }
}

/// Attempt a single mount for `source`. Returns the resulting edge on
/// success or the first errno encountered on failure. Never panics.
#[cfg(target_os = "none")]
fn try_mount_one(
    bootstrap: &Arc<Dentry>,
    source: crate::boot_cmdline::RootSource,
    flags: MountFlags,
) -> Result<Arc<super::dentry::MountEdge>, i64> {
    use crate::boot_cmdline::RootSource;

    match source {
        RootSource::VirtioBlk => {
            #[cfg(feature = "ext2")]
            {
                let dev = crate::block::default_device().ok_or(crate::fs::ENODEV)?;
                let fs = crate::fs::ext2::Ext2Fs::new_with_device(dev)
                    as Arc<dyn super::ops::FileSystem>;
                mount(MountSource::None, bootstrap, fs, flags)
            }
            #[cfg(not(feature = "ext2"))]
            {
                // ext2 compiled out — treat as "device not available"
                // so the fallback chain still walks to tarfs/ramfs.
                let _ = (bootstrap, flags);
                Err(crate::fs::ENODEV)
            }
        }
        RootSource::TarfsModule => {
            let module_bytes = find_rootfs_module().ok_or(crate::fs::ENOENT)?;
            let src = MountSource::RamdiskModule(module_bytes);
            mount(
                src,
                bootstrap,
                TarFs::new_arc() as Arc<dyn super::ops::FileSystem>,
                flags,
            )
        }
        RootSource::Ramfs | RootSource::Default => mount(
            MountSource::None,
            bootstrap,
            Arc::new(RamFs) as Arc<dyn super::ops::FileSystem>,
            flags,
        ),
    }
}

/// Locate the rootfs tarball module from the Limine module response and
/// convert the raw bootloader pointer into a `&'static [u8]`.
///
/// # Safety of the `unsafe` block
///
/// Limine guarantees that module payloads reside in
/// `EXECUTABLE_AND_MODULES` memory, which it preserves for the kernel's
/// entire lifetime. `file.addr()` and `file.size()` come directly from
/// the validated bootloader response and form a valid, non-overlapping
/// byte range. The resulting slice is therefore sound for `'static`.
#[cfg(target_os = "none")]
fn find_rootfs_module() -> Option<&'static [u8]> {
    let resp = crate::boot::MODULE_REQUEST.get_response()?;
    let file = resp
        .modules()
        .iter()
        .find(|f| f.path().to_bytes().ends_with(b"/boot/rootfs.tar"))?;
    // SAFETY: see doc comment above.
    Some(unsafe { core::slice::from_raw_parts(file.addr(), file.size() as usize) })
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

/// Register every built-in fstype (`ramfs`, `tmpfs`, `devfs`, `tarfs`,
/// and — when the `ext2` feature is on — `ext2`) with the fstype
/// registry. Called once from [`init`]; the registry itself is idempotent
/// on re-registration so a second call is harmless.
///
/// `tmpfs` is intentionally aliased to the ramfs factory: vibix does
/// not yet distinguish the two, but Linux userspace scripts reach for
/// `tmpfs` by default and nothing about our ramfs semantics violates
/// the tmpfs contract for the operations that currently exist.
fn register_builtin_filesystems() {
    register_filesystem(
        "ramfs",
        Box::new(|_src| Ok(Arc::new(RamFs) as Arc<dyn FileSystem>)),
    );
    register_filesystem(
        "tmpfs",
        Box::new(|_src| Ok(Arc::new(RamFs) as Arc<dyn FileSystem>)),
    );
    register_filesystem(
        "devfs",
        Box::new(|_src| Ok(Arc::new(DevFs) as Arc<dyn FileSystem>)),
    );
    register_filesystem(
        "tarfs",
        Box::new(|_src| Ok(TarFs::new_arc() as Arc<dyn FileSystem>)),
    );
    #[cfg(feature = "ext2")]
    register_filesystem(
        "ext2",
        Box::new(|src| {
            // Per issue #625: when the caller supplies a `/dev/...`
            // path as the mount source, walk it through the namespace
            // to find the backing block device. With no source path
            // (or an empty one) fall back to the boot-time default
            // device — preserves the pre-#625 behaviour for the boot
            // path that mounts ext2 via `init_with(VirtioBlk)` without
            // going through `mount(2)`.
            let dev = match src {
                MountSource::Path(p) if !p.is_empty() => crate::fs::vfs::resolve_block_device(p)?,
                _ => crate::block::default_device().ok_or(crate::fs::ENODEV)?,
            };
            Ok(crate::fs::ext2::Ext2Fs::new_with_device(dev) as Arc<dyn FileSystem>)
        }),
    );
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
