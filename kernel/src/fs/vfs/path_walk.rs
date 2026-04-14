//! `path_walk` — the single resolver for every path-based syscall
//! (RFC 0002 §Path resolution).
//!
//! Owns POSIX §4.13: absolute vs. relative, `.`/`..`, trailing-slash
//! `DIRECTORY` upgrade, symlink follow (bounded by `SYMLOOP_MAX`),
//! mount crossing, and `ENAMETOOLONG` / `ENOTDIR` classification.
//!
//! Never recursive: a symlink whose target has its own unresolved
//! suffix is handled by splicing `link_target + remaining_suffix`
//! back into a heap-allocated expansion buffer and re-seating the
//! cursor, so deeply nested symlinks cost stack bytes, not frames.
//!
//! Mount crossing is plumbed through the [`MountResolver`] trait so
//! the resolver compiles and tests without the (not-yet-merged)
//! global `MOUNT_TABLE`. Production code will ship a
//! `GlobalMountResolver` whose `mount_above` walks `MOUNT_TABLE` to
//! find the edge whose `root_dentry` matches; the default
//! [`NullMountResolver`] reads `Dentry.mount` for down-crossing,
//! which is enough for single-FS use and for tests that simulate a
//! stacked mount graph by pre-installing edges.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::dentry::{Dentry, MountEdge};
use super::inode::{Inode, InodeKind};
use super::{Access, Credential, DString, NAME_MAX, SYMLOOP_MAX};
use crate::fs::{EINVAL, ELOOP, ENAMETOOLONG, ENOENT, ENOTDIR};

/// POSIX cap on a full pathname, including NUL. Also the upper bound
/// on the remaining-path expansion buffer after symlink splicing —
/// once the pending tail exceeds this, further splicing returns
/// `ENAMETOOLONG` (matches Linux `PATH_MAX`).
pub const PATH_MAX: usize = 4096;

// --- Flags / last-component enum / cursor ------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct LookupFlags(pub u32);

impl LookupFlags {
    pub const FOLLOW: LookupFlags = LookupFlags(1 << 0);
    pub const DIRECTORY: LookupFlags = LookupFlags(1 << 1);
    pub const PARENT: LookupFlags = LookupFlags(1 << 2);
    pub const AT_EMPTY_PATH: LookupFlags = LookupFlags(1 << 3);
    pub const NOFOLLOW: LookupFlags = LookupFlags(1 << 4);
    pub const NOAUTO_MOUNT_CROSS: LookupFlags = LookupFlags(1 << 5);

    pub const fn contains(self, other: LookupFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for LookupFlags {
    type Output = LookupFlags;
    fn bitor(self, rhs: Self) -> Self {
        LookupFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for LookupFlags {
    type Output = LookupFlags;
    fn bitand(self, rhs: Self) -> Self {
        LookupFlags(self.0 & rhs.0)
    }
}

/// Classification of the final component. Creator syscalls (`create`,
/// `mkdir`, …) consult this to refuse reserved names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Last {
    /// A concrete component name. Caller can `mkdir`/`create` against it.
    Norm(DString),
    /// Resolution ended at the process root (`/` only, or `/..` at root).
    Root,
    /// Final component was `.`.
    Dot,
    /// Final component was `..`.
    DotDot,
}

/// Walk cursor: the current (dentry, inode) pair.
#[derive(Clone)]
pub struct Path {
    pub dentry: Arc<Dentry>,
    pub inode: Arc<Inode>,
}

pub struct NameIdata {
    pub root: Arc<Dentry>,
    pub cwd: Arc<Dentry>,
    pub path: Path,
    pub last: Last,
    pub flags: LookupFlags,
    pub symlink_depth: u32,
    pub cred: Credential,
    /// Every `MountEdge` the walker crossed. Retained so the
    /// corresponding `SuperBlock`s stay pinned for the duration of the
    /// walk. Dropped when `NameIdata` drops.
    pub edges: Vec<Arc<MountEdge>>,
}

impl NameIdata {
    /// Seed a fresh walk. `path` starts at `cwd`; if the caller knows
    /// the path is absolute, pass `cwd == root` — `path_walk`'s step 1
    /// will reseat anyway on the leading `/`.
    pub fn new(
        root: Arc<Dentry>,
        cwd: Arc<Dentry>,
        cred: Credential,
        flags: LookupFlags,
    ) -> Result<Self, i64> {
        let cwd_inode = cwd.inode.read().clone().ok_or(ENOENT)?;
        let path = Path {
            dentry: cwd.clone(),
            inode: cwd_inode,
        };
        Ok(Self {
            root,
            cwd,
            path,
            last: Last::Root,
            flags,
            symlink_depth: 0,
            cred,
            edges: Vec::new(),
        })
    }

    /// Override the starting cursor (used by `*at` syscalls when the fd
    /// is not `AT_FDCWD` and the path is relative).
    pub fn seed_from_dentry(&mut self, d: Arc<Dentry>) -> Result<(), i64> {
        let ino = d.inode.read().clone().ok_or(ENOENT)?;
        self.path = Path {
            dentry: d,
            inode: ino,
        };
        Ok(())
    }
}

// --- Mount-resolution seam --------------------------------------------

/// Decouples `path_walk` from the global `MOUNT_TABLE` (issue #233).
/// Production code ships a resolver backed by `MOUNT_TABLE.read()`;
/// tests supply a fake that simulates arbitrary mount topologies.
pub trait MountResolver: Send + Sync {
    /// If `d` is a mountpoint, return the edge whose `root_dentry` the
    /// walker should jump to. `None` when `d` is not a mount point or
    /// when `NOAUTO_MOUNT_CROSS` disables down-crossing.
    fn mount_below(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>>;

    /// Given a dentry that is the root of some mount, return the edge
    /// whose `root_dentry == d` so the walker can jump up to the
    /// mountpoint in the parent FS. `None` at the namespace root.
    fn mount_above(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>>;
}

/// Default resolver: reads `Dentry.mount` for down-crossing, never
/// crosses upward (the parent-side table doesn't exist yet). Enough
/// for single-FS walks and for every test that installs its mount
/// edges directly on `Dentry.mount` slots.
pub struct NullMountResolver;

impl MountResolver for NullMountResolver {
    fn mount_below(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        d.mount.read().clone()
    }
    fn mount_above(&self, _d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
        None
    }
}

// --- Resolver ---------------------------------------------------------

/// Resolve `path` against `nd`. On success `nd.path` is the resolved
/// (dentry, inode) and `nd.last` describes the final component.
///
/// Honours every flag on `nd.flags`: `AT_EMPTY_PATH`, `DIRECTORY`,
/// `FOLLOW`/`NOFOLLOW` on the final component, `NOAUTO_MOUNT_CROSS`.
pub fn path_walk(nd: &mut NameIdata, path: &[u8], mounts: &dyn MountResolver) -> Result<(), i64> {
    // Step 1 — empty path.
    if path.is_empty() {
        if nd.flags.contains(LookupFlags::AT_EMPTY_PATH) {
            nd.last = Last::Root;
            return final_checks(nd);
        }
        return Err(ENOENT);
    }
    if path.len() > PATH_MAX {
        return Err(ENAMETOOLONG);
    }
    if path.iter().any(|&b| b == 0) {
        return Err(EINVAL);
    }

    // The walker consumes a byte cursor. Symlink expansion splices
    // `link_target + unread_tail` into a fresh heap buffer and
    // re-points the cursor at byte 0 of the new buffer. `buf` owns
    // the currently-active byte string; `cur` is our read index.
    let mut buf: Vec<u8> = path.to_vec();
    let mut cur: usize = 0;

    // Step 2 — seed the cursor. Absolute paths reseat to nd.root.
    if buf.first() == Some(&b'/') {
        let root_inode = nd.root.inode.read().clone().ok_or(ENOENT)?;
        nd.path = Path {
            dentry: nd.root.clone(),
            inode: root_inode,
        };
        // Consume the leading slashes.
        while cur < buf.len() && buf[cur] == b'/' {
            cur += 1;
        }
    }
    // If the path is e.g. "/" the loop body never runs and Last stays Root.
    if cur >= buf.len() {
        nd.last = Last::Root;
        return final_checks(nd);
    }

    // Step 3 — iterative component walk.
    loop {
        // Carve the next component out of buf[cur..].
        let comp_end = buf[cur..]
            .iter()
            .position(|&b| b == b'/')
            .map(|p| cur + p)
            .unwrap_or(buf.len());
        let comp = &buf[cur..comp_end];
        // Is there anything after this component?
        let mut after = comp_end;
        let mut had_trailing_slash = false;
        while after < buf.len() && buf[after] == b'/' {
            after += 1;
            had_trailing_slash = true;
        }
        let is_final = after >= buf.len();
        // A trailing slash with no following component upgrades to
        // DIRECTORY (POSIX §4.13). Intermediate `//` is just eaten.
        if is_final && had_trailing_slash {
            nd.flags = nd.flags | LookupFlags::DIRECTORY;
        }

        if comp.is_empty() {
            // Leading "/" was consumed above; any empty component here
            // comes from a trailing slash — treat the cursor as done.
            nd.last = match &nd.last {
                // keep whatever classification we had (e.g. ".." at root)
                _ if Arc::ptr_eq(&nd.path.dentry, &nd.root) => Last::Root,
                _ => nd.last.clone(),
            };
            return final_checks(nd);
        }

        if comp == b"." {
            nd.last = Last::Dot;
        } else if comp == b".." {
            step_dotdot(nd, mounts)?;
            nd.last = Last::DotDot;
        } else {
            if comp.len() > NAME_MAX {
                return Err(ENAMETOOLONG);
            }
            // Search-permission on the parent (POSIX §4.13, may_lookup).
            nd.path
                .inode
                .ops
                .permission(&nd.path.inode, &nd.cred, Access::EXECUTE)?;

            let name = DString::try_from_bytes(comp)?;
            let child_inode = nd.path.inode.ops.lookup(&nd.path.inode, comp)?;
            let child_dentry = Dentry::new(
                name.clone(),
                Arc::downgrade(&nd.path.dentry),
                Some(child_inode.clone()),
            );
            nd.path = Path {
                dentry: child_dentry,
                inode: child_inode,
            };
            nd.last = Last::Norm(name);

            // Down-cross a mount if one is installed on this dentry.
            if !nd.flags.contains(LookupFlags::NOAUTO_MOUNT_CROSS) {
                if let Some(edge) = mounts.mount_below(&nd.path.dentry) {
                    let root = edge.root_dentry.clone();
                    let root_inode = root.inode.read().clone().ok_or(ENOENT)?;
                    nd.path = Path {
                        dentry: root,
                        inode: root_inode,
                    };
                    nd.edges.push(edge);
                }
            }

            // Symlink? Follow if not final, or final + FOLLOW.
            if nd.path.inode.kind == InodeKind::Link {
                let should_follow = !is_final
                    || (nd.flags.contains(LookupFlags::FOLLOW)
                        && !nd.flags.contains(LookupFlags::NOFOLLOW));
                if is_final && nd.flags.contains(LookupFlags::NOFOLLOW) {
                    return Err(ELOOP);
                }
                if should_follow {
                    nd.symlink_depth = nd.symlink_depth.saturating_add(1);
                    if nd.symlink_depth > SYMLOOP_MAX {
                        return Err(ELOOP);
                    }
                    // Splice: link_target + remaining_tail.
                    let mut target = [0u8; PATH_MAX];
                    let n = nd.path.inode.ops.readlink(&nd.path.inode, &mut target)?;
                    let tail = &buf[after..];
                    let total = n
                        .checked_add(if tail.is_empty() { 0 } else { 1 + tail.len() })
                        .ok_or(ENAMETOOLONG)?;
                    if total > PATH_MAX {
                        return Err(ENAMETOOLONG);
                    }
                    let mut spliced: Vec<u8> = Vec::with_capacity(total);
                    spliced.extend_from_slice(&target[..n]);
                    if !tail.is_empty() {
                        spliced.push(b'/');
                        spliced.extend_from_slice(tail);
                    }
                    // If the target is absolute, reseat to root and skip
                    // its leading slashes; else walk from the *parent*
                    // of the link (we already moved the cursor onto the
                    // link itself, so back up one).
                    let reseat_absolute = spliced.first() == Some(&b'/');
                    buf = spliced;
                    cur = 0;
                    if reseat_absolute {
                        let root_inode = nd.root.inode.read().clone().ok_or(ENOENT)?;
                        nd.path = Path {
                            dentry: nd.root.clone(),
                            inode: root_inode,
                        };
                        while cur < buf.len() && buf[cur] == b'/' {
                            cur += 1;
                        }
                    } else {
                        // Back up to the parent the link lived in.
                        let parent = nd.path.dentry.parent.upgrade().ok_or(ENOENT)?;
                        let parent_inode = parent.inode.read().clone().ok_or(ENOENT)?;
                        nd.path = Path {
                            dentry: parent,
                            inode: parent_inode,
                        };
                    }
                    // Restart outer loop with the new buffer.
                    if cur >= buf.len() {
                        nd.last = Last::Root;
                        return final_checks(nd);
                    }
                    continue;
                }
            }
        }

        if is_final {
            return final_checks(nd);
        }
        cur = after;
    }
}

fn step_dotdot(nd: &mut NameIdata, mounts: &dyn MountResolver) -> Result<(), i64> {
    // ".." at the process root stays at root.
    if Arc::ptr_eq(&nd.path.dentry, &nd.root) {
        return Ok(());
    }
    // If we're sitting on an FS root (other than the process root),
    // jump across the mount edge to the mountpoint in the parent FS.
    if let Some(edge) = mounts.mount_above(&nd.path.dentry) {
        let mp = edge.mountpoint.upgrade().ok_or(ENOENT)?;
        let mp_inode = mp.inode.read().clone().ok_or(ENOENT)?;
        nd.path = Path {
            dentry: mp,
            inode: mp_inode,
        };
        return Ok(());
    }
    // Normal upward step inside the same FS.
    let parent = nd.path.dentry.parent.upgrade().ok_or(ENOENT)?;
    let parent_inode = parent.inode.read().clone().ok_or(ENOENT)?;
    nd.path = Path {
        dentry: parent,
        inode: parent_inode,
    };
    Ok(())
}

fn final_checks(nd: &NameIdata) -> Result<(), i64> {
    // POSIX §4.13: DIRECTORY on a non-dir, or a trailing slash on a
    // non-dir, is `ENOTDIR`. path_walk OR-s `DIRECTORY` into `nd.flags`
    // whenever it saw a trailing slash, so the one check covers both.
    if nd.flags.contains(LookupFlags::DIRECTORY) && nd.path.inode.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Host tests — pure-logic coverage. Kernel-mode integration tests will
// arrive with #233 once a real MOUNT_TABLE exists.
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::dentry::MountEdge;
    use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
    use crate::fs::vfs::ops::{FileOps, InodeOps, SetAttr, Stat, StatFs, SuperOps};
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::{FsId, MountFlags};
    use alloc::collections::BTreeMap;
    use alloc::sync::{Arc, Weak};
    use alloc::vec;
    use alloc::vec::Vec;
    use spin::Mutex;

    // -------- Test harness: a BTreeMap-backed "FS" -----------------
    //
    // Tree layout for the default fixture:
    //   /          (dir, ino=1)
    //     a/       (dir, ino=2)
    //       b      (reg, ino=3)
    //       c      (reg, ino=4)
    //     l -> a   (link, ino=5, target="a")
    //     babs -> /a/b    (link, ino=6)
    //     loop1 -> loop2, loop2 -> loop1  (link, ino=7, 8)
    //     selfloop -> selfloop           (link, ino=9)
    //     chain1..chain5 -> chainN+1, final -> /a/b  (ino=10..15)
    //     notadir  (reg, ino=16)

    struct FakeFs {
        /// (parent ino, name) -> child inode
        children: Mutex<BTreeMap<(u64, Vec<u8>), Arc<Inode>>>,
        /// inode -> symlink target bytes (for readlink)
        links: Mutex<BTreeMap<u64, Vec<u8>>>,
    }

    struct FakeOps(Arc<FakeFs>);
    impl InodeOps for FakeOps {
        fn lookup(&self, dir: &Inode, name: &[u8]) -> Result<Arc<Inode>, i64> {
            self.0
                .children
                .lock()
                .get(&(dir.ino, name.to_vec()))
                .cloned()
                .ok_or(ENOENT)
        }
        fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
        fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
            Ok(())
        }
        fn permission(&self, _i: &Inode, _c: &Credential, _a: Access) -> Result<(), i64> {
            Ok(())
        }
        fn readlink(&self, inode: &Inode, buf: &mut [u8]) -> Result<usize, i64> {
            let links = self.0.links.lock();
            let t = links.get(&inode.ino).ok_or(EINVAL)?;
            if t.len() > buf.len() {
                return Err(ENAMETOOLONG);
            }
            buf[..t.len()].copy_from_slice(t);
            Ok(t.len())
        }
    }

    struct FakeFile;
    impl FileOps for FakeFile {}
    struct FakeSuper;
    impl SuperOps for FakeSuper {
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

    fn mk_inode(ino: u64, kind: InodeKind, fs: Arc<FakeFs>, sb: Weak<SuperBlock>) -> Arc<Inode> {
        Arc::new(Inode::new(
            ino,
            sb,
            Arc::new(FakeOps(fs)),
            Arc::new(FakeFile),
            kind,
            InodeMeta {
                mode: 0o755,
                nlink: 1,
                ..Default::default()
            },
        ))
    }

    struct Fixture {
        root: Arc<Dentry>,
        fs: Arc<FakeFs>,
    }

    fn build() -> Fixture {
        let fs = Arc::new(FakeFs {
            children: Mutex::new(BTreeMap::new()),
            links: Mutex::new(BTreeMap::new()),
        });
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(FakeSuper),
            "fake",
            512,
            SbFlags::default(),
        ));

        let root_inode = mk_inode(1, InodeKind::Dir, fs.clone(), Arc::downgrade(&sb));
        let a = mk_inode(2, InodeKind::Dir, fs.clone(), Arc::downgrade(&sb));
        let b = mk_inode(3, InodeKind::Reg, fs.clone(), Arc::downgrade(&sb));
        let c = mk_inode(4, InodeKind::Reg, fs.clone(), Arc::downgrade(&sb));
        let l = mk_inode(5, InodeKind::Link, fs.clone(), Arc::downgrade(&sb));
        let babs = mk_inode(6, InodeKind::Link, fs.clone(), Arc::downgrade(&sb));
        let loop1 = mk_inode(7, InodeKind::Link, fs.clone(), Arc::downgrade(&sb));
        let loop2 = mk_inode(8, InodeKind::Link, fs.clone(), Arc::downgrade(&sb));
        let selfloop = mk_inode(9, InodeKind::Link, fs.clone(), Arc::downgrade(&sb));
        let notadir = mk_inode(16, InodeKind::Reg, fs.clone(), Arc::downgrade(&sb));

        {
            let mut ch = fs.children.lock();
            ch.insert((1, b"a".to_vec()), a.clone());
            ch.insert((1, b"l".to_vec()), l.clone());
            ch.insert((1, b"babs".to_vec()), babs.clone());
            ch.insert((1, b"loop1".to_vec()), loop1.clone());
            ch.insert((1, b"loop2".to_vec()), loop2.clone());
            ch.insert((1, b"selfloop".to_vec()), selfloop.clone());
            ch.insert((1, b"notadir".to_vec()), notadir.clone());
            ch.insert((2, b"b".to_vec()), b.clone());
            ch.insert((2, b"c".to_vec()), c.clone());
        }
        {
            let mut li = fs.links.lock();
            li.insert(5, b"a".to_vec());
            li.insert(6, b"/a/b".to_vec());
            li.insert(7, b"loop2".to_vec());
            li.insert(8, b"loop1".to_vec());
            li.insert(9, b"selfloop".to_vec());
        }

        let root = Dentry::new_root(root_inode);
        Fixture { root, fs }
    }

    fn new_nd(fx: &Fixture, flags: LookupFlags) -> NameIdata {
        NameIdata::new(
            fx.root.clone(),
            fx.root.clone(),
            Credential::kernel(),
            flags,
        )
        .unwrap()
    }

    #[test]
    fn absolute_path_to_regular_file() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/a/b", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);
    }

    #[test]
    fn relative_path_from_cwd() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"a/b", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);
    }

    #[test]
    fn dot_and_dotdot() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/a/./b", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);

        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/a/../a/b", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);
    }

    #[test]
    fn dotdot_at_root_is_root() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/..", &NullMountResolver).unwrap();
        assert!(Arc::ptr_eq(&nd.path.dentry, &fx.root));
    }

    #[test]
    fn root_path_only_slash() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/", &NullMountResolver).unwrap();
        assert!(Arc::ptr_eq(&nd.path.dentry, &fx.root));
        assert_eq!(nd.last, Last::Root);
    }

    #[test]
    fn follow_relative_symlink() {
        let fx = build();
        // /l -> "a", so /l/b ⇒ /a/b
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/l/b", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);
    }

    #[test]
    fn follow_absolute_symlink() {
        let fx = build();
        // /babs -> "/a/b", followed because FOLLOW is set on final.
        let mut nd = new_nd(&fx, LookupFlags::FOLLOW);
        path_walk(&mut nd, b"/babs", &NullMountResolver).unwrap();
        assert_eq!(nd.path.inode.ino, 3);
    }

    #[test]
    fn nofollow_on_final_symlink_returns_eloop() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::NOFOLLOW);
        let e = path_walk(&mut nd, b"/l", &NullMountResolver);
        assert_eq!(e, Err(ELOOP));
    }

    #[test]
    fn symlink_loop_hits_symloop_max() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::FOLLOW);
        let e = path_walk(&mut nd, b"/selfloop", &NullMountResolver);
        assert_eq!(e, Err(ELOOP));
        assert!(nd.symlink_depth > SYMLOOP_MAX);
    }

    #[test]
    fn symlink_depth_is_counter_not_recursion() {
        // /loop1 -> loop2, /loop2 -> loop1: each follow increments the
        // counter by one, so SYMLOOP_MAX+1 follows should trip ELOOP.
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::FOLLOW);
        let e = path_walk(&mut nd, b"/loop1", &NullMountResolver);
        assert_eq!(e, Err(ELOOP));
    }

    #[test]
    fn trailing_slash_on_nondir_is_enotdir() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let e = path_walk(&mut nd, b"/a/b/", &NullMountResolver);
        assert_eq!(e, Err(ENOTDIR));
    }

    #[test]
    fn directory_flag_on_nondir_is_enotdir() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::DIRECTORY);
        let e = path_walk(&mut nd, b"/a/b", &NullMountResolver);
        assert_eq!(e, Err(ENOTDIR));
    }

    #[test]
    fn component_too_long_is_enametoolong() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let long: Vec<u8> = core::iter::repeat(b'x').take(NAME_MAX + 1).collect();
        let mut p: Vec<u8> = Vec::new();
        p.push(b'/');
        p.extend_from_slice(&long);
        let e = path_walk(&mut nd, &p, &NullMountResolver);
        assert_eq!(e, Err(ENAMETOOLONG));
    }

    #[test]
    fn total_path_too_long_is_enametoolong() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let p: Vec<u8> = core::iter::repeat(b'a').take(PATH_MAX + 1).collect();
        let e = path_walk(&mut nd, &p, &NullMountResolver);
        assert_eq!(e, Err(ENAMETOOLONG));
    }

    #[test]
    fn empty_path_without_flag_is_enoent() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let e = path_walk(&mut nd, b"", &NullMountResolver);
        assert_eq!(e, Err(ENOENT));
    }

    #[test]
    fn empty_path_with_at_empty_path_returns_cwd() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::AT_EMPTY_PATH);
        path_walk(&mut nd, b"", &NullMountResolver).unwrap();
        assert!(Arc::ptr_eq(&nd.path.dentry, &fx.root));
    }

    #[test]
    fn nul_byte_in_path_is_einval() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let e = path_walk(&mut nd, b"/a\0b", &NullMountResolver);
        assert_eq!(e, Err(EINVAL));
    }

    #[test]
    fn mount_crossing_down() {
        // Build two filesystems and plumb an edge: /a on the parent is
        // the mount point; crossing it lands at the child's root, which
        // in turn has a file "x" (ino=99 on the child FS).
        let fx_parent = build();
        let fx_child = {
            let fs = Arc::new(FakeFs {
                children: Mutex::new(BTreeMap::new()),
                links: Mutex::new(BTreeMap::new()),
            });
            let sb = Arc::new(SuperBlock::new(
                FsId(2),
                Arc::new(FakeSuper),
                "fake2",
                512,
                SbFlags::default(),
            ));
            let root_inode = mk_inode(50, InodeKind::Dir, fs.clone(), Arc::downgrade(&sb));
            let x = mk_inode(99, InodeKind::Reg, fs.clone(), Arc::downgrade(&sb));
            fs.children.lock().insert((50, b"x".to_vec()), x);
            Fixture {
                root: Dentry::new_root(root_inode),
                fs,
            }
        };

        // Install a MountEdge on the parent's "a" dentry, so walking
        // into /a/x ends on ino=99 via the child root.
        // First, make sure /a is present in the parent's children-dentry
        // cache (path_walk constructs a fresh dentry each lookup; our
        // MountResolver only sees that fresh dentry's `mount` slot).
        // Easiest: supply a resolver that matches by inode ino.
        struct InoResolver {
            ino_to_edge: BTreeMap<u64, Arc<MountEdge>>,
        }
        impl MountResolver for InoResolver {
            fn mount_below(&self, d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
                let i = d.inode.read();
                let i = i.as_ref()?;
                self.ino_to_edge.get(&i.ino).cloned()
            }
            fn mount_above(&self, _d: &Arc<Dentry>) -> Option<Arc<MountEdge>> {
                None
            }
        }
        let parent_sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(FakeSuper),
            "fake",
            512,
            SbFlags::default(),
        ));
        let edge = Arc::new(MountEdge {
            mountpoint: Arc::downgrade(&fx_parent.root), // placeholder
            super_block: parent_sb,
            root_dentry: fx_child.root.clone(),
            flags: MountFlags::default(),
        });
        let mut map = BTreeMap::new();
        map.insert(2u64, edge); // ino=2 is /a in the parent tree
        let resolver = InoResolver { ino_to_edge: map };

        let mut nd = new_nd(&fx_parent, LookupFlags::default());
        path_walk(&mut nd, b"/a/x", &resolver).unwrap();
        assert_eq!(nd.path.inode.ino, 99);
        assert_eq!(nd.edges.len(), 1);
        // Suppress the unused-fs-child warning.
        let _ = fx_child.fs.children.lock().len();
    }

    #[test]
    fn nonexistent_child_is_enoent() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        let e = path_walk(&mut nd, b"/nope", &NullMountResolver);
        assert_eq!(e, Err(ENOENT));
    }

    #[test]
    fn last_is_norm_for_named_final() {
        let fx = build();
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/a/b", &NullMountResolver).unwrap();
        match &nd.last {
            Last::Norm(n) => assert_eq!(n.as_bytes(), b"b"),
            other => panic!("expected Norm(b), got {:?}", other),
        }
    }

    #[test]
    fn seed_from_dentry_relative_walk() {
        let fx = build();
        // Walk to /a, then seed a new nd from that dentry and resolve "b".
        let mut nd = new_nd(&fx, LookupFlags::default());
        path_walk(&mut nd, b"/a", &NullMountResolver).unwrap();
        let a_dentry = nd.path.dentry.clone();

        let mut nd2 = new_nd(&fx, LookupFlags::default());
        nd2.seed_from_dentry(a_dentry).unwrap();
        path_walk(&mut nd2, b"b", &NullMountResolver).unwrap();
        assert_eq!(nd2.path.inode.ino, 3);
        let _ = vec![0u8]; // touch `vec!` macro import so future tests can use it
    }
}
