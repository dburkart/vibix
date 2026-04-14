//! Virtual filesystem core types.
//!
//! Foundation for RFC 0002 — every path-based syscall ultimately
//! resolves through these objects. Concrete filesystems (ramfs, tarfs,
//! devfs) plug in by implementing [`FileSystem`] and the three
//! operation traits [`SuperOps`], [`InodeOps`], [`FileOps`].
//!
//! No drivers live here yet; this module establishes the type layout
//! and the invariants, so later roadmap items can build on it without
//! retrofitting.
//!
//! ## Object relationships
//!
//! ```text
//!   SuperBlock (per mounted FS instance)
//!     ├── Arc<dyn SuperOps>
//!     └── root: Arc<Inode>
//!
//!   Inode  ── Weak<SuperBlock>   // breaks the SB→Inode→SB cycle
//!     ├── Arc<dyn InodeOps>
//!     └── Arc<dyn FileOps>       // for regular files
//!
//!   Dentry (cache-name-to-Inode)
//!     ├── Weak<Dentry> parent    // root self-parent via Arc::new_cyclic
//!     ├── Option<Arc<Inode>>     // None == negative dentry
//!     ├── Option<Arc<MountEdge>> // Some when this dentry is a mountpoint
//!     └── BTreeMap<DString, ChildState>
//!
//!   OpenFile (per sys_open success)
//!     ├── Arc<Dentry>
//!     ├── Arc<Inode>
//!     └── Arc<SuperBlock>        // strong — anchors SB lifetime
//! ```
//!
//! ## Threading
//!
//! Every type here is `Send + Sync`. Concurrent access is protected by
//! the primitives in [`crate::sync`]: [`crate::sync::BlockingRwLock`]
//! on `Inode.dir_rwsem` / `Inode.meta` / `Dentry.children` /
//! `Dentry.inode` / `Dentry.mount`; [`crate::sync::BlockingMutex`] on
//! `SuperBlock.rename_mutex` and `Inode.state`;
//! [`crate::sync::Semaphore`] on `ChildState::Loading`.

#![allow(dead_code)]

use alloc::vec::Vec;

pub mod dentry;
pub mod inode;
pub mod open_file;
pub mod ops;
pub mod path_walk;
pub mod super_block;

pub use dentry::{ChildState, DFlags, Dentry, MountEdge, MountFlags};
pub use inode::{Inode, InodeKind, InodeMeta, InodeState};
pub use open_file::OpenFile;
pub use ops::{
    default_permission, FileOps, FileSystem, InodeOps, MountSource, SetAttr, SetAttrMask, Stat,
    StatFs, SuperOps, Whence,
};
pub use path_walk::{
    path_walk, Last, LookupFlags, MountResolver, NameIdata, NullMountResolver, Path, PATH_MAX,
};
pub use super_block::{SbActiveGuard, SbFlags, SuperBlock};

/// POSIX-imposed cap on a single path component.
pub const NAME_MAX: usize = 255;

/// POSIX-imposed cap on symlink-follow depth during `path_walk`.
pub const SYMLOOP_MAX: u32 = 40;

/// Unique identifier for a mounted FS instance. Assigned by
/// `MountTable::mount`; stable for the lifetime of the [`SuperBlock`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct FsId(pub u64);

/// Wall-clock timestamp, POSIX `struct timespec` layout.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: u32,
}

/// Caller credentials consulted by [`InodeOps::permission`].
///
/// `Default` is deliberately not implemented: a default-constructed
/// `Credential` would be uid 0, which `default_permission` treats as
/// the root bypass — that would let any caller who reaches for
/// `Credential::default()` accidentally elevate. Construct via
/// [`Credential::kernel`] (root) or by setting fields explicitly.
#[derive(Clone, Debug)]
pub struct Credential {
    pub uid: u32,
    pub gid: u32,
    pub groups: Vec<u32>,
}

impl Credential {
    /// Kernel-internal credential: root. Use only from kernel code
    /// paths that are not acting on behalf of a userspace task.
    pub fn kernel() -> Self {
        Self {
            uid: 0,
            gid: 0,
            groups: Vec::new(),
        }
    }
}

/// Access modes checked against `InodeMeta.mode` by
/// [`default_permission`]. Mirrors the low three bits of POSIX
/// `access(2)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Access(pub u32);

impl Access {
    pub const READ: Access = Access(1 << 2); // R_OK
    pub const WRITE: Access = Access(1 << 1); // W_OK
    pub const EXECUTE: Access = Access(1 << 0); // X_OK
    pub const NONE: Access = Access(0);

    pub const fn bits(self) -> u32 {
        self.0
    }
    pub const fn contains(self, other: Access) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for Access {
    type Output = Access;
    fn bitor(self, rhs: Self) -> Self {
        Access(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Access {
    type Output = Access;
    fn bitand(self, rhs: Self) -> Self {
        Access(self.0 & rhs.0)
    }
}

/// Bounded directory-entry name. Allocates on the heap (we're always
/// in task context for VFS work) but caps the length at [`NAME_MAX`]
/// bytes — longer names are rejected at construction time with
/// `ENAMETOOLONG`.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DString {
    bytes: Vec<u8>,
}

impl DString {
    /// Construct from a byte slice. Rejects empty names, names longer
    /// than [`NAME_MAX`], and names containing `/` or NUL (both
    /// illegal per POSIX §4.5).
    pub fn try_from_bytes(s: &[u8]) -> Result<Self, i64> {
        if s.is_empty() || s.len() > NAME_MAX {
            return Err(super::ENAMETOOLONG);
        }
        if s.iter().any(|&b| b == b'/' || b == 0) {
            return Err(super::EINVAL);
        }
        Ok(Self { bytes: s.to_vec() })
    }

    /// Raw bytes. No trailing NUL.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

// Every type that appears in this module (or its submodules) must be
// Send + Sync so it can live behind `Arc` and be shared across tasks.
// If any of these loses `Send + Sync` during a refactor, the kernel
// fails to build.
const _: () = {
    const fn assert_send_sync<T: ?Sized + Send + Sync>() {}
    assert_send_sync::<FsId>();
    assert_send_sync::<Timespec>();
    assert_send_sync::<Credential>();
    assert_send_sync::<Access>();
    assert_send_sync::<DString>();
    assert_send_sync::<SuperBlock>();
    assert_send_sync::<Inode>();
    assert_send_sync::<InodeMeta>();
    assert_send_sync::<InodeState>();
    assert_send_sync::<Dentry>();
    assert_send_sync::<MountEdge>();
    assert_send_sync::<OpenFile>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dstring_rejects_empty() {
        assert!(DString::try_from_bytes(b"").is_err());
    }

    #[test]
    fn dstring_rejects_too_long() {
        let long = [b'a'; NAME_MAX + 1];
        assert!(DString::try_from_bytes(&long).is_err());
    }

    #[test]
    fn dstring_accepts_max_length() {
        let at_limit = [b'a'; NAME_MAX];
        assert!(DString::try_from_bytes(&at_limit).is_ok());
    }

    #[test]
    fn dstring_rejects_slash() {
        assert!(DString::try_from_bytes(b"foo/bar").is_err());
    }

    #[test]
    fn dstring_rejects_nul() {
        assert!(DString::try_from_bytes(b"foo\0bar").is_err());
    }

    #[test]
    fn dstring_roundtrip() {
        let d = DString::try_from_bytes(b"hello").unwrap();
        assert_eq!(d.as_bytes(), b"hello");
        assert_eq!(d.len(), 5);
        assert!(!d.is_empty());
    }

    #[test]
    fn access_bitflags() {
        let a = Access::READ | Access::EXECUTE;
        assert!(a.contains(Access::READ));
        assert!(!a.contains(Access::WRITE));
        assert!(a.contains(Access::EXECUTE));
    }
}
