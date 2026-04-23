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

pub mod backend;
pub mod dentry;
pub mod devfs;
pub mod gc_queue;
pub mod init;
pub mod inode;
pub mod mount_table;
pub mod open_file;
pub mod ops;
pub mod path_walk;
pub mod ramfs;
pub mod registry;
pub mod super_block;
pub mod tarfs;

pub use backend::VfsBackend;
pub use dentry::{ChildState, DFlags, Dentry, MountEdge, MountFlags};
pub use devfs::DevFs;
pub use gc_queue::{gc_drain, gc_drain_for, gc_overflow_count, gc_pending_count};
pub use init::{init, root};
pub use inode::{Inode, InodeKind, InodeMeta, InodeState};
pub use mount_table::{alloc_fs_id, mount, unmount, GlobalMountResolver, UmountFlags, MOUNT_TABLE};
pub use open_file::OpenFile;
pub use ops::{
    default_permission, FileOps, FileSystem, InodeOps, MountSource, SetAttr, SetAttrMask, Stat,
    StatFs, SuperOps, Whence,
};
pub use path_walk::{
    path_walk, Last, LookupFlags, MountResolver, NameIdata, NullMountResolver, Path, PATH_MAX,
};
pub use ramfs::RamFs;
pub use registry::{is_registered, lookup_and_build, register_filesystem, FsFactory};
pub use super_block::{SbActiveGuard, SbFlags, SuperBlock};
pub use tarfs::TarFs;

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

impl Timespec {
    /// Current wall-clock as a `Timespec`.
    ///
    /// Uses monotonic uptime (`crate::time::uptime_ns`) as the time
    /// source — it's always available, strictly monotonic, and cheap
    /// on both the kernel target and the host test build. The RTC is
    /// not queried here: it only resolves to 1-second precision and is
    /// a stub on the host. For filesystem timestamps that is fine —
    /// callers that want absolute wall-clock correctness must feed it
    /// through NTP / a userspace date service that adjusts the VFS
    /// epoch; an in-kernel "touch" syscall just needs a value that
    /// moves forward on each call.
    pub fn now() -> Self {
        let ns = crate::time::uptime_ns();
        Self {
            sec: (ns / 1_000_000_000) as i64,
            nsec: (ns % 1_000_000_000) as u32,
        }
    }
}

/// Caller credentials consulted by [`InodeOps::permission`].
///
/// Carries the full POSIX.1-2017 §2.4 saved-set-user-ID model: a real,
/// effective, and saved ID for both user and group, plus the
/// supplementary-group list. [`default_permission`] (and conforming
/// overrides of `InodeOps::permission`) consult the **effective** IDs
/// — `euid`, `egid`, `groups` — for access decisions; the real and
/// saved IDs exist so `setuid`/`setresuid` and friends can implement
/// the "drop privilege, reclaim later" pattern POSIX requires.
///
/// `Credential` values are immutable once constructed. A mid-syscall
/// credential change (another thread running `setuid`) builds a fresh
/// `Credential` and swaps the `Arc` inside
/// [`Task::credentials`](crate::task::Task) — syscall entries clone the
/// `Arc` once and carry that snapshot through the rest of the operation
/// so a concurrent change cannot tear the read.
///
/// `Default` is deliberately not implemented: a default-constructed
/// `Credential` would be uid 0, which `default_permission` treats as
/// the root bypass — that would let any caller who reaches for
/// `Credential::default()` accidentally elevate. Prefer
/// [`Credential::from_task_ids`] for a full six-ID construction from a
/// task snapshot; direct field-literal construction elsewhere in the
/// kernel is discouraged and should be limited to tests and the
/// privileged [`Credential::kernel`] helper.
#[derive(Clone, Debug)]
pub struct Credential {
    /// Real user ID (`getuid(2)`). The login identity; does not change
    /// on `setuid(2)` by an unprivileged process.
    pub uid: u32,
    /// Effective user ID (`geteuid(2)`). The identity consulted for
    /// DAC checks. Equal to `uid` for most processes; differs after
    /// `setuid(2)` or exec of a setuid binary.
    pub euid: u32,
    /// Saved set-user-ID (POSIX §2.4). Remembers a prior effective ID
    /// so an unprivileged process that temporarily dropped `euid` can
    /// reclaim it via `seteuid(suid)`.
    pub suid: u32,
    /// Real group ID (`getgid(2)`).
    pub gid: u32,
    /// Effective group ID (`getegid(2)`). Consulted for DAC group-bit
    /// checks alongside [`Self::groups`].
    pub egid: u32,
    /// Saved set-group-ID (POSIX §2.4). Group-side counterpart of
    /// [`Self::suid`].
    pub sgid: u32,
    /// Supplementary group list (`getgroups(2)`). A caller matches the
    /// group access bits of a file if `egid` OR any entry here equals
    /// the file's group.
    pub groups: Vec<u32>,
}

impl Credential {
    /// Kernel-internal credential: root on every ID. Use only from
    /// kernel code paths that are not acting on behalf of a userspace
    /// task (initial mount, kernel-thread I/O, test fixtures).
    ///
    /// Production userspace-driven VFS syscalls must **not** reach for
    /// this helper: they read the caller's per-task snapshot via
    /// `task.credentials.read().clone()` instead. Using
    /// `Credential::kernel()` on a userspace-initiated path is an
    /// unauthenticated full-DAC bypass (RFC 0004 §Security
    /// Considerations); the RFC 0004 Workstream A ↔ B CI gate and the
    /// `#[cfg(feature = "vfs_creds")]` guard on syscall dispatch arms
    /// exist specifically to prevent that regression while the
    /// Workstream B syscall wiring is still in progress.
    pub fn kernel() -> Self {
        Self {
            uid: 0,
            euid: 0,
            suid: 0,
            gid: 0,
            egid: 0,
            sgid: 0,
            groups: Vec::new(),
        }
    }

    /// Build a `Credential` from the full six-ID saved-set-user-ID
    /// tuple plus a supplementary group list. This is the preferred
    /// constructor for non-root credentials: it takes every field at
    /// once so forgetting one is a compile error rather than a silent
    /// `0` that reads as root.
    ///
    /// Field-literal construction (`Credential { uid, euid, ... }`) is
    /// discouraged outside of this module and tests; future additions
    /// to the struct (filesystem-UID, login-UID, audit-UID) would
    /// silently acquire arbitrary defaults at every call site that
    /// skipped them. Use `from_task_ids` so the compiler surfaces the
    /// new field.
    pub fn from_task_ids(
        uid: u32,
        euid: u32,
        suid: u32,
        gid: u32,
        egid: u32,
        sgid: u32,
        groups: Vec<u32>,
    ) -> Self {
        Self {
            uid,
            euid,
            suid,
            gid,
            egid,
            sgid,
            groups,
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
    /// Construct from a byte slice. Rejects empty names with `EINVAL`,
    /// names longer than [`NAME_MAX`] with `ENAMETOOLONG`, and names
    /// containing `/` or NUL with `EINVAL` (both illegal per POSIX §4.5).
    pub fn try_from_bytes(s: &[u8]) -> Result<Self, i64> {
        if s.is_empty() {
            return Err(super::EINVAL);
        }
        if s.len() > NAME_MAX {
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
    assert_send_sync::<VfsBackend>();
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dstring_rejects_empty() {
        assert_eq!(
            DString::try_from_bytes(b""),
            Err(super::super::EINVAL),
            "empty names must return EINVAL per POSIX, not ENAMETOOLONG"
        );
    }

    #[test]
    fn dstring_rejects_too_long() {
        let long = [b'a'; NAME_MAX + 1];
        assert_eq!(
            DString::try_from_bytes(&long),
            Err(super::super::ENAMETOOLONG)
        );
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
