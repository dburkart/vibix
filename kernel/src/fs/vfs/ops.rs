//! The four VFS operation traits (`FileSystem`, `SuperOps`,
//! `InodeOps`, `FileOps`) and their associated value types.
//!
//! These are the plug-in surface every concrete filesystem implements.
//! Concrete drivers (ramfs, tarfs, devfs) live in sibling modules and
//! provide `Arc<dyn *Ops>` on object construction.
//!
//! Most methods have sensible defaults so a read-only FS doesn't have
//! to stub a dozen write paths; overriding lookup/getattr is the
//! minimum viable FS.

use alloc::sync::Arc;

use super::inode::{Inode, InodeMeta};
use super::open_file::OpenFile;
use super::super_block::SuperBlock;
use super::{Access, Credential, InodeKind, Timespec};

/// Source of a mount operation. Separated from the target path so
/// future sources (block device, ramdisk module, network URL) can be
/// added without breaking the trait signature.
#[derive(Debug)]
pub enum MountSource<'a> {
    /// No backing — the FS synthesises its own storage (ramfs, devfs).
    None,
    /// A path in the current namespace (future: loop-mount support).
    Path(&'a [u8]),
    /// Static byte slice with 'static lifetime (initrd tarball).
    Static(&'static [u8]),
}

/// Linux `struct stat` layout (x86_64). Emitted by
/// [`InodeOps::getattr`]; copied verbatim to userspace. Always
/// zero-initialised before dispatch to close Sec-B4 (uninitialised
/// padding infoleak).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Stat {
    pub st_dev: u64,
    pub st_ino: u64,
    pub st_nlink: u64,
    pub st_mode: u32,
    pub st_uid: u32,
    pub st_gid: u32,
    pub __pad0: u32,
    pub st_rdev: u64,
    pub st_size: i64,
    pub st_blksize: i64,
    pub st_blocks: i64,
    pub st_atime: i64,
    pub st_atime_nsec: i64,
    pub st_mtime: i64,
    pub st_mtime_nsec: i64,
    pub st_ctime: i64,
    pub st_ctime_nsec: i64,
    pub __unused: [i64; 3],
}

const _: () = {
    assert!(core::mem::size_of::<Stat>() == 0x90);
    assert!(core::mem::align_of::<Stat>() == 8);
};

/// Bitmask describing which fields of [`SetAttr`] the caller wants
/// applied. Matches Linux `ATTR_*`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct SetAttrMask(pub u32);

impl SetAttrMask {
    pub const MODE: SetAttrMask = SetAttrMask(1 << 0);
    pub const UID: SetAttrMask = SetAttrMask(1 << 1);
    pub const GID: SetAttrMask = SetAttrMask(1 << 2);
    pub const SIZE: SetAttrMask = SetAttrMask(1 << 3);
    pub const ATIME: SetAttrMask = SetAttrMask(1 << 4);
    pub const MTIME: SetAttrMask = SetAttrMask(1 << 5);
    pub const CTIME: SetAttrMask = SetAttrMask(1 << 6);

    pub const fn contains(self, other: SetAttrMask) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for SetAttrMask {
    type Output = SetAttrMask;
    fn bitor(self, rhs: Self) -> Self {
        SetAttrMask(self.0 | rhs.0)
    }
}

/// Metadata update request. `mask` tells the driver which of the other
/// fields are authoritative; unmasked fields must be ignored.
#[derive(Clone, Copy, Debug, Default)]
pub struct SetAttr {
    pub mask: SetAttrMask,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
}

/// Filesystem-wide statistics returned by [`SuperOps::statfs`].
/// Mirrors Linux `struct statfs` field-by-field semantically (not
/// byte-compatibly — the syscall layer lays out the wire format).
#[derive(Clone, Copy, Debug, Default)]
pub struct StatFs {
    pub f_type: u64,
    pub f_bsize: u64,
    pub f_blocks: u64,
    pub f_bfree: u64,
    pub f_bavail: u64,
    pub f_files: u64,
    pub f_ffree: u64,
    pub f_namelen: u64,
}

/// `lseek(2)` reference point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Whence {
    Set,
    Cur,
    End,
}

/// Filesystem-type factory. One `Arc<dyn FileSystem>` is registered
/// per FS implementation; `mount` is invoked once per mount instance
/// to produce a fresh [`SuperBlock`].
pub trait FileSystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn mount(
        &self,
        source: MountSource<'_>,
        flags: super::MountFlags,
    ) -> Result<Arc<SuperBlock>, i64>;
}

/// Per-mount-instance operations.
pub trait SuperOps: Send + Sync {
    fn root_inode(&self) -> Arc<Inode>;
    fn sync(&self) -> Result<(), i64> {
        Ok(())
    }
    fn evict_inode(&self, _ino: u64) -> Result<(), i64> {
        Ok(())
    }
    fn statfs(&self) -> Result<StatFs, i64>;
    fn unmount(&self) -> Result<(), i64>;
}

/// Per-inode operations: namespace mutation, metadata, permission.
/// Non-directory inodes only need `getattr` / `setattr` / `permission`
/// / `readlink`; directory methods default to `EPERM` so a read-only
/// FS doesn't have to stub them.
pub trait InodeOps: Send + Sync {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, i64> {
        Err(super::super::ENOENT)
    }
    fn create(&self, _dir: &Inode, _name: &[u8], _mode: u16) -> Result<Arc<Inode>, i64> {
        Err(EPERM)
    }
    fn mkdir(&self, _dir: &Inode, _name: &[u8], _mode: u16) -> Result<Arc<Inode>, i64> {
        Err(EPERM)
    }
    fn unlink(&self, _dir: &Inode, _name: &[u8]) -> Result<(), i64> {
        Err(EPERM)
    }
    fn rmdir(&self, _dir: &Inode, _name: &[u8]) -> Result<(), i64> {
        Err(EPERM)
    }
    fn rename(
        &self,
        _old_dir: &Inode,
        _old_name: &[u8],
        _new_dir: &Inode,
        _new_name: &[u8],
    ) -> Result<(), i64> {
        Err(EPERM)
    }
    fn link(&self, _dir: &Inode, _name: &[u8], _target: &Inode) -> Result<(), i64> {
        Err(EPERM)
    }
    fn symlink(&self, _dir: &Inode, _name: &[u8], _target: &[u8]) -> Result<Arc<Inode>, i64> {
        Err(EPERM)
    }

    fn readlink(&self, _inode: &Inode, _buf: &mut [u8]) -> Result<usize, i64> {
        Err(EINVAL_OP)
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64>;
    fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
        Err(EPERM)
    }

    fn permission(&self, inode: &Inode, cred: &Credential, access: Access) -> Result<(), i64> {
        default_permission(inode, cred, access)
    }
}

/// Per-open-file operations. Regular-file I/O, directory reading,
/// control channel.
pub trait FileOps: Send + Sync {
    fn read(&self, _f: &OpenFile, _buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        Err(EINVAL_OP)
    }
    fn write(&self, _f: &OpenFile, _buf: &[u8], _off: u64) -> Result<usize, i64> {
        Err(EINVAL_OP)
    }
    fn seek(&self, _f: &OpenFile, _whence: Whence, _off: i64) -> Result<u64, i64> {
        Err(ESPIPE)
    }
    fn getdents(&self, _f: &OpenFile, _buf: &mut [u8], _cookie: &mut u64) -> Result<usize, i64> {
        Err(ENOTDIR)
    }
    fn ioctl(&self, _f: &OpenFile, _cmd: u32, _arg: usize) -> Result<i64, i64> {
        Err(ENOTTY)
    }
    fn flush(&self, _f: &OpenFile) -> Result<(), i64> {
        Ok(())
    }
    fn fsync(&self, _f: &OpenFile, _data_only: bool) -> Result<(), i64> {
        Ok(())
    }
}

// errno values used by default trait bodies. The broadly-used ones
// already live in `kernel::fs`; re-exported here for readability.
const EPERM: i64 = -1;
const EINVAL_OP: i64 = super::super::EINVAL;
const ENOTTY: i64 = -25;
const ENOTDIR: i64 = -20;
const ESPIPE: i64 = -29;
const EACCES: i64 = -13;

/// Default POSIX permission check: owner / group / other bits in
/// `InodeMeta.mode`. uid 0 (root) bypasses all checks. The `execute`
/// bit on a directory is interpreted as "search" per POSIX §4.5.
///
/// Drivers that need richer semantics (ACLs, capabilities) override
/// `InodeOps::permission` directly.
pub fn default_permission(inode: &Inode, cred: &Credential, access: Access) -> Result<(), i64> {
    if cred.uid == 0 {
        // Root bypass, with one twist: POSIX requires EXECUTE to still
        // fail on a non-dir file with no execute bits set anywhere, so
        // root can't "run" a data file. Matches Linux `generic_permission`.
        if access.contains(Access::EXECUTE) && inode.kind != InodeKind::Dir {
            let meta = inode.meta.read();
            if meta.mode & 0o111 == 0 {
                return Err(EACCES);
            }
        }
        return Ok(());
    }

    let meta = inode.meta.read();
    let mode = meta.mode as u32;
    let bits = if cred.uid == meta.uid {
        (mode >> 6) & 0o7
    } else if cred.gid == meta.gid || cred.groups.iter().any(|&g| g == meta.gid) {
        (mode >> 3) & 0o7
    } else {
        mode & 0o7
    };

    let want = access.bits();
    if (bits & want) == want {
        Ok(())
    } else {
        Err(EACCES)
    }
}

/// Placeholder used by the default `InodeOps::getattr` implementations
/// while we still don't have an `InodeMeta` snapshot helper. Kept as a
/// private helper so callers inside this crate can reach for it
/// without pulling in the whole stat-construction scaffolding.
#[allow(dead_code)]
pub(crate) fn meta_into_stat(
    meta: &InodeMeta,
    kind: InodeKind,
    fs_id: u64,
    ino: u64,
    out: &mut Stat,
) {
    let kind_bits: u32 = match kind {
        InodeKind::Reg => 0o100_000,
        InodeKind::Dir => 0o040_000,
        InodeKind::Link => 0o120_000,
        InodeKind::Chr => 0o020_000,
        InodeKind::Blk => 0o060_000,
        InodeKind::Fifo => 0o010_000,
        InodeKind::Sock => 0o140_000,
    };
    out.st_dev = fs_id;
    out.st_ino = ino;
    out.st_nlink = meta.nlink as u64;
    out.st_mode = kind_bits | (meta.mode as u32 & 0o7_777);
    out.st_uid = meta.uid;
    out.st_gid = meta.gid;
    out.st_rdev = meta.rdev;
    out.st_size = meta.size as i64;
    out.st_blksize = meta.blksize as i64;
    out.st_blocks = meta.blocks as i64;
    out.st_atime = meta.atime.sec;
    out.st_atime_nsec = meta.atime.nsec as i64;
    out.st_mtime = meta.mtime.sec;
    out.st_mtime_nsec = meta.mtime.nsec as i64;
    out.st_ctime = meta.ctime.sec;
    out.st_ctime_nsec = meta.ctime.nsec as i64;
}
