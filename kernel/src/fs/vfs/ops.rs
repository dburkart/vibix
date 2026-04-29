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
use crate::fs::{EACCES, EINVAL, ENODEV, ENOENT, ENOTDIR, ENOTTY, EPERM, ESPIPE};
use crate::mem::vmatree::{ProtUser, Share};
use crate::mem::vmobject::VmObject;

/// Source of a mount operation. Separated from the target path so
/// future sources (block device, ramdisk module, network URL) can be
/// added without breaking the trait signature.
pub enum MountSource<'a> {
    /// No backing — the FS synthesises its own storage (ramfs, devfs).
    None,
    /// A path in the current namespace (future: loop-mount support).
    Path(&'a [u8]),
    /// Static byte slice with 'static lifetime (initrd tarball).
    Static(&'static [u8]),
    /// Byte slice backed by a Limine ramdisk module. The caller is
    /// responsible for converting the bootloader's raw pointer + length
    /// into a `&'static [u8]` via an `unsafe` block at the callsite
    /// (see `vfs::init::find_rootfs_module`). Kept distinct from
    /// [`Static`](Self::Static) so logging/tracing can tell apart test
    /// fixtures from live boot modules.
    RamdiskModule(&'static [u8]),
}

impl core::fmt::Debug for MountSource<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MountSource::None => f.write_str("None"),
            MountSource::Path(p) => f.debug_tuple("Path").field(p).finish(),
            MountSource::Static(s) => f.debug_tuple("Static").field(&s.len()).finish(),
            MountSource::RamdiskModule(s) => {
                f.debug_tuple("RamdiskModule").field(&s.len()).finish()
            }
        }
    }
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
    /// Flush every dirty buffer belonging to this mount to stable
    /// storage. Called from the `umount` path (before
    /// [`unmount`](Self::unmount) detaches the superblock) and,
    /// eventually, by the `sync(2)` syscall (Workstream F).
    ///
    /// Contract (RFC 0004 §Buffer cache, issue #554):
    ///
    /// - In-memory filesystems (ramfs, tarfs, devfs) have no backing
    ///   device; the default impl returns `Ok(())`.
    /// - Filesystems backed by a [`BlockCache`](crate::block::cache::BlockCache)
    ///   must delegate to
    ///   [`BlockCache::sync_fs`](crate::block::cache::BlockCache::sync_fs)
    ///   with the mount's [`DeviceId`](crate::block::cache::DeviceId)
    ///   so only that mount's dirty buffers are flushed.
    /// - Best-effort error propagation: if multiple buffers fail, the
    ///   first error is returned and the rest are flushed anyway. A
    ///   dirty buffer that fails to flush remains enlisted for a later
    ///   retry (writeback daemon or a subsequent explicit sync).
    ///
    /// The `sb` argument is passed so a driver that owns more than one
    /// `BlockCache` (future sharded layout) can route to the right
    /// one; single-cache drivers can ignore it.
    fn sync_fs(&self, _sb: &SuperBlock) -> Result<(), i64> {
        Ok(())
    }
    /// Called during Phase B of `unmount()`, after the mount edge has been
    /// removed from the table (Phase A).  At this point the mount is
    /// irrevocably gone regardless of what this method does.
    ///
    /// **Contract (Linux-compatible, option a)**: this method **must not
    /// propagate errors** to the VFS layer.  Any I/O errors encountered while
    /// flushing dirty state (e.g. syncing a block device) must be absorbed
    /// inside the driver — logged if useful, then silently dropped.  A caller
    /// that receives `Ok(())` from `fs::vfs::unmount()` is guaranteed the
    /// mount is detached; a retry would receive `EINVAL`.
    ///
    /// Drivers that are purely in-memory (ramfs, devfs) implement this as a
    /// no-op.  Drivers backed by persistent storage should flush dirty data
    /// here and log errors via the kernel's serial log.
    fn unmount(&self);
}

/// Per-inode operations: namespace mutation, metadata, permission.
/// Non-directory inodes only need `getattr` / `setattr` / `permission`
/// / `readlink`; directory methods default to `EPERM` so a read-only
/// FS doesn't have to stub them.
pub trait InodeOps: Send + Sync {
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, i64> {
        Err(ENOENT)
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
        Err(EINVAL)
    }

    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64>;
    fn setattr(&self, _inode: &Inode, _attr: &SetAttr) -> Result<(), i64> {
        Err(EPERM)
    }

    fn permission(&self, inode: &Inode, cred: &Credential, access: Access) -> Result<(), i64> {
        default_permission(inode, cred, access)
    }

    /// Create a new FIFO (named pipe) inode under `dir` with the given
    /// `name` and `mode`. Regular filesystems return `EPERM`; only
    /// in-memory FSes that support `InodeKind::Fifo` override this.
    fn mkfifo(&self, _dir: &Inode, _name: &[u8], _mode: u16) -> Result<Arc<Inode>, i64> {
        Err(EPERM)
    }

    /// If this inode is a FIFO, return the shared `Arc<Pipe>` backing
    /// it. Used by `open(2)` on a `InodeKind::Fifo` inode to bind a
    /// `PipeReadEnd` / `PipeWriteEnd` to the caller's fd. Any filesystem
    /// that ever stores a `InodeKind::Fifo` inode must override this.
    fn fifo_pipe(&self) -> Option<Arc<crate::ipc::pipe::Pipe>> {
        None
    }

    /// If this inode represents a block device (`InodeKind::Blk`),
    /// return the underlying [`BlockDevice`] handle. Used by the
    /// `mount(2)` resolver to turn a `/dev/<name>` source path into the
    /// concrete backing device handed to filesystem factories like
    /// ext2.
    ///
    /// Default: `None`. Only devfs (and any future block-device-bearing
    /// FS) needs to override this.
    fn block_device(&self) -> Option<Arc<dyn crate::block::BlockDevice>> {
        None
    }
}

/// Per-open-file operations. Regular-file I/O, directory reading,
/// control channel.
pub trait FileOps: Send + Sync {
    fn read(&self, _f: &OpenFile, _buf: &mut [u8], _off: u64) -> Result<usize, i64> {
        Err(EINVAL)
    }
    fn write(&self, _f: &OpenFile, _buf: &[u8], _off: u64) -> Result<usize, i64> {
        // Read-only filesystems keep this default; signal "write not
        // permitted" rather than "bad argument".
        Err(EPERM)
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

    /// Driver hook fired exactly once per [`OpenFile`] right after the
    /// `OpenFile` is fully constructed (after `OpenFile::new` has handed
    /// the `SbActiveGuard` pin off to `dentry_pin_count`). The `OpenFile`
    /// reference is stable for the duration of the call.
    ///
    /// Default: no-op. Drivers that need a per-open refcount (ext2's
    /// orphan-finalize trigger, RFC 0004 §Final-close sequence) bump it
    /// here. Failure surfacing isn't supported — the open has already
    /// pinned the SB and the syscall layer has no rollback path; if a
    /// driver hook needs to fail, it must do so earlier (e.g. inside
    /// `InodeOps::lookup` / `InodeOps::create`).
    fn open(&self, _f: &OpenFile) {}

    /// Driver hook fired exactly once per [`OpenFile`] from
    /// [`OpenFile::Drop`], **before** the SB pin is released. The
    /// `OpenFile` reference is stable for the duration of the call.
    ///
    /// Default: no-op. Drivers that need a per-open refcount (ext2's
    /// orphan-finalize trigger) decrement it here and may run terminal
    /// finalize work synchronously (e.g. truncate-to-zero + free_inode
    /// for an unlinked-but-open inode whose count just hit zero). The
    /// hook is infallible — drop paths can't propagate errors to the
    /// caller; drivers should `kwarn!` and absorb any I/O failure (the
    /// next mount-time replay path will retry).
    fn release(&self, _f: &OpenFile) {}

    /// Produce a backing [`VmObject`] for an `mmap(2)` of this open file.
    ///
    /// Called by `sys_mmap` after it has validated the userspace
    /// arguments and looked up the [`OpenFile`]. The returned object is
    /// plugged into the caller's VMA tree at the chosen virtual address;
    /// page faults inside the resulting VMA are dispatched to
    /// [`VmObject::fault`] by the fault resolver.
    ///
    /// `file_offset` is the byte offset into the file at which the
    /// mapping begins (page-aligned per `mmap(2)` rules — `sys_mmap`
    /// rejects unaligned values with `EINVAL` before this hook fires).
    /// `len_pages` is the mapping length in 4 KiB pages. `share`
    /// distinguishes `MAP_PRIVATE` from `MAP_SHARED`. `prot` carries the
    /// `PROT_*` bits the caller requested; the FS may inspect these to
    /// reject unsupported combinations (e.g. a read-only FS rejecting
    /// `MAP_SHARED + PROT_WRITE`).
    ///
    /// The default impl returns `-ENODEV`, which `sys_mmap` translates
    /// to the userspace `ENODEV` errno per the RFC 0007 errno table.
    /// File types that are not memory-mappable (sockets, FIFOs,
    /// directories, devfs control nodes) keep this default. Concrete
    /// filesystems that support `mmap` (ext2, ramfs, tarfs) override it
    /// in follow-up issues.
    ///
    /// See `docs/RFC/0007-page-cache-file-mmap.md` §`FileOps::mmap` for
    /// the full contract; sys_mmap's argument validation and errno
    /// translation are issue #746.
    fn mmap(
        &self,
        _f: &OpenFile,
        _file_offset: u64,
        _len_pages: usize,
        _share: Share,
        _prot: ProtUser,
    ) -> Result<Arc<dyn VmObject>, i64> {
        Err(ENODEV)
    }
}

/// Default POSIX permission check: owner / group / other bits in
/// `InodeMeta.mode`. DAC decisions consult the **effective** IDs
/// (`euid`, `egid`, supplementary `groups`) per POSIX.1-2017 §2.4 —
/// `uid` and `gid` (real IDs) are not read here. `euid == 0` (root)
/// bypasses all checks. The `execute` bit on a directory is
/// interpreted as "search" per POSIX §4.5.
///
/// Drivers that need richer semantics (ACLs, capabilities) override
/// `InodeOps::permission` directly.
pub fn default_permission(inode: &Inode, cred: &Credential, access: Access) -> Result<(), i64> {
    if cred.euid == 0 {
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
    // POSIX §4.4.2 "File Access Permissions": once a class matches, its
    // bits decide the result — even if a later class (other) would be
    // more permissive. The first-match terminates semantics falls out
    // of the if/else-if chain below.
    let bits = if cred.euid == meta.uid {
        (mode >> 6) & 0o7
    } else if cred.egid == meta.gid || cred.groups.iter().any(|&g| g == meta.gid) {
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
    // Saturate u64 → i64 for size/blocks. Real filesystems never report
    // sizes above i64::MAX (Linux loff_t, ext4/btrfs on-disk limits are
    // all u63-max or lower); any such value indicates a driver bug or
    // corrupted metadata, and a huge positive st_size is more
    // diagnosable for userspace than a silently-negated one.
    out.st_size = meta.size.min(i64::MAX as u64) as i64;
    out.st_blksize = meta.blksize as i64;
    out.st_blocks = meta.blocks.min(i64::MAX as u64) as i64;
    out.st_atime = meta.atime.sec;
    out.st_atime_nsec = meta.atime.nsec as i64;
    out.st_mtime = meta.mtime.sec;
    out.st_mtime_nsec = meta.mtime.nsec as i64;
    out.st_ctime = meta.ctime.sec;
    out.st_ctime_nsec = meta.ctime.nsec as i64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::FsId;
    use alloc::sync::Arc;
    use alloc::vec;

    struct StubInodeOps;
    impl InodeOps for StubInodeOps {
        fn getattr(&self, _inode: &Inode, _out: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
    }

    struct StubFileOps;
    impl FileOps for StubFileOps {}

    struct StubSuper;
    impl SuperOps for StubSuper {
        fn root_inode(&self) -> Arc<Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(StatFs::default())
        }
        fn unmount(&self) {}
    }

    /// Build a regular-file inode with the given mode/uid/gid for
    /// driving `default_permission` in the tests below. Anchors a real
    /// `SuperBlock` so the inode's `Weak<SuperBlock>` stays live for
    /// the duration of the closure.
    fn with_inode<R>(mode: u16, uid: u32, gid: u32, f: impl FnOnce(&Inode) -> R) -> R {
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let ino = Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInodeOps),
            Arc::new(StubFileOps),
            InodeKind::Reg,
            InodeMeta {
                mode,
                uid,
                gid,
                nlink: 1,
                ..Default::default()
            },
        );
        f(&ino)
    }

    #[test]
    fn meta_into_stat_saturates_u64_max_size_and_blocks() {
        let meta = InodeMeta {
            size: u64::MAX,
            blocks: u64::MAX,
            ..Default::default()
        };
        let mut st = Stat::default();
        meta_into_stat(&meta, InodeKind::Reg, 1, 2, &mut st);
        assert_eq!(st.st_size, i64::MAX);
        assert_eq!(st.st_blocks, i64::MAX);
        assert!(st.st_size >= 0 && st.st_blocks >= 0);
    }

    #[test]
    fn meta_into_stat_preserves_in_range_size_and_blocks() {
        let meta = InodeMeta {
            size: 1_234_567,
            blocks: 2_400,
            blksize: 4096,
            ..Default::default()
        };
        let mut st = Stat::default();
        meta_into_stat(&meta, InodeKind::Reg, 1, 2, &mut st);
        assert_eq!(st.st_size, 1_234_567);
        assert_eq!(st.st_blocks, 2_400);
        assert_eq!(st.st_blksize, 4096);
    }

    // ---- Credential constructor + default_permission DAC tests ----

    #[test]
    fn credential_from_task_ids_populates_every_field() {
        let cred = Credential::from_task_ids(10, 11, 12, 20, 21, 22, vec![100, 101]);
        assert_eq!(cred.uid, 10);
        assert_eq!(cred.euid, 11);
        assert_eq!(cred.suid, 12);
        assert_eq!(cred.gid, 20);
        assert_eq!(cred.egid, 21);
        assert_eq!(cred.sgid, 22);
        assert_eq!(cred.groups, vec![100, 101]);
    }

    #[test]
    fn credential_kernel_is_root_on_every_id() {
        let cred = Credential::kernel();
        assert_eq!(cred.uid, 0);
        assert_eq!(cred.euid, 0);
        assert_eq!(cred.suid, 0);
        assert_eq!(cred.gid, 0);
        assert_eq!(cred.egid, 0);
        assert_eq!(cred.sgid, 0);
        assert!(cred.groups.is_empty());
    }

    #[test]
    fn permission_owner_class_uses_euid_not_uid() {
        // File 0o600 owned by uid 1000. Caller has real uid != 1000 but
        // effective uid == 1000 (i.e. ran a setuid binary owned by 1000).
        // POSIX requires the effective ID to win — owner class matches.
        with_inode(0o600, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(42, 1000, 42, 99, 99, 99, vec![]);
            assert!(default_permission(inode, &cred, Access::READ).is_ok());
            assert!(default_permission(inode, &cred, Access::WRITE).is_ok());
            // No execute bit → EXECUTE denied even for owner.
            assert_eq!(
                default_permission(inode, &cred, Access::EXECUTE),
                Err(EACCES)
            );
        });
    }

    #[test]
    fn permission_group_class_uses_egid_not_gid() {
        // File 0o040 (group-read only) owned by uid 1000, gid 2000.
        // Caller's real gid is unrelated, but effective gid matches.
        with_inode(0o040, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(50, 50, 50, 7777, 2000, 2000, vec![]);
            assert!(default_permission(inode, &cred, Access::READ).is_ok());
            // Group has no write bit → write denied via group class
            // (owner class doesn't match euid != 1000), and "other" is
            // 0 so the fall-through also denies.
            assert_eq!(default_permission(inode, &cred, Access::WRITE), Err(EACCES));
        });
    }

    #[test]
    fn permission_supplementary_groups_match_group_class() {
        // File 0o050 (group r-x) gid 2000. Caller's egid is something
        // else but 2000 is in the supplementary list → group class.
        with_inode(0o050, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(50, 50, 50, 60, 60, 60, vec![1500, 2000, 3000]);
            assert!(default_permission(inode, &cred, Access::READ).is_ok());
            assert!(default_permission(inode, &cred, Access::EXECUTE).is_ok());
            assert_eq!(default_permission(inode, &cred, Access::WRITE), Err(EACCES));
        });
    }

    #[test]
    fn permission_other_class_when_neither_owner_nor_group_match() {
        // File 0o604: owner rw, group ---, world r--. Caller is none of
        // owner/group/supplementary → falls through to "other" bits.
        with_inode(0o604, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(50, 50, 50, 60, 60, 60, vec![70, 80]);
            assert!(default_permission(inode, &cred, Access::READ).is_ok());
            assert_eq!(default_permission(inode, &cred, Access::WRITE), Err(EACCES));
        });
    }

    #[test]
    fn permission_owner_class_terminates_even_when_other_is_more_permissive() {
        // POSIX §4.4.2 first-match-terminates: if owner matches and
        // owner has --x, the caller is denied READ even though
        // "other" grants r--. (Linux-conformant behaviour.)
        with_inode(0o104, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(50, 1000, 50, 60, 60, 60, vec![]);
            assert_eq!(
                default_permission(inode, &cred, Access::READ),
                Err(EACCES),
                "owner class is consulted first; world r-- must not rescue the caller"
            );
            assert!(default_permission(inode, &cred, Access::EXECUTE).is_ok());
        });
    }

    #[test]
    fn permission_root_bypasses_via_euid_not_uid() {
        // euid==0 root bypass. The caller's *real* uid is non-zero
        // (post-`setuid(0)` from a setuid-root binary, before saved-uid
        // recovery) but effective uid is 0 → root powers apply.
        with_inode(0o000, 4242, 4242, |inode| {
            let cred = Credential::from_task_ids(1234, 0, 1234, 5678, 5678, 5678, vec![]);
            assert!(default_permission(inode, &cred, Access::READ).is_ok());
            assert!(default_permission(inode, &cred, Access::WRITE).is_ok());
        });
    }

    #[test]
    fn permission_root_execute_still_requires_one_x_bit_on_files() {
        // Linux generic_permission: even root cannot "execute" a regular
        // file with 0 execute bits anywhere. Mirrors that.
        with_inode(0o644, 1, 1, |inode| {
            let cred = Credential::kernel();
            assert_eq!(
                default_permission(inode, &cred, Access::EXECUTE),
                Err(EACCES)
            );
        });
        // One execute bit anywhere → root execute allowed.
        with_inode(0o744, 1, 1, |inode| {
            let cred = Credential::kernel();
            assert!(default_permission(inode, &cred, Access::EXECUTE).is_ok());
        });
    }

    #[test]
    fn fileops_mmap_default_returns_enodev() {
        // The default `FileOps::mmap` impl is the contract every
        // non-mmappable FS (sockets, FIFOs, control nodes, and — until
        // #753 — ext2) inherits. RFC 0007's errno table mandates
        // `ENODEV` for "file type not mmappable"; sys_mmap (issue #746)
        // translates the negative errno verbatim.
        use crate::fs::vfs::dentry::Dentry;
        use crate::fs::vfs::open_file::OpenFile;
        use crate::fs::vfs::super_block::SbActiveGuard;
        use crate::mem::vmatree::Share;
        let sb = Arc::new(SuperBlock::new(
            FsId(1),
            Arc::new(StubSuper),
            "stub",
            512,
            SbFlags::default(),
        ));
        let inode = Arc::new(Inode::new(
            1,
            Arc::downgrade(&sb),
            Arc::new(StubInodeOps),
            Arc::new(StubFileOps),
            InodeKind::Reg,
            InodeMeta::default(),
        ));
        let dentry = Dentry::new_root(inode.clone());
        let file_ops: Arc<dyn FileOps> = Arc::new(StubFileOps);
        let guard = SbActiveGuard::try_acquire(&sb).expect("guard");
        let of = OpenFile::new(dentry, inode, file_ops, sb.clone(), 0, guard);
        let r = StubFileOps.mmap(&of, 0, 1, Share::Private, 0);
        assert_eq!(r.err(), Some(crate::fs::ENODEV));
    }

    #[test]
    fn permission_real_uid_alone_does_not_grant_owner_class() {
        // Caller's real uid matches the file owner but euid does not.
        // Owner class must NOT match — POSIX consults effective IDs.
        with_inode(0o600, 1000, 2000, |inode| {
            let cred = Credential::from_task_ids(1000, 50, 1000, 60, 60, 60, vec![]);
            assert_eq!(
                default_permission(inode, &cred, Access::READ),
                Err(EACCES),
                "owner DAC must be gated on euid, not uid"
            );
        });
    }
}
