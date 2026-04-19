//! ext2 inode wave 3 — `Ext2Inode`, `iget`, inode cache, orphan list.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`) §Key data
//! structures and §Orphan list are the normative spec. Issue #559 (wave
//! 2 of Workstream D) lands the in-memory inode type, the `iget` loader
//! that turns an ino into an `Arc<Inode>`, the `Weak<Inode>` inode cache
//! that deduplicates repeat lookups, and the `Arc<Inode>` orphan list
//! that pins unlinked-but-open inodes so their blocks aren't freed
//! before the last close.
//!
//! # Split relative to RFC 0004
//!
//! The RFC sketches a single `Ext2Fs` type that merges the
//! "filesystem-type factory" and the "per-mount instance." The concrete
//! driver splits those along tarfs's pattern: [`Ext2Fs`] in `fs.rs` is
//! the factory (one per device, carries the single-mount latch) and
//! [`Ext2Super`] in `fs.rs` is the per-mount instance (carries the
//! buffer cache, block-group table, and now the inode cache and orphan
//! list). The orphan list and inode cache are *per-mount* — two mounts
//! of the same image on different devices must not share them — so
//! they sit on [`Ext2Super`].
//!
//! # iget arithmetic
//!
//! For ino `n` (1-based; `EXT2_ROOT_INO` = 2), the inode-table slot
//! lives at
//!
//! ```text
//! group         = (n - 1) / s_inodes_per_group
//! index_in_grp  = (n - 1) % s_inodes_per_group
//! byte_offset   = index_in_grp * inode_size
//! block_in_tbl  = byte_offset / block_size
//! offset_in_blk = byte_offset % block_size
//! absolute_blk  = bgdt[group].bg_inode_table + block_in_tbl
//! ```
//!
//! The inode table spans multiple blocks when
//! `s_inodes_per_group * inode_size > block_size`; `block_in_tbl`
//! encodes which block we need. `offset_in_blk` points at the first
//! byte of the slot inside that block. Rev-1 images store
//! `s_inode_size`-byte slots; the driver decodes the 128-byte prefix
//! and preserves the tail verbatim via the RMW encode path in
//! [`super::disk::Ext2Inode::encode_to_slot`].
//!
//! # Inode cache (`Weak`) vs. orphan list (`Arc`)
//!
//! The `inode_cache: Mutex<BTreeMap<u32, Weak<Inode>>>` is a **lookup
//! shortcut**, not an ownership root: if the VFS has released every
//! `Arc<Inode>` for a given ino, the cache entry's `Weak::upgrade()`
//! returns `None` and `iget` re-reads from disk. The [`orphan_list`] —
//! `Mutex<BTreeMap<u32, Arc<Inode>>>` — is the ownership root *while
//! the inode is unlinked-but-open*: its strong ref keeps the inode
//! resident so a racing last-`OpenFile` drop doesn't tear down the
//! inode before its blocks are freed. See RFC 0004 §Orphan-list
//! residency invariant.
//!
//! Wave 2 (#559) builds the orphan list as an empty map and the veto
//! logic on `Ext2Inode::unlinked`; no code path sets `unlinked = true`
//! yet — that's Workstream E's unlink path. The scaffolding is in place
//! so #564 (mount-time orphan-chain replay) and the later unlink path
//! have a map to push into.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use core::sync::atomic::AtomicBool;

use spin::Mutex;

use super::disk::{
    Ext2Inode as DiskInode, EXT2_INODE_SIZE_V0, EXT2_N_BLOCKS, EXT2_ROOT_INO, RO_COMPAT_LARGE_FILE,
};
use super::fs::Ext2Super;

use crate::fs::vfs::inode::{Inode, InodeKind, InodeMeta};
use crate::fs::vfs::ops::{FileOps, InodeOps, Stat};
use crate::fs::vfs::{SbFlags, SuperBlock, Timespec};
use crate::fs::{EINVAL, EIO, ENOENT};
use crate::sync::BlockingRwLock;

/// Parsed, driver-owned view of an on-disk inode's mutable fields. Sits
/// behind [`Ext2Inode::meta`] (a `BlockingRwLock`); `getattr` takes the
/// read lock and `setattr` (Workstream E) will take the write lock.
///
/// The fields mirror [`DiskInode`] but with the 32-bit uid/gid already
/// recomposed from the low/high halves. `i_blocks` stays in on-disk 512-
/// byte units; [`meta_into_stat`](crate::fs::vfs::ops::meta_into_stat)
/// forwards it unchanged to `st_blocks`.
#[derive(Clone, Debug)]
pub struct Ext2InodeMeta {
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    /// Byte size. On regular files with `RO_COMPAT_LARGE_FILE` set this
    /// carries the full 64-bit recomposition of `i_size` + the high
    /// half in `i_dir_acl` (RFC 0004 §On-disk types). Directories use
    /// the low 32 bits only; the high half is `i_dir_acl`.
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub links_count: u16,
    /// `i_blocks` in 512-byte units, as stored on disk. Not converted
    /// to fs-block units — the stat layer speaks the 512-byte unit too.
    pub i_blocks: u32,
    pub flags: u32,
    /// Raw 15-entry block pointer array. Index walker (#560) consumes
    /// this to resolve file-relative block indices to absolute disk
    /// blocks; wave 2 only carries it through.
    pub i_block: [u32; EXT2_N_BLOCKS],
}

impl Ext2InodeMeta {
    /// Build an `Ext2InodeMeta` from a decoded on-disk inode. The
    /// `large_file` flag toggles how `i_dir_acl_or_size_high` is
    /// interpreted (upper 32 bits of size on regular files vs.
    /// `i_dir_acl` on directories).
    fn from_disk(disk: &DiskInode, large_file: bool) -> Self {
        let mode = disk.i_mode;
        let is_reg = (mode & 0o170_000) == 0o100_000;
        let size = if is_reg && large_file {
            ((disk.i_dir_acl_or_size_high as u64) << 32) | (disk.i_size as u64)
        } else {
            disk.i_size as u64
        };
        Self {
            mode,
            uid: disk.uid(),
            gid: disk.gid(),
            size,
            atime: disk.i_atime,
            ctime: disk.i_ctime,
            mtime: disk.i_mtime,
            dtime: disk.i_dtime,
            links_count: disk.i_links_count,
            i_blocks: disk.i_blocks,
            flags: disk.i_flags,
            i_block: disk.i_block,
        }
    }
}

/// Lazy indirect-block walk cache. Populated by #560's walker and
/// invalidated by the metadata mutators in Workstream E. Wave 2 keeps
/// the slot as an `Option` so the type surface is stable for the next
/// PR to attach to without touching `Ext2Inode`'s field layout.
#[derive(Clone, Debug, Default)]
pub struct BlockMap;

/// Driver-level inode. Hung off the VFS [`Inode`] via
/// `inode.ops: Arc<dyn InodeOps>` and `inode.file_ops: Arc<dyn FileOps>`.
/// Held separately as an `Arc<Ext2Inode>` in the owning [`Ext2Super`]'s
/// `inode_cache` (`Weak`) and, on unlink-with-openers, `orphan_list`
/// (`Arc`).
///
/// Cycle hygiene: `super_ref` is `Weak` so the `Ext2Super → inode_cache
/// → Weak<Inode>` + `Weak<Ext2Super>` pair doesn't tie the super to the
/// inode. A live `Arc<Inode>` from [`Ext2Super::iget`] does hold the
/// super alive through the VFS [`SuperBlock`]'s `Arc<dyn SuperOps>`,
/// which is what keeps `iget` -> `cache.bread(...)` valid for as long
/// as any inode is live.
pub struct Ext2Inode {
    /// Back-reference to the owning per-mount state, weak to avoid a
    /// `Ext2Super → inode_cache → Ext2Inode → Ext2Super` cycle.
    pub super_ref: Weak<Ext2Super>,
    pub ino: u32,
    pub meta: BlockingRwLock<Ext2InodeMeta>,
    pub block_map: BlockingRwLock<Option<BlockMap>>,
    /// Set to `true` when the last hard link is removed (Workstream E);
    /// the orphan-list strong ref keeps the inode live until the last
    /// close. Wave 2 initialises this to `false` and never flips it;
    /// the surface exists so the unlink path and mount-time orphan
    /// replay (#564) have a well-known place to set it.
    pub unlinked: AtomicBool,
}

impl Ext2Inode {
    fn new(super_ref: Weak<Ext2Super>, ino: u32, meta: Ext2InodeMeta) -> Self {
        Self {
            super_ref,
            ino,
            meta: BlockingRwLock::new(meta),
            block_map: BlockingRwLock::new(None),
            unlinked: AtomicBool::new(false),
        }
    }
}

impl InodeOps for Ext2Inode {
    /// Populate a VFS [`Stat`] from this inode's decoded metadata.
    ///
    /// `st_dev` is the mount's [`FsId`](crate::fs::vfs::FsId); `st_ino`
    /// is the ext2 ino promoted to `u64`. Timestamps are second-granularity
    /// on disk, so `*_nsec` fields are zero. `st_blksize` reports the
    /// filesystem block size (matches what `statfs(2)` reports).
    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64> {
        let super_ref = self.super_ref.upgrade().ok_or(EIO)?;
        let meta = self.meta.read();

        let kind_bits: u32 = match inode.kind {
            InodeKind::Reg => 0o100_000,
            InodeKind::Dir => 0o040_000,
            InodeKind::Link => 0o120_000,
            InodeKind::Chr => 0o020_000,
            InodeKind::Blk => 0o060_000,
            InodeKind::Fifo => 0o010_000,
            InodeKind::Sock => 0o140_000,
        };

        out.st_dev = super_ref.fs_id;
        out.st_ino = inode.ino;
        out.st_nlink = meta.links_count as u64;
        out.st_mode = kind_bits | (meta.mode as u32 & 0o7_777);
        out.st_uid = meta.uid;
        out.st_gid = meta.gid;
        out.st_rdev = 0;
        out.st_size = meta.size.min(i64::MAX as u64) as i64;
        out.st_blksize = super_ref.block_size as i64;
        // ext2 `i_blocks` is already in 512-byte units; `st_blocks` is
        // also 512-byte units. No conversion.
        out.st_blocks = meta.i_blocks as i64;
        out.st_atime = meta.atime as i64;
        out.st_atime_nsec = 0;
        out.st_mtime = meta.mtime as i64;
        out.st_mtime_nsec = 0;
        out.st_ctime = meta.ctime as i64;
        out.st_ctime_nsec = 0;
        Ok(())
    }

    /// Directory-entry search for a single name.
    ///
    /// Wave 2 returns `ENOENT` unconditionally — the dir-entry walker
    /// is #562 (Workstream D6). The shape is here so callers through
    /// `path_walk` compile against the final trait surface and #562 can
    /// drop the iteration body in without rewriting callers.
    fn lookup(&self, _dir: &Inode, _name: &[u8]) -> Result<Arc<Inode>, i64> {
        Err(ENOENT)
    }
}

/// Placeholder `FileOps` for an ext2 inode. Wave 2 carries only the
/// defaults (read/write return `EINVAL`/`EPERM`, getdents returns
/// `ENOTDIR`). #561 replaces it with a read implementation once the
/// indirect-block walker (#560) lands.
pub struct Ext2FileOps;

impl FileOps for Ext2FileOps {}

/// Infer an [`InodeKind`] from the on-disk `i_mode` S_IFMT bits.
///
/// Ext2 encodes the file type in the top four bits of `i_mode`; they
/// match POSIX `S_IFMT`. An unknown value is mapped to `EIO` at the
/// `iget` call site — corrupt mode is a driver-won't-interpret-it
/// situation, not a panic.
fn inode_kind_from_mode(mode: u16) -> Result<InodeKind, i64> {
    match mode & 0o170_000 {
        0o100_000 => Ok(InodeKind::Reg),
        0o040_000 => Ok(InodeKind::Dir),
        0o120_000 => Ok(InodeKind::Link),
        0o020_000 => Ok(InodeKind::Chr),
        0o060_000 => Ok(InodeKind::Blk),
        0o010_000 => Ok(InodeKind::Fifo),
        0o140_000 => Ok(InodeKind::Sock),
        _ => Err(EIO),
    }
}

/// Project an [`Ext2InodeMeta`] into the VFS's generic [`InodeMeta`].
/// Kept as a pure function so the `Inode` constructor can call it once
/// without needing to plumb an `Ext2InodeMeta` field through the VFS.
fn vfs_meta_from(ext2_meta: &Ext2InodeMeta, block_size: u32) -> InodeMeta {
    InodeMeta {
        mode: ext2_meta.mode & 0o7_777,
        uid: ext2_meta.uid,
        gid: ext2_meta.gid,
        size: ext2_meta.size,
        nlink: ext2_meta.links_count as u32,
        atime: Timespec {
            sec: ext2_meta.atime as i64,
            nsec: 0,
        },
        mtime: Timespec {
            sec: ext2_meta.mtime as i64,
            nsec: 0,
        },
        ctime: Timespec {
            sec: ext2_meta.ctime as i64,
            nsec: 0,
        },
        rdev: 0,
        blksize: block_size,
        blocks: ext2_meta.i_blocks as u64,
    }
}

/// Per-mount inode cache. `Weak<Inode>` so an evicted inode is freed as
/// soon as the last `Arc` drops; the entry is swept on the next `iget`
/// miss.
///
/// The map is keyed by ext2 `u32` ino rather than the VFS's `u64` ino
/// to keep the per-mount structure compact — ext2 inodes never exceed
/// `u32::MAX` (it's the on-disk slot width).
pub type InodeCache = Mutex<BTreeMap<u32, Weak<Inode>>>;

/// Per-mount orphan list. `Arc<Inode>` strong refs keep an unlinked-
/// but-open inode resident so its blocks aren't freed before the last
/// close; RFC 0004 §Orphan-list residency invariant is normative.
///
/// Wave 2 (#559) constructs this as an empty map. The map is populated
/// by the unlink path (Workstream E) when `i_links_count` hits 0 with
/// openers still live, and by the mount-time orphan-chain replay
/// (#564) for inodes the previous mount left on `s_last_orphan`.
pub type OrphanList = Mutex<BTreeMap<u32, Arc<Inode>>>;

/// Construct an empty inode cache. Called once at mount by
/// [`Ext2Super`]'s constructor.
pub fn new_inode_cache() -> InodeCache {
    Mutex::new(BTreeMap::new())
}

/// Construct an empty orphan list.
pub fn new_orphan_list() -> OrphanList {
    Mutex::new(BTreeMap::new())
}

/// Load an inode by its ext2 ino.
///
/// Returns the same `Arc<Inode>` for repeat `iget` calls with the same
/// `ino` as long as at least one `Arc` is still live (via the inode
/// cache's `Weak` shortcut). On a cache miss the implementation reads
/// the inode-table block through the per-mount [`BlockCache`], decodes
/// the slot, constructs a fresh [`Ext2Inode`] + [`Inode`] pair,
/// publishes the `Weak` in the cache, and returns the strong `Arc`.
///
/// # Errors
///
/// - `EINVAL`: `ino == 0` or out of range (`ino > s_inodes_count`).
/// - `EIO`: corrupted geometry (group out of range, zero-sized
///   `s_inodes_per_group`), unreadable inode-table block, or an
///   unrecognised `i_mode` S_IFMT field.
pub fn iget(super_ref: &Arc<Ext2Super>, sb: &Arc<SuperBlock>, ino: u32) -> Result<Arc<Inode>, i64> {
    // ino 0 is reserved as the tombstone sentinel (RFC 0004 §Directory
    // operations). A caller that reaches here with ino 0 has an image
    // bug at best; refuse rather than compute a negative offset.
    if ino == 0 {
        return Err(EINVAL);
    }
    if ino > super_ref.sb_disk.s_inodes_count {
        return Err(EINVAL);
    }

    // 1. Fast path: cache hit.
    if let Some(arc) = super_ref
        .inode_cache
        .lock()
        .get(&ino)
        .and_then(Weak::upgrade)
    {
        return Ok(arc);
    }

    // 2. Miss: compute the inode-table slot location.
    let inodes_per_group = super_ref.sb_disk.s_inodes_per_group;
    if inodes_per_group == 0 {
        return Err(EIO);
    }
    let group = (ino - 1) / inodes_per_group;
    let index_in_group = (ino - 1) % inodes_per_group;
    let group_idx = group as usize;
    if group_idx >= super_ref.bgdt.len() {
        return Err(EIO);
    }
    let bg = &super_ref.bgdt[group_idx];

    let inode_size = super_ref.inode_size;
    let block_size = super_ref.block_size;
    // `inode_size` is ≤ block_size (validated at mount), so the
    // multiplication fits in u64.
    let byte_offset = (index_in_group as u64) * (inode_size as u64);
    let block_in_table = byte_offset / (block_size as u64);
    let offset_in_block = (byte_offset % (block_size as u64)) as usize;
    let absolute_block = (bg.bg_inode_table as u64)
        .checked_add(block_in_table)
        .ok_or(EIO)?;

    // 3. Read the inode-table block through the buffer cache and copy
    //    out the 128-byte slot prefix. Holding the buffer-data read
    //    lock only across the copy keeps the cache entry reusable.
    let bh = super_ref
        .cache
        .bread(super_ref.device_id, absolute_block)
        .map_err(|_| EIO)?;
    let mut slot = vec![0u8; EXT2_INODE_SIZE_V0];
    {
        let data = bh.data.read();
        if offset_in_block + EXT2_INODE_SIZE_V0 > data.len() {
            return Err(EIO);
        }
        slot.copy_from_slice(&data[offset_in_block..offset_in_block + EXT2_INODE_SIZE_V0]);
    }
    let disk_inode = DiskInode::decode(&slot);

    // 4. Build the in-memory Ext2Inode + InodeMeta. `large_file` says
    //    how to interpret the `i_dir_acl_or_size_high` slot on reg
    //    files; see RFC 0004 §On-disk types.
    let large_file = (super_ref.sb_disk.s_feature_ro_compat & RO_COMPAT_LARGE_FILE) != 0;
    let ext2_meta = Ext2InodeMeta::from_disk(&disk_inode, large_file);
    let kind = inode_kind_from_mode(ext2_meta.mode)?;
    let vfs_meta = vfs_meta_from(&ext2_meta, block_size);

    let ext2_inode = Arc::new(Ext2Inode::new(Arc::downgrade(super_ref), ino, ext2_meta));
    let inode = Arc::new(Inode::new(
        ino as u64,
        Arc::downgrade(sb),
        ext2_inode.clone() as Arc<dyn InodeOps>,
        Arc::new(Ext2FileOps) as Arc<dyn FileOps>,
        kind,
        vfs_meta,
    ));

    // 5. Install the Weak in the cache under the cache lock. Re-check
    //    residency: another thread may have raced us through the miss
    //    path. Winner-take-all — return the racing thread's Arc if
    //    they beat us to install.
    {
        let mut cache = super_ref.inode_cache.lock();
        if let Some(existing) = cache.get(&ino).and_then(Weak::upgrade) {
            return Ok(existing);
        }
        cache.insert(ino, Arc::downgrade(&inode));
    }
    // Keep ext2_inode alive past the Arc::downgrade above by implicitly
    // referencing it. The `inode.ops` Arc holds the last strong ref
    // through the dyn-trait object.
    let _ = ext2_inode;
    Ok(inode)
}

/// Convenience: `iget(EXT2_ROOT_INO)`. Called from [`Ext2Super`]'s
/// `root_inode` override to back the `SuperBlock::root` once-cell.
pub fn iget_root(super_ref: &Arc<Ext2Super>, sb: &Arc<SuperBlock>) -> Result<Arc<Inode>, i64> {
    iget(super_ref, sb, EXT2_ROOT_INO)
}

/// Small helper: test whether the superblock flags grant RW access.
/// Unused in wave 2 but exposed so Workstream E can consult the same
/// helper at each mutating entry point.
#[inline]
pub fn is_rw(sb: &SuperBlock) -> bool {
    !sb.flags.contains(SbFlags::RDONLY)
}

#[cfg(test)]
mod tests {
    //! Host-side unit tests that don't need the full kernel. The
    //! arithmetic and the `i_mode` decoder are pure functions; the
    //! integration test lives in `kernel/tests/ext2_inode_iget.rs` and
    //! exercises the real cache + ramdisk path.
    use super::*;

    #[test]
    fn inode_kind_recognises_every_posix_s_ifmt() {
        assert_eq!(inode_kind_from_mode(0o100_644), Ok(InodeKind::Reg));
        assert_eq!(inode_kind_from_mode(0o040_755), Ok(InodeKind::Dir));
        assert_eq!(inode_kind_from_mode(0o120_777), Ok(InodeKind::Link));
        assert_eq!(inode_kind_from_mode(0o020_600), Ok(InodeKind::Chr));
        assert_eq!(inode_kind_from_mode(0o060_600), Ok(InodeKind::Blk));
        assert_eq!(inode_kind_from_mode(0o010_644), Ok(InodeKind::Fifo));
        assert_eq!(inode_kind_from_mode(0o140_777), Ok(InodeKind::Sock));
        // 0 S_IFMT (corrupt mode) → EIO. Every other S_IFMT nibble is
        // covered above.
        assert_eq!(inode_kind_from_mode(0o000_000), Err(EIO));
        assert_eq!(inode_kind_from_mode(0o030_000), Err(EIO));
    }

    #[test]
    fn ext2_inode_meta_from_disk_recomposes_uid_gid() {
        let mut disk = DiskInode {
            i_mode: 0o100_644,
            i_uid: 0,
            i_size: 0,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_dtime: 0,
            i_gid: 0,
            i_links_count: 1,
            i_blocks: 0,
            i_flags: 0,
            i_block: [0u32; EXT2_N_BLOCKS],
            i_dir_acl_or_size_high: 0,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };
        disk.set_uid(0x1234_5678);
        disk.set_gid(0x9abc_def0);
        let meta = Ext2InodeMeta::from_disk(&disk, false);
        assert_eq!(meta.uid, 0x1234_5678);
        assert_eq!(meta.gid, 0x9abc_def0);
    }

    #[test]
    fn ext2_inode_meta_from_disk_size_high_on_regular_large_file() {
        // Regular file + large_file → i_size | (i_dir_acl << 32).
        let disk = DiskInode {
            i_mode: 0o100_644,
            i_uid: 0,
            i_size: 0x8000_0001,
            i_atime: 0,
            i_ctime: 0,
            i_mtime: 0,
            i_dtime: 0,
            i_gid: 0,
            i_links_count: 1,
            i_blocks: 0,
            i_flags: 0,
            i_block: [0u32; EXT2_N_BLOCKS],
            i_dir_acl_or_size_high: 0x7,
            l_i_uid_high: 0,
            l_i_gid_high: 0,
        };
        let meta = Ext2InodeMeta::from_disk(&disk, true);
        assert_eq!(meta.size, 0x0000_0007_8000_0001);

        // Regular file without large_file flag → only low 32 bits used.
        let meta_no_large = Ext2InodeMeta::from_disk(&disk, false);
        assert_eq!(meta_no_large.size, 0x8000_0001);

        // Directory ignores i_dir_acl_or_size_high for size even when
        // large_file is set (it's `i_dir_acl` there, not a size high-half).
        let dir_disk = DiskInode {
            i_mode: 0o040_755,
            ..disk.clone()
        };
        let dir_meta = Ext2InodeMeta::from_disk(&dir_disk, true);
        assert_eq!(dir_meta.size, 0x8000_0001);
    }

    #[test]
    fn vfs_meta_forwards_blocks_and_blksize() {
        let meta = Ext2InodeMeta {
            mode: 0o100_644,
            uid: 7,
            gid: 8,
            size: 1234,
            atime: 100,
            ctime: 200,
            mtime: 300,
            dtime: 0,
            links_count: 2,
            i_blocks: 16,
            flags: 0,
            i_block: [0u32; EXT2_N_BLOCKS],
        };
        let vfs = vfs_meta_from(&meta, 1024);
        assert_eq!(vfs.mode, 0o644);
        assert_eq!(vfs.uid, 7);
        assert_eq!(vfs.gid, 8);
        assert_eq!(vfs.size, 1234);
        assert_eq!(vfs.nlink, 2);
        assert_eq!(vfs.blksize, 1024);
        assert_eq!(vfs.blocks, 16);
        assert_eq!(vfs.atime.sec, 100);
        assert_eq!(vfs.ctime.sec, 200);
        assert_eq!(vfs.mtime.sec, 300);
    }

    #[test]
    fn new_inode_cache_and_orphan_list_start_empty() {
        let c = new_inode_cache();
        assert!(c.lock().is_empty());
        let o = new_orphan_list();
        assert!(o.lock().is_empty());
    }
}
