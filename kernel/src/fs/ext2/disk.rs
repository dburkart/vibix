//! On-disk ext2 types — `Ext2SuperBlock`, `Ext2GroupDesc`,
//! `Ext2Inode` (128-byte "good old" layout), and `Ext2DirEntry2`.
//!
//! RFC 0004 §Key data structures — "On-disk types" is the normative spec
//! this module implements. Every on-disk field is little-endian; every
//! accessor routes through explicit `u16::from_le_bytes` /
//! `u32::from_le_bytes` (never a raw `&field` or `ptr::read` on a packed
//! layout), so the driver would cross-compile unchanged to a big-endian
//! host if we ever needed one. The module is pure types + byte accessors:
//! no buffer-cache calls, no trait impls, no `bread`/`sync_dirty_buffer`.
//! Those live in sibling modules in later Workstream D issues.
//!
//! # Read-modify-write (RMW) discipline
//!
//! Inode slots on disk carry fields this driver does not parse — the
//! high halves of uid/gid (`l_i_uid_high`, `l_i_gid_high`), the various
//! reserved/OS-specific bytes (`i_faddr`, `i_generation`, `i_file_acl`,
//! the osd2 tail), and whatever the image creator stamped into the
//! layout we don't touch. Dropping those on a writeback path breaks
//! `e2fsck -D` (NFS fh generation) and corrupts images originally
//! written by Linux ext4 (the high-uid halves). The normative rule
//! (RFC 0004 §On-disk types, third bullet under "Direct `#[repr(C,
//! packed)]` translations"):
//!
//! > On-disk inode writes are always read-modify-write of the raw slot —
//! > the full 128 bytes (or `s_inode_size` in rev 1) are read into
//! > memory, parsed fields update in place, and the whole slot is
//! > written back. Unknown/reserved fields (`i_generation`, `i_file_acl`,
//! > `i_faddr`, the osd2 reserved bytes, `l_i_uid_high`/`l_i_gid_high`)
//! > are preserved verbatim.
//!
//! This module encodes that rule in the type surface: an inode is
//! never serialized "from scratch." The single encode entry point is
//! [`Ext2Inode::encode_to_slot`], which takes a mutable 128-byte slot
//! (already read from the inode-table block) and overlays only the
//! fields this driver owns, leaving everything else byte-for-byte
//! unchanged. The superblock and group-descriptor analogues
//! ([`Ext2SuperBlock::encode_to_slot`], [`Ext2GroupDesc::encode_to_slot`])
//! follow the same pattern for symmetry.
//!
//! # Bitmap math and `s_first_data_block`
//!
//! Bit `i` of block group `G`'s block bitmap corresponds to the
//! absolute block number
//!
//! ```text
//! s_first_data_block + G * s_blocks_per_group + i
//! ```
//!
//! On 1 KiB-block filesystems `s_first_data_block == 1` (the superblock
//! occupies block 1); on ≥ 2 KiB-block filesystems `s_first_data_block
//! == 0`. [`absolute_block`] is the canonical helper. Forgetting the
//! offset either leaks one block per group or double-allocates the
//! superblock/BGDT (RFC 0004 §Bitmap math).

#![allow(dead_code)]

use core::convert::TryInto;

// ---------------------------------------------------------------------------
// Superblock constants
// ---------------------------------------------------------------------------

/// Magic number at superblock offset 56 (little-endian `u16`). Every
/// valid ext2 image starts life with this value; mismatch is `EINVAL` at
/// mount.
pub const EXT2_MAGIC: u16 = 0xEF53;

/// Reserved inode number for the root directory. `iget(EXT2_ROOT_INO)`
/// is the mount-time entry point (RFC 0004 §Mount step 8).
pub const EXT2_ROOT_INO: u32 = 2;

/// Lowest inode number a userspace-visible file may occupy. Inodes
/// `1..=10` are reserved (`EXT2_BAD_INO=1`, `EXT2_ROOT_INO=2`,
/// `EXT2_ACL_IDX_INO=3`, `EXT2_ACL_DATA_INO=4`, `EXT2_BOOT_LOADER_INO=5`,
/// `EXT2_UNDEL_DIR_INO=6`, `EXT2_RESIZE_INO=7`, `EXT2_JOURNAL_INO=8`,
/// `EXT2_EXCLUDE_INO=9`, `EXT2_REPL_INO=10`). Live dirents that point
/// into this range are an image corruption (RFC 0004 §Directory
/// operations — "`inode != 0` but `inode < EXT2_GOOD_OLD_FIRST_INO`").
pub const EXT2_GOOD_OLD_FIRST_INO: u32 = 11;

/// Inode slot size in rev-0 images. Rev-1 images store
/// `s_inode_size`-byte slots (typically 256), but this driver clamps to
/// the 128-byte prefix and preserves the tail verbatim through RMW.
pub const EXT2_GOOD_OLD_INODE_SIZE: u16 = 128;

/// Revision level of the classic rev-0 layout. `s_first_ino` and
/// `s_inode_size` are implicit in rev-0 (= 11 and 128).
pub const EXT2_GOOD_OLD_REV: u32 = 0;

/// Revision level of the "dynamic" layout. Rev-1 adds explicit
/// `s_first_ino`/`s_inode_size` fields and the feature-flag triple.
pub const EXT2_DYNAMIC_REV: u32 = 1;

/// `s_state == EXT2_VALID_FS`: last umount was clean.
pub const EXT2_VALID_FS: u16 = 0x0001;

/// `s_state == EXT2_ERROR_FS`: kernel noticed inconsistency, or RW
/// mount set this to force a `fsck` on next boot.
pub const EXT2_ERROR_FS: u16 = 0x0002;

// ---------------------------------------------------------------------------
// Feature flags
// ---------------------------------------------------------------------------

/// `s_feature_incompat` bit: directory entries carry a `file_type`
/// byte. Required to read any modern `mkfs.ext2` image (RFC 0004 §
/// Feature-flag gate).
pub const INCOMPAT_FILETYPE: u32 = 0x0002;

/// `s_feature_ro_compat` bit: superblock backups are only kept on
/// groups whose number is a power of 3, 5, or 7. Required to avoid
/// corrupting sparse superblock backups (RFC 0004 §Feature-flag gate).
pub const RO_COMPAT_SPARSE_SUPER: u32 = 0x0001;

/// `s_feature_ro_compat` bit: files ≥ 2 GiB are supported — the upper
/// 32 bits of `i_size` live in `i_dir_acl` (a.k.a. `i_size_high` in
/// the ext4 layout).
pub const RO_COMPAT_LARGE_FILE: u32 = 0x0002;

// ---------------------------------------------------------------------------
// Directory-entry file types (when INCOMPAT_FILETYPE is set)
// ---------------------------------------------------------------------------

pub const EXT2_FT_UNKNOWN: u8 = 0;
pub const EXT2_FT_REG_FILE: u8 = 1;
pub const EXT2_FT_DIR: u8 = 2;
pub const EXT2_FT_CHRDEV: u8 = 3;
pub const EXT2_FT_BLKDEV: u8 = 4;
pub const EXT2_FT_FIFO: u8 = 5;
pub const EXT2_FT_SOCK: u8 = 6;
pub const EXT2_FT_SYMLINK: u8 = 7;

// ---------------------------------------------------------------------------
// Low-level byte accessors
// ---------------------------------------------------------------------------

/// Read a little-endian `u16` from `buf[off..off+2]`.
///
/// # Panics
///
/// Panics if `off + 2 > buf.len()`. All call sites in this module
/// supply compile-time-correct offsets that have already been bounded
/// against the struct size; panicking here is load-bearing as a
/// backstop against a future off-by-one in a private accessor.
#[inline]
pub fn read_u16_le(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
}

/// Read a little-endian `u32` from `buf[off..off+4]`. See
/// [`read_u16_le`] for the panic contract.
#[inline]
pub fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
}

/// Write a little-endian `u16` into `buf[off..off+2]`. Mirrors
/// [`read_u16_le`]; never reads the old value (the RMW overlay is the
/// caller's responsibility — this helper only writes).
#[inline]
pub fn write_u16_le(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Write a little-endian `u32` into `buf[off..off+4]`. Mirrors
/// [`write_u16_le`].
#[inline]
pub fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

// ---------------------------------------------------------------------------
// Bitmap math
// ---------------------------------------------------------------------------

/// Bit `i` of group `bg`'s block bitmap corresponds to the absolute
/// block number computed here. See RFC 0004 §Bitmap math:
///
/// ```text
/// absolute_block(bg, i) = s_first_data_block + bg * s_blocks_per_group + i
/// ```
///
/// The helper is `checked_*`-arithmetic internally: an overflow on a
/// malicious superblock returns `None`, which the caller maps to `EIO`
/// and forces the mount RO (see RFC 0004 §Security — "Integer overflow
/// in file-offset math"). Healthy images never overflow: `bg * bpg + i`
/// tops out near `s_blocks_count`, comfortably below `u32::MAX`.
#[inline]
pub fn absolute_block(
    s_first_data_block: u32,
    s_blocks_per_group: u32,
    bg: u32,
    i: u32,
) -> Option<u32> {
    bg.checked_mul(s_blocks_per_group)?
        .checked_add(i)?
        .checked_add(s_first_data_block)
}

// ---------------------------------------------------------------------------
// Ext2SuperBlock — 1024 bytes, resident at byte offset 1024 on disk.
// ---------------------------------------------------------------------------

/// Size of the on-disk superblock slot, in bytes. The superblock lives
/// at byte offset 1024 on disk regardless of the filesystem's block
/// size (RFC 0004 §On-disk types).
pub const EXT2_SUPERBLOCK_SIZE: usize = 1024;

/// Byte offset within the 1024-byte superblock slot where the magic
/// number lives (RFC 0004 §On-disk types: "Magic at offset 56").
pub const EXT2_SB_OFF_MAGIC: usize = 56;

/// Parsed ext2 superblock. Fields present here are the ones every
/// caller in the read path needs; everything else in the 1024-byte
/// slot (`s_algo_bitmap`, `s_prealloc_*`, journaling fields that rev-1
/// repurposed, the volume name + `s_last_mounted` path, the 204-byte
/// trailing reserved region, etc.) is preserved verbatim through the
/// RMW encode path.
///
/// The field order and byte offsets match the Poirier spec and
/// Linux's `struct ext2_super_block` in `include/linux/ext2_fs.h`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2SuperBlock {
    pub s_inodes_count: u32,
    pub s_blocks_count: u32,
    pub s_r_blocks_count: u32,
    pub s_free_blocks_count: u32,
    pub s_free_inodes_count: u32,
    pub s_first_data_block: u32,
    pub s_log_block_size: u32,
    pub s_log_frag_size: u32,
    pub s_blocks_per_group: u32,
    pub s_frags_per_group: u32,
    pub s_inodes_per_group: u32,
    pub s_mtime: u32,
    pub s_wtime: u32,
    pub s_mnt_count: u16,
    pub s_max_mnt_count: u16,
    pub s_magic: u16,
    pub s_state: u16,
    pub s_errors: u16,
    pub s_minor_rev_level: u16,
    pub s_lastcheck: u32,
    pub s_checkinterval: u32,
    pub s_creator_os: u32,
    pub s_rev_level: u32,
    pub s_def_resuid: u16,
    pub s_def_resgid: u16,
    // Rev-1 extended fields (meaningful only when s_rev_level >= EXT2_DYNAMIC_REV;
    // on rev-0 images the bytes read into here are zeros).
    pub s_first_ino: u32,
    pub s_inode_size: u16,
    pub s_block_group_nr: u16,
    pub s_feature_compat: u32,
    pub s_feature_incompat: u32,
    pub s_feature_ro_compat: u32,
    pub s_uuid: [u8; 16],
    pub s_last_orphan: u32,
}

// Field offsets within the 1024-byte superblock slot. Every constant
// here is cross-checked against the Poirier table (§3.1) and Linux's
// `struct ext2_super_block` in `fs/ext2/ext2.h`.
const SB_OFF_INODES_COUNT: usize = 0;
const SB_OFF_BLOCKS_COUNT: usize = 4;
const SB_OFF_R_BLOCKS_COUNT: usize = 8;
const SB_OFF_FREE_BLOCKS_COUNT: usize = 12;
const SB_OFF_FREE_INODES_COUNT: usize = 16;
const SB_OFF_FIRST_DATA_BLOCK: usize = 20;
const SB_OFF_LOG_BLOCK_SIZE: usize = 24;
const SB_OFF_LOG_FRAG_SIZE: usize = 28;
const SB_OFF_BLOCKS_PER_GROUP: usize = 32;
const SB_OFF_FRAGS_PER_GROUP: usize = 36;
const SB_OFF_INODES_PER_GROUP: usize = 40;
const SB_OFF_MTIME: usize = 44;
const SB_OFF_WTIME: usize = 48;
const SB_OFF_MNT_COUNT: usize = 52;
const SB_OFF_MAX_MNT_COUNT: usize = 54;
// SB_OFF_MAGIC is re-exported publicly as EXT2_SB_OFF_MAGIC.
const SB_OFF_STATE: usize = 58;
const SB_OFF_ERRORS: usize = 60;
const SB_OFF_MINOR_REV_LEVEL: usize = 62;
const SB_OFF_LASTCHECK: usize = 64;
const SB_OFF_CHECKINTERVAL: usize = 68;
const SB_OFF_CREATOR_OS: usize = 72;
const SB_OFF_REV_LEVEL: usize = 76;
const SB_OFF_DEF_RESUID: usize = 80;
const SB_OFF_DEF_RESGID: usize = 82;
const SB_OFF_FIRST_INO: usize = 84;
const SB_OFF_INODE_SIZE: usize = 88;
const SB_OFF_BLOCK_GROUP_NR: usize = 90;
const SB_OFF_FEATURE_COMPAT: usize = 92;
const SB_OFF_FEATURE_INCOMPAT: usize = 96;
const SB_OFF_FEATURE_RO_COMPAT: usize = 100;
const SB_OFF_UUID: usize = 104;
const SB_OFF_LAST_ORPHAN: usize = 232;

impl Ext2SuperBlock {
    /// Parse a 1024-byte superblock slot into owned fields. Does not
    /// validate magic or feature flags — the caller (`Ext2Fs::mount`)
    /// performs those checks because the response to a bad magic is
    /// `EINVAL`-refuse-mount, not a panic.
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_SUPERBLOCK_SIZE`.
    pub fn decode(slot: &[u8]) -> Self {
        assert!(
            slot.len() >= EXT2_SUPERBLOCK_SIZE,
            "superblock slot too short: {}",
            slot.len()
        );
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&slot[SB_OFF_UUID..SB_OFF_UUID + 16]);
        Self {
            s_inodes_count: read_u32_le(slot, SB_OFF_INODES_COUNT),
            s_blocks_count: read_u32_le(slot, SB_OFF_BLOCKS_COUNT),
            s_r_blocks_count: read_u32_le(slot, SB_OFF_R_BLOCKS_COUNT),
            s_free_blocks_count: read_u32_le(slot, SB_OFF_FREE_BLOCKS_COUNT),
            s_free_inodes_count: read_u32_le(slot, SB_OFF_FREE_INODES_COUNT),
            s_first_data_block: read_u32_le(slot, SB_OFF_FIRST_DATA_BLOCK),
            s_log_block_size: read_u32_le(slot, SB_OFF_LOG_BLOCK_SIZE),
            s_log_frag_size: read_u32_le(slot, SB_OFF_LOG_FRAG_SIZE),
            s_blocks_per_group: read_u32_le(slot, SB_OFF_BLOCKS_PER_GROUP),
            s_frags_per_group: read_u32_le(slot, SB_OFF_FRAGS_PER_GROUP),
            s_inodes_per_group: read_u32_le(slot, SB_OFF_INODES_PER_GROUP),
            s_mtime: read_u32_le(slot, SB_OFF_MTIME),
            s_wtime: read_u32_le(slot, SB_OFF_WTIME),
            s_mnt_count: read_u16_le(slot, SB_OFF_MNT_COUNT),
            s_max_mnt_count: read_u16_le(slot, SB_OFF_MAX_MNT_COUNT),
            s_magic: read_u16_le(slot, EXT2_SB_OFF_MAGIC),
            s_state: read_u16_le(slot, SB_OFF_STATE),
            s_errors: read_u16_le(slot, SB_OFF_ERRORS),
            s_minor_rev_level: read_u16_le(slot, SB_OFF_MINOR_REV_LEVEL),
            s_lastcheck: read_u32_le(slot, SB_OFF_LASTCHECK),
            s_checkinterval: read_u32_le(slot, SB_OFF_CHECKINTERVAL),
            s_creator_os: read_u32_le(slot, SB_OFF_CREATOR_OS),
            s_rev_level: read_u32_le(slot, SB_OFF_REV_LEVEL),
            s_def_resuid: read_u16_le(slot, SB_OFF_DEF_RESUID),
            s_def_resgid: read_u16_le(slot, SB_OFF_DEF_RESGID),
            s_first_ino: read_u32_le(slot, SB_OFF_FIRST_INO),
            s_inode_size: read_u16_le(slot, SB_OFF_INODE_SIZE),
            s_block_group_nr: read_u16_le(slot, SB_OFF_BLOCK_GROUP_NR),
            s_feature_compat: read_u32_le(slot, SB_OFF_FEATURE_COMPAT),
            s_feature_incompat: read_u32_le(slot, SB_OFF_FEATURE_INCOMPAT),
            s_feature_ro_compat: read_u32_le(slot, SB_OFF_FEATURE_RO_COMPAT),
            s_uuid: uuid,
            s_last_orphan: read_u32_le(slot, SB_OFF_LAST_ORPHAN),
        }
    }

    /// Overlay this struct's parsed fields onto an existing
    /// 1024-byte superblock slot, preserving every byte outside the
    /// parsed field set. This is the RMW write path: the caller must
    /// have read the current slot from disk (via the buffer cache)
    /// before calling this.
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_SUPERBLOCK_SIZE`.
    pub fn encode_to_slot(&self, slot: &mut [u8]) {
        assert!(
            slot.len() >= EXT2_SUPERBLOCK_SIZE,
            "superblock slot too short: {}",
            slot.len()
        );
        write_u32_le(slot, SB_OFF_INODES_COUNT, self.s_inodes_count);
        write_u32_le(slot, SB_OFF_BLOCKS_COUNT, self.s_blocks_count);
        write_u32_le(slot, SB_OFF_R_BLOCKS_COUNT, self.s_r_blocks_count);
        write_u32_le(slot, SB_OFF_FREE_BLOCKS_COUNT, self.s_free_blocks_count);
        write_u32_le(slot, SB_OFF_FREE_INODES_COUNT, self.s_free_inodes_count);
        write_u32_le(slot, SB_OFF_FIRST_DATA_BLOCK, self.s_first_data_block);
        write_u32_le(slot, SB_OFF_LOG_BLOCK_SIZE, self.s_log_block_size);
        write_u32_le(slot, SB_OFF_LOG_FRAG_SIZE, self.s_log_frag_size);
        write_u32_le(slot, SB_OFF_BLOCKS_PER_GROUP, self.s_blocks_per_group);
        write_u32_le(slot, SB_OFF_FRAGS_PER_GROUP, self.s_frags_per_group);
        write_u32_le(slot, SB_OFF_INODES_PER_GROUP, self.s_inodes_per_group);
        write_u32_le(slot, SB_OFF_MTIME, self.s_mtime);
        write_u32_le(slot, SB_OFF_WTIME, self.s_wtime);
        write_u16_le(slot, SB_OFF_MNT_COUNT, self.s_mnt_count);
        write_u16_le(slot, SB_OFF_MAX_MNT_COUNT, self.s_max_mnt_count);
        write_u16_le(slot, EXT2_SB_OFF_MAGIC, self.s_magic);
        write_u16_le(slot, SB_OFF_STATE, self.s_state);
        write_u16_le(slot, SB_OFF_ERRORS, self.s_errors);
        write_u16_le(slot, SB_OFF_MINOR_REV_LEVEL, self.s_minor_rev_level);
        write_u32_le(slot, SB_OFF_LASTCHECK, self.s_lastcheck);
        write_u32_le(slot, SB_OFF_CHECKINTERVAL, self.s_checkinterval);
        write_u32_le(slot, SB_OFF_CREATOR_OS, self.s_creator_os);
        write_u32_le(slot, SB_OFF_REV_LEVEL, self.s_rev_level);
        write_u16_le(slot, SB_OFF_DEF_RESUID, self.s_def_resuid);
        write_u16_le(slot, SB_OFF_DEF_RESGID, self.s_def_resgid);
        write_u32_le(slot, SB_OFF_FIRST_INO, self.s_first_ino);
        write_u16_le(slot, SB_OFF_INODE_SIZE, self.s_inode_size);
        write_u16_le(slot, SB_OFF_BLOCK_GROUP_NR, self.s_block_group_nr);
        write_u32_le(slot, SB_OFF_FEATURE_COMPAT, self.s_feature_compat);
        write_u32_le(slot, SB_OFF_FEATURE_INCOMPAT, self.s_feature_incompat);
        write_u32_le(slot, SB_OFF_FEATURE_RO_COMPAT, self.s_feature_ro_compat);
        slot[SB_OFF_UUID..SB_OFF_UUID + 16].copy_from_slice(&self.s_uuid);
        write_u32_le(slot, SB_OFF_LAST_ORPHAN, self.s_last_orphan);
    }

    /// Compute the filesystem's block size in bytes: `1024 <<
    /// s_log_block_size`. Returns `None` if `s_log_block_size >= 32`
    /// (which would overflow `u32`) — the caller maps this to `EINVAL`
    /// at mount.
    #[inline]
    pub fn block_size(&self) -> Option<u32> {
        if self.s_log_block_size >= 32 {
            None
        } else {
            Some(1024u32 << self.s_log_block_size)
        }
    }
}

// ---------------------------------------------------------------------------
// Ext2GroupDesc — 32 bytes per block group
// ---------------------------------------------------------------------------

/// On-disk group-descriptor slot size in bytes (RFC 0004 §On-disk
/// types — "`Ext2GroupDesc` — 32 bytes").
pub const EXT2_GROUP_DESC_SIZE: usize = 32;

/// Parsed group descriptor. `bg_block_bitmap`, `bg_inode_bitmap`, and
/// `bg_inode_table` are **absolute block numbers** (not group-relative)
/// — the mount path pulls them out into the per-fs "metadata-forbidden"
/// bitmap (RFC 0004 §Indirect-block walker).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2GroupDesc {
    pub bg_block_bitmap: u32,
    pub bg_inode_bitmap: u32,
    pub bg_inode_table: u32,
    pub bg_free_blocks_count: u16,
    pub bg_free_inodes_count: u16,
    pub bg_used_dirs_count: u16,
    pub bg_pad: u16,
    /// 12-byte reserved trail. Zero on `mkfs.ext2`; preserved on every
    /// RMW write.
    pub bg_reserved: [u8; 12],
}

const BGD_OFF_BLOCK_BITMAP: usize = 0;
const BGD_OFF_INODE_BITMAP: usize = 4;
const BGD_OFF_INODE_TABLE: usize = 8;
const BGD_OFF_FREE_BLOCKS_COUNT: usize = 12;
const BGD_OFF_FREE_INODES_COUNT: usize = 14;
const BGD_OFF_USED_DIRS_COUNT: usize = 16;
const BGD_OFF_PAD: usize = 18;
const BGD_OFF_RESERVED: usize = 20;

impl Ext2GroupDesc {
    /// Parse a 32-byte group-descriptor slot.
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_GROUP_DESC_SIZE`.
    pub fn decode(slot: &[u8]) -> Self {
        assert!(
            slot.len() >= EXT2_GROUP_DESC_SIZE,
            "group-desc slot too short: {}",
            slot.len()
        );
        let mut reserved = [0u8; 12];
        reserved.copy_from_slice(&slot[BGD_OFF_RESERVED..BGD_OFF_RESERVED + 12]);
        Self {
            bg_block_bitmap: read_u32_le(slot, BGD_OFF_BLOCK_BITMAP),
            bg_inode_bitmap: read_u32_le(slot, BGD_OFF_INODE_BITMAP),
            bg_inode_table: read_u32_le(slot, BGD_OFF_INODE_TABLE),
            bg_free_blocks_count: read_u16_le(slot, BGD_OFF_FREE_BLOCKS_COUNT),
            bg_free_inodes_count: read_u16_le(slot, BGD_OFF_FREE_INODES_COUNT),
            bg_used_dirs_count: read_u16_le(slot, BGD_OFF_USED_DIRS_COUNT),
            bg_pad: read_u16_le(slot, BGD_OFF_PAD),
            bg_reserved: reserved,
        }
    }

    /// Overlay parsed fields onto an existing 32-byte slot (RMW write
    /// path). Trailing `bg_reserved` bytes in the slot are preserved
    /// byte-for-byte.
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_GROUP_DESC_SIZE`.
    pub fn encode_to_slot(&self, slot: &mut [u8]) {
        assert!(
            slot.len() >= EXT2_GROUP_DESC_SIZE,
            "group-desc slot too short: {}",
            slot.len()
        );
        write_u32_le(slot, BGD_OFF_BLOCK_BITMAP, self.bg_block_bitmap);
        write_u32_le(slot, BGD_OFF_INODE_BITMAP, self.bg_inode_bitmap);
        write_u32_le(slot, BGD_OFF_INODE_TABLE, self.bg_inode_table);
        write_u16_le(slot, BGD_OFF_FREE_BLOCKS_COUNT, self.bg_free_blocks_count);
        write_u16_le(slot, BGD_OFF_FREE_INODES_COUNT, self.bg_free_inodes_count);
        write_u16_le(slot, BGD_OFF_USED_DIRS_COUNT, self.bg_used_dirs_count);
        write_u16_le(slot, BGD_OFF_PAD, self.bg_pad);
        slot[BGD_OFF_RESERVED..BGD_OFF_RESERVED + 12].copy_from_slice(&self.bg_reserved);
    }
}

// ---------------------------------------------------------------------------
// Ext2Inode — "good old" 128-byte rev-0 layout
// ---------------------------------------------------------------------------

/// Number of entries in `Ext2Inode::i_block`. 12 direct + 1 single-
/// indirect + 1 double-indirect + 1 triple-indirect = 15 (RFC 0004 §
/// Indirect-block walker).
pub const EXT2_N_BLOCKS: usize = 15;

/// "Good old" (rev-0) inode slot size in bytes. Rev-1 images store
/// `s_inode_size`-byte slots with a tail region after offset 128; the
/// driver reads and preserves that tail verbatim via RMW.
pub const EXT2_INODE_SIZE_V0: usize = EXT2_GOOD_OLD_INODE_SIZE as usize;

/// Parsed ext2 inode. Only the fields the driver owns are decoded; the
/// rest (`i_generation`, `i_file_acl`, `i_faddr`, `i_osd1`, the osd2
/// trail minus the uid/gid high halves) stay in the raw slot and ride
/// through RMW untouched. This is the normative rule — see the module
/// docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2Inode {
    pub i_mode: u16,
    /// Low 16 bits of the UID. Combined with `l_i_uid_high` to form
    /// the full 32-bit UID; see [`Ext2Inode::uid`] / [`Ext2Inode::set_uid`].
    pub i_uid: u16,
    pub i_size: u32,
    pub i_atime: u32,
    pub i_ctime: u32,
    pub i_mtime: u32,
    pub i_dtime: u32,
    /// Low 16 bits of the GID. Combined with `l_i_gid_high` to form
    /// the full 32-bit GID; see [`Ext2Inode::gid`] / [`Ext2Inode::set_gid`].
    pub i_gid: u16,
    pub i_links_count: u16,
    /// `i_blocks` is in **512-byte units**, not fs-block units (RFC
    /// 0004 §On-disk types — "i_blocks is in 512-byte units").
    pub i_blocks: u32,
    pub i_flags: u32,
    /// 15 block pointers: 12 direct, 1 single-indirect, 1 double-
    /// indirect, 1 triple-indirect. Zero means "hole."
    pub i_block: [u32; EXT2_N_BLOCKS],
    /// `i_dir_acl` on directories; upper 32 bits of `i_size` on
    /// regular files when `RO_COMPAT_LARGE_FILE` is set.
    pub i_dir_acl_or_size_high: u32,
    /// High 16 bits of the UID (osd2.linux2, offset 120..122 within
    /// the 128-byte slot). Together with `i_uid` this forms the full
    /// 32-bit uid.
    pub l_i_uid_high: u16,
    /// High 16 bits of the GID (osd2.linux2, offset 122..124).
    pub l_i_gid_high: u16,
}

// Field offsets within the 128-byte inode slot. Cross-referenced
// against Linux's `struct ext2_inode` in `fs/ext2/ext2.h` and the
// Poirier table (§5.1).
const INODE_OFF_MODE: usize = 0;
const INODE_OFF_UID: usize = 2;
const INODE_OFF_SIZE: usize = 4;
const INODE_OFF_ATIME: usize = 8;
const INODE_OFF_CTIME: usize = 12;
const INODE_OFF_MTIME: usize = 16;
const INODE_OFF_DTIME: usize = 20;
const INODE_OFF_GID: usize = 24;
const INODE_OFF_LINKS_COUNT: usize = 26;
const INODE_OFF_BLOCKS: usize = 28;
const INODE_OFF_FLAGS: usize = 32;
// i_osd1: offset 36..40 — preserved verbatim by RMW
const INODE_OFF_I_BLOCK: usize = 40; // 15 u32s, through offset 100.
// i_generation: offset 100..104 — preserved verbatim by RMW
// i_file_acl:   offset 104..108 — preserved verbatim by RMW
const INODE_OFF_DIR_ACL_OR_SIZE_HIGH: usize = 108;
// i_faddr:      offset 112..116 — preserved verbatim by RMW
// i_osd2[12]:   offset 116..128; within it:
//   - fragment bits:        116..118 (l_i_frag / l_i_fsize, preserved)
//   - i_pad1:               118..120 (preserved)
//   - l_i_uid_high:         120..122
//   - l_i_gid_high:         122..124
//   - reserved2:            124..128 (preserved)
const INODE_OFF_L_I_UID_HIGH: usize = 120;
const INODE_OFF_L_I_GID_HIGH: usize = 122;

impl Ext2Inode {
    /// Parse a 128-byte inode slot. Does not validate `i_mode` or
    /// enforce bounds on `i_block[]`; those checks are the read-path's
    /// job because the correct response is "`EIO`-force-RO," not
    /// panic (RFC 0004 §Indirect-block walker).
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_INODE_SIZE_V0`.
    pub fn decode(slot: &[u8]) -> Self {
        assert!(
            slot.len() >= EXT2_INODE_SIZE_V0,
            "inode slot too short: {}",
            slot.len()
        );
        let mut i_block = [0u32; EXT2_N_BLOCKS];
        for (i, entry) in i_block.iter_mut().enumerate() {
            *entry = read_u32_le(slot, INODE_OFF_I_BLOCK + 4 * i);
        }
        Self {
            i_mode: read_u16_le(slot, INODE_OFF_MODE),
            i_uid: read_u16_le(slot, INODE_OFF_UID),
            i_size: read_u32_le(slot, INODE_OFF_SIZE),
            i_atime: read_u32_le(slot, INODE_OFF_ATIME),
            i_ctime: read_u32_le(slot, INODE_OFF_CTIME),
            i_mtime: read_u32_le(slot, INODE_OFF_MTIME),
            i_dtime: read_u32_le(slot, INODE_OFF_DTIME),
            i_gid: read_u16_le(slot, INODE_OFF_GID),
            i_links_count: read_u16_le(slot, INODE_OFF_LINKS_COUNT),
            i_blocks: read_u32_le(slot, INODE_OFF_BLOCKS),
            i_flags: read_u32_le(slot, INODE_OFF_FLAGS),
            i_block,
            i_dir_acl_or_size_high: read_u32_le(slot, INODE_OFF_DIR_ACL_OR_SIZE_HIGH),
            l_i_uid_high: read_u16_le(slot, INODE_OFF_L_I_UID_HIGH),
            l_i_gid_high: read_u16_le(slot, INODE_OFF_L_I_GID_HIGH),
        }
    }

    /// Overlay the driver-owned fields onto an existing 128-byte
    /// inode slot. **This is the only legitimate way to prepare an
    /// inode slot for writeback.** The caller must read the current
    /// slot from disk (via the buffer cache), decode it if needed,
    /// mutate the in-memory struct, then call this to produce the
    /// bytes that go back onto disk.
    ///
    /// Preserves, byte-for-byte:
    /// - `i_osd1` (offset 36..40)
    /// - `i_generation` (100..104)
    /// - `i_file_acl` (104..108)
    /// - `i_faddr` (112..116)
    /// - osd2 fragment / pad fields (116..120, 124..128)
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_INODE_SIZE_V0`.
    pub fn encode_to_slot(&self, slot: &mut [u8]) {
        assert!(
            slot.len() >= EXT2_INODE_SIZE_V0,
            "inode slot too short: {}",
            slot.len()
        );
        write_u16_le(slot, INODE_OFF_MODE, self.i_mode);
        write_u16_le(slot, INODE_OFF_UID, self.i_uid);
        write_u32_le(slot, INODE_OFF_SIZE, self.i_size);
        write_u32_le(slot, INODE_OFF_ATIME, self.i_atime);
        write_u32_le(slot, INODE_OFF_CTIME, self.i_ctime);
        write_u32_le(slot, INODE_OFF_MTIME, self.i_mtime);
        write_u32_le(slot, INODE_OFF_DTIME, self.i_dtime);
        write_u16_le(slot, INODE_OFF_GID, self.i_gid);
        write_u16_le(slot, INODE_OFF_LINKS_COUNT, self.i_links_count);
        write_u32_le(slot, INODE_OFF_BLOCKS, self.i_blocks);
        write_u32_le(slot, INODE_OFF_FLAGS, self.i_flags);
        for (i, entry) in self.i_block.iter().enumerate() {
            write_u32_le(slot, INODE_OFF_I_BLOCK + 4 * i, *entry);
        }
        write_u32_le(
            slot,
            INODE_OFF_DIR_ACL_OR_SIZE_HIGH,
            self.i_dir_acl_or_size_high,
        );
        write_u16_le(slot, INODE_OFF_L_I_UID_HIGH, self.l_i_uid_high);
        write_u16_le(slot, INODE_OFF_L_I_GID_HIGH, self.l_i_gid_high);
    }

    /// Recompose the full 32-bit UID from the `i_uid` low-half and the
    /// `l_i_uid_high` osd2.linux2 high-half. `chown` always writes
    /// both halves; reading both halves keeps images originally
    /// produced by a 32-bit-uid Linux ext4 intact.
    #[inline]
    pub fn uid(&self) -> u32 {
        (self.l_i_uid_high as u32) << 16 | (self.i_uid as u32)
    }

    /// Recompose the full 32-bit GID. See [`Self::uid`].
    #[inline]
    pub fn gid(&self) -> u32 {
        (self.l_i_gid_high as u32) << 16 | (self.i_gid as u32)
    }

    /// Split a full 32-bit UID into the low (`i_uid`) and high
    /// (`l_i_uid_high`) halves. Mirrors Linux's `ext2_write_inode`:
    /// any `chown` to a value that fits in `u32` round-trips
    /// byte-for-byte.
    #[inline]
    pub fn set_uid(&mut self, uid: u32) {
        self.i_uid = uid as u16;
        self.l_i_uid_high = (uid >> 16) as u16;
    }

    /// Split a full 32-bit GID into `i_gid` + `l_i_gid_high`. See
    /// [`Self::set_uid`].
    #[inline]
    pub fn set_gid(&mut self, gid: u32) {
        self.i_gid = gid as u16;
        self.l_i_gid_high = (gid >> 16) as u16;
    }
}

// ---------------------------------------------------------------------------
// Ext2DirEntry2 — variable-length directory record
// ---------------------------------------------------------------------------

/// Size of the fixed header of an `ext2_dir_entry_2` record (inode +
/// rec_len + name_len + file_type, before the name bytes).
pub const EXT2_DIR_REC_HEADER_LEN: usize = 8;

/// Parsed fixed-size header of a directory record. The caller owns
/// slicing the name bytes out of the parent buffer using the returned
/// `name_len` — copying them here would force an allocation on every
/// iteration for no gain.
///
/// RFC 0004 §Directory operations is normative for the per-record
/// validation rules; this struct is the decode step they operate on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext2DirEntry2 {
    /// Inode number. `inode == 0` is the universal tombstone (RFC
    /// 0004 §Directory operations).
    pub inode: u32,
    /// Record length including header + name + padding, 4-byte
    /// aligned. Must be `>= 8`, 4-byte aligned, and `cursor + rec_len
    /// <= block_end`.
    pub rec_len: u16,
    /// Name byte count. On a live record, `name_len > 0`.
    pub name_len: u8,
    /// `file_type` (`EXT2_FT_*`) when the FS has `INCOMPAT_FILETYPE`
    /// set; otherwise this byte is the high byte of `name_len` on
    /// pre-rev-1 images. The driver always decodes both fields; the
    /// caller decides which interpretation to trust based on the
    /// superblock's incompat flags.
    pub file_type: u8,
}

impl Ext2DirEntry2 {
    /// Parse the 8-byte header at the start of `slot`. Does not
    /// validate the fields (the caller — lookup, getdents64 — enforces
    /// the rec_len / name_len / file_type rules per RFC 0004 §
    /// Directory operations and turns any violation into `EIO`).
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_DIR_REC_HEADER_LEN`.
    pub fn decode_header(slot: &[u8]) -> Self {
        assert!(
            slot.len() >= EXT2_DIR_REC_HEADER_LEN,
            "dir-entry slot too short: {}",
            slot.len()
        );
        Self {
            inode: read_u32_le(slot, 0),
            rec_len: read_u16_le(slot, 4),
            name_len: slot[6],
            file_type: slot[7],
        }
    }

    /// Write the 8-byte header to the start of `slot`. Does not
    /// write name bytes — the caller is responsible for copying
    /// `name[..name_len]` into `slot[8..8+name_len]` (and for zero-
    /// filling any padding up to `rec_len`, per the 4-byte-align
    /// contract).
    ///
    /// # Panics
    ///
    /// Panics if `slot.len() < EXT2_DIR_REC_HEADER_LEN`.
    pub fn encode_header_to_slot(&self, slot: &mut [u8]) {
        assert!(
            slot.len() >= EXT2_DIR_REC_HEADER_LEN,
            "dir-entry slot too short: {}",
            slot.len()
        );
        write_u32_le(slot, 0, self.inode);
        write_u16_le(slot, 4, self.rec_len);
        slot[6] = self.name_len;
        slot[7] = self.file_type;
    }
}

/// 4-byte align a directory-record payload length (header + name
/// bytes). Returns `None` on overflow, which the caller maps to
/// `ENAMETOOLONG`/`EIO`.
///
/// `rec_len` in the on-disk format is always `align4(8 + name_len)`
/// *for a minimally-sized* record; larger `rec_len` values indicate
/// trailing slack (used by the dirent-insert split path).
#[inline]
pub fn align4_rec_len(header_plus_name: usize) -> Option<usize> {
    header_plus_name.checked_add(3).map(|v| v & !3)
}

// ---------------------------------------------------------------------------
// Host unit tests — round-trip every struct against golden bytes from
// a `mkfs.ext2` image. The fixture was produced deterministically with
//
//     dd if=/dev/zero of=golden.img bs=1024 count=1024
//     E2FSPROGS_FAKE_TIME=1000000000 mkfs.ext2 -b 1024 -N 64 -I 128 -F \
//         -U 00000000-0000-0000-0000-000000000001 \
//         -E hash_seed=11111111-2222-3333-4444-555555555555 \
//         -M / -t ext2 \
//         -O '^dir_index,^has_journal,^ext_attr,^resize_inode' \
//         golden.img
//
// so re-running the generator on another host produces identical
// bytes. Rather than check in the 1 MiB image, the tests inline the
// specific byte slices they decode — the superblock (1024 bytes), the
// first group descriptor (32 bytes), the root inode (128 bytes at
// byte offset 5*1024 + 128 = 5248), and the root-directory data block
// (64 bytes of the 1024-byte block at byte offset 13*1024 = 13312,
// which is enough to cover `.`, `..`, and `lost+found`).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 1024 bytes of the `mkfs.ext2` superblock, byte-for-byte.
    /// Offset 0 corresponds to on-disk byte offset 1024.
    const GOLDEN_SB: &[u8; 1024] = include_bytes!("fixtures/golden_superblock.bin");

    /// 32 bytes of the first group descriptor, byte-for-byte. Offset 0
    /// corresponds to on-disk byte offset 2048 (block 2 on a 1 KiB
    /// filesystem).
    const GOLDEN_BGD0: &[u8; 32] = include_bytes!("fixtures/golden_bgd0.bin");

    /// 128 bytes of the root inode (ino 2), byte-for-byte. Offset 0
    /// corresponds to on-disk byte offset 5248 (block 5 × 1024 + 1 ×
    /// 128).
    const GOLDEN_ROOT_INODE: &[u8; 128] =
        include_bytes!("fixtures/golden_root_inode.bin");

    /// 64 bytes of the root directory's first block, covering the
    /// `.`, `..`, and `lost+found` records.
    const GOLDEN_ROOT_DIR: &[u8; 64] = include_bytes!("fixtures/golden_root_dir.bin");

    #[test]
    fn superblock_magic_offset_is_56() {
        // Normative pin: magic lives at byte 56 regardless of
        // anything else the superblock carries. If this ever moves,
        // every image-parsing tool would break in lockstep.
        assert_eq!(EXT2_SB_OFF_MAGIC, 56);
        assert_eq!(read_u16_le(GOLDEN_SB, 56), EXT2_MAGIC);
    }

    #[test]
    fn constants_match_rfc() {
        assert_eq!(EXT2_MAGIC, 0xEF53);
        assert_eq!(EXT2_ROOT_INO, 2);
        assert_eq!(EXT2_GOOD_OLD_FIRST_INO, 11);
        assert_eq!(EXT2_GOOD_OLD_INODE_SIZE, 128);
        assert_eq!(INCOMPAT_FILETYPE, 0x0002);
        assert_eq!(RO_COMPAT_SPARSE_SUPER, 0x0001);
        assert_eq!(RO_COMPAT_LARGE_FILE, 0x0002);
    }

    #[test]
    fn superblock_decodes_and_matches_mkfs_params() {
        let sb = Ext2SuperBlock::decode(GOLDEN_SB);
        assert_eq!(sb.s_magic, EXT2_MAGIC);
        // `-N 64 -b 1024 -b 1024 count=1024` in the mkfs invocation.
        assert_eq!(sb.s_inodes_count, 64);
        assert_eq!(sb.s_blocks_count, 1024);
        // 1 KiB blocks → s_log_block_size == 0 → block_size() == 1024.
        assert_eq!(sb.s_log_block_size, 0);
        assert_eq!(sb.block_size(), Some(1024));
        // 1 KiB filesystem → s_first_data_block == 1 (RFC 0004 §
        // Bitmap math).
        assert_eq!(sb.s_first_data_block, 1);
        // Rev-1 "dynamic" layout (mkfs.ext2 default for modern images).
        assert_eq!(sb.s_rev_level, EXT2_DYNAMIC_REV);
        assert_eq!(sb.s_first_ino, EXT2_GOOD_OLD_FIRST_INO);
        assert_eq!(sb.s_inode_size, EXT2_GOOD_OLD_INODE_SIZE);
        // Features: mkfs.ext2 enables filetype, sparse_super, and
        // large_file by default on the "ext2" mkfs type.
        assert!(sb.s_feature_incompat & INCOMPAT_FILETYPE != 0);
        assert!(sb.s_feature_ro_compat & RO_COMPAT_SPARSE_SUPER != 0);
        assert!(sb.s_feature_ro_compat & RO_COMPAT_LARGE_FILE != 0);
        // The mkfs invocation pinned the UUID to this fixed value.
        let want_uuid = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(sb.s_uuid, want_uuid);
    }

    #[test]
    fn superblock_roundtrip_is_byte_identical() {
        let sb = Ext2SuperBlock::decode(GOLDEN_SB);
        let mut slot = *GOLDEN_SB;
        sb.encode_to_slot(&mut slot);
        // Every byte should be unchanged: the decode recovered every
        // field the encoder writes, and the encoder preserves
        // everything else via the RMW contract.
        assert_eq!(&slot[..], &GOLDEN_SB[..]);
    }

    #[test]
    fn superblock_rmw_preserves_unknown_tail() {
        // Stamp a recognisable pattern into bytes that the decoder
        // does not parse (e.g., offset 236..1024 — beyond
        // `s_last_orphan`). After encode_to_slot, those bytes must
        // still be intact.
        let sb = Ext2SuperBlock::decode(GOLDEN_SB);
        let mut slot = *GOLDEN_SB;
        for (i, b) in slot[236..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let expected_tail: [u8; 1024 - 236] = {
            let mut t = [0u8; 1024 - 236];
            for (i, b) in t.iter_mut().enumerate() {
                *b = (i % 251) as u8;
            }
            t
        };
        sb.encode_to_slot(&mut slot);
        assert_eq!(&slot[236..], &expected_tail[..]);
        // And the parsed prefix round-trips unchanged.
        let sb2 = Ext2SuperBlock::decode(&slot);
        assert_eq!(sb, sb2);
    }

    #[test]
    fn group_desc_decodes_and_matches_mkfs() {
        let bgd = Ext2GroupDesc::decode(GOLDEN_BGD0);
        // Per `dumpe2fs`:
        //   Block bitmap at 3, Inode bitmap at 4, Inode table at 5.
        assert_eq!(bgd.bg_block_bitmap, 3);
        assert_eq!(bgd.bg_inode_bitmap, 4);
        assert_eq!(bgd.bg_inode_table, 5);
        // 998 free blocks, 53 free inodes, 2 directories (/ and
        // lost+found).
        assert_eq!(bgd.bg_free_blocks_count, 998);
        assert_eq!(bgd.bg_free_inodes_count, 53);
        assert_eq!(bgd.bg_used_dirs_count, 2);
    }

    #[test]
    fn group_desc_roundtrip_is_byte_identical() {
        let bgd = Ext2GroupDesc::decode(GOLDEN_BGD0);
        let mut slot = *GOLDEN_BGD0;
        bgd.encode_to_slot(&mut slot);
        assert_eq!(&slot[..], &GOLDEN_BGD0[..]);
    }

    #[test]
    fn group_desc_rmw_preserves_reserved_tail() {
        let mut bgd = Ext2GroupDesc::decode(GOLDEN_BGD0);
        // Stamp the reserved bytes with a pattern, decode into the
        // in-memory struct via encode/decode, and verify the pattern
        // survives.
        bgd.bg_reserved = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc,
        ];
        let mut slot = *GOLDEN_BGD0;
        bgd.encode_to_slot(&mut slot);
        let bgd2 = Ext2GroupDesc::decode(&slot);
        assert_eq!(bgd, bgd2);
        assert_eq!(
            &slot[BGD_OFF_RESERVED..BGD_OFF_RESERVED + 12],
            &bgd.bg_reserved[..]
        );
    }

    #[test]
    fn root_inode_decodes_matches_mkfs() {
        let inode = Ext2Inode::decode(GOLDEN_ROOT_INODE);
        // mkfs.ext2 stamps root as 040755 (directory + rwxr-xr-x).
        // 0o40755 = 0x41ed.
        assert_eq!(inode.i_mode, 0o40755);
        // root owner/group = 0 on mkfs.
        assert_eq!(inode.uid(), 0);
        assert_eq!(inode.gid(), 0);
        // Link count: `.` + `..` from lost+found + the dirent itself
        // = 3. (The directory's self `.` is not reflected in
        // `i_links_count`; mkfs gives 3 for the live `..` from
        // `lost+found` plus the `/` backlink plus `/`.)
        assert_eq!(inode.i_links_count, 3);
        // Size: the root directory block size = 1024.
        assert_eq!(inode.i_size, 1024);
        // i_blocks: one 1 KiB data block = 2 × 512-byte sectors.
        assert_eq!(inode.i_blocks, 2);
        // i_block[0] = 13 (the root directory's data block).
        assert_eq!(inode.i_block[0], 13);
        for b in &inode.i_block[1..] {
            assert_eq!(*b, 0);
        }
    }

    #[test]
    fn root_inode_roundtrip_is_byte_identical() {
        let inode = Ext2Inode::decode(GOLDEN_ROOT_INODE);
        let mut slot = *GOLDEN_ROOT_INODE;
        inode.encode_to_slot(&mut slot);
        assert_eq!(&slot[..], &GOLDEN_ROOT_INODE[..]);
    }

    #[test]
    fn inode_rmw_preserves_unknown_osd2_and_generation() {
        // Stamp the osd2 fragment/pad bytes (116..120) and the
        // generation/faddr/file_acl region (100..112, 112..116) with
        // a pattern. After decode + encode_to_slot, those bytes must
        // survive byte-for-byte — they are not in the parsed field
        // set.
        let mut slot = *GOLDEN_ROOT_INODE;
        let stamp: &[(usize, &[u8])] = &[
            // i_generation (100..104)
            (100, &[0xde, 0xad, 0xbe, 0xef]),
            // i_file_acl (104..108)
            (104, &[0xca, 0xfe, 0xba, 0xbe]),
            // i_faddr (112..116)
            (112, &[0x12, 0x34, 0x56, 0x78]),
            // osd2 fragment/pad (116..120)
            (116, &[0xa1, 0xa2, 0xa3, 0xa4]),
            // osd2 reserved trail (124..128)
            (124, &[0xb1, 0xb2, 0xb3, 0xb4]),
        ];
        for (off, bytes) in stamp {
            slot[*off..*off + bytes.len()].copy_from_slice(bytes);
        }
        let inode = Ext2Inode::decode(&slot);
        let mut slot2 = slot;
        inode.encode_to_slot(&mut slot2);
        for (off, bytes) in stamp {
            assert_eq!(&slot2[*off..*off + bytes.len()], *bytes, "offset {}", off);
        }
    }

    #[test]
    fn inode_rmw_preserves_high_uid_gid_halves() {
        // Regression test for the most load-bearing RMW field: the
        // osd2.linux2 high halves of uid/gid. Drop them and every
        // image produced on a 32-bit-UID Linux ext4 volume
        // silently loses the upper 16 bits of every owner.
        let mut slot = *GOLDEN_ROOT_INODE;
        // Stamp high uid = 0xaabb, high gid = 0xccdd.
        slot[INODE_OFF_L_I_UID_HIGH..INODE_OFF_L_I_UID_HIGH + 2].copy_from_slice(&0xaabbu16.to_le_bytes());
        slot[INODE_OFF_L_I_GID_HIGH..INODE_OFF_L_I_GID_HIGH + 2].copy_from_slice(&0xccddu16.to_le_bytes());
        let inode = Ext2Inode::decode(&slot);
        assert_eq!(inode.l_i_uid_high, 0xaabb);
        assert_eq!(inode.l_i_gid_high, 0xccdd);
        // uid/gid reflect the full 32-bit recomposition.
        assert_eq!(inode.uid(), 0xaabb_0000);
        assert_eq!(inode.gid(), 0xccdd_0000);
        // Writing back preserves the bytes.
        let mut slot2 = slot;
        inode.encode_to_slot(&mut slot2);
        assert_eq!(
            &slot2[INODE_OFF_L_I_UID_HIGH..INODE_OFF_L_I_UID_HIGH + 2],
            &0xaabbu16.to_le_bytes()
        );
        assert_eq!(
            &slot2[INODE_OFF_L_I_GID_HIGH..INODE_OFF_L_I_GID_HIGH + 2],
            &0xccddu16.to_le_bytes()
        );
    }

    #[test]
    fn set_uid_gid_splits_across_halves() {
        let mut inode = Ext2Inode::decode(GOLDEN_ROOT_INODE);
        inode.set_uid(0x1234_5678);
        inode.set_gid(0x9abc_def0);
        assert_eq!(inode.i_uid, 0x5678);
        assert_eq!(inode.l_i_uid_high, 0x1234);
        assert_eq!(inode.uid(), 0x1234_5678);
        assert_eq!(inode.i_gid, 0xdef0);
        assert_eq!(inode.l_i_gid_high, 0x9abc);
        assert_eq!(inode.gid(), 0x9abc_def0);
    }

    #[test]
    fn dir_entries_decode_dot_dotdot_lostfound() {
        // Entry 0: "." → ino 2, rec_len 12, name_len 1, ft DIR
        let e0 = Ext2DirEntry2::decode_header(&GOLDEN_ROOT_DIR[0..8]);
        assert_eq!(e0.inode, 2);
        assert_eq!(e0.rec_len, 12);
        assert_eq!(e0.name_len, 1);
        assert_eq!(e0.file_type, EXT2_FT_DIR);
        assert_eq!(&GOLDEN_ROOT_DIR[8..9], b".");

        // Entry 1 at offset 12: ".." → ino 2, rec_len 12, name_len 2, ft DIR
        let e1 = Ext2DirEntry2::decode_header(&GOLDEN_ROOT_DIR[12..20]);
        assert_eq!(e1.inode, 2);
        assert_eq!(e1.rec_len, 12);
        assert_eq!(e1.name_len, 2);
        assert_eq!(e1.file_type, EXT2_FT_DIR);
        assert_eq!(&GOLDEN_ROOT_DIR[20..22], b"..");

        // Entry 2 at offset 24: "lost+found" → ino 11, rec_len fills
        // the rest of the block (1000 = 0x3e8), name_len 10, ft DIR.
        let e2 = Ext2DirEntry2::decode_header(&GOLDEN_ROOT_DIR[24..32]);
        assert_eq!(e2.inode, 11);
        assert_eq!(e2.rec_len, 1000); // 1024 - 12 - 12 = 1000
        assert_eq!(e2.name_len, 10);
        assert_eq!(e2.file_type, EXT2_FT_DIR);
        assert_eq!(&GOLDEN_ROOT_DIR[32..42], b"lost+found");
    }

    #[test]
    fn dir_entry_roundtrip_is_byte_identical() {
        let e = Ext2DirEntry2::decode_header(&GOLDEN_ROOT_DIR[0..8]);
        let mut slot = [0u8; 8];
        e.encode_header_to_slot(&mut slot);
        assert_eq!(&slot[..], &GOLDEN_ROOT_DIR[0..8]);
    }

    #[test]
    fn absolute_block_formula_matches_rfc() {
        // RFC 0004 §Bitmap math: s_first_data_block + bg *
        // s_blocks_per_group + i.
        //
        // 1 KiB-block filesystems: s_first_data_block == 1.
        assert_eq!(absolute_block(1, 8192, 0, 0), Some(1));
        assert_eq!(absolute_block(1, 8192, 0, 100), Some(101));
        assert_eq!(absolute_block(1, 8192, 1, 0), Some(8193));
        // 2 KiB+ filesystems: s_first_data_block == 0.
        assert_eq!(absolute_block(0, 4096, 0, 0), Some(0));
        assert_eq!(absolute_block(0, 4096, 3, 42), Some(12330));
        // Overflow → None.
        assert_eq!(absolute_block(1, u32::MAX, u32::MAX, 0), None);
    }

    #[test]
    fn align4_rec_len_basic() {
        assert_eq!(align4_rec_len(8), Some(8));
        assert_eq!(align4_rec_len(9), Some(12));
        assert_eq!(align4_rec_len(12), Some(12));
        assert_eq!(align4_rec_len(13), Some(16));
        // Overflow guard.
        assert_eq!(align4_rec_len(usize::MAX), None);
    }

    #[test]
    fn block_size_guard_against_absurd_log() {
        // A hostile image with s_log_block_size >= 32 would overflow
        // `1024 << n`. We return None rather than panic; the mount
        // path translates that to EINVAL.
        let mut slot = *GOLDEN_SB;
        write_u32_le(&mut slot, SB_OFF_LOG_BLOCK_SIZE, 32);
        let sb = Ext2SuperBlock::decode(&slot);
        assert_eq!(sb.block_size(), None);
        write_u32_le(&mut slot, SB_OFF_LOG_BLOCK_SIZE, 0);
        let sb = Ext2SuperBlock::decode(&slot);
        assert_eq!(sb.block_size(), Some(1024));
    }
}
