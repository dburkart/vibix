//! ext2 filesystem driver — `Ext2Fs`, `Ext2Super`, mount sequence.
//!
//! RFC 0004 (`docs/RFC/0004-ext2-filesystem-driver.md`), Workstream D.
//! Issue #558 (wave 2) implements the driver shell: the [`FileSystem`]
//! factory, the [`SuperOps`] per-mount instance, and the mount pipeline
//! that walks from "raw block device" to "validated, ready-for-lookup
//! superblock object". The inode, dir-entry, and allocator surfaces live
//! in sibling wave-3/4 issues (#559, #560).
//!
//! # Mount pipeline (RFC 0004 §Mount)
//!
//! 1. Read the 1024-byte on-disk superblock at device byte offset 1024.
//!    This is done *without* the buffer cache — the block size isn't
//!    known until the SB is parsed, and the cache needs the block size
//!    at construction.
//! 2. Parse and validate: `s_magic == 0xEF53`; `block_size()` returns
//!    `Some(_)` (rejecting `s_log_block_size >= 32`); rev-level is
//!    rev-0 or rev-1; `s_inode_size` is sane; group count ≥ 1.
//! 3. Gate feature flags:
//!    - Unknown `s_feature_incompat` bit → `EINVAL`, refuse mount.
//!    - Unknown `s_feature_ro_compat` bit → force RO (mark the
//!      [`SbFlags::RDONLY`] and the driver's [`Ext2MountFlags`] bit).
//!    - Unknown `s_feature_compat` bit → ignored.
//! 4. Construct a [`BlockCache`] sized to the parsed block size,
//!    register a [`DeviceId`] against it, and `bread` the block group
//!    descriptor table starting at `s_first_data_block + 1`.
//! 5. If the effective mount is RW and the caller did not set
//!    [`MountFlags::RDONLY`], stamp `s_state := EXT2_ERROR_FS` and write
//!    the superblock back (via `bread` + RMW + `mark_dirty` +
//!    `sync_dirty_buffer`). A clean unmount will rewrite `EXT2_VALID_FS`
//!    later (Workstream F). RO mounts MUST NOT write anything.
//! 6. Allocate an [`FsId`](crate::fs::vfs::FsId), build the [`SuperBlock`]
//!    with the resolved [`SbFlags`], and return it.
//!
//! The root inode is *not* populated at mount time in wave 2. Wave 3
//! (#559) adds `read_inode`/`lookup` and wires `sb.root.call_once(...)`
//! in from the caller that first resolves ino 2.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use super::disk::{
    Ext2GroupDesc, Ext2SuperBlock, EXT2_DYNAMIC_REV, EXT2_ERROR_FS, EXT2_GOOD_OLD_FIRST_INO,
    EXT2_GOOD_OLD_INODE_SIZE, EXT2_GOOD_OLD_REV, EXT2_GROUP_DESC_SIZE, EXT2_MAGIC,
    EXT2_SUPERBLOCK_SIZE, INCOMPAT_FILETYPE, RO_COMPAT_LARGE_FILE, RO_COMPAT_SPARSE_SUPER,
};

use crate::block::cache::{BlockCache, DeviceId};
use crate::block::BlockDevice;
use crate::fs::vfs::inode::Inode;
use crate::fs::vfs::mount_table::alloc_fs_id;
use crate::fs::vfs::ops::{FileSystem, MountSource, StatFs, SuperOps};
use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
use crate::fs::vfs::MountFlags;
use crate::fs::{EBUSY, EINVAL, EIO, ENODEV};

/// Byte offset of the primary superblock on *every* ext2 volume,
/// regardless of block size (RFC 0004 §On-disk types). The driver reads
/// this via direct `BlockDevice::read_at` before the cache is
/// constructed.
pub const SUPERBLOCK_BYTE_OFFSET: u64 = 1024;

/// Default resident-buffer cap for the per-mount [`BlockCache`]. Large
/// enough to keep the root directory and a handful of indirect blocks
/// pinned on a small filesystem; small enough to not strain the kernel
/// heap on the boot-time tests. Tuning deferred to a real workload.
const BLOCK_CACHE_CAPACITY: usize = 128;

/// Bitmask of every `s_feature_incompat` bit the driver *understands*
/// well enough to mount RW. Anything outside this set in the SB's
/// incompat mask is a mount-time `EINVAL`.
///
/// Today the driver only teaches itself [`INCOMPAT_FILETYPE`]; the
/// directory-entry walker in #559 reads `file_type` when the bit is
/// set and falls back to "consult inode mode" when it isn't.
const SUPPORTED_INCOMPAT: u32 = INCOMPAT_FILETYPE;

/// Bitmask of every `s_feature_ro_compat` bit the driver understands
/// *and* is safe to write through. An unknown RO_COMPAT bit forces the
/// mount read-only — the kernel can read the filesystem but can't write
/// to it without risking corruption of a feature it doesn't model.
const SUPPORTED_RO_COMPAT: u32 = RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE;

/// Per-mount flag set carried alongside the VFS [`MountFlags`] /
/// [`SbFlags`] pair.
///
/// The VFS's `MountFlags` covers the subset the generic layer enforces
/// (RDONLY, NOEXEC, NOSUID, NODEV); this type adds the ext2-specific
/// bits that the driver needs to branch on internally. Today that's
/// just `NOATIME` (RFC 0004 §Mount — skip atime writes on read paths)
/// and the synthesised `FORCED_RDONLY` bit that records "the user asked
/// for RW but feature flags demoted us".
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(transparent)]
pub struct Ext2MountFlags(pub u32);

impl Ext2MountFlags {
    /// User-requested: skip `s_atime` / `i_atime` updates on read.
    /// Mirrors `MS_NOATIME`. Not stored by [`MountFlags`] because the
    /// generic VFS walk layer doesn't need to see it.
    pub const NOATIME: Ext2MountFlags = Ext2MountFlags(1 << 0);
    /// Synthesised: caller requested RW but an unknown RO_COMPAT bit
    /// forced the driver to demote the mount to RO. Recorded so
    /// `/proc/mounts` (future) can report "ro" without losing the
    /// information that it wasn't user-requested.
    pub const FORCED_RDONLY: Ext2MountFlags = Ext2MountFlags(1 << 1);
    /// Caller explicitly requested read-only mount.
    pub const RDONLY: Ext2MountFlags = Ext2MountFlags(1 << 2);
    /// Caller requested `NOSUID` (matches [`MountFlags::NOSUID`]).
    pub const NOSUID: Ext2MountFlags = Ext2MountFlags(1 << 3);
    /// Caller requested `NODEV` (matches [`MountFlags::NODEV`]).
    pub const NODEV: Ext2MountFlags = Ext2MountFlags(1 << 4);

    pub const fn contains(self, other: Ext2MountFlags) -> bool {
        (self.0 & other.0) == other.0
    }
}

impl core::ops::BitOr for Ext2MountFlags {
    type Output = Ext2MountFlags;
    fn bitor(self, rhs: Self) -> Self {
        Ext2MountFlags(self.0 | rhs.0)
    }
}

impl core::ops::BitOrAssign for Ext2MountFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

/// Driver-level filesystem factory. Registered once per *device* at
/// boot (or once per test, at construction time). `FileSystem::mount`
/// is invoked at most once per instance — the single-mount latch in
/// [`Self::mounted`] rejects a second attempt with [`EBUSY`].
///
/// The backing device is injected at construction (`new_with_device`)
/// rather than resolved from the [`MountSource`] — the VFS's
/// `MountSource` enum doesn't yet carry a block-device variant, and
/// production boot will own the default virtio-blk via the same
/// constructor.
pub struct Ext2Fs {
    /// Backing device. Held at the `Arc<dyn BlockDevice>` granularity
    /// so the buffer cache, writeback daemon (future), and the mount
    /// table can each hold their own clone.
    device: Arc<dyn BlockDevice>,
    /// Single-mount latch. `false` until a successful `mount`, then
    /// `true` until `unmount` clears it. Prevents an invalid-mount
    /// attempt from burning the factory (matches the tarfs pattern).
    mounted: AtomicBool,
    /// Self-reference so `Ext2Super::unmount` can upgrade it and clear
    /// the latch. `Arc::new_cyclic` fills this in at construction.
    self_ref: Weak<Ext2Fs>,
    /// Weak pointer to the currently-mounted `Ext2Super`, set on a
    /// successful `mount` and cleared on `unmount`. Exposed via
    /// [`Ext2Fs::current_super`] so integration tests (and the future
    /// `/proc/mounts` consumer) can reach the concrete per-mount type
    /// without a dyn-Any downcast on `Arc<dyn SuperOps>`.
    current_super: spin::Mutex<Weak<Ext2Super>>,
}

impl Ext2Fs {
    /// Construct an `Ext2Fs` bound to `device`. The factory lives as
    /// `Arc<dyn FileSystem>` inside the mount table; the caller hands
    /// it an already-brought-up block device (virtio-blk in production,
    /// an in-memory [`BlockDevice`] in tests).
    pub fn new_with_device(device: Arc<dyn BlockDevice>) -> Arc<Self> {
        Arc::new_cyclic(|weak| Self {
            device,
            mounted: AtomicBool::new(false),
            self_ref: weak.clone(),
            current_super: spin::Mutex::new(Weak::new()),
        })
    }

    /// Total addressable capacity of the backing device, in bytes.
    /// Exposed for test scaffolding that wants to mint a matching-sized
    /// ramdisk.
    pub fn device_capacity(&self) -> u64 {
        self.device.capacity()
    }

    /// Upgrade the weak reference to the currently-mounted
    /// [`Ext2Super`]. Returns `None` if the factory hasn't been
    /// mounted, if an `unmount` has run, or if the `Arc<Ext2Super>` has
    /// been fully dropped (which shouldn't happen while the VFS
    /// [`SuperBlock`] holds a strong ref through `sb.ops`).
    ///
    /// Test-oriented: production callers route through
    /// `SuperBlock::ops`. This is the escape hatch tests need to reach
    /// `iget` / `inode_cache` / `orphan_list` without a dyn-Any
    /// downcast.
    pub fn current_super(&self) -> Option<Arc<Ext2Super>> {
        self.current_super.lock().upgrade()
    }
}

impl FileSystem for Ext2Fs {
    fn name(&self) -> &'static str {
        "ext2"
    }

    fn mount(&self, _source: MountSource<'_>, flags: MountFlags) -> Result<Arc<SuperBlock>, i64> {
        // 1. Read and parse the primary superblock *before* claiming the
        //    mount latch. A malformed SB must not burn the factory —
        //    the caller should be able to drop in a good image and try
        //    again. Matches tarfs's "parse-before-latch" discipline
        //    (issue #274).
        let mut sb_slot = [0u8; EXT2_SUPERBLOCK_SIZE];
        // The device's block size may be smaller than 1024 (e.g. a
        // 512-byte-sector ramdisk), but `read_at` requires both offset
        // and length to be a multiple of device block_size. Our
        // constant (1024) is a multiple of every power-of-two block
        // size ≤ 1024, so only pathological devices (>1024-byte
        // sectors whose layout makes 1024 misaligned) fail — those
        // aren't in scope for ext2 anyway. Propagate BadAlign /
        // OutOfRange as `ENODEV` rather than unwrapping; the device
        // may simply be too small.
        self.device
            .read_at(SUPERBLOCK_BYTE_OFFSET, &mut sb_slot)
            .map_err(|_| ENODEV)?;
        let on_disk_sb = Ext2SuperBlock::decode(&sb_slot);

        // 2. Validate magic + geometry. Unknown rev level or
        //    out-of-range `s_log_block_size` is EINVAL (matches Linux
        //    ext2 `ext2_fill_super`).
        if on_disk_sb.s_magic != EXT2_MAGIC {
            return Err(EINVAL);
        }
        let block_size = on_disk_sb.block_size().ok_or(EINVAL)?;
        if on_disk_sb.s_rev_level != EXT2_GOOD_OLD_REV && on_disk_sb.s_rev_level != EXT2_DYNAMIC_REV
        {
            return Err(EINVAL);
        }
        // Resolve the effective on-disk inode size:
        //   rev-0: always 128 bytes (`s_inode_size` is not meaningful).
        //   rev-1: read `s_inode_size`; must be a power of two in
        //   [128, block_size] (ext2 spec §3.1).
        let inode_size = if on_disk_sb.s_rev_level == EXT2_GOOD_OLD_REV {
            EXT2_GOOD_OLD_INODE_SIZE as u32
        } else {
            let s = on_disk_sb.s_inode_size as u32;
            if s < EXT2_GOOD_OLD_INODE_SIZE as u32 || s > block_size || !s.is_power_of_two() {
                return Err(EINVAL);
            }
            s
        };
        // `s_first_ino` for rev-0 is fixed at 11 (reserved-inode range
        // ends there); rev-1 carries it explicitly. Used by the
        // allocator (issue #560) — validated here so we catch a
        // corrupt value at mount time.
        let first_ino = if on_disk_sb.s_rev_level == EXT2_GOOD_OLD_REV {
            EXT2_GOOD_OLD_FIRST_INO
        } else {
            on_disk_sb.s_first_ino
        };
        if on_disk_sb.s_blocks_per_group == 0 || on_disk_sb.s_inodes_per_group == 0 {
            return Err(EINVAL);
        }
        if on_disk_sb.s_blocks_count == 0 || on_disk_sb.s_inodes_count == 0 {
            return Err(EINVAL);
        }

        // 3. Feature-flag gate. INCOMPAT bits we don't model refuse the
        //    mount outright (the filesystem uses a structure we'd
        //    misread). RO_COMPAT bits we don't model demote to RO (the
        //    bits affect metadata integrity but reads are safe). COMPAT
        //    bits are ignored by definition.
        let unknown_incompat = on_disk_sb.s_feature_incompat & !SUPPORTED_INCOMPAT;
        if unknown_incompat != 0 {
            return Err(EINVAL);
        }
        let unknown_ro_compat = on_disk_sb.s_feature_ro_compat & !SUPPORTED_RO_COMPAT;

        // 4. Compose the effective mount/sb-flag sets.
        let mut ext2_flags = Ext2MountFlags::default();
        if flags.contains(MountFlags::RDONLY) {
            ext2_flags |= Ext2MountFlags::RDONLY;
        }
        if flags.contains(MountFlags::NOSUID) {
            ext2_flags |= Ext2MountFlags::NOSUID;
        }
        if flags.contains(MountFlags::NODEV) {
            ext2_flags |= Ext2MountFlags::NODEV;
        }
        let mut effective_rdonly = flags.contains(MountFlags::RDONLY);
        if unknown_ro_compat != 0 {
            effective_rdonly = true;
            ext2_flags |= Ext2MountFlags::FORCED_RDONLY;
        }

        // 5. Claim the single-mount latch. From here, any error path
        //    must clear it before returning.
        if self
            .mounted
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(EBUSY);
        }

        // Helper closure: roll the latch back on any error after claim.
        let unlatch = || {
            self.mounted.store(false, Ordering::SeqCst);
        };

        // 6. Construct the per-mount buffer cache. The cache panics if
        //    `block_size` isn't a multiple of the device's block size;
        //    guard here so a misaligned mount returns EINVAL instead
        //    of tripping the panic. (Mount runs in task context, not a
        //    syscall entry, but a loud EINVAL is still strictly better
        //    than a kernel panic.)
        let dev_bs = self.device.block_size();
        if dev_bs == 0 || block_size % dev_bs != 0 {
            unlatch();
            return Err(EINVAL);
        }
        let cache = BlockCache::new(self.device.clone(), block_size, BLOCK_CACHE_CAPACITY);
        let device_id = cache.register_device();

        // 7. Read the group descriptor table. BGDT starts at the block
        //    immediately after the superblock block: for 1 KiB blocks
        //    (`s_first_data_block == 1`) that's block 2; for ≥ 2 KiB
        //    blocks (`s_first_data_block == 0`) that's block 1. The
        //    table holds one 32-byte entry per group; total groups =
        //    ceil(s_blocks_count / s_blocks_per_group).
        let groups = div_ceil(on_disk_sb.s_blocks_count, on_disk_sb.s_blocks_per_group);
        if groups == 0 {
            unlatch();
            return Err(EINVAL);
        }
        let entries_per_block = block_size / EXT2_GROUP_DESC_SIZE as u32;
        if entries_per_block == 0 {
            // Block size smaller than a single BGD entry is nonsense.
            unlatch();
            return Err(EINVAL);
        }
        let bgdt_blocks = div_ceil(groups, entries_per_block);
        let bgdt_start_block = (on_disk_sb.s_first_data_block as u64) + 1;
        let mut bgdt: Vec<Ext2GroupDesc> = Vec::with_capacity(groups as usize);
        'bgdt: for blk_off in 0..bgdt_blocks {
            let blk = bgdt_start_block + blk_off as u64;
            let bh = match cache.bread(device_id, blk) {
                Ok(bh) => bh,
                Err(_) => {
                    unlatch();
                    return Err(EIO);
                }
            };
            let data = bh.data.read();
            let slot = &data[..];
            let mut off = 0usize;
            while off + EXT2_GROUP_DESC_SIZE <= slot.len() {
                if bgdt.len() as u32 >= groups {
                    break 'bgdt;
                }
                bgdt.push(Ext2GroupDesc::decode(
                    &slot[off..off + EXT2_GROUP_DESC_SIZE],
                ));
                off += EXT2_GROUP_DESC_SIZE;
            }
        }
        debug_assert_eq!(bgdt.len() as u32, groups);

        // 7b. Mount-time orphan-chain validation (issue #564, RFC 0004
        //     §Orphan list + §Mount-time recovery). Runs as a raw walk
        //     *before* the `s_state := ERROR_FS` stamp so that a
        //     corrupt chain demotes us to RO before any write hits
        //     disk. The walk phase is pure-read; the pin phase (which
        //     needs the `Arc<SuperBlock>`) runs after construction
        //     below. We stash the surviving inos here for phase 2.
        let (orphan_verdict, orphan_inos) = super::orphan::walk_orphan_chain_raw(
            &cache,
            device_id,
            &on_disk_sb,
            &bgdt,
            inode_size,
            block_size,
        );
        if orphan_verdict == super::orphan::ForceRo::Yes {
            effective_rdonly = true;
            ext2_flags |= Ext2MountFlags::FORCED_RDONLY;
        }

        // 8. RW bring-up: stamp `s_state := ERROR_FS` so an unclean
        //    crash is detectable on the next mount. The canonical
        //    `VALID_FS` is rewritten only by a clean unmount. RO
        //    mounts MUST NOT touch the device.
        if !effective_rdonly {
            // Fetch the superblock block through the cache (block `s_first_data_block`
            // on 1 KiB filesystems = block 1; on ≥ 2 KiB = block 0).
            let sb_block_no = sb_block_for(block_size);
            let sb_offset_in_block = sb_offset_within_block(block_size);
            let sb_bh = match cache.bread(device_id, sb_block_no) {
                Ok(bh) => bh,
                Err(_) => {
                    unlatch();
                    return Err(EIO);
                }
            };
            {
                let mut data = sb_bh.data.write();
                let slot = &mut data[sb_offset_in_block..sb_offset_in_block + EXT2_SUPERBLOCK_SIZE];
                let mut updated = on_disk_sb.clone();
                updated.s_state = EXT2_ERROR_FS;
                updated.encode_to_slot(slot);
            }
            cache.mark_dirty(&sb_bh);
            if cache.sync_dirty_buffer(&sb_bh).is_err() {
                unlatch();
                return Err(EIO);
            }
        }

        // 9. Build the per-mount SuperOps + VFS SuperBlock. The root
        //    inode is NOT populated here — wave 3 (#559) wires
        //    `sb.root.call_once(...)` once `read_inode(EXT2_ROOT_INO)`
        //    lands.
        let fs_id = alloc_fs_id();
        let mut sb_flags = SbFlags::default();
        if effective_rdonly {
            sb_flags = sb_flags | SbFlags::RDONLY;
        }
        if flags.contains(MountFlags::NOSUID) {
            sb_flags = sb_flags | SbFlags::NOSUID;
        }
        if flags.contains(MountFlags::NODEV) {
            sb_flags = sb_flags | SbFlags::NODEV;
        }
        if flags.contains(MountFlags::NOEXEC) {
            sb_flags = sb_flags | SbFlags::NOEXEC;
        }

        let super_ops: Arc<Ext2Super> = Arc::new_cyclic(|weak| Ext2Super {
            fs_id: fs_id.0,
            cache,
            device_id,
            block_size,
            inode_size,
            first_ino,
            sb_disk: spin::Mutex::new(on_disk_sb),
            bgdt: spin::Mutex::new(bgdt),
            ext2_flags,
            owner: self.self_ref.clone(),
            inode_cache: super::inode::new_inode_cache(),
            ext2_inode_cache: super::inode::new_ext2_inode_cache(),
            orphan_list: super::inode::new_orphan_list(),
            alloc_mutex: spin::Mutex::new(()),
            self_ref: weak.clone(),
        });

        let sb = Arc::new(SuperBlock::new(
            fs_id,
            super_ops.clone(),
            "ext2",
            block_size,
            sb_flags,
        ));

        // Record a `Weak<Ext2Super>` in the factory so `current_super()`
        // can hand the concrete type back to callers (tests, the future
        // `/proc/mounts`). Must happen before `iget_root` below: the
        // caller holds an `Arc<Ext2Super>` already (`super_ops`), but
        // stashing the weak here centralises the bookkeeping.
        *self.current_super.lock() = Arc::downgrade(&super_ops);

        // Populate `sb.root` before returning so path-walk callers that
        // start at the mount's root observe a ready-to-use inode. A
        // failure here (corrupt root inode, I/O error reading the
        // root-inode block) must roll back the mount — including the
        // single-mount latch — so the factory can be retried against a
        // repaired image.
        match super::inode::iget_root(&super_ops, &sb) {
            Ok(root) => {
                sb.root.call_once(|| root);
            }
            Err(e) => {
                // Releasing the latch here mirrors the `unlatch` helper
                // above. The BlockCache / SuperBlock Arcs are dropped
                // on function return.
                unlatch();
                return Err(e);
            }
        }

        // Phase 2 of mount-time orphan-chain validation (#564): now
        // that the SuperBlock is built and the root inode is live,
        // pin each surviving orphan ino into
        // `super_ops.orphan_list` so its blocks remain reserved for
        // the life of the mount. A failure here is logged and
        // skipped — a successful raw walk proved the slot looked
        // orphan-ish, and a late pin failure shouldn't retroactively
        // tear down a mount the caller has committed to.
        super::orphan::pin_orphans(&super_ops, &sb, &orphan_inos);

        Ok(sb)
    }
}

/// Per-mount state: the parsed superblock, the BGDT, the buffer cache
/// bound to this mount's [`DeviceId`], and the flag sets that branch
/// hot paths. Held as `Arc<Ext2Super>` by both the VFS's `SuperBlock`
/// (via `Arc<dyn SuperOps>`) and any future inode / dentry that needs
/// to walk back to it.
pub struct Ext2Super {
    /// Allocated [`FsId`](crate::fs::vfs::FsId) for `statfs.f_type`-
    /// adjacent plumbing; used as `st_dev` on inodes of this mount.
    pub fs_id: u64,
    /// Per-mount buffer cache. Registered with `device_id` at mount
    /// time; every `bread` / `mark_dirty` / `sync_dirty_buffer` routes
    /// through this cache so `sync_fs` can scope to this mount only.
    pub cache: Arc<BlockCache>,
    /// The DeviceId handed out by `cache.register_device()` at mount.
    /// Held so per-mount `sync_fs` can be scoped correctly.
    pub device_id: DeviceId,
    /// Effective on-disk block size (bytes). Matches the `SuperBlock`'s
    /// `block_size`; duplicated here so `statfs` doesn't need to walk
    /// back through the Weak<SuperBlock>.
    pub block_size: u32,
    /// Effective on-disk inode slot size (bytes). 128 on rev-0; the
    /// rev-1 value (may be 256, 512, 1024, …) when present.
    pub inode_size: u32,
    /// First user-allocatable inode number. 11 on rev-0; `s_first_ino`
    /// on rev-1. Needed by the allocator (#560).
    pub first_ino: u32,
    /// The last parsed superblock. Updated by the allocator (#565, #566)
    /// when it decrements / increments `s_free_blocks_count` /
    /// `s_free_inodes_count`; `statfs` snapshots fields under the lock.
    ///
    /// Lock ordering: acquire `sb_disk` **after** `bgdt` when both are
    /// needed in the same critical section. The allocator paths observe
    /// this by updating the group descriptor first, then the superblock
    /// counter (matching the RFC 0004 §Write Ordering rule: bitmap
    /// clear+flush → group-descriptor update → superblock update).
    pub sb_disk: spin::Mutex<Ext2SuperBlock>,
    /// Block group descriptor table. One entry per group; the
    /// allocator updates free-counts in-place and flushes them back to
    /// the on-disk BGDT block in the same critical section.
    pub bgdt: spin::Mutex<Vec<Ext2GroupDesc>>,
    /// Driver-level mount flags — atime skip, forced-RO, NOSUID, etc.
    pub ext2_flags: Ext2MountFlags,
    /// Back-reference to the owning factory so `unmount` can clear the
    /// single-mount latch. `Weak` breaks the `Ext2Fs → SuperBlock →
    /// Ext2Super → Ext2Fs` cycle.
    owner: Weak<Ext2Fs>,
    /// Weak-ref inode cache. Populated by
    /// [`iget`](super::inode::iget); a hit returns the same
    /// `Arc<Inode>` so repeat lookups dedup. Wave 3 (#559) introduces
    /// this; Workstream E populates it on every inode read.
    pub inode_cache: super::inode::InodeCache,
    /// Driver-private parallel cache of `Weak<Ext2Inode>` keyed on the
    /// same ext2 ino as [`inode_cache`]. The unlink path (#569) and
    /// future setattr/truncate paths consume this to recover the
    /// concrete `Arc<Ext2Inode>` without a dyn-Any downcast on
    /// `Arc<dyn InodeOps>`.
    pub ext2_inode_cache: super::inode::Ext2InodeCache,
    /// Strong-ref orphan list. Holds `Arc<Inode>` for every
    /// unlinked-but-open inode on this mount so its blocks aren't
    /// freed before the last close (RFC 0004 §Orphan-list residency
    /// invariant). Wave 3 constructs it empty; the unlink path (E)
    /// and mount-time orphan replay (#564) populate it.
    pub orphan_list: super::inode::OrphanList,
    /// Serializes the inode / block allocator paths (#566, #565). The
    /// allocator reads the on-disk superblock, BGDT, and bitmap blocks
    /// fresh through the buffer cache on every call — the disk is the
    /// source of truth; the in-memory `sb_disk` / `bgdt` snapshots are
    /// mount-time copies used for geometry lookups only and may be
    /// stale after an allocation. Held uncontended in the single-
    /// threaded test harness; a future Workstream E concurrency pass
    /// may promote this to a sleeping mutex when long I/O stalls
    /// appear on real hardware.
    pub alloc_mutex: spin::Mutex<()>,
    /// Self-reference so [`SuperOps::root_inode`] can hand `iget_root`
    /// a strong `Arc<Ext2Super>` without the caller threading one in.
    /// Filled in by [`Arc::new_cyclic`] at mount time.
    self_ref: Weak<Ext2Super>,
}

impl SuperOps for Ext2Super {
    fn root_inode(&self) -> Arc<Inode> {
        // Wave 3 (#559) wires the root inode into `SuperBlock::root` at
        // mount time via `iget_root`. Callers are expected to read
        // `sb.root.get()` directly; `root_inode` is a legacy hook and
        // reaching it means the caller bypassed the once-cell. Upgrade
        // the self-reference, resolve the matching SuperBlock through
        // the mount table's `fs_id`, and return the cached root inode.
        // If the self-weak or the cache entry is gone, we're mid-drop
        // and the caller's `Arc<Inode>` clone is ill-defined — panic
        // loudly rather than hand back a stub.
        let super_arc = self
            .self_ref
            .upgrade()
            .expect("Ext2Super dropped before root_inode was invoked");
        // We can't construct a fresh Arc<Inode> without an Arc<SuperBlock>
        // here — one isn't reachable from SuperOps. Consult the
        // inode_cache (populated at mount by `iget_root`); the VFS
        // holds a strong ref via `sb.root`, so the Weak upgrade
        // succeeds for as long as the mount is live.
        let cache = super_arc.inode_cache.lock();
        let weak = cache
            .get(&super::disk::EXT2_ROOT_INO)
            .expect("root inode must be cached at mount time");
        weak.upgrade()
            .expect("SuperBlock::root holds a strong ref to the root inode")
    }

    fn statfs(&self) -> Result<StatFs, i64> {
        let sb = self.sb_disk.lock();
        Ok(StatFs {
            // `EXT2_SUPER_MAGIC` as seen by Linux userspace `statfs(2)`
            // — the on-disk magic promoted to a 64-bit u64 slot.
            f_type: EXT2_MAGIC as u64,
            f_bsize: self.block_size as u64,
            f_blocks: sb.s_blocks_count as u64,
            f_bfree: sb.s_free_blocks_count as u64,
            // `f_bavail` = unreserved free blocks. RFC 0004 §Mount
            // permits reporting `f_bfree` directly until the
            // reservation accounting in the allocator (#560) lands; do
            // the subtraction anyway when it doesn't underflow.
            f_bavail: sb.s_free_blocks_count.saturating_sub(sb.s_r_blocks_count) as u64,
            f_files: sb.s_inodes_count as u64,
            f_ffree: sb.s_free_inodes_count as u64,
            f_namelen: crate::fs::vfs::NAME_MAX as u64,
        })
    }

    /// VFS eviction hook: the last `Arc<Inode>` for `ino` (excluding
    /// any orphan-list pin) just dropped, and the `gc_queue` drainer
    /// is calling us to finalize.
    ///
    /// If `ino` is present in [`Ext2Super::orphan_list`], run the
    /// RFC 0004 §Final-close sequence via
    /// [`super::orphan_finalize::finalize`]: truncate-to-zero,
    /// unchain from the on-disk orphan list (stamp `i_dtime` tombstone),
    /// free the inode in the bitmap, then drop the in-memory pin.
    /// Ordering note: unchain-before-free is load-bearing — see the
    /// `orphan_finalize` module docs. A non-orphan ino (a normal inode falling out of
    /// the VFS cache) is a no-op — ext2 has no dirty-inode writeback
    /// yet; that lives behind the future `sync` path.
    ///
    /// Errors are swallowed with a `kwarn!`: the VFS drainer has no
    /// useful fallback and leaving the orphan-list pin in place means
    /// the next mount-time replay (#564) will see the entry and retry
    /// the sequence.
    fn evict_inode(&self, ino: u64) -> Result<(), i64> {
        // ino comes in as u64 from the VFS; ext2's ino space is u32.
        // Values above u32::MAX can't reference a real on-disk inode.
        let Ok(ext2_ino) = u32::try_from(ino) else {
            return Ok(());
        };
        // Fast path: non-orphan cache eviction. Nothing to do.
        let is_orphan = { self.orphan_list.lock().contains_key(&ext2_ino) };
        if !is_orphan {
            return Ok(());
        }
        // Upgrade the self_ref to a strong Arc<Ext2Super> so the
        // finalize free-function can be called. The Arc is live because
        // `gc_queue` upgraded its own Weak<SuperBlock> before calling
        // us, and that SuperBlock holds an Arc<dyn SuperOps> = Arc of
        // this very Ext2Super.
        let Some(super_arc) = self.self_ref.upgrade() else {
            return Ok(());
        };
        match super::orphan_finalize::finalize(&super_arc, ext2_ino) {
            Ok(()) => Ok(()),
            Err(e) => {
                crate::kwarn!(
                    "ext2: orphan finalize ino {}: errno={}, leaving pin for replay",
                    ext2_ino,
                    e,
                );
                Ok(())
            }
        }
    }

    fn sync_fs(&self, _sb: &SuperBlock) -> Result<(), i64> {
        // Scope the flush to just this mount's DeviceId — shared-device
        // concurrent mounts (RFC 0004 §Buffer cache) must not leak.
        // Map the block-layer error into the VFS's `i64` errno.
        match self.cache.sync_fs(self.device_id) {
            Ok(()) => Ok(()),
            Err(_) => Err(EIO),
        }
    }

    fn unmount(&self) {
        // Contract: unmount must not propagate errors (see SuperOps
        // docs, §Phase B contract). Best-effort flush the dirty set.
        // An error here is logged-and-dropped; a retry is a no-op at
        // this point because the VFS has already detached the mount.
        let _ = self.cache.sync_fs(self.device_id);

        // TODO(#559+): rewrite `s_state := EXT2_VALID_FS` on a clean
        // unmount. Requires wave 3 to have touched the filesystem
        // through the mutating surface; a wave-2 unmount that ran no
        // writes can safely leave s_state as ERROR_FS (the next mount
        // will still recognise it as ext2 and a later fsck will be
        // run anyway).

        // Release the single-mount latch so a subsequent mount of the
        // same factory can succeed. Also clear the weak back-reference
        // exposed via `Ext2Fs::current_super` so a stale `Weak` can't
        // upgrade after unmount-then-remount into a different
        // `Ext2Super`.
        if let Some(fs) = self.owner.upgrade() {
            *fs.current_super.lock() = Weak::new();
            fs.mounted.store(false, Ordering::SeqCst);
        }
    }
}

/// Integer ceiling division. Wraps `u32::div_ceil` with a
/// debug-only non-zero assertion so a stray `div_ceil(_, 0)` trips
/// loudly under tests while still compiling to a single CPU DIV in
/// release builds.
fn div_ceil(a: u32, b: u32) -> u32 {
    debug_assert!(b != 0);
    u32::div_ceil(a, b)
}

/// Cache-block index that holds the primary superblock.
///
/// The superblock occupies 1024 bytes at disk byte offset 1024. For 1
/// KiB blocks that's block 1; for 2 KiB blocks that's block 0 (offset
/// 1024 within the block); for 4 KiB blocks that's block 0 (offset
/// 1024 within the block); etc. Exposed as a helper because both the
/// mount-RW stamp path and an eventual `sync_super` (wave 3+) need
/// the same arithmetic.
fn sb_block_for(block_size: u32) -> u64 {
    SUPERBLOCK_BYTE_OFFSET / block_size as u64
}

/// Byte offset of the primary superblock inside its cache block.
fn sb_offset_within_block(block_size: u32) -> usize {
    (SUPERBLOCK_BYTE_OFFSET % block_size as u64) as usize
}

#[cfg(test)]
mod tests {
    //! Host-side unit tests: exercise the arithmetic and the
    //! feature-flag gate. The full mount pipeline is covered by the
    //! integration test `kernel/tests/ext2_mount.rs` which runs under
    //! QEMU against a real `mkfs.ext2` fixture image.
    use super::*;

    #[test]
    fn sb_block_for_handles_common_block_sizes() {
        // 1 KiB blocks: superblock is at byte 1024 → block 1.
        assert_eq!(sb_block_for(1024), 1);
        assert_eq!(sb_offset_within_block(1024), 0);
        // 2 KiB blocks: still byte 1024, which lives at offset 1024
        // within block 0.
        assert_eq!(sb_block_for(2048), 0);
        assert_eq!(sb_offset_within_block(2048), 1024);
        // 4 KiB blocks: same story.
        assert_eq!(sb_block_for(4096), 0);
        assert_eq!(sb_offset_within_block(4096), 1024);
    }

    #[test]
    fn div_ceil_matches_formula() {
        assert_eq!(div_ceil(1, 1), 1);
        assert_eq!(div_ceil(0, 1), 0);
        assert_eq!(div_ceil(1, 4), 1);
        assert_eq!(div_ceil(5, 4), 2);
        assert_eq!(div_ceil(8, 4), 2);
        assert_eq!(div_ceil(u32::MAX / 2, 2), (u32::MAX / 2 + 1) / 2);
    }

    #[test]
    fn supported_incompat_covers_filetype_only() {
        // If a new feature bit is added to SUPPORTED_INCOMPAT without
        // also teaching the dir-entry walker / inode reader about it,
        // someone will forget to update the RO_COMPAT set on the same
        // change. Pin both so review catches the half-update.
        assert_eq!(SUPPORTED_INCOMPAT, INCOMPAT_FILETYPE);
        assert_eq!(
            SUPPORTED_RO_COMPAT,
            RO_COMPAT_SPARSE_SUPER | RO_COMPAT_LARGE_FILE
        );
    }

    #[test]
    fn ext2_mount_flags_bitops_and_contains() {
        let f = Ext2MountFlags::NOATIME | Ext2MountFlags::RDONLY;
        assert!(f.contains(Ext2MountFlags::NOATIME));
        assert!(f.contains(Ext2MountFlags::RDONLY));
        assert!(!f.contains(Ext2MountFlags::NODEV));

        let mut g = Ext2MountFlags::default();
        g |= Ext2MountFlags::FORCED_RDONLY;
        assert!(g.contains(Ext2MountFlags::FORCED_RDONLY));
        assert!(!g.contains(Ext2MountFlags::RDONLY));
    }
}
