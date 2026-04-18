---
rfc: 0004
title: Ext2 Filesystem Driver
status: Accepted
created: 2026-04-18
---

# RFC 0004: Ext2 Filesystem Driver

## Abstract

This RFC specifies a real, on-disk, writable, permission-aware filesystem for
vibix: a second extended filesystem (ext2) driver plus the surrounding
subsystems it depends on — the missing POSIX write syscalls
(`mkdir`/`rmdir`/`unlink`/`rename`/`link`/`symlink`/`chmod`/`chown`/`truncate`
/`utimensat`/`access`), per-task credential enforcement
(`setuid`/`setgid`/`setgroups` family plumbed through the syscall entry path),
a block-device buffer cache, `mount(2)`/`umount2(2)` syscalls, and a boot path
that mounts an ext2 disk image as the root filesystem. Conformance is
measured by porting `pjdfstest` (a 2-clause BSD POSIX conformance suite,
~8,600 tests) into vibix's in-QEMU integration suite. This is the fourth
filesystem to plug into the RFC 0002 VFS (after `tarfs`, `ramfs`, `devfs`),
and the first one that persists.

## Motivation

Vibix today has a solid RFC 0002 VFS
(`kernel/src/fs/vfs/{ops,inode,dentry,super_block,open_file,path_walk,mount_table}.rs`)
and a writable reference implementation in `ramfs`
(`kernel/src/fs/vfs/ramfs.rs`), but no way for the kernel to persist anything
across reboots. The state as of 2026-04-18:

- **Three filesystems mount:** `/` (ramfs or tarfs), `/dev` (devfs, RO), `/tmp`
  (ramfs). ramfs is writable but ephemeral; tarfs is read-only; devfs is
  read-only synthetic. Nothing survives a reboot.
- **Block layer is a single polled virtio-blk device**
  (`kernel/src/block/virtio_blk.rs`) with `read(lba, buf) / write(lba, buf)`,
  no cache, no async, no interrupts. It has no consumer.
- **The VFS trait surface is complete** (`kernel/src/fs/vfs/ops.rs:191`
  `trait InodeOps` covers `lookup/create/mkdir/unlink/rmdir/rename/link/
  symlink/readlink/getattr/setattr/permission`), but the **matching POSIX
  write syscalls are unwired** (`kernel/src/arch/x86_64/syscalls/vfs.rs`
  wires `open/stat/mknod/read/write/fsync/lseek/getdents64/fcntl/dup3` but
  not `mkdir/unlink/rename/link/symlink/chmod/chown/truncate/utimensat`).
- **Credentials exist but are not enforced.** `Credential { uid, gid, groups }`
  lives at `kernel/src/fs/vfs/mod.rs:107`, and `default_permission` at
  `kernel/src/fs/vfs/ops.rs:232` already implements POSIX §4.4.2 owner/group
  /other checks — but every syscall call site passes `Credential::kernel()`
  (euid=0), so permissions are plumbed but never gated.
- **There is no `mount(2)`.** All mounts are hardcoded at
  `kernel/src/fs/vfs/init.rs`.
- **There is no external FS conformance suite.**

To close the "writable, permission-aware, multi-level" requirement in the
prioritization playbook (`docs/agent-playbooks/prioritization.md`,
`track:filesystem` = *"Needed for real multi-level, writable,
permission-aware filesystem"*), vibix must persist to block storage, enforce
POSIX DAC, and run a third-party conformance suite that catches the subtle
semantics a hand-written suite won't.

## Background

### Prior art surveyed

- **Card, Tweedie, Ts'o, "Design and Implementation of the Second Extended
  Filesystem" (Linux Expo 1994).** Originating paper. Establishes block
  groups as the unit of locality and bitmap residence; inode allocator tries
  parent directory's group first, quadratic-hashes to a different group on
  failure; no journal by design.
- **McKusick, Joy, Leffler, Fabry, "A Fast File System for UNIX" (ACM TOCS
  2(3), 1984).** Ext2's direct ancestor. The locality rationale (cylinder
  groups) is obsolete on virtio-blk but the bitmap-bounded-scan and
  per-group-locking rationales survive.
- **Bach, *The Design of the UNIX Operating System*, Ch. 3 (1986).**
  Canonical description of the buffer cache: hash by `(dev, block_no)`, LRU
  free list, delayed write, `getblk` scenarios.
- **Poirier, *The Second Extended File System — Internal Layout*, 2001–2019.**
  https://www.nongnu.org/ext2-doc/ext2.html . Byte-level reference for every
  on-disk structure. Field offsets and flag values in §Design are sourced
  here.
- **Linux `fs/ext2/`** (kernel.org documentation + source). Reference
  implementation, ~5 KLOC. Five-vtable model
  (`super_operations`/`inode_operations`/`file_operations`/
  `dentry_operations`/`address_space_operations`) where nearly all data I/O
  is `generic_*` helpers parameterized by a single filesystem-specific
  callback, `ext2_get_block(inode, iblock, bh, create)`. ext2 is a
  buffer_head + page-cache filesystem in Linux; vibix will implement a
  buffer-cache-only model and defer the page cache.
- **SerenityOS `Kernel/FileSystem/Ext2FS/`** (~2,200 LOC C++). Modern,
  readable ext2 driver in an idiomatic ring-0 environment. Three-layer split:
  `FileBackedFileSystem → BlockBasedFileSystem → Ext2FS`. The
  `BlockBasedFileSystem::DiskCache` (10,000 LRU entries, intrusive
  dirty/clean lists, write-back) is the design vibix's buffer cache mirrors
  most closely. Its `InodeMetadata::may_read/may_write/may_execute(
  Credentials const&)` and `Credentials` as an
  `AtomicRefCounted<Credentials>` snapshot are the model for workstream B.
- **xv6 `bio.c`, `fs.c`, `log.c`** (~600 LOC of disk fs + 130 LOC buffer
  cache in C). The minimal viable reference. vibix's buffer cache uses xv6's
  five `getblk` scenarios as the correctness baseline.
- **redoxfs `src/disk/{mod,cache}.rs`** (Rust microkernel FS). Not ext2, but
  its `pub trait Disk { read_at, write_at, size }` is the cleanest Rust
  shape for a block-device abstraction and `DiskCache<T: Disk>` demonstrates
  composability vibix will mirror.
- **POSIX.1-2017 §2.1.2 (sticky bit), §4.4.2 (file access permissions), §2.4
  (saved set-user-ID), plus syscall descriptions for every syscall added
  here.** Defines the exact permission algorithm (first-match terminates —
  owner permissions shadow group permissions even if group grants more),
  unlink-while-open semantics, rename atomicity.
- **pjdfstest** (https://github.com/pjd/pjdfstest, 2-clause BSD, Dawidek
  et al. 2006). 237 `.t` files · 3,550 `expect` invocations · ~8,600 test
  cases on Linux ext4. Originally sh+C+TAP. A working GSoC-2022 Rust
  rewrite (https://github.com/saidsay-so/pjdfstest) removes the C helper
  and replaces TAP with `inventory`-registered Rust tests — vibix's port
  base.
- **Tweedie, "Journaling the Linux ext2fs Filesystem" (1998).** Explicit
  enumeration of what ext2 does *not* provide (crash consistency), which
  motivated ext3. Ganger et al., "Soft Updates" (TOCS 18(2), 2000),
  formalizes the three metadata ordering rules ext2 violates and `fsck`
  repairs. Gatla et al., "Towards Robust File System Checkers" (FAST 2018),
  documents `fsck` bugs. vibix accepts ext2's post-crash `fsck` cost as
  documented weakness.
- **Formal verification:** FSCQ (Chen et al., SOSP 2015, Coq-verified FS)
  and BilbyFs (Amani et al., ASPLOS 2016, Cogent-verified) are the closest
  prior work. ext2 itself is unverified. We will cite FSCQ's POSIX spec as
  the semantic target but not attempt verification.

### What vibix has today (as of 2026-04-18)

- **RFC 0002 VFS:** `Inode`/`Dentry`/`SuperBlock`/`OpenFile` in
  `kernel/src/fs/vfs/`; `FileSystem`/`SuperOps`/`InodeOps`/`FileOps` traits
  in `kernel/src/fs/vfs/ops.rs`. Multi-mount via `GlobalMountResolver`
  (`mount_table.rs`). Path walk crosses mounts, resolves symlinks with
  `SYMLOOP_MAX = 40`. `permission()` returns `EACCES`/`EPERM` per POSIX.
- **Three filesystem implementations:** `ramfs.rs` (writable, ephemeral —
  **the reference for ext2 op-vector wiring**), `devfs.rs` (RO, 4 char
  devices), `tarfs.rs` (RO initramfs).
- **Block layer:** `virtio_blk.rs` sync polled `read`/`write` in 512-byte
  sectors with a 4 KiB bounce buffer. No cache. No async. No interrupts.
- **VFS syscalls already wired** (`kernel/src/arch/x86_64/syscalls/vfs.rs`):
  `open`/`openat`/`stat`/`fstat`/`lstat`/`newfstatat`/`chdir`/`getcwd`/
  `mknod`/`read`/`write`/`fsync`/`lseek`/`getdents64`/`fcntl`/`dup3`,
  plus `O_CREAT|O_EXCL|O_TRUNC|O_APPEND` support (#425).
- **Credential model:** `Credential { uid, gid, groups }` at
  `kernel/src/fs/vfs/mod.rs:107`; POSIX §4.4.2 algorithm implemented in
  `InodeOps::default_permission` at `kernel/src/fs/vfs/ops.rs:232`. Every
  caller currently passes `Credential::kernel()`.

### What is missing

1. The 12+ POSIX write syscalls listed in §Motivation (Workstream A).
2. Per-task credentials threaded into every VFS syscall entry (Workstream B).
3. A block-device buffer cache (Workstream C).
4. An ext2 read path — superblock/BGDT/bitmap/inode/indirect-walk/dirent/
   file/symlink read (Workstream D).
5. An ext2 write path — bitmap allocators + create/unlink/rename/truncate/
   chmod/chown/orphan-list/valid-fs-flag (Workstream E).
6. A `mount(2)` syscall and a boot path that can mount an ext2 image as `/`
   (Workstream F).
7. A conformance runner that ports pjdfstest into the QEMU integration suite
   (Workstream G).

## Design

### Overview

Seven workstreams. A, B, C are immediately startable (wave 1). D blocks on C.
E blocks on D + A + B. F blocks on D. G blocks on E + F.

```
wave 1:  A (syscalls)   B (credentials)   C (buffer cache)
wave 2:                                    D (ext2 read)   <- needs C
wave 3:  E (ext2 write) <- needs D + A + B    F (mount/root) <- needs D
wave 4:  G (pjdfstest) <- needs E + F
```

### Key data structures

#### On-disk types — `kernel/src/fs/ext2/disk/`

Direct `#[repr(C, packed)]` translations of the Poirier spec and Linux
`fs/ext2/ext2.h`. Every field is little-endian; accessors are explicit
`u16/u32` LE readers so the driver will cross-compile unchanged to a BE
target if ever needed.

- `Ext2SuperBlock` — 1024 bytes, resident at byte offset 1024 on disk,
  irrespective of block size. Magic at offset 56 = `EXT2_SUPER_MAGIC =
  0xEF53`. Block size is `1024 << s_log_block_size`. Feature flags at
  offsets 92/96/100 (`s_feature_compat`, `s_feature_incompat`,
  `s_feature_ro_compat`).
- `Ext2GroupDesc` — 32 bytes. `bg_block_bitmap`, `bg_inode_bitmap`,
  `bg_inode_table` are absolute block numbers.
- `Ext2Inode` — 128 bytes in rev 0, `s_inode_size` bytes in rev 1.
  `i_block[15]`: 12 direct + 1 single-indirect + 1 double + 1 triple.
  `i_blocks` is in **512-byte units**, not fs-block units. Every block
  allocated against the inode — data block, *and every indirect/
  double-indirect/triple-indirect block* — adds `(block_size / 512)` to
  `i_blocks`; every freed block subtracts the same. Truncate and file
  extension paths must account for the freed/allocated indirect blocks, not
  just the data blocks, or `e2fsck -fy` will rewrite `i_blocks` on every
  touched image.
- `Ext2DirEntry2` — variable-length `{ u32 inode, u16 rec_len, u8 name_len,
  u8 file_type, name[name_len] }`, 4-byte aligned, cannot span a block.
- **On-disk inode writes are always read-modify-write of the raw slot** —
  the full 128 bytes (or `s_inode_size` in rev 1) are read into memory,
  parsed fields update in place, and the whole slot is written back.
  Unknown/reserved fields (`i_generation`, `i_file_acl`, `i_faddr`, the
  osd2 reserved bytes, `l_i_uid_high`/`l_i_gid_high`) are preserved
  verbatim — dropping them would break NFS fh generation and `e2fsck -D`.
- **`l_i_uid_high`/`l_i_gid_high` (osd2.linux2) carry bits 16..31 of
  uid/gid.** The driver reads/writes both halves; `chown` of a value that
  does not fit in u32 returns `EOVERFLOW` (u32 limit is well above POSIX
  UID_MAX = 65535 in practice, but the check protects against future
  enlargement).
- **Nanosecond timestamps truncate.** `utimensat`'s `timespec` nanoseconds
  are dropped at the disk layer; `stat` returns `tv_nsec = 0`. ext4-style
  `*_extra` fields are out of scope.

**Bitmap-to-absolute-block math (all allocator paths).** Bit `i` of the
block bitmap for group `G` corresponds to absolute block number
`s_first_data_block + G * s_blocks_per_group + i`, *not* to block `i`.
On 1 KiB-block filesystems `s_first_data_block == 1` (the superblock
occupies block 1); on ≥2 KiB-block filesystems `s_first_data_block == 0`.
Mount asserts the relation. Forgetting the offset either leaks one block
per group or double-allocates the superblock/BGDT. Bitmap bits past
`s_blocks_count` (in the partial last group) are treated as **set**
(unavailable); `mkfs.ext2` zero-fills them and the driver honors the
count, not the bitmap width.

Similarly, inode bitmap bit `i` of group `G` corresponds to inode number
`G * s_inodes_per_group + i + 1` (inodes are 1-indexed; ino 0 is never
valid). Bits past `s_inodes_count` are treated as set.

Constants: `EXT2_ROOT_INO = 2`, `EXT2_GOOD_OLD_FIRST_INO = 11`,
`EXT2_GOOD_OLD_INODE_SIZE = 128`, `EXT2_GOOD_OLD_REV = 0`,
`EXT2_DYNAMIC_REV = 1`.

#### Feature-flag gate (mount safety)

Per spec:

- **Unknown `s_feature_incompat` bit → refuse mount (EINVAL).**
- **Unknown `s_feature_ro_compat` bit → force `MS_RDONLY`.**
- **Unknown `s_feature_compat` bit → ignore.**

MVP supports:

- `INCOMPAT_FILETYPE` (0x0002) — required to read any modern `mkfs.ext2`
  image.
- `RO_COMPAT_SPARSE_SUPER` (0x0001) — required to avoid corrupting sparse
  superblock backups.
- `RO_COMPAT_LARGE_FILE` (0x0002) — required to correctly interpret files
  ≥ 2 GiB (uses `i_dir_acl` as upper 32 bits of file size).

MVP refuses:

- `INCOMPAT_COMPRESSION`, `INCOMPAT_META_BG`, `INCOMPAT_RECOVER`,
  `INCOMPAT_JOURNAL_DEV` (ext3+).
- `RO_COMPAT_BTREE_DIR` (HTree — we do linear directory search; this
  triggers a force-RO).

#### In-memory types — `kernel/src/fs/ext2/`

```rust
pub struct Ext2Fs {
    device: Arc<dyn BlockDevice>,
    cache: Arc<BlockCache>,
    sb: BlockingRwLock<Ext2SuperBlock>,
    bgdt: BlockingRwLock<Vec<Ext2GroupDesc>>,
    inode_cache: Mutex<BTreeMap<u32, Weak<Inode>>>,
    orphan_list: Mutex<BTreeMap<u32, Arc<Inode>>>, // strong ref — see below
    mount_flags: MountFlags,
}
impl FileSystem for Ext2Fs { ... }
impl SuperOps for Ext2Fs { ... }

pub struct Ext2Inode {
    fs: Weak<Ext2Fs>,
    ino: u32,
    meta: BlockingRwLock<Ext2InodeMeta>,  // parsed i_mode/uid/gid/size/etc.
    block_map: BlockingRwLock<Option<BlockMap>>, // lazy indirect-walk cache
    unlinked: AtomicBool, // set when i_links_count reaches 0 while open
}
impl InodeOps for Ext2Inode { ... }
impl FileOps for Ext2Inode { ... }
```

**Orphan-list residency invariant.** `orphan_list` holds **strong**
`Arc<Inode>` references for every unlinked-but-open inode on this mount —
not inode numbers, not `Weak` refs. This is the only reference path that
keeps the `Inode` resident after the last `OpenFile` closes between the
`unlink` and a racing final-close on another CPU. Before dropping an
`Inode` into `gc_queue`, `Inode::drop` in `kernel/src/fs/vfs/inode.rs:106`
checks `unlinked.load()`; if set, eviction/`evict_inode` is vetoed (the
orphan-list-final-close path owns the free). This simultaneously closes
two hazards the previous draft left open: (a) data blocks being freed by
`evict_inode` before the orphan-list pass walks, and (b) a re-`iget` of
the same ino between last-close-on-CPU-A and orphan-walk-on-CPU-B
observing a partially-freed inode.

`inode_cache` remains `Weak<Inode>` — it is a lookup shortcut, not an
ownership root. When the last `OpenFile` closes on an unlinked inode,
the `orphan_list.remove(ino)` drop decrements strong count to zero and
triggers the real free path.

#### Buffer cache — `kernel/src/block/buffer_cache.rs`

```rust
pub struct BufferHead {
    pub device: DeviceId,
    pub block_no: u64,
    pub data: BlockingRwLock<Box<[u8]>>, // block_size
    state: AtomicU8,         // VALID | DIRTY | LOCKED_IO
    clock_ref: AtomicU8,     // CLOCK-Pro reference bit (multi-valued)
}

pub struct BlockCache {
    device: Arc<dyn BlockDevice>,
    block_size: usize,
    entries: RwLock<HashMap<(DeviceId, u64), Arc<BufferHead>>>,
    dirty: Mutex<Vec<Weak<BufferHead>>>,
    clock_hand: AtomicUsize,
    max_buffers: usize,
}

impl BlockCache {
    pub fn bread(&self, blk: u64) -> Result<Arc<BufferHead>, BlkError>;
    pub fn mark_dirty(&self, bh: &Arc<BufferHead>);
    pub fn sync_dirty_buffer(&self, bh: &Arc<BufferHead>)
        -> Result<(), BlkError>; // blocks until device ack
    pub fn sync_fs(&self) -> Result<(), BlkError>;
    pub fn release(&self, bh: Arc<BufferHead>); // refcount-- ; may evict
}
```

Replacement: **CLOCK-Pro** (Jiang, Chen, Zhang, USENIX ATC 2005), chosen
for its scan resistance at O(1) per access (Jiang et al. 2005). ARC
(Megiddo & Modha, FAST 2003) is stronger but its 2-list metadata cost is
unjustifiable at the cache sizes we target; LRU is cheap per-access but
unbounded-degrades under `find /`-shape scans. At 4 MiB ≈ 1,024 buffers a
single recursive-walk would otherwise thrash LRU. Metadata per entry:
one reference byte + one state byte + the `Arc` strong-count.

**Eviction invariants** (Workstream C must uphold all four, any one
violation is a correctness bug — not a perf bug):

1. **Never evict a pinned buffer.** The CLOCK-Pro hand skips any
   `BufferHead` whose `Arc::strong_count > 1` (i.e., a caller holds a
   live handle from `bread`). If an entire sweep finds no evictable
   buffer, `bread` returns `ENOMEM` rather than blocking, and the caller
   is expected to release its handles. This prevents the draft's
   previous hazard of two distinct `Arc<BufferHead>`s coexisting for the
   same `(dev, blk)` — which would silently desynchronize the dirty bit.
2. **Never evict DIRTY + LOCKED_IO.** A buffer mid-`sync_dirty_buffer`
   has both bits set; eviction must skip it. A buffer that is DIRTY but
   not LOCKED_IO is written back *synchronously* by the writeback daemon
   (not the evictor — see #3) and only then evicted.
3. **`bread` never performs synchronous writeback during eviction.** If
   the cache is full and every entry is either pinned or dirty,
   `bread` returns `ENOMEM`; it must not call `sync_dirty_buffer` from
   inside a path that a VFS caller is holding. The background writeback
   daemon (or an explicit `sync_fs`) is the only legitimate origin of
   dirty flushing. This closes the OS-engineer B5 hazard: no VFS lock
   ever transitively holds the virtio-blk spin lock.
4. **Single-cache-entry invariant.** An evicted buffer is removed from
   `entries` before its `Arc` refcount can drop to 0 from the map side;
   `bread` that finds no entry allocates, inserts, and pins *under*
   `entries.write()` so no race creates a duplicate.

Write-back policy: all metadata writes go through `mark_dirty`+sync (via
`sync_dirty_buffer`) on atomicity-critical paths (bitmap allocate, dirent
insert/delete, rename destination write, superblock valid-FS flag, orphan
list). Data writes are `mark_dirty`-only (delayed). `fsync(fd)` flushes
all dirty buffers whose owner inode matches the fd's inode; `sync_fs`
flushes all. A background writeback daemon flushes every 30 seconds.

**Writeback daemon lifecycle.** The daemon runs as a dedicated kernel
thread per `BlockCache` (so one per Ext2Fs mount); it acquires an
`SbActiveGuard` per sweep to keep the superblock resident and skips any
mount whose `SuperBlock.draining == true`. `SuperOps::unmount` sets
`draining`, synchronously flushes the cache, joins the daemon, and only
then releases the block device.

Each Ext2Fs owns its own `BlockCache` keyed by `(DeviceId, u64)`. Block
size is carried on the `BlockCache` struct itself — not in the key —
since each mount owns its cache at its own block size, avoiding mismatches.

#### Credentials — `kernel/src/fs/vfs/mod.rs` (extended)

```rust
pub struct Credential {
    pub uid: u32,  pub euid: u32,  pub suid: u32,  // NEW: euid/suid/sgid
    pub gid: u32,  pub egid: u32,  pub sgid: u32,
    pub groups: Vec<u32>, // supplementary; cap NGROUPS_MAX = 32
}

// On Task:
pub struct Task {
    pub credentials: BlockingRwLock<Arc<Credential>>,
    // ...
}
```

`Credential` is immutable; `setuid(2)` and relatives build a new one and
swap the `Arc`, following POSIX §2.4 saved-set-user-ID semantics:

- **Privileged** (`euid == 0`): `setuid(uid)` sets all three (ruid/euid/suid)
  to `uid`. `setresuid(r, e, s)` sets any, `-1` = unchanged.
- **Unprivileged**: `setuid(uid)` sets only `euid`, and only to `ruid` or
  `suid`. Similarly for the rest of the family.

`Credential::kernel()` is preserved for genuinely kernel-initiated paths
(initial mount, kernel-thread I/O). All userspace-initiated VFS syscalls
read `task.credentials.read().clone()` once at entry and pass the resulting
`Arc<Credential>` through the path walk.

### Algorithms and protocols

#### Mount

1. Open the block device. Read 1 KiB at byte offset 1024 via
   `device.read_at(block(1024), &mut buf)` directly (not via the
   not-yet-initialized buffer cache).
2. Parse `Ext2SuperBlock`. Validate magic 0xEF53, block size in {1024, 2048,
   4096}, `s_inodes_per_group > 0`, `s_blocks_per_group > 0`, feature flags
   (see above).
3. Create the per-fs `BlockCache` sized by kernel cmdline (default 4 MiB).
4. Read BGDT: block 2 on 1 KiB filesystems, block 1 otherwise; `N = ceil(
   s_blocks_count / s_blocks_per_group)` descriptors.
5. If `s_state != EXT2_VALID_FS` → log warning, force `MS_RDONLY`.
6. If the mount is read-write (not forced-RO, not `MS_RDONLY` from caller,
   not RO from an unknown `RO_COMPAT` bit): clear `s_state` →
   `EXT2_ERROR_FS`, `sync_dirty_buffer` the superblock **before
   `mount(2)` returns** (one extra 1 KiB write at mount time — cheap and
   closes the OS-A4 hazard where a crash between mount and first flush
   would leave on-disk `s_state == VALID_FS`, defeating the force-`e2fsck`
   signal). **RO mounts skip step 6 entirely** — a read-only mount must
   not touch the disk at all, to honor the contract that RO is
   non-destructive even when the on-disk `s_state` was already stale.
7. Walk the on-disk orphan chain from `s_last_orphan` before allowing
   userspace access (see §unlink-while-open + orphan list for the
   recovery protocol and chain-validation rules). RO mounts log orphan
   entries but do not drain them.
8. `iget(EXT2_ROOT_INO = 2)` → root inode; attach via
   `SuperBlock::set_root()`; register in the global mount table via the
   existing `mount_table.rs` API.

#### Indirect-block walker

```
P = block_size / 4        // pointers per indirect block

iblock in [0, 12)                       -> i_block[iblock]            (direct)
iblock in [12, 12+P)                    -> i_block[12]  then index iblock-12
iblock in [12+P, 12+P+P^2)              -> i_block[13]  two-level
iblock in [12+P+P^2, 12+P+P^2+P^3)      -> i_block[14]  three-level
```

Allocating-variant (`create=true`): walks the same path; on a zero pointer
it allocates a new block via the bitmap allocator (§Allocator below) and
writes the slot atomically (sync-dirty) before returning. Every allocated
indirect block (single, double, triple) increments the inode's `i_blocks`
by `(block_size / 512)` and counts against the parent group's free-block
count — same accounting as a data block.

**Every block pointer read from any slot — `i_block[0..12]`, a single-
indirect slot, a double-indirect slot, a triple-indirect slot — is
validated before it is handed to `bread`:**

- Pointer `p = 0` → hole; read returns a zero block, write allocates.
- `p < s_first_data_block` → `EIO`, force-RO the mount.
- `p >= s_blocks_count` → `EIO`, force-RO the mount.
- `p` aliases a metadata region — the superblock (block 0 or 1 depending
  on `s_first_data_block`), the BGDT blocks, any `bg_block_bitmap`,
  `bg_inode_bitmap`, or `bg_inode_table` run for any group — → `EIO`,
  force-RO the mount. A cached "metadata-forbidden" bitmap is computed
  once at mount and consulted on every pointer read; the cost is one
  byte per block (or a range list) and closes the most dangerous
  confused-deputy attack in the driver (crafted image aims a user-data
  write at the BGDT or an inode table, rewriting `i_mode` to gain
  privilege).

Per-inode `BlockMap` caches resolved indirect-block numbers to avoid
re-reading indirect blocks on sequential access. **Invalidation uses a
`u64` epoch stamp:** writers that change the map (setattr/truncate/
extend) bump the epoch under the `block_map` write lock; readers record
the epoch before dereferencing a cached entry and re-walk if the epoch
differs post-read. This is strictly stronger than lock-drop-on-write and
avoids the SMP stale-resolution hazard from OS-A5.

#### Directory operations

Directories are regular files whose content is a packed stream of
`Ext2DirEntry2` records padded to 4-byte alignment. Records never cross a
block boundary.

**Per-record validation (on every read, before consumption).** The RFC's
§Security bullet on `rec_len` is refined here and is normative for the
iterator implementation:

- `rec_len >= 8` (record header size) and `rec_len` is 4-byte aligned.
- `rec_len + cursor <= block_end` (no overrun into the next block).
- `name_len + 8 <= rec_len` (name fits inside the record).
- **For a live entry (`inode != 0`):** `name_len > 0`. A zero-length
  name on a live record is an image corruption — return `EIO` and
  force-RO.
- **For any entry:** `file_type` (when `INCOMPAT_FILETYPE` is enabled)
  must be one of the known values (`UNKNOWN/REG/DIR/CHRDEV/BLKDEV/FIFO/
  SOCK/SYMLINK`); an out-of-range `file_type` on a live entry is `EIO`.
- **`inode == 0` is the universal tombstone.** It can appear at any
  slot, not just the first. All iterators (lookup, getdents64,
  insertion slot-scan, rename walk) **unconditionally skip** records
  with `inode == 0` — they never surface to userspace and never hand a
  name back as live. The insertion path treats any zero-inode slot
  whose `rec_len` accommodates the new entry as reusable.
- **`inode != 0` but `inode < EXT2_GOOD_OLD_FIRST_INO` (and not
  `EXT2_ROOT_INO = 2`)** — `EIO`. Reserved ino range 1..10 excluding 2
  is never directly referenced by a live dirent; an image that does is
  malicious.
- **`inode > s_inodes_count`** — `EIO`.

**Lookup:** iterate records, skipping `inode == 0`; match by `name_len` +
`name[]`. O(entries).

**getdents64:** same iteration; `d_ino` is the dirent's `inode`, never 0
(skipped); `d_type` mirrors `file_type` when `INCOMPAT_FILETYPE` is live,
else `DT_UNKNOWN`.

**Insert:** scan each block for a slot where either (a) the slot is a
live entry (`inode != 0`) whose slack `rec_len - align4(8 + name_len) >=
align4(8 + new_name_len)` lets the entry be split; or (b) the slot is a
tombstone (`inode == 0`) whose `rec_len >= align4(8 + new_name_len)`, in
which case the tombstone is overwritten in place. If neither fits in any
existing block, append a new full-block record by extending the
directory file.

**Delete:** preferred path — find the entry's predecessor in the same
block and grow the predecessor's `rec_len` to swallow the deleted
record. When the deleted entry is first in the block (no predecessor),
fall back to zeroing its `inode` field and leaving `rec_len` unchanged;
the slot is now a tombstone reusable by a future insert. `e2fsck`
tolerates both forms.

#### Allocator

"First-fit in parent's group, linear spill":

1. **Inodes** — to create inode in directory `D`, compute `G = (D.ino - 1)
   / s_inodes_per_group`. Scan group G's inode bitmap for the first zero
   bit. If group is full, advance `G → (G + 1) mod n_groups` and retry;
   loop to exhaustion.
2. **Blocks** — same policy, anchored on the inode's group.

Both allocators set the bitmap bit with `sync_dirty_buffer` (synchronous
write) before returning the number. The "try the parent's group first"
locality rule follows Card, Tweedie & Ts'o 1994; the specific quadratic-
hash spill in Linux `fs/ext2/ialloc.c` is *not* adopted here — linear
spill is simpler, still pjdfstest-correct, and documented as such.
Orlov's directory-spreading heuristic and preallocation windows are
deferred to v2 (§Alternatives).

#### Create write-ordering (soft-updates rule)

`InodeOps::create`/`mkdir`/`mknod`/`symlink` follow a normative
sequence; any reversal can produce a dangling dirent that references a
free or garbage inode (worst-case: `e2fsck` later reassigns the inode
number to a new file, and the stale dirent now points at someone else's
data). Each `sync_dirty_buffer` below must complete before the next
step starts:

1. Allocate inode bit in the inode bitmap + parent-group
   `bg_free_inodes_count -= 1`. `sync_dirty_buffer(bitmap_bh)`.
2. Write the full inode slot with `i_links_count >= 1`, `i_mode` set,
   `i_blocks = 0`, `i_dtime = 0`. `sync_dirty_buffer(inode_table_bh)`.
3. Insert the dirent in the parent directory block with the
   newly-allocated ino. `sync_dirty_buffer(parent_dir_bh)`.
4. Update parent directory's `i_mtime`/`i_ctime` and, for `mkdir`, bump
   parent's `i_links_count` (for the new `..` backlink). Write back.

**Partial-failure rollback.** If step 3 fails (e.g., extending the
parent directory hits `ENOSPC`), the driver must roll back step 1 — free
the inode bit and restore `bg_free_inodes_count` — under the same
`sync_dirty_buffer` discipline, before returning the error. If the
rollback itself fails mid-sequence (I/O error during rollback), the
driver clears `s_state = EXT2_ERROR_FS` and force-ROs the mount; the
on-disk leak is explicit, `e2fsck -fy` is required. This is the same
posture Linux ext2 takes: the valid-FS flag is the contract that says
"a clean umount saw a consistent image." A crash *between* steps does
not cause corruption because the ordering ensures `e2fsck` sees either
(a) bitmap set, inode zero-populated, no dirent → the inode is a leaked
free slot (cheap to reap), or (b) all three set → live file. The
ordering *never* produces a dirent pointing at a not-yet-populated or
freed inode.

The same discipline applies to `rename` (§rename below) and to
`Ext2Inode::setattr`-for-truncate: allocations and frees in a cross-
operation sequence follow "write dirent last on grow; unlink dirent
first on shrink" and rollback on the allocation side if the dirent step
fails.

#### unlink-while-open + orphan list

POSIX requires the directory entry be removed at `unlink()` time, but the
inode and data blocks must persist until the last `close()`. ext2's
on-disk support for this is the superblock field `s_last_orphan`: head of
a singly-linked list of inodes marked-deleted-but-still-open. The chain
is threaded through each orphaned inode's `i_dtime` slot — **dual-use of
`i_dtime` is intentional and requires strict sequencing**.

**`i_dtime` dual-use rule.** While an inode is on the orphan chain,
`i_dtime` holds the next-ino link (or 0 for the chain tail). Only when
the inode is *removed from the chain and freed to the inode bitmap* is
`i_dtime` rewritten to the wall-clock deletion time. Writing a wall-
clock timestamp before unlinking from the chain corrupts the chain —
`e2fsck` will follow `i_dtime` (now a second-since-epoch value) into a
random inode and either free live data or spin on a cycle. This is the
single most-subtle orphan-list bug in hobby kernels.

**Sequence for `unlink` (directory-entry gone, inode may persist).**

1. Walk parent directory, locate dirent, delete it (predecessor-rec_len
   merge or first-slot tombstone per §Directory operations).
   `sync_dirty_buffer(parent_dir_bh)`.
2. Decrement `i_links_count` on the inode.
3. If the new `i_links_count == 0` **and** in-memory openers > 0:
   - Insert `Arc<Inode>` into `Ext2Fs.orphan_list` (strong ref — see
     §In-memory types).
   - On disk: write `i_dtime := sb.s_last_orphan` (thread new node onto
     chain), `sync_dirty_buffer(inode_table_bh)`. Then update
     `sb.s_last_orphan := ino`, `sync_dirty_buffer(sb_bh)`.
4. If `i_links_count == 0` and no openers: skip the chain, go directly
   to the free sequence below (the recovery path on crash is identical
   to the orphan-list path, just without the on-disk chain bookkeeping).

**Sequence for final `close()` on an unlinked inode (ordering is
normative — reversing these steps produces `e2fsck` complaints).**

1. **Unlink from on-disk orphan chain first.** Walk from
   `sb.s_last_orphan`; unlink this ino from the chain (if head, update
   `sb.s_last_orphan := next`; else update the predecessor's
   `i_dtime`). `sync_dirty_buffer(sb_bh)` (and the predecessor's
   inode-table block, if applicable).
2. **Free all data + indirect blocks** via the block bitmap; decrement
   `i_blocks` accordingly; `sync_dirty_buffer(bitmap_bh)` once per
   touched bitmap block.
3. **Free the inode slot** in the inode bitmap + parent-group
   `bg_free_inodes_count += 1`. `sync_dirty_buffer(inode_bitmap_bh)`.
4. **Now — and only now — rewrite the inode slot** with
   `i_dtime := wall_clock_time`, `i_links_count = 0`, and zeroed
   `i_block[]` / `i_size`. `sync_dirty_buffer(inode_table_bh)`.
5. Drop the `Arc<Inode>` from `orphan_list`; the last strong ref drops
   and triggers the in-memory free.

**On-mount orphan-chain validation (defensive against hostile images).**
Before mount returns, walk `sb.s_last_orphan` and validate every link:

- Cap chain walk at `s_inodes_count` iterations — any longer is a cycle
  or under-linked corruption. Cycle detected → force-RO, log.
- Track a `visited: BitVec<s_inodes_count>`; re-visiting a node ==
  cycle. Force-RO, log.
- At each step, validate `ino` is in
  `[EXT2_GOOD_OLD_FIRST_INO, s_inodes_count]` (or `EXT2_ROOT_INO = 2`
  if ever — it never should be, but the check refuses it explicitly).
  An out-of-range ino or one pointing into reserved range 1..10 (and
  not 2) → refuse-free the entry and force-RO.
- **Never free root/reserved inodes via the orphan path.** Ino 2
  (root) and 1..10 except 2 are rejected with a logged warning before
  any bitmap clear.

Surviving entries (valid ino, no cycle) are drained by the same final-
close sequence above. On a read-only mount, orphan entries are left
alone and a log message directs the user to run host `e2fsck` — RO
never writes.

A crash during the on-disk orphan sequence is safe: if the in-memory
orphan-list mirror and the on-disk chain disagree after a crash,
`e2fsck` treats the on-disk chain as authoritative (Linux policy, which
the RFC adopts). The only invariant that must hold across a crash is:
"every ino on the on-disk chain has `i_links_count == 0` and a valid
inode-table entry."

#### rename — POSIX atomicity without a journal

- **Self-rename** (the old and new arguments resolve to the same
  directory entry *or* to different directory entries for the same
  existing inode — determined by resolved inode identity, not by
  path-string equality): no-op, return 0. POSIX §rename explicitly
  requires the "different dentries, same inode" case also to succeed
  without side effects.
- **Same-directory rename:** overwrite one dirent's name in one block —
  the write is a single sector-sized update, inherently atomic at the
  block layer. `sync_dirty_buffer`. Crash before = old name, after =
  new name.
- **Cross-directory rename (no target, no overwrite).** Link count
  bookkeeping is ordered to match Linux ext2 so `e2fsck -fy` never has
  to rewrite `i_links_count`:
  1. `i_links_count += 1` on the source inode + sync the inode-table
     block. The inode now transiently has link-count 2 (reflecting that
     both old and new dentries will reference it during the crash
     window). This must happen *before* step 2.
  2. Write the new dirent in dst_dir. `sync_dirty_buffer(dst_dir_bh)`.
  3. Delete the old dirent in src_dir. `sync_dirty_buffer(src_dir_bh)`.
  4. `i_links_count -= 1` on the source inode + sync the inode-table
     block.
  - **Crash between steps 2 and 3:** both old and new dirents reference
    the same inode; on-disk `i_links_count == 2` matches. `e2fsck`
    leaves it as a hardlink; the user removes the stale entry. This is
    the documented ext2 rename crash window (Pillai et al., "All File
    Systems Are Not Created Equal," OSDI 2014, catalogs this as a
    known ext2 property; we preserve the intended invariant,
    modulo writeback ordering that `e2fsck` reconciles). No journal =
    no rename atomicity across a crash; we document rather than fake.
- **Overwrite an existing target** (`target` exists and `renameat2` was
  not called with `RENAME_NOREPLACE`):
  1. Bump source `i_links_count` as above; sync.
  2. Rewrite the target dirent's `ino` in place in dst_dir to point at
     the source inode. `sync_dirty_buffer(dst_dir_bh)`. This is a
     single in-block write.
  3. Delete the old dirent in src_dir. `sync_dirty_buffer(src_dir_bh)`.
  4. Decrement source `i_links_count` on the source inode.
  5. Decrement the victim inode's `i_links_count`; if it drops to 0,
     the orphan-list path kicks in (openers > 0 → chain; else free
     now).
- **Cross-device:** `EXDEV` (POSIX-mandated).
- **Source is an ancestor of target:** `EINVAL`.
- **Renaming a mountpoint:** `EBUSY`.

#### Lock ordering (normative)

The existing VFS contract
(`kernel/src/fs/vfs/ramfs.rs:340`, `super_block.rs:58`) establishes a
total order across rename's two `dir_rwsem` locks (ino order); the ext2
driver extends that total order to its own per-fs locks. **Acquire in
this order, release in reverse:**

```
sb.rename_mutex                                (rename path only)
  Ext2Fs.sb (read-lock per op; write-lock only on feature-flag mutation)
    dir_rwsem[ino = min(src, dst)]             (path-walk, rename)
      dir_rwsem[ino = max(src, dst)]           (rename only)
        Ext2Inode.meta                         (per involved inode)
          Ext2Inode.block_map                  (per involved inode)
            Ext2Fs.bgdt                        (allocator paths)
              Ext2Fs.orphan_list               (unlink/final-close)
                BlockCache.entries             (bread / eviction)
                  BufferHead.data              (block I/O)
                    // *** NO BLOCK-DEVICE SPIN LOCK HERE ***
```

**Invariant (pinned by Workstream C + D + E review):** *no VFS lock
(anything from `sb.rename_mutex` down through `BlockCache.entries`) is
ever held across a synchronous block I/O wait.* `BufferHead.data` is
released immediately after the copy; `sync_dirty_buffer`'s wait happens
only after the buffer's state transitions to LOCKED_IO and its
`BufferHead.data` lock is released. The virtio-blk spin lock is
therefore never contended by a VFS-lock holder, which closes the OS-B1
priority-inversion hazard. This invariant is trivially upheld on UP
vibix today (no second CPU can contend), but is the normative contract
for any future SMP landing.

#### `mount(2)` / `umount2(2)`

```c
long mount(const char *source, const char *target, const char *fstype,
           unsigned long flags, const void *data);
long umount2(const char *target, int flags);
```

MVP flags: `MS_RDONLY` (1), `MS_NOSUID` (2), `MS_NODEV` (4), `MS_NOATIME`
(1024). `data` is interpreted by the filesystem driver; ext2 ignores it
for MVP.

Superuser-only: `euid != 0 → EPERM`.

`umount2` supports `MNT_DETACH` (2) so an open fd on a mount doesn't wedge
umount; the superblock stays pinned until the last fd closes. Active-pin
accounting already exists on `SuperBlock`.

#### Boot path

The Limine block-device module that currently carries a tar archive (tarfs
root) is replaced by an ext2 disk image produced in-build via host
`mkfs.ext2`. The boot path:

1. virtio-blk probes.
2. `kernel/src/fs/vfs/init.rs` reads a kernel cmdline `root=` (default to
   the virtio-blk device); mounts it as ext2 at `/`.
3. If the ext2 mount fails (no disk, bad magic, incompatible features),
   fall back to the existing tarfs-on-ramdisk path so the kernel still
   reaches PID 1.
4. `/dev` remains devfs; `/tmp` remains ramfs; both mount on top of the
   ext2 root.

### Kernel–Userspace Interface

New syscalls follow Linux x86_64 syscall numbering (already the vibix
convention).

**Directory mutations:** `mkdir` (83) / `mkdirat` (258), `rmdir` (84),
`unlink` (87) / `unlinkat` (263), `rename` (82) / `renameat` (264) /
`renameat2` (316, `RENAME_NOREPLACE` only for MVP; `RENAME_EXCHANGE` and
`RENAME_WHITEOUT` are out of scope, see §Alternatives), `link` (86) /
`linkat` (265), `symlink` (88) / `symlinkat` (266), `readlink` (89) /
`readlinkat` (267). **`readlink` does not NUL-terminate** the returned
buffer (POSIX-mandated); callers must use the return value as the
byte count.

**Metadata mutations:** `chmod` (90) / `fchmod` (91) / `fchmodat` (268),
`chown` (92) / `fchown` (93) / `lchown` (94) / `fchownat` (260),
`truncate` (76) / `ftruncate` (77), `utimensat` (280), `faccessat` (269),
`faccessat2` (439). The bare `access(2)` (21) is provided via
`faccessat(AT_FDCWD, path, mode, 0)` — its effective-vs-real uid
semantics match Linux: `access` uses the **real** UID + real GID,
`faccessat2(AT_EACCESS)` uses the **effective** UID + effective GID.
Setuid programs probing on behalf of the invoking user rely on `access`
using ruid; specify both paths.

**Credentials:** `getuid` (102) / `geteuid` (107), `getgid` (104) /
`getegid` (108), `setuid` (105), `setgid` (106), `setreuid` (113) /
`setregid` (114), `setresuid` (117) / `setresgid` (119),
`setgroups` (116), `getgroups` (115).

**Mount:** `mount` (165), `umount2` (166).

Linux's `statfs`/`statvfs`, `setfsuid`/`setfsgid`, xattr, quota,
`fallocate`, and Linux capabilities (`CAP_*`) are **out of scope**.

#### File-backed mmap scope (explicit epic boundary)

Both `mmap(MAP_SHARED, fd)` and `mmap(MAP_PRIVATE, fd)` against an ext2
file return `ENODEV` for this epic. This is deliberate and has a
visible userspace consequence: **`execve(2)` of a dynamically-linked
ELF binary from ext2 is not supported in this epic.** glibc's `ld.so`
maps the PLT/GOT and text pages of every shared library via file-backed
`mmap`; without it, dynamic loading fails. The epic's userspace target
is statically-linked binaries only (pjdfstest-style test drivers).

To make the failure mode unambiguous (rather than returning `ENODEV`
deep inside `execve` and leaving the caller to debug an opaque mapping
failure), `execve` must detect a `PT_INTERP` program header on the
target ELF and return `ENOEXEC` up-front for any ext2-backed binary
carrying one, until a follow-up RFC lands file-backed `MAP_PRIVATE`
via buffer-cache page-in-on-fault. This is a deliberate constraint the
roadmap must honor; see Workstream F task list for the `execve` gate.

#### `utimensat(2)` semantics

Signature: `utimensat(dirfd, pathname, const struct timespec times[2],
int flags)`. The spec is subtle enough that each case is pinned:

- **`times == NULL` (or both `tv_nsec == UTIME_NOW`):** update both
  atime and mtime to the current wall-clock. Permission: caller must be
  file owner *or* hold write permission on the file. This allows
  `touch file` to update timestamps on files the caller can write even
  if they do not own.
- **`times[i].tv_nsec == UTIME_NOW`:** update that field to the current
  wall-clock. Permission rule: same as above.
- **`times[i].tv_nsec == UTIME_OMIT`:** leave that field unchanged.
- **Explicit `timespec` values (any other `tv_nsec`):** update to the
  specified value. Permission: caller must be the **file owner**
  (POSIX-required — write permission alone is insufficient, because
  explicit backdating of mtime is an anti-forensics primitive and must
  not be grantable via ACL/mode bit).
- **`flags & AT_SYMLINK_NOFOLLOW`:** operate on the symlink itself,
  not its target. ext2 symlink timestamps are stored in the symlink's
  own inode and update normally.
- **Nanosecond values:** ext2 on-disk stores only seconds; `tv_nsec` is
  truncated (see §Key data structures).

Errors: `EACCES` (insufficient permission for UTIME_NOW case),
`EPERM` (explicit-time case by non-owner), `EINVAL` (invalid `tv_nsec`
outside [0, 1e9) and not UTIME_NOW/UTIME_OMIT), `EROFS`, `ENOENT`,
`ENOTDIR`, `EFAULT`.

#### `chmod`/`chown` SUID/SGID clearing (POSIX-mandated)

- **`chown`/`fchown`/`lchown`/`fchownat` by a non-privileged caller on
  success:** clear `S_ISUID` unconditionally; clear `S_ISGID` if the
  file's mode has the group-execute bit set (`S_IXGRP`). This prevents
  the privilege-escalation footgun where a user `chown`s their own
  setuid binary to another user and the binary retains its SUID bit.
  A privileged caller (`euid == 0`) **also** clears these bits by
  default — POSIX leaves this implementation-defined; we match Linux
  (always clear) rather than the historical BSD behavior (leave).
- **`chmod`/`fchmod`/`fchmodat`:** if the caller is not a member of the
  file's group *and* is not privileged, the `S_ISGID` bit is silently
  cleared from the requested mode before write. `S_ISUID` is not
  auto-cleared on `chmod` (callers explicitly set/clear it).
- **`write(2)` on a file that has `S_ISUID` or (`S_ISGID | S_IXGRP`)
  set:** implementations may clear those bits on success. Linux does;
  vibix matches. Out-of-scope refinement: Linux additionally clears
  only on non-privileged writes — we adopt the same rule.

These rules are enforced in `Ext2Inode::setattr` before the inode-table
writeback; misses here are CVEs, not bugs.

#### Per-syscall errno table (MVP — exact values userspace binds to)

The table is the normative list pjdfstest tests against. Where POSIX
permits either of two values, we pick one and commit.

| Syscall | Error | Meaning |
|---|---|---|
| `rename` | `EXDEV` | Cross-device rename |
| `rename` | `ENOTEMPTY` | Target is a non-empty directory (we pick this over `EEXIST`) |
| `rename` | `EEXIST` | Only when `renameat2(RENAME_NOREPLACE)` hits existing target |
| `rename` | `EBUSY` | Source or target is a mountpoint |
| `rename` | `EINVAL` | Source is ancestor of target, or source == "." / ".." |
| `rename` | `EISDIR` | New is directory but old is not |
| `rename` | `ENOTDIR` | Old is directory but new is an existing non-directory |
| `unlink` | `EISDIR` | Target is a directory (use `rmdir`) |
| `unlink` | `EBUSY` | Target is a mountpoint |
| `unlink` | `EPERM` | Sticky-bit directory, caller not owner of file or dir |
| `rmdir` | `ENOTEMPTY` | Directory has entries other than `.`/`..` |
| `rmdir` | `EBUSY` | Mountpoint |
| `link` | `EXDEV` | Cross-device |
| `link` | `EMLINK` | `i_links_count` already `LINK_MAX` (= 65,000) |
| `link` | `EPERM` | Source is a directory (POSIX disallows hardlinked directories) |
| `link` | `EEXIST` | New path already exists |
| `symlink` | `EEXIST` | New path already exists |
| `symlink` | `ENAMETOOLONG` | Target string > 4095 bytes |
| `mkdir` | `EEXIST` | Path already exists |
| `mkdir` | `ENOSPC` | No free inodes or blocks |
| `truncate`/`ftruncate` | `EFBIG` | Size > `MAX_FILESIZE` (2 TiB for 4 KiB blocks with `RO_COMPAT_LARGE_FILE`) |
| `truncate`/`ftruncate` | `EISDIR` | Target is a directory |
| `truncate`/`ftruncate` | `EINVAL` | Negative size |
| `chmod`/`chown` | `EPERM` | Non-privileged caller of `chown` not the owner, or `chown` to different user by non-privileged |
| `mount` | `EPERM` | `euid != 0` |
| `mount` | `EBUSY` | Target already has a mount, or source is already mounted RW elsewhere |
| `mount` | `ENODEV` | Unknown fstype |
| `mount` | `EINVAL` | Bad superblock, unknown INCOMPAT bit, bad flags |
| `umount2` | `EBUSY` | Busy and `MNT_DETACH` not set |
| `setuid`/`setgid` | `EPERM` | Unprivileged transition outside `{ruid, euid, suid}` |
| `setuid`/`setgid` | `EINVAL` | Out-of-range uid/gid (rejected before any state change) |
| `setgroups` | `EPERM` | Unprivileged caller |
| `setgroups` | `EINVAL` | Size > `NGROUPS_MAX` |
| `utimensat` | `EACCES` | UTIME_NOW path, caller lacks ownership and write permission |
| `utimensat` | `EPERM` | Explicit-time path, caller is not owner |
| `utimensat` | `EINVAL` | `tv_nsec` out of range and not UTIME_NOW/UTIME_OMIT |
| `readlink` | `EINVAL` | Target is not a symlink |
| `execve` | `ENOEXEC` | Target has `PT_INTERP` (dynamic) and is ext2-backed (this epic) |
| Any path | `ENAMETOOLONG` | A single component > 255 bytes, or total path > `PATH_MAX = 4096` |
| Any metadata | `EROFS` | Mount is RO (including force-RO) |
| Any read from corrupt on-disk data | `EIO` | Bounds/bitmap/dirent/chain validation failure; force-RO follows |

`setresuid`/`setreuid` unprivileged semantics (POSIX §2.4 saved-set-uid):
- `setreuid(r, e)`: `r` must be `-1` or `∈ {old ruid, old euid}`; `e`
  must be `-1` or `∈ {old ruid, old euid, old suid}`. On success, if
  `ruid` changed *or* `euid` changed to a value `!=` old ruid, update
  `suid := new euid`. Otherwise `suid` is unchanged.
- `setresuid(r, e, s)`: each of `r`/`e`/`s` must be `-1` or
  `∈ {old ruid, old euid, old suid}`. Matching rule for `suid` writes
  the literal `s` argument (or leaves unchanged on `-1`); there is no
  implicit `suid := euid` for the privileged path because the caller
  controls all three fields explicitly.
- Supplementary groups are **not** cleared on any `setuid*`/`setgid*`
  transition (matches Linux, not BSD). `setgroups` remains the
  explicit-mutation path.

## Security Considerations

- **Workstream A must not merge until Workstream B lands (hard CI gate).**
  Until per-task credentials are plumbed (B), every VFS syscall runs as
  root. If A's new syscalls (`mkdir`/`unlink`/`chmod`/`chown`/...) land
  first, they become reachable from ring-3 with `Credential::kernel()` —
  an unauthenticated full-DAC bypass. Two enforcement mechanisms,
  belt-and-suspenders:
  1. CI check on A's PRs that fails if B's `Task::credentials` field is
     not yet on main. The check is a grep for the added field; one line.
  2. Each new A syscall gates its dispatch arm behind a compile-time
     `#[cfg(feature = "vfs_creds")]` that Workstream B turns on in the
     same PR that lands the credential plumbing. A-only builds
     return `ENOSYS`.
  The goal is that there is no ordering of merges that exposes an
  unauthenticated DAC-bypass window, even transiently.
- **Setuid exec from untrusted ext2 images.** An ext2 image with a
  setuid-root binary is on-disk-valid and will elevate at exec.
  Mitigations: (a) `MS_NOSUID` is honored by the exec path at inode
  `permission()`; mounts of non-rootfs volumes default to `MS_NOSUID`;
  (b) the build-time rootfs image is produced reproducibly from a
  hashed manifest and CI verifies the image hash before boot, so a
  compromised dependency cannot smuggle an SUID-root binary into the
  rootfs.
- **Orphan-chain and directory-entry confusion.** The driver applies the
  following validations on every read from an untrusted on-disk
  structure (see §unlink-while-open + orphan list and §Directory
  operations for the normative rules):
  - Every inode number dereferenced from any path (orphan chain, dirent,
    inode bitmap walk) is bounded to `[EXT2_GOOD_OLD_FIRST_INO,
    s_inodes_count]` (allowing `EXT2_ROOT_INO = 2` only at its
    designated mount-root touchpoint). Ino 0 is reserved and never
    valid in a live dirent.
  - Orphan-chain walks are capped at `s_inodes_count` iterations and
    use a visited `BitVec` to detect cycles. A bad chain forces-RO,
    never panics, never loops.
  - Dirent records validate `rec_len >= 8`, 4-byte aligned,
    `rec_len + cursor <= block_end`, `8 + name_len <= rec_len`;
    **additionally** `name_len > 0` on live (non-tombstone) records,
    `file_type` in the known set under `INCOMPAT_FILETYPE`, and
    `inode == 0` is treated as a tombstone at any position (not just
    first-of-block).
  - Every block pointer (direct, single-, double-, triple-indirect) is
    validated against `[s_first_data_block, s_blocks_count)` and
    checked not to alias any metadata region (superblock, BGDT,
    per-group bitmaps, per-group inode tables). Aliasing is the
    classic confused-deputy attack (user-data write lands on a bitmap
    or inode table, rewriting `i_mode` to gain privilege); the
    metadata-forbidden bitmap computed at mount closes it.
  - `Ext2Fs::iget(0)` is statically unreachable — the API rejects ino 0
    at the entry, so a hostile dirent with `inode == 0` that somehow
    slipped past the tombstone skip cannot index the inode table at a
    negative offset.
- **Fast-symlink path confusion.** The inline-read path for fast
  symlinks is gated on `S_ISLNK(i_mode) && i_blocks == 0 && i_size <= 60`
  — all three. Relying only on `i_blocks == 0` would let a crafted
  image point at non-symlink metadata and leak up to 60 bytes of
  `i_block[]` (or, without the `i_size` clamp, 60 bytes of adjacent
  inode-table memory if `i_size` is huge) to userspace via `readlink`.
  The copy to the user buffer is `min(i_size, 60, user_buflen)`.
- **Integer overflow in file-offset math.** `ftruncate(INT64_MAX)`,
  `lseek + write` past `MAX_FILESIZE`, indirect-block index arithmetic,
  dirent-split `rec_len` arithmetic (adding `align4(8 + new_name_len)`
  must not overflow `u16`), bitmap bit-index math (bounds on
  `byte * 8 + bit` against the group's declared width), and
  `s_blocks_count * block_size` (bounds the on-disk size) — all use
  checked arithmetic (`checked_add`/`checked_mul`) and reject invalid
  inputs with `EFBIG`/`EINVAL`.
- **TOCTOU in dirent replacement.** Rename's overwrite path writes one
  dirent in place (the new dirent's slot) — the target name never
  "disappears" during the operation. The cross-dir window (temporary
  hardlink after crash) is a crash-consistency issue, not a TOCTOU.
  The broader "walk a path, `permission()` succeeds, another thread
  `chmod`s the directory before the op" case is narrow under UP + the
  lock ordering above; under SMP (follow-up RFC) each mutating op
  re-validates `permission()` against the still-pinned dentry before
  the metadata write.
- **Errno disclosure oracle.** Distinguishing `EIO` from `EINVAL` on a
  read that walks to a block pointer lets an attacker probe which
  block numbers are "valid" on an attacker-supplied image. For MVP we
  fold all "off-disk / malformed / metadata-alias" cases to `EIO`;
  `EINVAL` is reserved for user-argument validation failures. No
  kernel addresses appear in any errno return.
- **Sticky-bit enforcement.** `unlink`/`rename` in a directory with
  `S_ISVTX` requires caller == file owner OR directory owner OR root.
  Enforced at `InodeOps::permission` in the ext2 driver; tested by
  pjdfstest `unlink/11.t`.
- **SMP scope bound.** The per-Ext2Fs `BlockCache`, `inode_cache`, and
  bitmap allocator are single-locked. This is correct on UP vibix
  (the present state); **SMP is out of scope for this epic and will
  require a follow-up RFC** for per-group locking + atomic bitmap CAS
  before landing, to close the bitmap TOCTOU (scan → set → sync) that
  a racing second CPU could otherwise exploit for double-allocation.
  A compile-time `#[cfg(not(smp))]` assertion on `Ext2Fs` keeps the
  constraint load-bearing.

## Performance Considerations

- **Buffer-cache size.** 4 MiB default (configurable via kernel cmdline
  `blockcache=SIZE`). At 4 KiB block size = 1,024 buffers. Enough for full
  directory-listing + small-file workloads. Pjdfstest fits comfortably.
- **No file-data readahead in MVP.** Single-block reads per indirect walk.
  Adding readahead on sequential patterns is a v2 concern with clear ROI
  (sequential `cat` on a 1 MiB file currently = 256 virtio-blk trips).
- **Linear directory search.** O(entries per directory) per lookup. Fine
  for < ~10,000 entries. `INCOMPAT_DIR_INDEX` (HTree) is deferred; force-RO
  on volumes that require it.
- **Synchronous metadata writes.** Bitmap allocate, dirent insert/delete,
  rename destination write, superblock state flag, and orphan list are
  all `sync_dirty_buffer` writes. Metadata-heavy workloads (`rm -rf`,
  tarball unpack) will be noticeably slower than journaling Linux ext2/ext4
  until a journal lands (post-epic RFC).
- **SMP contention.** The per-Ext2Fs `BlockCache` is single-locked. Fine
  for UP vibix (SMP is post-epic). The `inode_cache` HashMap is also
  single-locked; eviction is refcount-driven.
- **Indirect-block walk cache per inode.** Stops the driver from re-reading
  indirect blocks on sequential large-file I/O. Invalidated on any
  structural change (write-extend, truncate).

## Alternatives Considered

- **MinixFS instead of ext2.** Simpler (~800 LOC Linux driver), also
  permission-aware, has `mkfs.minix`. Rejected: (a) pjdfstest targets
  ext2 semantics (quirks like `i_blocks`-in-512-byte-units, feature-flag
  gate, fast symlinks) and would need rework on MinixFS; (b) ext2 tooling
  (`debugfs`, `dumpe2fs`, `e2fsck`, `tune2fs`) is already installed on
  every developer laptop; (c) SerenityOS, Redox and Linux all have strong
  ext2 precedent to crib from, weaker MinixFS precedent.
- **ext4 without journaling.** Close to ext2 but adds extents, HTree,
  64-bit addresses, checksums, `flex_bg`, `metadata_csum`. `mkfs.ext4`
  default enables most of these → effectively 2–3× the driver surface for
  no new test coverage. `mkfs.ext2` with no extra feature bits is
  driver-stable. Rejected.
- **Custom "simplefs"** (xv6-log-structured or redoxfs-COW-style).
  Rejected: no conformance suite targets a custom fs; pedagogical win of
  reading an industry-standard image is lost.
- **FAT32.** No uid/gid/mode on disk. Fails the "permission-aware"
  requirement. Out.
- **Page-cache-based I/O** (vs buffer-cache-only). Linux ext2 uses the
  page cache + `buffer_head` overlay. vibix has no page cache; adding one
  is a separate RFC. Cost of staying buffer-cache-only: no
  `mmap(MAP_SHARED)` of file data (returns `ENODEV`), and a copy per
  `read`/`write`. Benefit: ~600 LOC of buffer-cache code vs ~3,000 LOC of
  Linux-equivalent page cache.
- **LRU vs CLOCK vs 2Q vs ARC for the buffer cache.** LRU (xv6
  bio.c-style) is simplest — pointer shuffle per access. CLOCK (Corbato
  1968, Bach §3.3) is one ref-bit per buffer, no reshuffle. 2Q (Johnson
  & Shasha, VLDB 1994) and ARC (Megiddo & Modha, FAST 2003) are better but
  add metadata costs that hurt small caches. Chose **CLOCK-Pro** (Jiang
  et al. 2005) for scan resistance at the cost of one extra byte per
  buffer.
- **Orlov allocator from day one.** LWN-folklore ~20–30% fragmentation
  reduction on aged trees; no peer-reviewed quantitative evaluation.
  Parent-group-first + linear-spill is sufficient for pjdfstest
  correctness. Deferred to v2.
- **In-kernel `fsck.ext2`.** e2fsprogs `fsck.ext2` is ~50 KLOC. Out.
  vibix expects host `e2fsck` on image build; a stale `s_state` at mount
  forces `MS_RDONLY` and logs a warning.
- **POSIX capabilities (CAP_CHOWN, CAP_DAC_OVERRIDE, etc.).** Collapse
  `euid == 0` to "all caps." Per user constraint (phase 0), explicit out
  of scope for this epic.
- **xfstests as primary conformance.** Requires two block devices,
  `mount(2)` tree with more flags, and sudo — practical only once vibix
  has a loopback block layer and a broader mount surface. Stretch goal.
- **Two-phase `fsopen`/`fsmount`** (Linux 5.2+, SerenityOS style). Cleaner
  API (staged mount options, fd-carried mount context) but more syscall
  surface. Single-call `mount(2)` is MVP; two-phase is a follow-up.
- **Mount as non-root (user-mount, FUSE-style).** Out of scope; mount(2)
  is superuser-only for the epic.

## Open Questions

- [ ] **Default block size for vibix's build-time rootfs image.** 4 KiB
      matches host defaults; 1 KiB makes indirect-block math smaller and
      eases testing on tiny disk images. Pick during Workstream F.
- [ ] **Writeback-daemon cadence** — 30 s (Linux default) vs a shorter
      interval for QEMU-only test runs (<60 s total). Pick during
      Workstream C.
- [ ] **`setuid` as a wrapper over `setresuid`?** Internally, `setuid`,
      `setreuid`, and `setresuid` are all special cases of the saved-set
      transitions. Ship one internal kernel primitive; pick during
      Workstream B whether all four syscalls exist or only the most
      expressive. Deferred to implementation.
- [ ] **Port pjdfstest by forking the Rust rewrite with a vibix-nix shim,
      or by hand-translating test bodies to direct-syscall Rust?** Pin a
      specific upstream commit of `pjd/pjdfstest` or `saidsay-so/
      pjdfstest` in Workstream G; derive the exact test count from that
      pin rather than quoting folklore. Deferred to implementation.
- [ ] **NGROUPS_MAX value.** Set to 32 for MVP (matches the draft).
      Linux uses 65,536; a too-small cap can mask a DAC denial the user
      expected to succeed and drive users toward mode 777. Revisit
      during Workstream B — an `NGROUPS_MAX = 1024` or `65536` costs a
      slightly larger `Vec<u32>` per `Credential` and no other complexity.
      Deferred to implementation.
- [ ] **Unprivileged mount (design space reservation).** `mount(2)` is
      superuser-only for this epic. A follow-up RFC for
      `CLONE_NEWNS`-style unprivileged mounts will need room in the
      dispatcher to condition permission checks on the caller's
      namespace, not just `euid == 0`. Workstream F must not hardwire
      the `euid == 0` check deep into dispatch; put it at the syscall
      entry so later refactoring is cheap.
- [ ] **`statfs`/`statvfs` stub.** Out of scope by phase-0 constraint,
      but even a minimal stub filling `f_bsize`/`f_blocks`/`f_bfree`/
      `f_namemax=255` unblocks `df` and glibc's `pathconf`. Revisit
      whether to add a ~50 LOC stub in Workstream F after the ext2
      read path lands. Deferred to implementation.

### Resolved during peer review

- Cross-directory rename crash window — *accepted and documented* per
  Pillai et al. 2014 framing (§rename above).
- SMP correctness — *explicit out-of-scope* (§Security, "SMP scope
  bound"); a follow-up RFC will add per-group locking + atomic bitmap
  CAS before any SMP landing.
- File-backed mmap — *explicit out-of-scope* (§Kernel-Userspace
  Interface, "File-backed mmap scope"); epic's userspace target is
  static binaries only, `execve` of dynamic ELFs returns `ENOEXEC`.
- Orphan-chain recovery, `i_dtime` dual-use sequencing, dirent
  `inode == 0` universal skip, `s_first_data_block` offset,
  `i_blocks`-counts-indirects rule, lock ordering, soft-updates write
  ordering — all specified normatively in §Design.

### Deferred to follow-up RFCs

ext3-style journal, page cache (+ mmap file backing), HTree directories
(`INCOMPAT_DIR_INDEX`), extended attributes (`*xattr`), quota
(`quotactl`), in-kernel `fsck`, POSIX capabilities, SMP-aware cache
sharding, `RENAME_EXCHANGE`/`RENAME_WHITEOUT`, unprivileged mount.

## Implementation Roadmap

Workstreams A, B, C start in wave 1 (parallel, no cross-blockers). D blocks
on C. E blocks on D + A + B. F blocks on D. G blocks on E + F.

### Workstream A — POSIX write syscalls (wave 1)

All syscalls land behind `#[cfg(feature = "vfs_creds")]`; the feature
gate is flipped on by Workstream B's final PR. Until then the syscall
arms compile to `ENOSYS`. A's PRs carry a CI check that fails if B's
`Task::credentials` field is absent from main (belt-and-suspenders
against an unauthenticated DAC-bypass window).

- [ ] sys: wire `mkdir`/`mkdirat` + `rmdir` to `InodeOps::mkdir`/`rmdir`
- [ ] sys: wire `unlink`/`unlinkat` to `InodeOps::unlink`
- [ ] sys: wire `link`/`linkat` + `symlink`/`symlinkat` + `readlink`/`readlinkat` (no NUL-terminate)
- [ ] sys: wire `rename` + `renameat` + `renameat2(RENAME_NOREPLACE)`; errno table per §Kernel-Userspace Interface
- [ ] sys: wire `chmod`/`fchmod`/`fchmodat` + `chown`/`fchown`/`lchown`/`fchownat` — enforce POSIX SUID/SGID clearing on `chown`/`chmod` success
- [ ] sys: wire `truncate`/`ftruncate` to `InodeOps::setattr` (size field); checked arithmetic against `MAX_FILESIZE`
- [ ] sys: wire `utimensat`/`futimens` with UTIME_NOW/UTIME_OMIT/AT_SYMLINK_NOFOLLOW permission matrix
- [ ] sys: wire `faccessat`/`faccessat2` with real-vs-effective UID distinction; `access(2)` as `faccessat(AT_FDCWD, path, mode, 0)`

### Workstream B — Credential enforcement (wave 1)

- [ ] task: extend `Credential` with `euid`/`suid`/`egid`/`sgid`; add `Task::credentials: BlockingRwLock<Arc<Credential>>`; add `Credential::from_task_ids(...)` constructor (discourage field-literal pattern in future call sites)
- [ ] sys: wire `getuid`/`geteuid` + `getgid`/`getegid`
- [ ] sys: wire `setuid`/`setreuid`/`setresuid` + `setgid`/`setregid`/`setresgid` with POSIX saved-set-uid semantics per the errno table; supplementary groups **not** cleared on uid/gid transitions (Linux rule)
- [ ] sys: wire `setgroups`/`getgroups`; cap `NGROUPS_MAX = 32` (revisit per Open Question)
- [ ] sys: replace `Credential::kernel()` at every VFS syscall entry with the per-task credential; flip `vfs_creds` feature gate on in the same PR that lands this

### Workstream C — Block buffer cache (wave 1)

- [ ] block: introduce `pub trait BlockDevice { fn read_at; fn write_at; fn block_size; fn capacity; }`; migrate `virtio_blk` behind it
- [ ] block: `BufferHead { data, state, clock_ref }` with state = `VALID | DIRTY | LOCKED_IO`; `BlockCache` keyed on `(DeviceId, u64)`, block_size carried on the cache struct
- [ ] block: `bread`/`mark_dirty`/`sync_dirty_buffer`/`release` API with CLOCK-Pro replacement; **eviction skips any `Arc::strong_count > 1` buffer and any DIRTY+LOCKED_IO buffer**; `bread` returns `ENOMEM` rather than synchronously flushing
- [ ] block: `sync_fs(sb)` flushes all dirty buffers owned by a mount
- [ ] block: periodic writeback daemon per mount — runs under `SbActiveGuard`, skips `draining` superblocks, joined by `SuperOps::unmount`; 30 s cadence cmdline-configurable
- [ ] block: **invariant assertion** — no spin lock is held across a block-I/O wait; `BufferHead.data` lock released before `sync_dirty_buffer`'s device wait

### Workstream D — ext2 read path (wave 2, blocked on C)

- [ ] fs/ext2/disk: `#[repr(C, packed)]` on-disk types + explicit-LE accessors for every field; read-modify-write discipline (full-slot RMW preserving unknown/reserved fields + `l_i_uid_high`/`l_i_gid_high`)
- [ ] fs/ext2: `Ext2Fs` implements `FileSystem` + `SuperOps`; mount reads superblock + BGDT, validates feature flags, force-RO on RO_COMPAT mismatch; **RW mount synchronously writes `s_state := ERROR_FS` before returning**; **RO mount never writes**; bitmap math uses `s_first_data_block` offset
- [ ] fs/ext2: `Ext2Inode` implements `InodeOps::getattr`/`lookup`; iget via inode-table block read; inode cache keyed by `Weak<Inode>`; `orphan_list: Mutex<BTreeMap<u32, Arc<Inode>>>` holds strong refs; `Inode::drop` vetoes eviction on `unlinked == true`
- [ ] fs/ext2: indirect-block walker (direct / single / double / triple) with per-inode walk cache invalidated via epoch stamp; **every pointer bounds-checked against `[s_first_data_block, s_blocks_count)` and metadata-forbidden bitmap**
- [ ] fs/ext2: `FileOps::read` through the buffer cache
- [ ] fs/ext2: `FileOps::getdents64` + directory `lookup` via `Ext2DirEntry2` iteration — **skip `inode == 0` universally**; validate `rec_len`, `name_len > 0` on live, `file_type` in known set, reject ino 0 / reserved range in live dirents
- [ ] fs/ext2: fast symlink gated on `S_ISLNK && i_blocks == 0 && i_size <= 60`, copy clamped to `min(i_size, 60, user_buflen)`; slow symlink read otherwise
- [ ] fs/ext2: **on-mount orphan-chain validation** — bounded walk, cycle detection via `BitVec`, refuse reserved inos; surviving entries drained (RW) or logged (RO)

### Workstream E — ext2 write path (wave 3, blocked on D + A + B)

- [ ] fs/ext2: block bitmap allocator (first-fit in parent's group, linear spill); `sync_dirty_buffer` on bitmap write; update `bg_free_blocks_count` + `s_free_blocks_count`; rollback on downstream failure
- [ ] fs/ext2: inode bitmap allocator (same policy); rollback on downstream failure
- [ ] fs/ext2: `FileOps::write` — extend path allocates data + indirect blocks, updates `i_blocks` by `(block_size/512)` per block (data *and* every indirect); sparse holes
- [ ] fs/ext2: `InodeOps::create`/`mkdir`/`mknod` — normative create ordering (bitmap → inode → dirent, each `sync_dirty_buffer`); `rec_len` split on dirent insert; mkdir bumps parent `i_links_count` for the `..` backlink
- [ ] fs/ext2: `InodeOps::unlink`/`rmdir` — dirent delete with `rec_len` merge (or first-of-block tombstone); `i_links_count` decrement; enter orphan path if `i_links_count == 0 && openers > 0`
- [ ] fs/ext2: `InodeOps::link`/`symlink` — fast-symlink inline storage; `link` checks `EMLINK` against `LINK_MAX`
- [ ] fs/ext2: `InodeOps::rename` — same-dir + cross-dir; **i_links_count++ before new dirent, --after old dirent removed**; overwrite path rewrites target dirent ino in place; POSIX atomicity, sticky bit, `renameat2(RENAME_NOREPLACE)`
- [ ] fs/ext2: `InodeOps::setattr` for chmod/chown/truncate/utimensat — SUID/SGID clearing per §Kernel-Userspace Interface; writeback to inode table
- [ ] fs/ext2: **orphan list** — `s_last_orphan` on disk, `Arc<Inode>` strong-ref mirror; normative final-close sequence (unlink from chain *first*, free blocks, free inode bit, *then* rewrite `i_dtime` as wall-clock)
- [ ] fs/ext2: valid-FS flag — `s_state` clear on RW mount (sync), set on clean umount; force-RO on stale mount

### Workstream F — mount(2) + root-fs plumbing (wave 3, blocked on D)

- [ ] sys: `mount(2)` — superuser-only check **at syscall entry** (not deep in dispatch, to leave room for future unprivileged-mount RFC); flags `MS_RDONLY`/`MS_NOSUID`/`MS_NODEV`/`MS_NOATIME`; dispatch by fstype string
- [ ] sys: `umount2(2)` — `MNT_DETACH`; pinned superblock until last fd closes
- [ ] boot: accept an ext2-formatted virtio-blk disk as root; mount `/` before spawning init; tarfs fallback on mount failure; rootfs default keeps SUID on, non-rootfs defaults `MS_NOSUID`
- [ ] boot: **execve gate** — reject `PT_INTERP` ELFs from ext2-backed inodes with `ENOEXEC` (epic scope: static binaries only)
- [ ] xtask: produce a deterministic ext2 rootfs image via host `mkfs.ext2 -t ext2 -b 4096 -O ^dir_index,^has_journal,^ext_attr` in the build; CI verifies image hash before boot (rootfs-image trust boundary)

### Workstream G — pjdfstest port (wave 4, blocked on E + F)

- [ ] userspace: fork `saidsay-so/pjdfstest` (Rust, GSoC 2022) at a pinned commit; adapt `nix` calls to vibix syscall wrappers (or hand-port test bodies — pick during implementation)
- [ ] xtask: add a `pjdfstest` integration target; run inside QEMU; emit `TEST_PASS`/`TEST_FAIL` markers per test case
- [ ] ci: wire `xtask pjdfstest` into the smoke target; gate merges on full-suite pass

### Label assignments (per `docs/agent-playbooks/prioritization.md`)

- A, B, C, D, E, F → `priority:P1`, `area:fs`, `track:filesystem`. B adds
  `area:security`; C adds `area:driver`; F adds `area:userspace`.
- G → `priority:P2`, `area:fs`, `area:debug`, `track:filesystem` (valuable
  but not blocking PID-1 ext2 boot).
