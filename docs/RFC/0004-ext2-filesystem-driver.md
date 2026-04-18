---
rfc: 0004
title: Ext2 Filesystem Driver
status: Draft
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
  `i_blocks` is in **512-byte units**, not fs-block units — the most common
  hobby-kernel bug.
- `Ext2DirEntry2` — variable-length `{ u32 inode, u16 rec_len, u8 name_len,
  u8 file_type, name[name_len] }`, 4-byte aligned, cannot span a block.

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
    orphan_list: Mutex<Vec<u32>>,
    mount_flags: MountFlags,
}
impl FileSystem for Ext2Fs { ... }
impl SuperOps for Ext2Fs { ... }

pub struct Ext2Inode {
    fs: Weak<Ext2Fs>,
    ino: u32,
    meta: BlockingRwLock<Ext2InodeMeta>,  // parsed i_mode/uid/gid/size/etc.
    block_map: BlockingRwLock<Option<BlockMap>>, // lazy indirect-walk cache
}
impl InodeOps for Ext2Inode { ... }
impl FileOps for Ext2Inode { ... }
```

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

Replacement: **CLOCK-Pro** (Jiang, Chen, Zhang, USENIX ATC 2005). One
reference bit per buffer, advanced on access, cleared on scan. Small caches
(≤1,024 buffers) are most vulnerable to scan pollution, which plain LRU
handles badly; CLOCK-Pro is scan-resistant at O(1) per access with a single
byte of metadata per entry.

Write-back policy: all metadata writes go through `mark_dirty`+sync (via
`sync_dirty_buffer`) on atomicity-critical paths (bitmap allocate, dirent
insert/delete, rename destination write, superblock valid-FS flag, orphan
list). Data writes are `mark_dirty`-only (delayed). `fsync(fd)` flushes
all dirty buffers whose owner inode matches the fd's inode; `sync_fs`
flushes all. A background writeback daemon flushes every 30 seconds.

Each Ext2Fs owns its own `BlockCache` keyed by its own block size; this
avoids block-size-mismatch hazards when multiple filesystems mount on the
same block device in the future.

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
6. In-memory: clear `s_state` → `EXT2_ERROR_FS`, mark superblock buffer
   dirty (will write back on next `sync_fs` or `umount`).
7. `iget(EXT2_ROOT_INO = 2)` → root inode; attach via
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
writes the slot atomically (sync-dirty) before returning.

Per-inode `BlockMap` caches resolved indirect-block numbers to avoid
re-reading indirect blocks on sequential access; invalidated on any
`setattr`/`truncate`/write-that-extends.

#### Directory operations

Directories are regular files whose content is a packed stream of
`Ext2DirEntry2` records padded to 4-byte alignment. Records never cross a
block boundary.

**Lookup:** iterate records, match by `name_len` + `name[]`. O(entries).

**Insert:** scan each block for an entry whose slack
`rec_len - align4(8 + name_len) ≥ align4(8 + new_name_len)`. If found,
split the entry (shorten its `rec_len`, append new record). If not,
append a new full-block record by extending the directory file.

**Delete:** find the entry's predecessor in the same block; grow the
predecessor's `rec_len` to swallow the deleted record. Special case:
deleted entry is first in block → zero its inode field; scanners treat
`inode == 0` in a first slot as a valid blank. This exact convention is
what `e2fsck` expects (getting it wrong is the single most common
hobby-kernel ext2 bug).

#### Allocator

"First-fit in parent's group, linear spill":

1. **Inodes** — to create inode in directory `D`, compute `G = (D.ino - 1)
   / s_inodes_per_group`. Scan group G's inode bitmap for the first zero
   bit. If group is full, advance `G → (G + 1) mod n_groups` and retry;
   loop to exhaustion.
2. **Blocks** — same policy, anchored on the inode's group.

Both allocators set the bitmap bit with `sync_dirty_buffer` (synchronous
write) before returning the number, matching the Card §3.2 policy
("allocate inodes in the same group as the parent directory"). Orlov's
directory-spreading heuristic and preallocation windows are deferred to
v2 (§Alternatives).

#### unlink-while-open + orphan list

POSIX requires the directory entry be removed at `unlink()` time, but the
inode and data blocks must persist until the last `close()`. ext2's
on-disk support for this is the superblock field `s_last_orphan`: head of a
singly-linked list (`i_dtime` repurposed as `next`) of inodes marked-deleted
but still open.

Sequence for `unlink`:

1. `sync_dirty_buffer` the dirent delete.
2. `i_links_count -= 1` in the inode.
3. If `i_links_count == 0` and in-memory openers > 0: prepend ino to
   `s_last_orphan` chain (on disk) and the in-memory `orphan_list`.
4. On final `close()` for the inode: remove from orphan list, free all
   data blocks (block bitmap), free the inode itself (inode bitmap), set
   `i_dtime` to the deletion time.

A crash with entries on the orphan list is recoverable by `e2fsck`, which
walks `s_last_orphan` and frees each inode.

#### rename — POSIX atomicity without a journal

- **Self-rename** (paths resolve to the same directory entry): no-op,
  return 0.
- **Same-directory rename:** overwrite one dirent in one block — single
  sector-sized write; inherently atomic at the block layer. `sync_dirty_buffer`.
  Crash before = old name, after = new name.
- **Cross-directory rename:**
  1. Write new dirent in dst_dir. `sync_dirty_buffer` dst_dir block.
  2. Delete old dirent in src_dir. `sync_dirty_buffer` src_dir block.
  - **Crash between steps 1 and 2:** both old and new dirents reference the
    same inode — i.e., a temporary hardlink. `e2fsck` leaves it as a
    hardlink; the user must `rm` the stale entry. This is identical to
    Linux ext2's behavior (journal-free) and is documented.
- **Overwrite an existing target:** if `target` exists and `renameat2`
  was not called with `RENAME_NOREPLACE`, the overwrite decrements
  target's `i_links_count` after the new dirent is in place (orphan-list
  applies if the target had openers).
- **Cross-device:** `EXDEV` (POSIX-mandated).

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
convention). Errno returns follow POSIX.1-2017 per the list in §Background.

**Directory mutations:** `mkdir` (83) / `mkdirat` (258), `rmdir` (84),
`unlink` (87) / `unlinkat` (263), `rename` (82) / `renameat2` (316,
`RENAME_NOREPLACE` only for MVP), `link` (86) / `linkat` (265),
`symlink` (88) / `symlinkat` (266), `readlink` (89) / `readlinkat` (267).

**Metadata mutations:** `chmod` (90) / `fchmod` (91) / `fchmodat` (268),
`chown` (92) / `fchown` (93) / `lchown` (94) / `fchownat` (260),
`truncate` (76) / `ftruncate` (77), `utimensat` (280), `faccessat` (269),
`faccessat2` (439).

**Credentials:** `getuid` (102) / `geteuid` (107), `getgid` (104) /
`getegid` (108), `setuid` (105), `setgid` (106), `setreuid` (113) /
`setregid` (114), `setresuid` (117) / `setresgid` (119),
`setgroups` (116), `getgroups` (115).

**Mount:** `mount` (165), `umount2` (166).

Linux's `statfs`/`statvfs`, `setfsuid`/`setfsgid`, xattr, quota,
`fallocate`, and Linux capabilities (`CAP_*`) are **out of scope**.

## Security Considerations

- **Permission enforcement gap before Workstream B lands.** Until per-task
  credentials are plumbed, every VFS syscall runs as root regardless of
  caller. The wave ordering enforces B landing before A's *new* syscalls
  become reachable from ring-3 to avoid widening this window; *existing*
  wired syscalls (open/read/write) remain root-gated as today, which is a
  pre-existing limitation tracked separately.
- **Setuid exec from untrusted ext2 images.** An ext2 image with a
  setuid-root binary is on-disk-valid and will elevate at exec. Mitigation:
  `MS_NOSUID` is honored by the exec path at inode `permission()`; the
  rootfs mount default keeps SUID on (required for `/bin/su`-like
  functionality) but mounts of non-rootfs volumes default to `MS_NOSUID`.
- **Filesystem confusion attacks.** Malformed superblock/BGDT/inode/dirent
  fields can drive kernel memory corruption. Mitigation: every read from
  disk is bounds-checked against `s_blocks_count` / `s_inodes_count` and
  against the mounted block size; bad values produce `EIO` at operation
  time (or `EINVAL` at mount time) rather than a panic. `Ext2DirEntry2`
  iteration explicitly validates `rec_len ≥ 8`, `rec_len` aligned,
  `rec_len + cursor ≤ block_end`, `name_len ≤ rec_len - 8`.
- **Integer overflow in file-offset math.** `ftruncate(INT64_MAX)`,
  `lseek + write` past 2 TiB, indirect-block index arithmetic — all use
  checked arithmetic (`checked_add`/`checked_mul`) and reject invalid
  inputs with `EFBIG`/`EINVAL`.
- **TOCTOU in dirent replacement.** Rename's overwrite path writes one
  dirent in place (the new dirent's slot) — the target name never
  "disappears" during the operation. The cross-dir window (temporary
  hardlink after crash) is a crash-consistency issue, not a TOCTOU.
- **Kernel-address leakage via errno.** Errnos are pure enum discriminants;
  no kernel addresses. Verified at code review of each added syscall.
- **Sticky-bit enforcement.** `unlink`/`rename` in a directory with
  `S_ISVTX` requires caller == file owner OR directory owner OR root.
  Enforced at `InodeOps::permission` in the ext2 driver; tested by
  pjdfstest `unlink/11.t`.

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
- [ ] **Cross-directory rename crash window** — accept the
      "temporary-hardlink-after-crash" mode as documented, or add a
      best-effort ordering hook? Leaning accept-and-document.
- [ ] **Writeback-daemon cadence** — 30 s (Linux default) vs a shorter
      interval for QEMU-only test runs (<60 s total). Pick during
      Workstream C.
- [ ] **`setuid` as a wrapper over `setresuid`?** Internally, `setuid`,
      `setreuid`, and `setresuid` are all special cases of the saved-set
      transitions. Ship one internal kernel primitive; pick during
      Workstream B whether all four syscalls exist or only the most
      expressive.
- [ ] **Port pjdfstest by forking the Rust rewrite with a vibix-nix shim,
      or by hand-translating test bodies to direct-syscall Rust?** Deferred
      to Workstream G; research brief gives evidence for both.
- [ ] **Deferred to follow-up RFCs:** ext3-style journal, page cache
      (+ mmap file backing), HTree directories (`INCOMPAT_DIR_INDEX`),
      extended attributes (`*xattr`), quota (`quotactl`), in-kernel `fsck`,
      POSIX capabilities, SMP-aware cache sharding.

## Implementation Roadmap

Workstreams A, B, C start in wave 1 (parallel, no cross-blockers). D blocks
on C. E blocks on D + A + B. F blocks on D. G blocks on E + F.

### Workstream A — POSIX write syscalls (wave 1)

- [ ] sys: wire `mkdir`/`mkdirat` + `rmdir` to `InodeOps::mkdir`/`rmdir`
- [ ] sys: wire `unlink`/`unlinkat` to `InodeOps::unlink`
- [ ] sys: wire `link`/`linkat` + `symlink`/`symlinkat` + `readlink`/`readlinkat`
- [ ] sys: wire `rename`/`renameat` + `renameat2(RENAME_NOREPLACE)`
- [ ] sys: wire `chmod`/`fchmod`/`fchmodat` + `chown`/`fchown`/`lchown`/`fchownat`
- [ ] sys: wire `truncate`/`ftruncate` to `InodeOps::setattr` (size field)
- [ ] sys: wire `utimensat`/`futimens` + `faccessat`/`faccessat2`

### Workstream B — Credential enforcement (wave 1)

- [ ] task: extend `Credential` with `euid`/`suid`/`egid`/`sgid`; add `Task::credentials: BlockingRwLock<Arc<Credential>>`
- [ ] sys: wire `getuid`/`geteuid` + `getgid`/`getegid`
- [ ] sys: wire `setuid`/`setreuid`/`setresuid` + `setgid`/`setregid`/`setresgid` with POSIX saved-set-uid semantics
- [ ] sys: wire `setgroups`/`getgroups`; cap `NGROUPS_MAX = 32`
- [ ] sys: replace `Credential::kernel()` at every VFS syscall entry with the per-task credential

### Workstream C — Block buffer cache (wave 1)

- [ ] block: `BufferHead { data, state, clock_ref }` + `BlockCache` keyed on `(device, block_no, block_size)`
- [ ] block: `bread`/`mark_dirty`/`sync_dirty_buffer`/`release` API with CLOCK-Pro replacement
- [ ] block: `sync_fs(sb)` flushes all dirty buffers owned by a mount
- [ ] block: sync-on-eviction when cache is full and no clean candidate
- [ ] block: periodic writeback daemon (30 s cadence, cmdline-configurable)

### Workstream D — ext2 read path (wave 2, blocked on C)

- [ ] fs/ext2/disk: `#[repr(C, packed)]` on-disk types + explicit-LE accessors for every field
- [ ] fs/ext2: `Ext2Fs` implements `FileSystem` + `SuperOps`; mount reads superblock + BGDT, validates feature flags, force-RO on RO_COMPAT mismatch
- [ ] fs/ext2: `Ext2Inode` implements `InodeOps::getattr`/`lookup`; iget via inode-table block read; inode cache
- [ ] fs/ext2: indirect-block walker (direct / single / double / triple) with per-inode walk cache
- [ ] fs/ext2: `FileOps::read` through the buffer cache
- [ ] fs/ext2: `FileOps::getdents64` + directory `lookup` via `Ext2DirEntry2` iteration with edge-case validation
- [ ] fs/ext2: fast symlink (`i_blocks == 0`, ≤60 chars, stored inline) + slow symlink read

### Workstream E — ext2 write path (wave 3, blocked on D + A + B)

- [ ] fs/ext2: block bitmap allocator (first-fit in parent's group, linear spill)
- [ ] fs/ext2: inode bitmap allocator (same policy)
- [ ] fs/ext2: `FileOps::write` (extend, sparse holes, allocate-on-write)
- [ ] fs/ext2: `InodeOps::create`/`mkdir`/`mknod` — dirent insert with `rec_len` split
- [ ] fs/ext2: `InodeOps::unlink`/`rmdir` — dirent delete with `rec_len` merge; `i_links_count` decrement
- [ ] fs/ext2: `InodeOps::link`/`symlink` (including fast-symlink inline storage)
- [ ] fs/ext2: `InodeOps::rename` — same-dir + cross-dir, POSIX atomicity, sticky bit, `renameat2(RENAME_NOREPLACE)`
- [ ] fs/ext2: `InodeOps::setattr` for chmod/chown/truncate/utimensat — writeback to inode table
- [ ] fs/ext2: orphan list (`s_last_orphan` on disk, in-memory mirror); `i_dtime` set on last close
- [ ] fs/ext2: valid-FS flag — clear on mount, set on clean umount; force-RO on stale mount

### Workstream F — mount(2) + root-fs plumbing (wave 3, blocked on D)

- [ ] sys: `mount(2)` — superuser-only; flags `MS_RDONLY`/`MS_NOSUID`/`MS_NODEV`/`MS_NOATIME`; dispatch by fstype string
- [ ] sys: `umount2(2)` — `MNT_DETACH`
- [ ] boot: accept an ext2-formatted virtio-blk disk as root; mount `/` before spawning init; tarfs fallback on mount failure
- [ ] xtask: produce a deterministic ext2 rootfs image via host `mkfs.ext2 -t ext2 -b 4096` in the build

### Workstream G — pjdfstest port (wave 4, blocked on E + F)

- [ ] userspace: fork `saidsay-so/pjdfstest` (Rust, GSoC 2022) under the vibix tree; adapt `nix` calls to vibix syscall wrappers (or hand-port test bodies — pick during implementation)
- [ ] xtask: add a `pjdfstest` integration target; run inside QEMU; emit `TEST_PASS`/`TEST_FAIL` markers per test case
- [ ] ci: wire `xtask pjdfstest` into the smoke target; gate merges on full-suite pass

### Label assignments (per `docs/agent-playbooks/prioritization.md`)

- A, B, C, D, E, F → `priority:P1`, `area:fs`, `track:filesystem`. B adds
  `area:security`; C adds `area:driver`; F adds `area:userspace`.
- G → `priority:P2`, `area:fs`, `area:debug`, `track:filesystem` (valuable
  but not blocking PID-1 ext2 boot).
