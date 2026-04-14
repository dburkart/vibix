---
rfc: 0002
title: Virtual Filesystem Layer
status: In Review
created: 2026-04-14
---

# RFC 0002: Virtual Filesystem Layer

## Abstract

This RFC proposes a virtual filesystem (VFS) layer for vibix that sits
between the existing per-process fd table (`kernel/src/fs/mod.rs`) and
concrete filesystem drivers. It adopts the classic vnode model (Kleiman,
USENIX 1986) in idiomatic Rust: three refcounted in-kernel objects —
`SuperBlock` (a mounted filesystem instance), `Inode` (a persistent
file/dir/symlink object, one per `(fs_id, ino)`), and `Dentry` (a cached
name edge connecting a parent directory inode to a child inode) — driven
by four dyn-dispatch traits (`FileSystem`, `SuperOps`, `InodeOps`,
`FileOps`). A mount table attaches superblocks at dentries; path
resolution walks the dentry tree, crossing mounts, and terminates at an
`Arc<Inode>`. A new `VfsBackend` adapter bridges the VFS `FileOps` trait
to the existing `FileBackend` trait so path-opened files reuse today's
`FileDescTable`. The initial root filesystem is `tarfs` (a read-only
USTAR reader over a Limine-loaded ramdisk module), unblocking issue #85
(multi-level directory support), #87 (POSIX-compatible semantics), and
the `/init` load path on the road to PID 1 (#121).

## Motivation

Today vibix has:

- **A per-process fd table with two backends**
  (`kernel/src/fs/mod.rs`) — `SerialBackend` and whatever ad-hoc
  `FileBackend` a caller hands to `FileDescTable::alloc_fd`. There is no
  path-to-file mapping; `open("/init", ...)` is impossible.
- **A working virtio-blk driver** (`kernel/src/block/virtio_blk.rs`,
  read-only, polled) that can produce bytes from a disk image but has no
  consumer.
- **A plan for `execve("/init")`** (issue #121) that cannot land until
  something can resolve `/init` to an inode and read its bytes.

Four gaps must close before userspace is viable:

1. **A stable in-kernel name→inode lookup** — `sys_open` needs a way to
   turn `"/init"` (or `"./bin/sh"`) into an object with read/mmap
   operations. The existing `FileBackend` trait has no path, no metadata,
   no directory enumeration.
2. **A pluggable filesystem driver interface** — so that `tarfs`
   (read-only initrd), `ramfs` (writable in-memory), `devfs` (synthetic
   `/dev`), and eventually a real on-disk FS plug in without the VFS
   changing shape. The OSDev Wiki's VFS and File Systems pages warn
   explicitly that "designing the VFS around a specific filesystem tends
   to contaminate the VFS interface" and recommends ramfs as the first
   FS precisely to avoid that.
3. **A mount table** — so the initial root is `tarfs`, `/dev` is
   `devfs`, and later `/` can be remounted onto a block device without a
   rewrite. Mount crossings must be explicit, not a special case in one
   filesystem's `lookup`.
4. **Directory semantics** — `getdents64`, `mkdir`, `unlink`, `stat`,
   and `rename` have tight POSIX.1-2017 contracts (see §4.13, pathname
   resolution) that the fd table cannot express. Issue #85 (multi-level
   directories), #86 (permissions), and #87 (POSIX semantics) all block
   on a real VFS.

This RFC defines the data structures, path-resolution algorithm, mount
protocol, and syscall contracts required to land those four. It also
locks in the minimum starter FS set (`tarfs` read-only, `ramfs`
writable) and defines the compatibility story with the existing fd
table so the migration is incremental.

## Background

### Prior art surveyed

- **Kleiman, *Vnodes: An Architecture for Multiple File System Types in
  Sun UNIX*, USENIX Summer 1986.** The foundational VFS paper. Four
  explicit design goals: (a) clean layering between FS-independent and
  FS-dependent code; (b) a well-defined operation interface; (c) support
  for local/remote/stateful/stateless filesystems; (d) filesystem
  operations atomic w.r.t. the VFS. The vnode interface has survived
  ~40 years largely unchanged and is the low-risk default.
- **Linux VFS.** `fs/namei.c`, `fs/open.c`,
  `Documentation/filesystems/vfs.rst`, `.../path-lookup.rst`. Five-object
  model (`super_block`/`inode`/`dentry`/`file`/`vfsmount`) with
  per-object `*_operations` vtables. Path walk is a two-tier
  ref-walk/RCU-walk algorithm; directory-mod serialization via
  `i_rwsem`; mount crossing gated by `mount_lock` seqlock. We copy the
  shape but explicitly defer RCU-walk (see Alternatives).
- **SerenityOS `Kernel/FileSystem/`.** `VirtualFileSystem` namespace
  plus `Custody` (dentry-equivalent; one-to-one with an inode, forms a
  parent chain). `Mount { Details { guest_fs, guest_inode },
  host_custody }` inside a `VFSRootContext` (mount namespaces). The
  `symlink_recursion_limit = 8` static gives us a concrete, audited
  value to adopt.
- **Redox schemes.** `KernelScheme` trait registered in an
  `RwLock<HashMap<SchemeId, Handle>>`. Deliberately rejected here — see
  Alternatives — because POSIX path compatibility is a hard requirement
  for musl userspace and scheme-based naming is not POSIX.
- **OSDev Wiki.** `VFS`, `File Systems`, `Initrd`, `USTAR`, and
  `Hierarchical VFS Theory` pages. Recommends: initrd loaded as a
  Multiboot/Limine module; parse as USTAR; unpack or project into a
  ramfs; mount at `/`. Mount resolution as longest-prefix match over a
  flat list is acceptable for a first pass.
- **POSIX.1-2017 XSH §4.13 (Pathname Resolution)**, plus the syscall
  descriptions for `open`, `openat`, `stat`, `mkdir`, `rmdir`, `unlink`,
  `rename`, `link`, `symlink`, `readlink`, `getdents`-analog. These are
  cited literally in the Design and Security sections.
- **Plan 9 per-process namespace (Pike et al., 1992)** considered and
  rejected — see Alternatives.
- **NFS silly-rename / OPEN4_RESULT_PRESERVE_UNLINKED.** Informs the
  unlink-while-open semantics (§Design, *Inode lifecycle*).
- **Theseus (OSDI 2020).** Notes that spill-free Rust affine ownership
  cannot preserve POSIX unlink-while-open; we follow the opposite
  choice — POSIX semantics first, at the cost of refcounted `Arc<Inode>`
  with interior mutability.

### What vibix has today

- `kernel/src/fs/mod.rs` — `FileBackend` trait (`read(&[u8]) /
  write(&[u8])`), `FileDescription { backend: Arc<dyn FileBackend>,
  flags: u32 }`, `FileDescTable` (per-process; `alloc_fd`, `close_fd`,
  `dup`, `dup2`, `clone_for_fork`, `close_cloexec`). No path, no inode,
  no directory iteration.
- `kernel/src/block/mod.rs` — read-only `read(lba, buf)` over the first
  virtio-blk device. Enough to back a future `blkdev-backed tarfs` or
  ext2 driver; out of scope for this RFC to actually wire through.
- The x86_64 syscall dispatcher (`kernel/src/arch/x86_64/syscall.rs`)
  already routes `read`/`write`/`close`/`dup`/`dup2` through
  `FileDescTable` (#125). It does **not** yet handle `open`/`stat`/
  `getdents`/`mkdir`/`unlink` — those arrive with this RFC.

## Design

### Overview

Three concrete object types — `SuperBlock`, `Inode`, `Dentry` — and four
operation traits — `FileSystem`, `SuperOps`, `InodeOps`, `FileOps` —
plus a small `MountTable` and a `NameIdata`-style path-walker. A new
`OpenFile` struct holds per-fd state (offset, flags, dentry-at-open);
adapter `VfsBackend` wraps `Arc<OpenFile>` as a `dyn FileBackend` so the
existing fd table consumes VFS files with no changes to its public API.

```
                 syscall layer (open, stat, read, getdents, ...)
                         |
                         v
                    path_walk(nd) ---+--- MountTable ---+
                         |                              |
                         v                              v
                   Arc<Dentry> -----> Arc<Inode> <--- Arc<SuperBlock>
                                             |
                                             v
                                      &dyn InodeOps        (FS-specific)
                                             |
                                             v
                                   read_iter / write_iter / lookup / ...

          FileDescTable (existing)  ---> Arc<FileDescription> ---> Arc<dyn FileBackend>
                                                                        ^
                                                              VfsBackend { open_file: Arc<OpenFile> }
```

The dashed boundary is: everything the existing fd table sees is a `dyn
FileBackend`; everything below it is the VFS. We do **not** break the
existing `FileBackend` trait — `SerialBackend` keeps working for stdio
before any mount is set up.

### Key Data Structures

All three object types live in `kernel/src/fs/vfs/`. They are `Send +
Sync`; concurrent access is protected by the locking discipline in the
next subsection.

```rust
// kernel/src/fs/vfs/mod.rs

pub struct SuperBlock {
    pub fs_id: FsId,                    // unique per mounted instance
    pub ops: Arc<dyn SuperOps>,
    pub fs_type: &'static str,          // "tarfs", "ramfs", ...
    pub root: OnceLock<Arc<Inode>>,     // set during FileSystem::mount
    pub block_size: u32,                // info only; not a hard limit
    pub flags: SbFlags,                 // RDONLY, NOEXEC, NOSUID, NODEV
}

pub struct Inode {
    pub ino: u64,
    pub sb: Weak<SuperBlock>,           // breaks SB -> Inode -> SB cycle
    pub ops: Arc<dyn InodeOps>,
    pub file_ops: Arc<dyn FileOps>,     // for regulars; dirs use dir_ops from ops
    pub meta: RwLock<InodeMeta>,        // mode, uid, gid, size, nlink, times
    pub state: Mutex<InodeState>,       // dirty, unlinked, pinned counts
    pub kind: InodeKind,                // Reg, Dir, Link, Chr, Blk, Fifo, Sock
}

pub struct InodeMeta {
    pub mode:  u16,                     // S_IFMT | S_I[RWX][UGO] | S_IS[UG]ID | S_ISVTX
    pub uid:   u32,
    pub gid:   u32,
    pub size:  u64,
    pub nlink: u32,
    pub atime: Timespec,
    pub mtime: Timespec,
    pub ctime: Timespec,
    pub rdev:  u64,                     // for S_IFCHR / S_IFBLK
    pub blksize: u32,
    pub blocks:  u64,
}

pub struct Dentry {
    pub name: DString,                  // bounded (NAME_MAX = 255)
    pub parent: Weak<Dentry>,           // `/` parents itself via a special root ctor
    pub inode: RwLock<Option<Arc<Inode>>>, // None == negative dentry
    pub mount: RwLock<Option<Arc<MountEdge>>>, // Some when this dentry IS a mountpoint
    pub children: RwLock<BTreeMap<DString, Arc<Dentry>>>, // cached by name
    pub flags: DFlags,                  // IS_ROOT, DISCONNECTED, ...
}

pub struct MountEdge {
    pub mountpoint: Weak<Dentry>,       // dentry in the PARENT fs
    pub super_block: Arc<SuperBlock>,   // mounted FS instance
    pub root_dentry: Arc<Dentry>,       // root of the mounted FS
    pub flags: MountFlags,
}

pub struct OpenFile {
    pub dentry: Arc<Dentry>,            // dentry at time of open (stable)
    pub inode:  Arc<Inode>,             // for perf; always == *dentry.inode.read()
    pub offset: Mutex<u64>,             // for read/write/lseek
    pub flags:  u32,                    // O_*, preserved from open()
    pub ops:    Arc<dyn FileOps>,       // copied out of inode at open() time
}
```

The four operation traits (elided methods are trivial; see the file for
full signatures):

```rust
pub trait FileSystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn mount(&self, source: MountSource, flags: MountFlags)
        -> Result<Arc<SuperBlock>, i64>;
}

pub trait SuperOps: Send + Sync {
    fn root_inode(&self) -> Arc<Inode>;
    fn sync(&self)   -> Result<(), i64> { Ok(()) }                  // no-op for RO FS
    fn evict_inode(&self, ino: u64) -> Result<(), i64> { Ok(()) }   // last Arc dropped
    fn statfs(&self) -> Result<StatFs, i64>;
    fn unmount(&self) -> Result<(), i64>;
}

pub trait InodeOps: Send + Sync {
    // Directory-only: unused methods return EPERM or ENOTDIR as appropriate.
    fn lookup(&self, dir: &Inode, name: &[u8])   -> Result<Arc<Inode>, i64>;
    fn create(&self, dir: &Inode, name: &[u8], mode: u16) -> Result<Arc<Inode>, i64>;
    fn mkdir (&self, dir: &Inode, name: &[u8], mode: u16) -> Result<Arc<Inode>, i64>;
    fn unlink(&self, dir: &Inode, name: &[u8])   -> Result<(), i64>;
    fn rmdir (&self, dir: &Inode, name: &[u8])   -> Result<(), i64>;
    fn rename(&self, old_dir: &Inode, old_name: &[u8],
                     new_dir: &Inode, new_name: &[u8]) -> Result<(), i64>;
    fn link  (&self, dir: &Inode, name: &[u8], target: &Inode) -> Result<(), i64>;
    fn symlink(&self, dir: &Inode, name: &[u8], target: &[u8]) -> Result<Arc<Inode>, i64>;

    // Symlink-only:
    fn readlink(&self, inode: &Inode, buf: &mut [u8]) -> Result<usize, i64>;

    // Metadata (all inode kinds):
    fn getattr(&self, inode: &Inode, out: &mut Stat) -> Result<(), i64>;
    fn setattr(&self, inode: &Inode, attr: &SetAttr) -> Result<(), i64>;

    // Permission check hook. Default walks mode/uid/gid.
    fn permission(&self, inode: &Inode, cred: &Credential, access: Access)
        -> Result<(), i64> { default_permission(inode, cred, access) }
}

pub trait FileOps: Send + Sync {
    fn read (&self, f: &OpenFile, buf: &mut [u8], off: u64) -> Result<usize, i64>;
    fn write(&self, f: &OpenFile, buf: &[u8],    off: u64) -> Result<usize, i64>;
    fn seek (&self, f: &OpenFile, whence: Whence, off: i64) -> Result<u64, i64>;
    fn getdents(&self, f: &OpenFile, buf: &mut [u8], cookie: &mut u64)
        -> Result<usize, i64>;
    fn ioctl(&self, f: &OpenFile, cmd: u32, arg: usize) -> Result<i64, i64> { Err(-25) } // ENOTTY
    fn flush(&self, f: &OpenFile) -> Result<(), i64> { Ok(()) }
    fn fsync(&self, f: &OpenFile, data_only: bool) -> Result<(), i64> { Ok(()) }
    // mmap support deferred — VmObject::File arrives with RFC 0003.
}
```

### Algorithms and Protocols

#### Path resolution

A single resolver `path_walk(nd: &mut NameIdata) -> Result<(), i64>`
drives every path syscall. It is the only component that crosses mount
boundaries, follows symlinks, and interprets `.` / `..`. This
consolidates the POSIX §4.13 rules in one place.

```rust
pub struct NameIdata {
    pub root:    Arc<Dentry>,           // process root (always "/" for now)
    pub cwd:     Arc<Dentry>,           // at entry; fd in openat path
    pub path:    Path,                  // current (dentry) walk cursor
    pub last:    Last,                  // last component type for creators
    pub flags:   LookupFlags,           // FOLLOW, DIRECTORY, PARENT, AT_EMPTY_PATH
    pub symlink_depth: u8,              // incremented per symlink follow
    pub cred:    Credential,            // caller's (uid, gid, groups)
}

pub enum Last {
    Norm(DString),                      // a concrete final name
    Root,                               // "/" absolute
    Dot,                                // "."
    DotDot,                             // ".."
}
```

The algorithm, in order:

1. If the path is empty and `AT_EMPTY_PATH` is set, the fd's dentry is
   the result. Otherwise return `ENOENT`.
2. If the path starts with `/`, seed `nd.path = nd.root`; else seed
   from `nd.cwd` (or the fd's dentry for `*at`).
3. For each `/`-separated component `c`:
   - If `c` is empty (leading, trailing, or repeated `/`), skip —
     except that a trailing `/` sets `LookupFlags::DIRECTORY` on the
     final component.
   - If `c == "."`, continue.
   - If `c == ".."`, move to `path.parent` *after* crossing any mount
     edge we're currently sitting on (upward crossing: if
     `path.dentry == sb.root`, jump to `mount.mountpoint` in the parent
     FS; root's parent is root itself).
   - Else look up `c` in `path.dentry.children`. If absent, call
     `inode_ops.lookup(parent_inode, c)` and insert the result
     (`Some(inode)` on hit, `None` as a negative dentry on `ENOENT` — we
     cache negative dentries only when safe; see Security).
   - After resolving, if the child dentry is a mountpoint (has
     `Some(mount)`), jump down: replace `path` with
     `(mount.super_block, mount.root_dentry)`.
   - If the resolved inode is a symlink and this is not the final
     component *or* `FOLLOW` is set: increment `symlink_depth` (return
     `ELOOP` on > 40, matching Linux `SYMLOOP_MAX`), read the link via
     `inode_ops.readlink`, and recursively path-walk the target
     (absolute targets restart at `nd.root`).
4. After the final component: if `LookupFlags::DIRECTORY` and the
   resolved inode is not `S_IFDIR`, return `ENOTDIR`.

Dentry children use a `BTreeMap<DString, Arc<Dentry>>` — log(n)
lookup, deterministic iteration order for directory reads, no hash
collisions to reason about. This is a deliberate simplification over
Linux's hashed dcache; it is revisited in Performance Considerations.

The walk is **not** RCU-lock-free. Every resolved dentry takes a read
lock on `children` for the duration of the lookup. This is the
single-CPU reality today (see Alternatives for RCU-walk rationale).

#### Mount and unmount

```
mount(source: MountSource, target_path: &str, fs_type: &str, flags):
    fs = FS_REGISTRY.get(fs_type)?;        // ENODEV if not registered
    sb = fs.mount(source, flags)?;          // FS-specific; returns SuperBlock
    target_nd = path_walk(target_path)?;    // must exist, must be a directory
    if target_nd.inode.kind != InodeKind::Dir { return Err(ENOTDIR); }
    // Atomic install under MOUNT_TABLE.write():
    let edge = Arc::new(MountEdge {
        mountpoint: Arc::downgrade(&target_nd.dentry),
        super_block: sb.clone(),
        root_dentry: sb.root_dentry.clone(),
        flags,
    });
    *target_nd.dentry.mount.write() = Some(edge.clone());
    MOUNT_TABLE.write().push(edge);
    Ok(())

unmount(target_path: &str, flags):
    // Walk to the mount root, not through it: stop at the first mount edge.
    edge = MOUNT_TABLE.read().find(target_path)?;
    if !flags.contains(MNT_FORCE) {
        if edge.super_block.has_open_files() { return Err(EBUSY); }
    }
    edge.super_block.ops.unmount()?;
    *edge.mountpoint.upgrade().unwrap().mount.write() = None;
    MOUNT_TABLE.write().retain(|e| !Arc::ptr_eq(e, &edge));
```

`MOUNT_TABLE` is a single global `RwLock<Vec<Arc<MountEdge>>>`. For the
≤ 8 mounts we expect (`/`, `/dev`, `/proc`, `/tmp`, `/sys`), linear scan
is correct and easy to reason about. We will revisit when an RFC adds
bind mounts or mount namespaces.

#### Inode lifecycle

Inodes are refcounted via `Arc<Inode>`. The superblock keeps a weak
table (`RwLock<BTreeMap<u64, Weak<Inode>>>`) so repeated lookups of the
same `ino` return the same object — this is the invariant `st_ino +
st_dev uniquely identifies a file` depends on.

Two pinning sources:

- **Dentry link:** `Dentry.inode = Some(Arc<Inode>)` holds a strong
  ref. A negative dentry holds no Inode.
- **Open file:** `OpenFile.inode` holds a strong ref.

Unlink semantics (POSIX, §Design of unlink): `inode_ops.unlink(dir,
name)` removes the on-disk directory entry and decrements `nlink`. It
does **not** drop the inode. If `nlink == 0` and there are still open
files, the inode is in the *unlinked-but-open* state (`InodeState::
unlinked = true`); when the last `OpenFile` Arc drops, `Drop` calls
`sb.ops.evict_inode(ino)` which frees on-disk resources. This is the
POSIX contract that Theseus chose not to implement. We follow POSIX.

Cross-FS boundaries: `link` and `rename` must check
`src_inode.sb.fs_id == dst_inode.sb.fs_id`; if not, return `EXDEV`.

### Kernel–Userspace Interface

Syscall numbers align with Linux x86_64 numbering to keep ABI
compatibility with musl. (`mmap` = 9 is already wired; we keep the rest
compatible.)

| #    | Name       | Args                                              | Returns |
|------|------------|---------------------------------------------------|---------|
|  2   | open       | `path: *const u8, flags: u32, mode: u16`          | fd \| -errno |
| 257  | openat     | `dfd: i32, path: *const u8, flags: u32, mode: u16`| fd \| -errno |
|  4   | stat       | `path: *const u8, out: *mut Stat`                 | 0 \| -errno |
|  5   | fstat      | `fd: u32, out: *mut Stat`                         | 0 \| -errno |
|  6   | lstat      | `path: *const u8, out: *mut Stat`                 | 0 \| -errno |
| 262  | fstatat    | `dfd, path, out, flags`                           | 0 \| -errno |
|  8   | lseek      | `fd: u32, off: i64, whence: u32`                  | new_off \| -errno |
| 217  | getdents64 | `fd: u32, buf: *mut u8, len: u64`                 | bytes \| -errno |
| 83   | mkdir      | `path, mode`                                      | 0 \| -errno |
| 84   | rmdir      | `path`                                            | 0 \| -errno |
| 87   | unlink     | `path`                                            | 0 \| -errno |
| 82   | rename     | `oldpath, newpath`                                | 0 \| -errno |
| 86   | link       | `oldpath, newpath`                                | 0 \| -errno |
| 88   | symlink    | `target, linkpath`                                | 0 \| -errno |
| 89   | readlink   | `path, buf, bufsiz`                               | bytes \| -errno |
| 79   | getcwd     | `buf, size`                                       | bytes \| -errno |
| 80   | chdir      | `path`                                            | 0 \| -errno |

**`struct Stat`** follows the Linux x86_64 layout so musl's `sys/stat.h`
works unmodified: `dev, ino, nlink, mode, uid, gid, pad, rdev, size,
blksize, blocks, atime{sec,nsec}, mtime{sec,nsec}, ctime{sec,nsec}`
(aligned, 144 bytes). `st_dev` is `SuperBlock::fs_id`; `st_ino` is
`Inode::ino`; `st_mode` encodes `InodeKind` into the `S_IFMT` bits and
`InodeMeta::mode` into the low 12.

**`struct linux_dirent64`** (the `getdents64` wire format):
`{ u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }` —
`d_type` uses the Linux `DT_*` enumeration (`DT_REG=8, DT_DIR=4,
DT_LNK=10, DT_CHR=2, DT_BLK=6, DT_FIFO=1, DT_SOCK=12, DT_UNKNOWN=0`).

**`AT_FDCWD` = -100**, **`AT_SYMLINK_NOFOLLOW` = 0x100**,
**`AT_REMOVEDIR` = 0x200**, **`AT_EMPTY_PATH` = 0x1000** — numeric
values copied from Linux.

**Limits (matching Linux):** `PATH_MAX = 4096`, `NAME_MAX = 255`,
`SYMLOOP_MAX = 40`, `OPEN_MAX = 1024` (already set by `FileDescTable`).

**Errno mapping** is the existing `ENOENT/EBADF/ENOMEM/EAGAIN/EINVAL/
EMFILE/ENAMETOOLONG` set in `kernel/src/fs/mod.rs` extended with
`ENOTDIR = -20`, `EISDIR = -21`, `EXDEV = -18`, `ENOSPC = -28`,
`EROFS = -30`, `EACCES = -13`, `EPERM = -1`, `EEXIST = -17`,
`ELOOP = -40`, `ENOTEMPTY = -39`, `ENODEV = -19`, `EBUSY = -16`,
`ENOTTY = -25`.

### Locking discipline

One rule: **all VFS locks are taken leaf-to-root. Never hold a parent's
lock while acquiring a child's.** Concretely:

- `SuperBlock.inode_table` (`RwLock<BTreeMap<u64, Weak<Inode>>>`) —
  held only for lookup-or-insert; never held across `InodeOps` calls.
- `Dentry.children` (`RwLock<BTreeMap<DString, Arc<Dentry>>>`) — read
  during path walk; write only when inserting a new dentry or invalidating.
  Released before calling into `InodeOps::lookup`.
- `Inode.meta` (`RwLock<InodeMeta>`) — `getattr`/`setattr` serialize on
  this. Reads allowed during directory ops.
- `Inode.state` (`Mutex<InodeState>`) — for `nlink` decrement, dirty
  flag, unlinked flag. Short critical sections only.
- `MOUNT_TABLE` (`RwLock<Vec<Arc<MountEdge>>>`) — read during every
  path walk (brief; released when cursor stabilizes); write only in
  mount/unmount.

`InodeOps::rename` is the one operation that must lock two directory
inodes. Order: lock the directory with the **smaller `fs_id, ino`
pair** first (lexicographic); if both are the same directory, only one
lock. This is the standard "lock-by-address-order" deadlock avoidance,
transplanted onto our stable `(fs_id, ino)` identity pair.

All locks use the existing `sync::spinlock::SpinMutex` and
`sync::rwlock::RwLock` primitives. None of them disable interrupts —
VFS calls only from the syscall context, never from an ISR.

### Concrete filesystems for day 1

Three drivers land with the VFS layer; all implement `FileSystem`,
`SuperOps`, `InodeOps`, `FileOps`.

- **`tarfs` (read-only, USTAR)** — backed by a Limine ramdisk module.
  Parses the USTAR archive at mount time into an in-memory
  `(path -> (InodeKind, offset_in_ramdisk, length, mode, uid, gid,
  mtime))` index. All inodes are projected from that index; all reads
  memcpy out of the ramdisk slice. `unlink`/`mkdir`/`write` return
  `EROFS`. Mounted at `/` in the boot path after `mem::init()`.

- **`ramfs` (read-write, in-memory)** — `Vec<u8>` page-granular
  backing per regular inode; `BTreeMap<DString, Arc<Inode>>` for dirs.
  Supports the full `InodeOps`/`FileOps` surface except `fsync`
  (no-op). Intended mount point: `/tmp`.

- **`devfs` (synthetic)** — exposes `/dev/null`, `/dev/zero`,
  `/dev/tty` (`SerialBackend`-wrapped), `/dev/console` (same).
  Directory is fixed; entries are static. Supports `stat`, `read`,
  `write`; `unlink`/`rename`/`mkdir` return `EPERM`.

`tarfs` is the minimum to load `/init` from the ramdisk; `devfs`
replaces the hardcoded stdio in `FileDescTable::new_with_stdio()`;
`ramfs` gives userspace a writable directory for `/tmp`.

### Integration with the existing fd table

`open(path, flags, mode)` steps:

```rust
fn sys_open(path: &CStr, flags: u32, mode: u16) -> Result<i32, i64> {
    let mut nd = NameIdata::from_current(path, flags.into())?;
    path_walk(&mut nd)?;
    check_open_permission(&nd, flags)?;
    if flags & O_TRUNC != 0 { nd.dentry.inode.read().as_ref().unwrap()
        .ops.setattr(&*nd.inode(), &SetAttr { size: Some(0), ..Default::default() })?; }
    let of = Arc::new(OpenFile { dentry: nd.dentry.clone(), inode: nd.inode(),
                                 offset: Mutex::new(0), flags, ops: nd.inode().file_ops.clone() });
    let backend: Arc<dyn FileBackend> = Arc::new(VfsBackend { open_file: of });
    let fd_table = current_task().fd_table();
    fd_table.alloc_fd(Arc::new(FileDescription { backend, flags }))
}
```

Where `VfsBackend` is:

```rust
pub struct VfsBackend { pub open_file: Arc<OpenFile> }
impl FileBackend for VfsBackend {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        let n = self.open_file.ops.read(&self.open_file, buf, *off)?;
        *off += n as u64;
        Ok(n)
    }
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        let mut off = self.open_file.offset.lock();
        let n = self.open_file.ops.write(&self.open_file, buf, *off)?;
        *off += n as u64;
        Ok(n)
    }
}
```

The existing `FileDescTable` is unchanged. `SerialBackend`-wired stdio
keeps working until userspace `open`s `/dev/console` over `devfs`.
`clone_for_fork` and `close_cloexec` are correct by inheritance — they
shallow-clone `Arc<FileDescription>`, which shallow-clones the
underlying `Arc<dyn FileBackend>`, which for `VfsBackend` shallow-clones
the `Arc<OpenFile>` — so both tasks share the same file offset, which
is POSIX-correct for `dup`/`fork`.

### Initialization order

VFS init slots in after `mem::init()` and before `task::init()`. The
`vibix::init()` sequence gains one line:

```
serial::init()
arch::init()
mem::init()
arch::init_apic(...)
time::init()
fs::vfs::init()                 // NEW: register fs drivers, mount "/", "/dev", "/tmp"
                                // (no interrupts yet; everything is synchronous)
[sti]
task::init()
```

`fs::vfs::init()` calls, in order: (1) register `tarfs`, `ramfs`,
`devfs` in `FS_REGISTRY`; (2) mount `tarfs` from the Limine ramdisk at
`/`; (3) mount `devfs` at `/dev` (after creating `/dev` if missing —
tarfs is readonly, so the initrd tar must contain an empty `/dev`
directory entry); (4) mount `ramfs` at `/tmp` (same caveat).

## Security Considerations

**Path-traversal and root-escape.** `..` from the root dentry resolves
to root itself (POSIX §4.13). Mount-crossing upward from an FS root
re-enters the parent FS at the mountpoint; the walker explicitly checks
`path.dentry == sb.root && path.dentry.mount.read().is_some()` before
delegating to the parent FS. No `chroot` yet (issue-tracked follow-up),
so `nd.root` is always `/`; when `chroot` lands, `..` at `chroot` root
must not escape, matching Linux.

**Userspace path copy.** `sys_open`/`sys_stat`/etc. copy the pathname
out of userspace with a bounded `copy_from_user_cstr(ptr, max:
PATH_MAX)` helper that validates the range is in a user VMA and returns
`ENAMETOOLONG` on overflow or `EFAULT` on a bad pointer. The helper
lives adjacent to the existing syscall ABI code (`arch/x86_64/
syscall.rs`). No path buffer is trusted past the copy.

**Symlink attacks.** `SYMLOOP_MAX = 40` hard bounds recursion. We
explicitly track per-walk depth, not per-process. `AT_SYMLINK_NOFOLLOW`
is honored for `fstatat`/`linkat`/`unlinkat`. For the future network
FS, `LOOKUP_NO_SYMLINKS`-equivalent flags are deferred — we refuse to
mount anything net-originated until then.

**TOCTOU on permission checks.** `permission()` runs during path walk
under the parent dentry's child-map read lock, and the resulting
`Arc<Inode>` is consumed before the lock is released. Because the
directory modification ops (`unlink`, `rename`) must take the parent
inode's `meta` write lock *and* hold it while modifying children, a
permission check on `foo` cannot race with an unlink of `foo` under the
same parent — the permission observer and the unlinker serialize on
the parent's `meta`.

**Information disclosure via errno.** We follow Linux's distinction:
return `ENOENT` for a missing component regardless of whether the
component didn't exist or whether the caller lacked search permission
on the parent. Lacking search permission on any intermediate directory
must return `EACCES`. This is the `may_lookup()` protocol — checked at
each component boundary, not only at the final. Lack of permission
at the *final* component, combined with the final being absent, favors
`EACCES` over `ENOENT` (matching Linux), to avoid leaking the presence
of entries in a directory the caller cannot search.

**Privilege model.** Credentials live on the task (`Credential { uid,
gid, groups }`); today all processes run as `uid=0, gid=0` because
userspace has no setuid path yet. `default_permission` nonetheless
implements the full POSIX mode-bit check (owner/group/other × r/w/x),
so the model is in place for when userspace gets non-zero uids (issue
#86).

**Setuid/setgid on `write`.** The POSIX requirement "on a write to a
regular file, clear S_ISUID and S_ISGID (if group-exec)" is implemented
in `generic_file_write` as a pre-return step on the inode meta. We take
the conservative form: clear both bits on any non-privileged write, to
match Linux.

**Sticky bit.** `S_ISVTX` on a directory restricts `unlink`/`rename` of
entries to the entry's owner, the directory's owner, or uid 0. Enforced
in the VFS layer before calling `InodeOps::unlink` / `InodeOps::
rename`, not in individual drivers — so all filesystems inherit the
check.

**Negative dentry caching is gated.** A negative dentry is only
inserted when `InodeOps::lookup` returns `ENOENT` *and* the caller had
search permission on the parent. If permission check fails, we do not
cache — preventing an unprivileged caller from poisoning the cache on
behalf of a privileged caller.

**Unmount and open files.** `unmount` without `MNT_FORCE` returns
`EBUSY` if `SuperBlock::has_open_files()` is true (the SB keeps a
counter of live `OpenFile`s). This prevents use-after-free on
FS-specific state; the `Arc<SuperBlock>` on the mount edge is dropped
only after all open files and dentries release their refs.

## Performance Considerations

**Path walk cost.** Every `open`/`stat`/`unlink` walks from root. With
a cold cache this is `O(depth × log(fanout))` for the `BTreeMap`
children. Hot paths (small working set) stay warm because dentries are
cached until their Inode's refcount drops. On a single CPU with no
concurrent lookups, we do **not** need RCU-walk. Projected cost for the
typical initrd layout (`/init`, `/bin/sh`, `/etc/passwd`, depth ≤ 3):
< 20 map lookups per open, each touching L1-resident map nodes.

**Lock contention.** All VFS locks are per-object except
`MOUNT_TABLE`. `MOUNT_TABLE` reads in every path walk could contend on
SMP. We plan for SMP explicitly: `MOUNT_TABLE` migrates to a seqlock on
the SMP RFC (see Alternatives); the single reader shape in single-CPU
today generates no measurable cost.

**Memory overhead.** Every cached dentry is ~128 bytes + name;
`Inode` is ~200 bytes + `Arc`/`RwLock` overhead. A 10k-file
initrd therefore costs ~3 MiB of dentry+inode cache. That's acceptable
against our ~32 MiB boot budget. An LRU cap on the dentry cache is
deferred to a follow-up RFC — today we cache indefinitely, relying on
`Arc` refcounts to reclaim on unmount.

**Directory iteration.** `getdents64` iterates the FS-specific
directory via `FileOps::getdents(f, buf, cookie)`. `cookie` is the
resume token between calls. For `tarfs` and `ramfs` (BTreeMap-backed),
the cookie is the last returned name — stable across modifications for
BTreeMap's sorted iteration. `tarfs` is read-only so modifications are
impossible; `ramfs` promises a "no entry inserted before cookie is
visible twice" guarantee — matching Linux's `d_off` semantics.

**Block I/O path** (future, not in this RFC): when a block-backed FS
eventually lands, reads go `FileOps::read → inode_ops read → (page
cache or) block::read(lba, buf)`. We do not add a page cache in this
RFC; regular-file reads from `tarfs` memcpy out of the ramdisk, and
`ramfs` reads memcpy out of the inode's inline buffer. A page cache is
a separate RFC that depends on `VmObject::File` from the VM layer
(RFC 0001 §Alternatives Considered).

## Alternatives Considered

**Redox-style schemes (`scheme:path`).** Gives URL-ish naming, first-class
per-process namespaces, and moves most FS logic to userspace daemons.
Rejected because: (a) musl and every POSIX program expect
`open("/path", ...)`, not `open("file:path", ...)` — we would need a
compatibility shim that is itself a VFS; (b) the kernel gains no actual
simplicity because we still need path resolution for the `file:`
scheme; (c) userspace FS servers require IPC and context switches on
the syscall hot path, which we cannot afford on a single-core,
no-mmu-optimized kernel. We adopt the classical vnode model instead;
we revisit when we have SMP, mmu optimizations, and a working IPC
layer.

**Linux-style RCU-walk.** Wins dramatically on multicore — ~10%
kernel-build speedup in the original RCU-walk merge. Rejected for v1
because: vibix is single-CPU today; RCU-walk requires inodes and
dentries to be RCU-freed (deferred free via `call_rcu`), which means
we need an RCU implementation we don't yet have; and the design
complexity (two-tier walker, seqlock revalidation, `-ECHILD` fallback)
is substantial. The op-vector shape we pick here does not foreclose
adding RCU-walk later — we would wrap the relevant `RwLock`s in
seqlocks and teach the walker to retry. Tracked as a P3 follow-up.

**SerenityOS Custody chain (one Custody per path-in-tree, refcounted,
parented).** Functionally equivalent to our dentry with `parent:
Weak<Dentry>`. The only difference is Serenity's Custody is immutable
after construction while our Dentry caches children; this is
intentional — we get the O(log n) lookup win at the cost of a
`RwLock<BTreeMap>`.

**Plan 9 per-process namespace.** Appealing (cheap sandboxing, uniform
naming) but requires a completely different syscall API (`bind` not
`mount`), and every POSIX assumption (global `/tmp`, global `/dev`)
would need a shim. Deferred to a future "namespaces" RFC if we ever
need it; not on the critical path.

**Single global flat `HashMap<PathBuf, Arc<Inode>>`** (OSDev "simple
path scanning"). Simple but breaks hard links (two names → one inode,
but the map keys are paths), breaks rename atomicity, and makes
mounts awkward. Rejected.

**Starting with ext2 instead of tarfs.** Ext2 requires a block cache,
inode bitmap/map/block-group traversal, and at minimum a read-only
implementation that is ~5× the tarfs code for zero functional gain at
bring-up. OSDev Wiki explicitly recommends *against* designing the VFS
against a real on-disk format first. Tarfs → ext2 is the right sequence.

**`BTreeMap<DString, Arc<Dentry>>` vs `HashMap`.** BTreeMap gives
deterministic iteration (correct for `getdents` without a secondary
sort), and our fanout (≤ a few hundred children for typical kernel
dirs, bounded by memory for `ramfs`) keeps log(n) competitive. HashMap
would need a secondary sort for `getdents` and makes negative-dentry
hash collisions a new invariant to track. BTreeMap wins on simplicity.

## Open Questions

1. **Do we want a page cache for regular-file reads in v1?** Argued no
   above; `tarfs` and `ramfs` memcpy directly. A page cache becomes
   load-bearing as soon as a block-backed FS exists. Deferred to the
   RFC that introduces ext2.
2. **Does `OpenFile::offset` need to survive `exec()`?** POSIX says
   yes (the open file description survives, only fds flagged
   `O_CLOEXEC` are closed). Our `close_cloexec` already does the right
   thing. Confirming here for the record.
3. **`st_ino` for `devfs` synthetic entries** — do we synthesize
   stable inode numbers (`hash(path)`), or allocate per-mount? The
   reference `devtmpfs` uses per-instance counters. We adopt that.
   Deferred to implementation issue.
4. **Symlink target storage size.** POSIX `readlink` on a link with
   `st_size > PATH_MAX` is allowed but rare. Our `tarfs` honors the
   archive-specified link name (bounded by USTAR's 100-byte field);
   `ramfs` allocates arbitrarily and reports `st_size` honestly.
5. **File locks (`flock`, `fcntl(F_SETLK)`).** Not needed for PID 1.
   Deferred to the POSIX-readiness track (#87).
6. **Negative dentry eviction.** We cache indefinitely today. Under
   memory pressure the cache needs bounds. Deferred to the same
   follow-up RFC as positive-dentry LRU.
7. **Per-process root and cwd.** Cwd must be per-task; this RFC
   assumes we add a `cwd: Arc<Dentry>` field to `Task` in the same
   change set that adds `sys_chdir` / `sys_getcwd`. Called out in the
   Implementation Roadmap.
8. **Mount source for `tarfs`.** Today we have a Limine ramdisk
   module. The `MountSource` enum will need a `RamdiskModule(*const
   u8, usize)` variant; this is uncontroversial but pinned here so
   reviewers see the shape.

## Implementation Roadmap

Ordered dependency-first. Each item is independently landable and
testable. Rough size estimates in parentheses.

- [ ] Add the core VFS types (`SuperBlock`, `Inode`, `Dentry`,
      `MountEdge`, `OpenFile`) and the four operation traits, with
      unit tests exercising refcount lifecycle and weak-ref safety
      under `Arc` drop. No FS drivers yet. (~600 LOC)
- [ ] Implement `path_walk` + `NameIdata` with host-side unit tests
      over a stubbed `InodeOps::lookup`. Cover absolute/relative,
      `.`/`..`, symlinks (stubbed), trailing slash, `SYMLOOP_MAX`,
      `ENOTDIR`, `ENAMETOOLONG`. (~400 LOC + tests)
- [ ] Add `MountTable` + mount/unmount helpers with host-side unit
      tests over stub filesystems. Cover nested mounts, upward
      crossing on `..`, `EBUSY` on in-use unmount. (~250 LOC)
- [ ] Implement `ramfs` (read-write, BTreeMap-backed) as the first
      real `FileSystem` consumer. Unit tests on host for
      create/unlink/rename/getdents. (~500 LOC)
- [ ] Implement `tarfs` (USTAR reader) over a fixed byte slice. Host
      unit tests mounting a small handcrafted USTAR archive. (~400
      LOC)
- [ ] Implement `devfs` with `/dev/null`, `/dev/zero`, `/dev/console`
      (wraps `SerialBackend`), `/dev/tty` (ditto). (~200 LOC)
- [ ] Wire `VfsBackend` into `FileDescTable` and teach
      `clone_for_fork` to preserve `Arc<OpenFile>` sharing. Add
      integration test on host. (~150 LOC)
- [ ] Add the VFS syscalls to the dispatcher: `open`, `openat`,
      `stat`, `fstat`, `lstat`, `fstatat`, `getdents64`, `mkdir`,
      `rmdir`, `unlink`, `rename`, `link`, `symlink`, `readlink`,
      `chdir`, `getcwd`, `lseek`. Each with a userspace-pointer
      copy-in/copy-out boundary. (~800 LOC)
- [ ] Add `cwd: Arc<Dentry>` to `Task`; teach `fork`/`exec` to
      inherit it. Wire `sys_chdir`/`sys_getcwd`. (~100 LOC)
- [ ] Wire `fs::vfs::init()` into `vibix::init()` after `mem::init()`.
      Mount `tarfs` at `/` from the Limine ramdisk module; mount
      `devfs` at `/dev`; mount `ramfs` at `/tmp`. (~100 LOC)
- [ ] Add a QEMU integration test: build a tiny USTAR archive
      containing `/hello` (a `Hello\n` byte), boot vibix with that
      archive as the ramdisk module, and have the kernel read
      `/hello` through the VFS and panic if the content doesn't
      match. (~100 LOC + test harness)
- [ ] Update `kernel/src/fs/mod.rs` docs and `docs/README.md` to
      reference the new `kernel/src/fs/vfs/` module. (docs-only)
