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
  host_custody }` inside a `VFSRootContext` (mount namespaces).
  Serenity's `symlink_recursion_limit = 8` is a historical reference;
  vibix uses `SYMLOOP_MAX = 40` to match Linux/POSIX minimum
  (addresses [Acad-B3]). See §Path resolution for the iterative
  resolver that enforces it.
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
    pub rename_mutex: BlockingMutex<()>, // s_vfs_rename_mutex — directory-rename
                                        // global tiebreaker (see §Rename)
    pub open_files: AtomicUsize,        // pins from live OpenFile; unmount barrier
    pub draining: AtomicBool,           // set by unmount; blocks new opens
}

pub struct Inode {
    pub ino: u64,
    pub sb: Weak<SuperBlock>,           // breaks SB -> Inode -> SB cycle
    pub ops: Arc<dyn InodeOps>,
    pub file_ops: Arc<dyn FileOps>,     // for regulars; dirs use dir_ops from ops
    pub dir_rwsem: BlockingRwLock<()>,  // i_rwsem analog: serializes directory
                                        // mutation *and* permission checks on
                                        // children. WRITE for mkdir/rmdir/
                                        // unlink/rename/create/symlink/link;
                                        // READ for lookup + permission during
                                        // path walk. Non-dirs never acquire.
    pub meta: BlockingRwLock<InodeMeta>,// mode/uid/gid/size/nlink/times/rdev/
                                        // blksize/blocks. Separate from
                                        // dir_rwsem so stat() does not
                                        // serialize with directory mutation.
    pub state: BlockingMutex<InodeState>, // dirty, unlinked flag, pin counts
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
    pub parent: Weak<Dentry>,           // root self-parent, installed via
                                        // Arc::new_cyclic in vfs::init
    pub inode: BlockingRwLock<Option<Arc<Inode>>>, // None == negative dentry
    pub mount: BlockingRwLock<Option<Arc<MountEdge>>>, // Some when THIS dentry is
                                        // a mountpoint. Mutated *only* while
                                        // holding MOUNT_TABLE.write() — see
                                        // §Mount and unmount.
    pub children: BlockingRwLock<BTreeMap<DString, ChildState>>,
                                        // ChildState = Loading | Negative |
                                        // Resolved(Arc<Dentry>).
                                        // Loading is used to deduplicate
                                        // concurrent lookups; see §Path
                                        // resolution for the protocol.
    pub flags: DFlags,                  // IS_ROOT, DISCONNECTED, ...
}

pub enum ChildState {
    Loading(Arc<Semaphore>),            // a walker is calling InodeOps::lookup;
                                        // others wait on the semaphore
    Negative,                           // lookup returned ENOENT (cached)
    Resolved(Arc<Dentry>),              // positive dentry
}

pub struct MountEdge {
    pub mountpoint: Weak<Dentry>,       // dentry in the PARENT fs
    pub super_block: Arc<SuperBlock>,   // mounted FS instance
    pub root_dentry: Arc<Dentry>,       // root of the mounted FS
    pub flags: MountFlags,
}

pub struct OpenFile {
    pub dentry: Arc<Dentry>,            // dentry at time of open. Unlink of the
                                        // underlying inode does NOT invalidate
                                        // this dentry — we observe the POSIX
                                        // "unlinked but open" state via
                                        // inode.state.unlinked.
    pub inode:  Arc<Inode>,             // inode resolved at open() time;
                                        // stable for the lifetime of OpenFile
                                        // (may be != *dentry.inode.read() post-
                                        // unlink/rename — the INODE is the
                                        // authoritative reference for I/O).
    pub offset: BlockingMutex<u64>,     // for read/write/lseek
    pub flags:  u32,                    // O_*, preserved from open()
    pub ops:    Arc<dyn FileOps>,       // copied out of inode at open() time
    pub sb:     Arc<SuperBlock>,        // strong ref: keeps the SB alive for
                                        // the duration of the open. This is
                                        // the anchor that closes OS-B6 — no
                                        // Inode can outlive its SuperBlock
                                        // while any OpenFile holds it.
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

The algorithm, in order. Note — this resolver is **iterative**, never
recursive: symlinks expand their targets into a pushed-down remaining-
path buffer and the outer for-loop resumes (Academic-B3, OS-A4).
`symlink_total` is a single counter over the entire resolution, not a
recursion depth, matching Linux `SYMLOOP_MAX` and POSIX §4.13 exactly.

1. If the path is empty and `AT_EMPTY_PATH` is set, the fd's dentry is
   the result. Otherwise return `ENOENT`.
2. If the path starts with `/`, seed `nd.path = nd.root`; else seed
   from `nd.cwd` (or the fd's dentry for `*at` when the supplied fd
   is not `AT_FDCWD`; absolute paths ignore a non-`AT_FDCWD` fd, per
   Linux ABI).
3. For each `/`-separated component `c`:
   - If `c` is empty (leading, trailing, or repeated `/`), skip —
     except that a trailing `/` sets `LookupFlags::DIRECTORY` on the
     final component.
   - If `c == "."`, continue.
   - If `c == ".."`, move to `path.parent` *after* crossing any mount
     edge we're currently sitting on (upward crossing: if
     `path.dentry == sb.root`, jump to `mount.mountpoint` in the parent
     FS; root's parent is root itself).
   - Else: acquire `path.inode.dir_rwsem.read()` (held through step
     3d and the permission check in step 4, released when the walker
     advances past this parent):
     a. Read `path.dentry.children`. If the entry is
        `ChildState::Resolved(d)` with `d.inode.read().is_some()`,
        advance. If `ChildState::Negative`, return `ENOENT`.
     b. If the entry is `ChildState::Loading(sem)`, release the
        `children` read lock, wait on the semaphore, then retry (3a).
     c. If no entry: acquire `children.write()`, re-check (another
        walker may have won the race), else insert
        `ChildState::Loading(Arc::new(Semaphore::new(0)))` and
        release the write lock. We are now the sole resolver for
        this `(parent, name)`.
     d. Call `InodeOps::lookup(parent_inode, c)`. On `Ok(inode)`,
        build the `Arc<Dentry>`; on `Err(ENOENT)`, prepare a
        `Negative`; on any other error, propagate (see below for
        cleanup).
     e. Acquire `children.write()`, replace `Loading` with
        `Resolved(dentry)` or `Negative`. Signal the semaphore so
        waiters wake. Release. (If `InodeOps::lookup` returned any
        error other than `ENOENT`, remove the `Loading` entry
        entirely — do **not** cache — and signal the semaphore so
        waiters re-resolve.)
   - After resolving, perform the permission check with
     `InodeOps::permission(parent_inode, cred, X_OK)` — MAY_EXEC on
     the *parent* directory. This is the search-permission check
     required by POSIX §4.13 and runs *under* `dir_rwsem.read()`
     (see §Locking discipline for why that serializes with unlinkers)
     [Sec-B2, Acad-B2]. If the parent is non-searchable, return
     `EACCES` regardless of whether the child exists
     (matches Linux `may_lookup`; prevents directory enumeration via
     errno timing) [Sec-A5].
   - If the child dentry is a mountpoint (has `Some(edge)` in
     `path.dentry.mount`), jump down: clone `edge.root_dentry` into
     the cursor. The `Arc<MountEdge>` is retained in `nd` so the
     mount cannot be uninstalled under us [OS-A3].
   - If the resolved inode is a symlink and this is not the final
     component *or* `LookupFlags::FOLLOW` is set: increment
     `symlink_total` (return `ELOOP` on > 40 = `SYMLOOP_MAX`); if
     `LookupFlags::NOFOLLOW` is also set on the final component,
     return `ELOOP` regardless of count (POSIX `open(O_NOFOLLOW)`
     behavior); read the link via `InodeOps::readlink` into a
     kernel-side `[u8; PATH_MAX]` staging buffer; push the remaining
     path onto a `SmallVec<[Component; 16]>` stack *after* the link
     target's components; if the target is absolute, reseat the
     walker at `nd.root` and continue from the expanded stack.
4. After the final component: if `LookupFlags::DIRECTORY` and the
   resolved inode is not `S_IFDIR`, return `ENOTDIR`. If there was a
   trailing `/` and the resolved inode is a non-directory, return
   `ENOTDIR` (POSIX §4.13).

Dentry children use a `BTreeMap<DString, ChildState>` — log(n)
lookup, deterministic iteration order for directory reads, and the
`ChildState::Loading` placeholder gives us Linux's `d_alloc_parallel`
effect without Linux's hashed-parallel-lookup machinery. This closes
the lookup-dedup race [OS-B1].

The walk is **not** RCU-lock-free. `dir_rwsem.read()` is held across
the `InodeOps::lookup` call; for local filesystems this is
memory-only and non-blocking; for future I/O-backed filesystems the
lock is held across a blocking read (which is acceptable on a
non-preemptive kernel and revisited when RCU-walk lands — see
Alternatives).

**Symlink recursion limit** — the Background reference to
SerenityOS's `symlink_recursion_limit = 8` was a historical note, not
a normative choice. The normative limit is `SYMLOOP_MAX = 40`
(matching Linux; POSIX §4.13 minimum is 8). This resolves the
Background/Design inconsistency [Acad-B3].

#### Mount and unmount

Install and uninstall both hold `MOUNT_TABLE.write()` across *both*
mutations (mount-table vector *and* `Dentry.mount` slot). This closes
the torn-view race [OS-B4, Sec-B6]. Unmount also sets the `draining`
flag before checking `open_files`, closing the TOCTOU [OS-B5]. All
`Weak::upgrade().unwrap()` panics are replaced with error paths; the
walker's retained `Arc<MountEdge>` (§Path resolution) guarantees the
mountpoint dentry is still upgradeable during the install/uninstall
windows that matter.

```
mount(source: MountSource, target_path: &str, fs_type: &str,
      flags: MountFlags) -> Result<(), i64>:
    let fs = FS_REGISTRY.get(fs_type).ok_or(ENODEV)?;
    let sb = fs.mount(source, flags)?;               // FS-specific
    let target_nd = path_walk(target_path, LF::DIRECTORY)?;
    if target_nd.inode.kind != InodeKind::Dir { return Err(ENOTDIR); }

    let edge = Arc::new(MountEdge {
        mountpoint:  Arc::downgrade(&target_nd.dentry),
        super_block: sb.clone(),
        root_dentry: sb.root.get().unwrap().primary_dentry(),
        flags,
    });

    // Single critical section: both mutations under MOUNT_TABLE.write().
    let mut mt = MOUNT_TABLE.write();
    let mut slot = target_nd.dentry.mount.write();
    if slot.is_some() { return Err(EBUSY); } // mountpoint already in use
    *slot = Some(edge.clone());
    mt.push(edge);
    Ok(())

unmount(target_path: &str, flags: MountFlags) -> Result<(), i64>:
    let target_nd = path_walk(target_path, LF::NOAUTO_MOUNT_CROSS)?;

    // All state changes below happen under MOUNT_TABLE.write() to make
    // install/uninstall and the open-file check a single atomic bracket.
    let mut mt = MOUNT_TABLE.write();

    let edge = mt.iter()
        .find(|e| Arc::ptr_eq(&e.root_dentry, &target_nd.dentry))
        .cloned().ok_or(EINVAL)?;

    // 1) Set draining: any sys_open after this point sees sb.draining
    //    and returns ENOENT/EIO; see sys_open below.
    edge.super_block.draining.store(true, Ordering::SeqCst);

    // 2) Now it is safe to count open files and decide.
    if !flags.contains(MNT_FORCE)
        && edge.super_block.open_files.load(Ordering::SeqCst) > 0
    {
        // Revert the drain flag — abort cleanly.
        edge.super_block.draining.store(false, Ordering::SeqCst);
        return Err(EBUSY);
    }

    // 3) Drain any pending Inode drops queued by the GC path so
    //    SuperOps::unmount sees a quiescent SB.
    vfs::gc_drain_for(&edge.super_block);

    edge.super_block.ops.unmount()?;

    // 4) Both mutations still under MOUNT_TABLE.write() — atomic
    //    from any concurrent path_walk's perspective.
    let mp = edge.mountpoint.upgrade().ok_or(ESTALE)?;
    *mp.mount.write() = None;
    mt.retain(|e| !Arc::ptr_eq(e, &edge));
    Ok(())
```

`MOUNT_TABLE` is a single global `BlockingRwLock<Vec<Arc<MountEdge>>>`.
For the ≤ 8 mounts we expect (`/`, `/dev`, `/proc`, `/tmp`, `/sys`),
linear scan is correct and easy to reason about. We will revisit when
an RFC adds bind mounts or mount namespaces. On the single-CPU, non-
preemptive kernel vibix runs today, the `MOUNT_TABLE.read()` critical
section in path walk cannot contend with anything (only syscall-context
readers, run-to-completion); we'll add the non-preemptive assumption as
a note in §Performance Considerations [Acad-A4].

#### Inode lifecycle

Inodes are refcounted via `Arc<Inode>`. The superblock keeps a weak
table (`RwLock<BTreeMap<u64, Weak<Inode>>>`) so repeated lookups of the
same `ino` return the same object — this is the invariant `st_ino +
st_dev uniquely identifies a file` depends on.

Pinning sources, in order of lifetime:

- **SB → root Inode:** `SuperBlock::root` holds a strong
  `Arc<Inode>`. `Inode.sb` is `Weak<SuperBlock>` — the cycle is
  broken on the inode side.
- **MountEdge → SB:** every live `MountEdge` holds
  `Arc<SuperBlock>`. So long as any mount edge references the SB,
  it is alive.
- **OpenFile → SB + Inode:** `OpenFile` holds a strong
  `Arc<SuperBlock>` *and* `Arc<Inode>`. This is the anchor that
  closes [OS-B6]: every open fd directly pins its SB, so the SB
  outlives every Inode it owns — `Inode.sb.upgrade()` inside an
  `evict_inode` call always succeeds.
- **Dentry → Inode:** `ChildState::Resolved(dentry)` with
  `dentry.inode = Some(Arc<Inode>)`. A negative dentry holds no
  Inode.

**Invariant (stated for future contributors, formalizes [Acad-A2]):**
an Inode with `nlink == 0` is retained iff `open_files_on_inode > 0`;
when both reach zero, the Inode is GC-eligible. GC happens via the
deferred `vfs::gc_queue` (see §Locking discipline) — `Inode::Drop`
enqueues; the drain path calls `SuperOps::evict_inode` with no VFS
locks held. This closes [OS-B3].

**Unlink semantics** (POSIX): `InodeOps::unlink(dir, name)` removes
the directory-entry mapping and decrements `nlink`. It does **not**
drop the inode. If `nlink == 0` and there are live `OpenFile`s, the
inode enters the *unlinked-but-open* state (`InodeState::unlinked =
true`); when the last `OpenFile` drops, the inode becomes GC-
eligible. This is the POSIX contract that Theseus chose not to
implement; we follow POSIX.

**Cross-FS boundaries:** `link` and `rename` check
`src_inode.sb.fs_id == dst_inode.sb.fs_id`; if not, return `EXDEV`.

**Self-parenting root.** `Dentry::parent: Weak<Dentry>` of the root
dentry points back at the root itself. The root is constructed via
`Arc::new_cyclic`, not `Weak::new()`, so `parent.upgrade()` returns
`Some(root)` (matters for the `..` step in §Path resolution) [OS-A4].

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

**`mode` arg width.** Mode arguments at the syscall boundary are
declared `u32` (`umode_t`); only the low 16 bits are meaningful. This
matches how `%rdx` is populated by glibc/musl (zero-extended from
`unsigned int`) and avoids the truncation ambiguity flagged in
[US-A1].

**`struct Stat`** is a byte-for-byte match of the Linux x86_64
`struct stat` (the ABI every musl program compiled against Linux
expects). Layout, with explicit offsets and the mandatory trailing
`__unused[3]` (addresses [US-B1]):

```rust
#[repr(C)]
pub struct Stat {
    pub st_dev:     u64,   // 0x00
    pub st_ino:     u64,   // 0x08
    pub st_nlink:   u64,   // 0x10
    pub st_mode:    u32,   // 0x18
    pub st_uid:     u32,   // 0x1c
    pub st_gid:     u32,   // 0x20
    pub __pad0:     u32,   // 0x24
    pub st_rdev:    u64,   // 0x28
    pub st_size:    i64,   // 0x30
    pub st_blksize: i64,   // 0x38
    pub st_blocks:  i64,   // 0x40
    pub st_atime:   i64,   // 0x48
    pub st_atime_nsec: i64,// 0x50
    pub st_mtime:   i64,   // 0x58
    pub st_mtime_nsec: i64,// 0x60
    pub st_ctime:   i64,   // 0x68
    pub st_ctime_nsec: i64,// 0x70
    pub __unused:   [i64; 3], // 0x78..0x90  (REQUIRED for Linux ABI)
}
// size_of::<Stat>() == 0x90 == 144 ; alignment 8.
// Host test (required): static_assert equivalent via const eval
// plus a cross-checked offset table matching linux-uapi struct stat.
```

`Stat` is **always zero-initialized** before any driver's
`InodeOps::getattr` runs (`let mut out = Stat::default();`) and is
copied out to userspace as a single `copy_to_user(ptr, &out,
size_of::<Stat>())` call — closing the uninitialized-padding kernel-
infoleak [Sec-B4]. Same rule applies to `linux_dirent64` records.

`st_dev` = `SuperBlock::fs_id`; `st_ino` = `Inode::ino`; `st_mode`
packs `InodeKind` into `S_IFMT` and `InodeMeta::mode` into the low 12.

**`struct linux_dirent64`** (the `getdents64` wire format):
`{ u64 d_ino; i64 d_off; u16 d_reclen; u8 d_type; char d_name[]; }` —
`d_type` uses Linux `DT_*` (`DT_REG=8, DT_DIR=4, DT_LNK=10, DT_CHR=2,
DT_BLK=6, DT_FIFO=1, DT_SOCK=12, DT_UNKNOWN=0`). `d_reclen` is
padded up to a multiple of 8 bytes so the next record begins on an
8-byte boundary (musl's `readdir64` casts to `struct dirent*` and
depends on this) [US-A5]. Bytes between `d_name\0` and the end of
the record are zero-filled [Sec-B4].

**`O_*` flags** (Linux x86_64 numeric values — addresses [US-B2]):

| Flag          | Value    | Handled as |
|---------------|----------|------------|
| `O_RDONLY`    | `0o0`    | accept mask bit; low 2 bits = access mode |
| `O_WRONLY`    | `0o1`    | accept |
| `O_RDWR`      | `0o2`    | accept |
| `O_ACCMODE`   | `0o3`    | mask for extracting the three above |
| `O_CREAT`     | `0o100`  | may create if absent; requires write perm on parent |
| `O_EXCL`      | `0o200`  | with `O_CREAT`: `EEXIST` if present |
| `O_TRUNC`     | `0o1000` | truncate regular files; `EISDIR` on dirs |
| `O_APPEND`    | `0o2000` | write appends at `size` atomically |
| `O_NONBLOCK`  | `0o4000` | accepted; only meaningful for fifos/sockets/dev |
| `O_DIRECTORY` | `0o200000` | require `S_IFDIR`; else `ENOTDIR` |
| `O_NOFOLLOW`  | `0o400000` | final-component symlink → `ELOOP` |
| `O_CLOEXEC`   | `0o2000000` | stored on the fd slot (see [US-A2] follow-up) |
| `O_PATH`      | `0o10000000` | accepted; no I/O, stat-only fd |
| `O_TMPFILE`   | `0o20200000` | `EINVAL` for now (explicit reject) |

**Required `open`/`openat` error paths** (pin in the VFS layer; all
drivers inherit — addresses [US-B3]):

- `O_TRUNC` on a directory → `EISDIR` (POSIX XSH `open`).
- `O_DIRECTORY` with a non-directory target → `ENOTDIR`.
- `O_CREAT|O_EXCL` with an existing path → `EEXIST`.
- Write-mode flags (`O_WRONLY`/`O_RDWR`/`O_TRUNC`) on a SB with
  `SbFlags::RDONLY` → `EROFS`.
- `O_NOFOLLOW` with a terminal symlink → `ELOOP`.
- `O_TRUNC` requires write permission on the file (`MAY_WRITE`),
  independent of the access mode; failure → `EACCES`.
- `open` on a non-existent final component without `O_CREAT` →
  `ENOENT`.

**`rename` VFS-layer preconditions** (before any `InodeOps::rename`
call — addresses [US-B4], [OS-A5]):

- `old_name` or `new_name` equal to `.` or `..` → `EINVAL`.
- `src_sb.fs_id != dst_sb.fs_id` → `EXDEV`.
- Source inode is an ancestor of destination parent (directory cycle)
  → `EINVAL`.
- `S_ISVTX` on source parent and caller neither owns the entry nor
  owns the directory → `EACCES`.

**`readlink` contract** (addresses [US-B5]): `EINVAL` if the target
inode is not `S_IFLNK`. On success, returns `min(target_len, bufsiz)`
bytes, **not** NUL-terminated (matches Linux/POSIX; musl depends on
this). If `target_len > bufsiz`, the output is silently truncated and
the return value is `bufsiz`.

**`*at` family and `AT_EMPTY_PATH`** (addresses [US-B6]):

| Syscall | Accepted `AT_*` flags | Required behavior |
|---|---|---|
| `openat`   | (none)                    | `dfd==AT_FDCWD`: identical to `open`. Absolute `path`: ignore `dfd`. Non-dir `dfd`: `ENOTDIR`. |
| `fstatat`  | `AT_SYMLINK_NOFOLLOW`, `AT_EMPTY_PATH` | `AT_EMPTY_PATH` + `""`: stat the file behind `dfd` (musl's `fstat` path). |
| `linkat`   | `AT_SYMLINK_FOLLOW`, `AT_EMPTY_PATH`   | follow vs not follow source symlink; empty-path → hard-link the file behind the fd. |
| `unlinkat` | `AT_REMOVEDIR`                         | `AT_REMOVEDIR` makes this act as `rmdir`. |
| `symlinkat`| (none)                                 | `dfd` resolves the dir for `linkpath` only. |
| `readlinkat`| `AT_EMPTY_PATH`                       | empty-path: readlink the symlink behind `dfd`. |

Other `AT_*` bits → `EINVAL`.

**`lseek` whence** (addresses [US-A4]): `SEEK_SET=0`, `SEEK_CUR=1`,
`SEEK_END=2`, `SEEK_DATA=3`, `SEEK_HOLE=4`. `lseek` on a non-seekable
fd → `ESPIPE`.

**`AT_FDCWD` = -100**, **`AT_SYMLINK_NOFOLLOW` = 0x100**,
**`AT_REMOVEDIR` = 0x200**, **`AT_SYMLINK_FOLLOW` = 0x400**,
**`AT_EMPTY_PATH` = 0x1000** — numeric values copied from Linux.

**Limits (matching Linux):** `PATH_MAX = 4096`, `NAME_MAX = 255`,
`SYMLOOP_MAX = 40`, `OPEN_MAX = 1024` (already set by `FileDescTable`).

**Errno mapping** extends the existing `ENOENT/EBADF/ENOMEM/EAGAIN/
EINVAL/EMFILE/ENAMETOOLONG` set in `kernel/src/fs/mod.rs` with:
`ENOTDIR = -20`, `EISDIR = -21`, `EXDEV = -18`, `ENOSPC = -28`,
`EROFS = -30`, `EACCES = -13`, `EPERM = -1`, `EEXIST = -17`,
`ELOOP = -40`, `ENOTEMPTY = -39`, `ENODEV = -19`, `EBUSY = -16`,
`ENOTTY = -25`, `ESPIPE = -29`, `ERANGE = -34`, `ESTALE = -116`
[US-A4, US-A6].

### Locking discipline

This section was rewritten in defense cycle 1 to address OS-B1/B2/B3/
B4/B5/B6, Security-B2/B6, and Academic-B1/B2. The one-sentence
invariant is:

> **A directory's `dir_rwsem` covers all operations that affect its
> name→child binding: `lookup`, `permission` on entries, and every
> mutator. Nothing else covers that binding.**

The lock inventory, in acquisition order (outer first):

1. **`SuperBlock.rename_mutex`** (`BlockingMutex<()>`) — the
   `s_vfs_rename_mutex` analog. Taken *only* by `rename()` on the
   source superblock (and, if different, the destination's), before
   any directory `dir_rwsem`. Per-SB scope is enough because
   `rename` across filesystems returns `EXDEV`. This single lock
   prevents the ancestor-forming concurrent-rename deadlock cited by
   the Academic reviewer [B1] and is the same tiebreaker Linux uses
   (`fs/namei.c::lock_rename`, Documentation/filesystems/directory-
   locking).
2. **Directory `Inode.dir_rwsem`** (`BlockingRwLock<()>`) — one per
   directory inode.
   - **Read** acquired during path walk: held from entering the
     `children` lookup through the `InodeOps::lookup` call through
     the permission check on the resolved entry, until the walker
     advances past that parent. This is what closes the permission
     TOCTOU [Sec-B2, Acad-B2]: `permission()` is observed under the
     *same* lock that `unlink`/`rename` take for write.
   - **Write** acquired by every directory mutator: `mkdir`, `rmdir`,
     `unlink`, `rename`, `create`, `symlink`, `link`. Held across the
     `InodeOps` call and across the `children`-map update.
   - For `rename` across two parents, both `dir_rwsem`s are taken in
     (fs_id, ino)-lex order *after* the per-SB rename_mutex has been
     acquired (see §Rename for the full ancestor-first walk).
3. **`Dentry.children`** (`BlockingRwLock<BTreeMap<DString,
   ChildState>>`) — protects the in-memory cache only. Always taken
   under the parent's `dir_rwsem`. Held briefly (map insert/remove/
   get); never across `InodeOps` calls. See §Path resolution for
   the `Loading`-placeholder dedup protocol that closes [OS-B1].
4. **`SuperBlock.inode_table`** (`BlockingRwLock<BTreeMap<u64,
   Weak<Inode>>>`) — held only for lookup-or-insert inside
   `SuperOps::inode` helpers; never across `InodeOps` calls.
5. **`Inode.meta`** (`BlockingRwLock<InodeMeta>`) — attribute read/
   write. May be acquired while holding a `dir_rwsem`; never the
   reverse. `stat()` does not take `dir_rwsem`.
6. **`Inode.state`** (`BlockingMutex<InodeState>`) — nlink, unlinked
   flag, dirty flag. Short, non-nested critical sections.
7. **`MOUNT_TABLE`** (`BlockingRwLock<Vec<Arc<MountEdge>>>`) — see
   §Mount and unmount for the atomic install/uninstall protocol.
   During path walk, the walker clones `Arc<MountEdge>` out of the
   table and releases the global lock before descending; the Arc
   pins the mount across the `InodeOps::lookup` call [OS-A3].

**What is forbidden.** A thread holding `dir_rwsem` must not acquire
another `dir_rwsem` unless it first took `rename_mutex` (so only
`rename` nests). A thread holding `children` must not call into
`InodeOps`. A thread holding `meta` must not acquire `dir_rwsem`. A
thread holding `state` must not acquire any other VFS lock. Mount
install/uninstall are the only places `MOUNT_TABLE` nests with
`Dentry.mount` — they are always paired under `MOUNT_TABLE.write()`.

**Deferred eviction.** To close [OS-B3] (reentrancy under `Drop`),
the last-ref drop of an `Arc<Inode>` does **not** call
`SuperOps::evict_inode` inline. Instead, `Inode::Drop` pushes the
(`fs_id`, `ino`) pair onto a per-CPU `vfs::gc_queue` (bounded ring +
spinlock) and sets a flag on the current task that, on the next
return-to-userspace or at `task::schedule()`, the kernel drains the
queue by calling `evict_inode` on each with *no* VFS locks held. This
makes `evict_inode` free to call back into the VFS (`free on-disk
blocks`, `update parent dir`) without the reentrancy landmine. For
synchronous eviction (`unmount`), the SB's `draining` flag is set
first and the unmount path explicitly drains `gc_queue` before
returning.

**No ISR callers.** All VFS locks are the blocking variants
(`BlockingMutex`, `BlockingRwLock`) from `kernel/src/sync/mutex.rs`.
VFS code runs only in syscall context or in the drain path of
`task::schedule()`. When the block layer grows an interrupt-driven
completion (out of scope for this RFC), the completion must enqueue
into a softirq-style deferred worker and the VFS call must land from
that worker, not from the ISR. Added as an advisory constraint in
§Performance Considerations [OS-A8].

**Primitive names.** `BlockingRwLock` is the tree's existing blocking
reader-writer lock (`kernel/src/sync/rwlock.rs`); `BlockingMutex` is
`kernel/src/sync/mutex.rs::BlockingMutex`. These replace the
earlier-draft `RwLock`/`Mutex` names that did not match the tree
[OS-A2]. None of them disables interrupts.

#### Rename — full protocol

Addresses OS-B2 and Academic-B1. `rename(old_dir, old_name, new_dir,
new_name)`:

1. If `old_dir.sb.fs_id != new_dir.sb.fs_id`, return `EXDEV`.
2. Reject `old_name` or `new_name` that is `.` or `..`
   (`EINVAL`, POSIX §4.13).
3. `rename_mutex = old_dir.sb.rename_mutex.lock()`. One
   per-superblock mutex; no ordering needed.
4. If `old_dir_ino == new_dir_ino`, acquire `dir_rwsem.write()` once.
   Otherwise walk the ancestry chain of `new_dir` upward through
   `Dentry.parent`. If any ancestor's inode is `old_inode` (the
   inode being renamed, not the parent), return `EINVAL` (POSIX
   directory-cycle prohibition). Then take the two parents'
   `dir_rwsem.write()` in (fs_id, ino)-lex order.
5. Perform the sibling checks (`EEXIST`/`ENOTEMPTY`/sticky bit under
   §Security). Call `InodeOps::rename`. Update both `children` maps
   (removing the negative-dentry at `new_dir/new_name` if present,
   inserting the moved `Arc<Dentry>`, removing from
   `old_dir/old_name`). All of this under the two `dir_rwsem.write()`s.
6. Release both `dir_rwsem`s, then `rename_mutex`.

The per-superblock `rename_mutex` is what makes the ancestry walk in
step 4 safe: no other rename on this SB can mutate the tree's
shape concurrently, so the ancestor walk cannot be invalidated
mid-walk.

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

`open(path, flags, mode)` steps. All `unwrap()`s in the Draft-cycle
pseudocode were user-triggerable panics [Sec-B3]; they are replaced
with explicit error returns. `check_open_permission` is pinned below.

```rust
fn sys_open(path: &CStr, flags: u32, mode: u32) -> Result<i32, i64> {
    // 1. Path walk with the right LookupFlags derived from O_*.
    let lf = lookup_flags_from_open(flags)?;
    let mut nd = NameIdata::from_current(path, lf)?;

    // 2. Handle O_CREAT|O_EXCL atomically.
    if flags & O_CREAT != 0 {
        path_walk_parent(&mut nd)?;                 // stop at parent
        // Under parent's dir_rwsem.write() (via sys_open's caller):
        let _g = nd.parent.inode.dir_rwsem.write();
        match InodeOps_lookup(&nd.parent, &nd.last_name) {
            Ok(_) if flags & O_EXCL != 0 => return Err(EEXIST),
            Ok(inode) => nd.set_final(inode),
            Err(ENOENT) => {
                check_permission(&nd.parent, nd.cred, W_OK | X_OK)?;
                check_sb_writable(&nd.parent)?;     // SbFlags::RDONLY -> EROFS
                let inode = InodeOps_create(&nd.parent, &nd.last_name,
                                            mode_low16(mode))?;
                nd.set_final(inode);
            }
            Err(e) => return Err(e),
        }
    } else {
        path_walk(&mut nd)?;
    }

    let inode = nd.final_inode().ok_or(ENOENT)?;    // no unwrap
    let sb = inode.sb.upgrade().ok_or(ESTALE)?;      // no unwrap

    // 3. SB barriers (§Security: NOSUID/NOEXEC/NODEV are enforced here
    //    and at mmap/exec; draining blocks opens on an unmounting SB).
    if sb.draining.load(Ordering::SeqCst) { return Err(ENOENT); }
    check_sb_mount_flags(&sb, flags, &inode)?;       // Sec-B1

    // 4. O_* preconditions (US-B3):
    if flags & O_TRUNC != 0 {
        if inode.kind == InodeKind::Dir { return Err(EISDIR); }
        if sb.flags.contains(SbFlags::RDONLY) { return Err(EROFS); }
        check_permission(&inode, nd.cred, W_OK)?;
    }
    if flags & O_DIRECTORY != 0 && inode.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    if flags & O_NOFOLLOW != 0 && inode.kind == InodeKind::Link {
        return Err(ELOOP);
    }
    check_open_permission(&inode, nd.cred, access_mode(flags))?;

    // 5. Truncate now that permission is validated.
    if flags & O_TRUNC != 0 && inode.kind == InodeKind::Reg {
        inode.ops.setattr(&inode, &SetAttr {
            size: Some(0), ..Default::default()
        })?;
    }

    // 6. Build the OpenFile. Pinning the SB here is what makes
    //    OS-B6 safe: the Inode can never outlive its SB.
    sb.open_files.fetch_add(1, Ordering::SeqCst);
    let of = Arc::new(OpenFile {
        dentry:  nd.dentry.clone(),
        inode:   inode.clone(),
        offset:  BlockingMutex::new(0),
        flags,
        ops:     inode.file_ops.clone(),
        sb:      sb.clone(),
    });
    // OpenFile::Drop decrements sb.open_files.

    let backend: Arc<dyn FileBackend> = Arc::new(VfsBackend { open_file: of });
    let fd_table = current_task().fd_table();
    fd_table.alloc_fd(Arc::new(FileDescription { backend, flags }))
}
```

where `check_open_permission(inode, cred, access)` returns:
- `EISDIR` if `access & W_OK != 0` and `inode.kind == Dir`;
- `EACCES` if `InodeOps::permission` returns denial;
- `EROFS` if the SB is read-only and the open is write-mode.

`check_sb_mount_flags(sb, flags, inode)` enforces NOSUID/NOEXEC/NODEV
(Sec-B1): NOSUID clears `S_ISUID`/`S_ISGID` bits in the returned
stat metadata and at exec time; NOEXEC is checked at `mmap(PROT_EXEC)`
and at exec of a file from this SB; NODEV returns `EPERM` on open of
`S_IFCHR`/`S_IFBLK` inodes through a NODEV mount.

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
`/` with flags `RDONLY`; (3) mount `devfs` at `/dev` with flags
`NOSUID|NOEXEC`; (4) mount `ramfs` at `/tmp` with flags
`NOSUID|NODEV`. The initrd tar **must** contain empty `/dev` and
`/tmp` directory entries; `fs::vfs::init()` panics with a diagnostic
if either is missing rather than silently skipping the overlay
[Sec-A6]. `cargo xtask initrd` will be extended to emit those stubs.

`fs::vfs::init()` runs **before** `sti`, and all three mount
operations are synchronous (memcpy-only, no I/O). This is safe today
because every mount source is memory-resident. A future
`FileSystem::mount` impl that blocks on I/O cannot run pre-`sti` —
we mark that contract on the `FileSystem::mount` trait doc (addresses
[OS-A7]).

## Security Considerations

**Mount flags are enforced** (addresses [Sec-B1]). `SbFlags` is not
documentation — each bit has a concrete enforcement site:

- `NOSUID` — `check_sb_mount_flags` in `sys_open` masks out
  `S_ISUID`/`S_ISGID` from the returned `stat.st_mode`. More
  importantly, `execve` refuses to honor setuid/setgid bits on any
  file whose SB carries `NOSUID` (enforced in the exec path when
  that lands; called out here so the exec implementer cannot miss
  it). Implication: `ramfs` at `/tmp` is mounted `NOSUID` in the
  default init (see §Initialization order below, updated).
- `NOEXEC` — refuses `mmap(PROT_EXEC)` backed by a file on this SB
  and refuses `execve` of such a file. Also checked in `sys_open`
  if `O_PATH` is *not* set and any exec-relevant VM follow-up is
  intended.
- `NODEV` — refuses `open` of `S_IFCHR`/`S_IFBLK` inodes through a
  NODEV mount (`EPERM`).
- `RDONLY` — already plumbed in the `EROFS` cases in §ABI.

`NOSUID` on `/tmp` (ramfs) is the default so a future non-root
user cannot drop a setuid binary there. Mount flags are adjustable
per-mount by the (future) root-only `mount(2)` syscall.

**Path-traversal and root-escape.** `..` from the root dentry resolves
to root itself (POSIX §4.13). Mount-crossing upward from an FS root
re-enters the parent FS at the mountpoint; the walker explicitly checks
`path.dentry == sb.root && path.dentry.mount.read().is_some()` before
delegating to the parent FS. No `chroot` yet; when it lands, `..` at
`chroot` root must not escape.

**Userspace path copy.** `sys_open`/`sys_stat`/etc. copy the pathname
out of userspace with a fault-tolerant `copy_from_user_cstr(ptr, max:
PATH_MAX)` helper that sets SMAP/STAC for the duration of the copy
(AMD64 SMAP convention) and catches page faults per byte via the
existing `#PF` resolver's "kernel touched user memory" path. The copy
returns `ENAMETOOLONG` on overflow or `EFAULT` on a bad pointer. The
result is placed in a kernel-heap buffer and all downstream path
processing uses that kernel copy only [Sec-A2]. The helper lives
adjacent to the existing syscall ABI code (`arch/x86_64/syscall.rs`).

**Output-buffer zero-init** (addresses [Sec-B4]). Every kernel→user
output struct — `Stat`, `linux_dirent64`, `statfs`, `StatVfs` — is
zero-initialized in a stack-local before being handed to a driver
`getattr`/`statfs`/`getdents` callback, and the copy-out is a single
`copy_to_user` of the exact `size_of::<T>()` (for fixed-size output)
or of the filled `d_reclen` (for dirents, with trailing bytes up to
the 8-byte boundary also explicitly zeroed). Drivers are **not**
trusted to zero padding.

**O_NOFOLLOW and symlink races** (addresses [Sec-B5]). `O_NOFOLLOW`
is a bit in `open`'s `flags` argument; §Path resolution honors it at
the final component (`ELOOP` on a terminal symlink). `AT_SYMLINK_
NOFOLLOW` is the flag analog for the `*at` family. Together they
close the classic `/tmp` symlink race where a daemon opens
`/tmp/well_known` and an attacker swaps it for a symlink to `/etc/
passwd`: any careful daemon passes `O_NOFOLLOW`. `SYMLOOP_MAX = 40`
is the hard bound on total symlinks in a single resolution (not a
recursion depth — the resolver is iterative, see §Path resolution).

**TOCTOU on permission checks is closed by `dir_rwsem`** (addresses
[Sec-B2], [OS-A6]). The walker holds `parent.dir_rwsem.read()`
across:
1. The `children`-map lookup (or `InodeOps::lookup` call),
2. The permission check (`InodeOps::permission(parent, cred, X_OK)`
   and/or the final-component access check),
3. The "publish" into the walker's cursor.

Directory mutators (`unlink`, `rename`, `rmdir`, `mkdir`, `create`,
`symlink`, `link`) all hold `parent.dir_rwsem.write()` across their
entire operation. A reader-writer lock cannot have simultaneous
read and write holders, therefore a permission check on `foo`
cannot race with an `unlink(foo)` on the same parent. This is the
exact `i_rwsem` pattern Linux uses.

**Information disclosure via errno.** `may_lookup` returns `EACCES`
when the parent is non-searchable; the resolver returns `EACCES`
rather than `ENOENT` in that case, at every component boundary,
including the final. This matches Linux `fs/namei.c::may_lookup`
and prevents directory enumeration via errno [Sec-A5].

**Privilege model.** Credentials live on the task (`Credential { uid,
gid, groups }`); today all processes run as `uid=0, gid=0` because
userspace has no setuid path yet. `default_permission` nonetheless
implements the full POSIX mode-bit check (owner/group/other × r/w/x),
so the model is in place for when userspace gets non-zero uids (#86).

**Setuid/setgid on `write`.** POSIX requires clearing `S_ISUID` and
clearing `S_ISGID` iff the group-exec bit is set. We implement the
POSIX-exact rule, not the earlier "clear both unconditionally" that
[Sec-A7] flagged. The carve-out is documented in a comment on the
write path.

**Sticky bit.** `S_ISVTX` on a directory restricts `unlink`/`rename`
of entries to the entry's owner, the directory's owner, or uid 0.
Enforced in the VFS layer under the parent's `dir_rwsem.write()`
before calling `InodeOps::unlink` / `InodeOps::rename`.

**Negative dentry caching is gated and invalidated.** A negative
`ChildState::Negative` is only inserted when `InodeOps::lookup`
returns `ENOENT` *and* the caller had search permission on the
parent (prevents poisoning). It is also invalidated on any
`create`/`mkdir`/`rename-into` at the same `(parent, name)`: the
mutator takes `dir_rwsem.write()`, removes any `Negative` sibling,
then inserts the new positive entry [Sec-A3].

**Directory-entry cookie safety** (addresses [Sec-A4]). `getdents64`
accepts a user-supplied `cookie` and delegates to `FileOps::
getdents(f, buf, cookie)`. Drivers MUST treat an unrecognized
cookie as "resume at the smallest key ≥ cookie" (for `BTreeMap`
drivers this is a `range(cookie..)` scan), MUST NOT panic on an
unknown cookie, and MUST NOT return entries the caller could not
obtain via a fresh `opendir`+walk. A separate host test exercises
this per driver.

**Unmount and open files.** `unmount` without `MNT_FORCE` returns
`EBUSY` if `SuperBlock::open_files > 0`. The TOCTOU between the
check and the unmount [OS-B5] is closed by: (a) taking
`MOUNT_TABLE.write()` across the entire unmount bracket, and (b)
setting `sb.draining = true` before the check, so any concurrent
`sys_open` that resolved into this SB *before* we took the lock
will observe `draining` on its way to incrementing `open_files`
and return `ENOENT`. With `MOUNT_TABLE.write()` held, no new
walker can reach the mount root, because the walker descends via
`MOUNT_TABLE.read()` and the `Arc<MountEdge>` clone (§Path
resolution).

**Mount-point bootstrap**: [Sec-A6] noted that `/dev` and `/tmp`
rely on tarfs containing those directories as mount points. The
initrd build process (`cargo xtask initrd`, follow-up) is required
to emit stub `/dev/` and `/tmp/` directory entries; if either is
absent at boot, `fs::vfs::init()` panics with a diagnostic rather
than silently mounting devfs/ramfs into a read-only tarfs hole.

**Per-fd CLOEXEC follow-up**. [US-A2] correctly identifies that
`FileDescTable::dup2` inherits `O_CLOEXEC` when POSIX requires it
be cleared on the new fd. This is pre-existing in
`kernel/src/fs/mod.rs` and out of scope for this RFC's semantic
changes, but is captured as an implementation issue in the
roadmap.

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
the SMP RFC (see Alternatives); on single-CPU today the reader-shape
cost is zero because vibix runs kernel code to completion —
`MOUNT_TABLE` read critical sections cannot be pre-empted and therefore
cannot contend with writers or with each other. The same reasoning
applies to `dir_rwsem` read critical sections along the path walk: on a
non-preemptive kernel, a reader holds the lock uncontested for its
entire critical section. When we go preemptive (kernel RFC TBD) we will
re-evaluate every lock class documented here.

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

**Inline eviction on last `Arc::drop` vs deferred GC queue.** The
natural Rust shape is to put teardown logic in `impl Drop for
Dentry`/`Inode` — on last drop, unlink from parent, call
`InodeOps::evict`, etc. Rejected: Drop can fire while we hold
sibling locks (e.g., replacing a parent's child map entry drops the
old `Arc<Dentry>`), so in-Drop eviction re-enters the lock stack and
can deadlock or trigger nested `Drop` chains. Instead, `Drop` only
pushes the victim onto a per-CPU `vfs::gc_queue`, and the queue is
drained at well-defined points (syscall return path, idle task). This
also means eviction never runs from an interrupt handler. Borrowed
from Linux's `dput()`+`iput()` structure, which is deferred for the
same reason.

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
2. **`st_ino` for `devfs` synthetic entries** — do we synthesize
   stable inode numbers (`hash(path)`), or allocate per-mount? The
   reference `devtmpfs` uses per-instance counters. We adopt that.
   Deferred to implementation issue.
3. **File locks (`flock`, `fcntl(F_SETLK)`).** Not needed for PID 1.
   Deferred to the POSIX-readiness track (#87).
4. **Negative dentry eviction.** We cache indefinitely today. Under
   memory pressure the cache needs bounds. Deferred to the same
   follow-up RFC as positive-dentry LRU.
5. **Mount source for `tarfs`.** Today we have a Limine ramdisk
   module. The `MountSource` enum will need a `RamdiskModule(*const
   u8, usize)` variant; this is uncontroversial but pinned here so
   reviewers see the shape.

## Confirmations

These items are sometimes framed as open questions but are in fact
settled by the relevant specifications/literature. Pinned here so
implementers don't re-litigate them:

- **Open-file offset survives `exec()`.** POSIX.1-2017 XSH `exec()`
  §2.1.1.1 specifies that open file descriptions persist across
  `exec` — only fds flagged `O_CLOEXEC` are closed, and the
  description (including the seek offset) is the per-fd state that
  survives. Our existing `FileDescTable::close_cloexec()` path is
  correct; no behavior change needed at exec for the offset field.
- **Per-process cwd.** The per-process current working directory is
  settled by Ritchie & Thompson's original UNIX paper and codified in
  POSIX. We add a `cwd: Arc<Dentry>` field to `Task` and `sys_chdir`/
  `sys_getcwd` in the implementation roadmap; there is no design
  choice to make here.
- **`readlink` on links with `st_size > PATH_MAX`.** POSIX permits it
  but callers must size their buffer; `readlink` returns at most
  `bufsize` bytes and does not NUL-terminate. Our `tarfs` caps link
  names at USTAR's 100-byte field; `ramfs` allocates arbitrarily and
  reports `st_size` honestly, matching Linux.

## Implementation Roadmap

Ordered dependency-first. Each item is independently landable and
testable. Rough size estimates in parentheses.

- [ ] Add the core VFS types (`SuperBlock`, `Inode`, `Dentry`,
      `MountEdge`, `OpenFile`) and the four operation traits,
      including `dir_rwsem` on `Inode`, `rename_mutex` on `SuperBlock`,
      and the `ChildState::{Loading, Negative, Resolved}` placeholder
      enum on `Dentry`. Unit tests exercise refcount lifecycle and
      weak-ref safety under `Arc` drop. No FS drivers yet. (~700 LOC)
- [ ] Implement the deferred-eviction GC queue
      (`vfs::gc_queue`, per-CPU, drained on syscall return and in the
      idle task). `impl Drop for Dentry`/`Inode` pushes only; teardown
      runs in the drain path. Unit tests force nested drops under a
      held parent lock to prove no re-entry. (~200 LOC)
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
- [ ] Fix the `O_CLOEXEC` bit value in `fs::flags` (currently
      `1 << 19`; Linux defines `O_CLOEXEC = 0o2000000`,
      i.e. `1 << 19` as octal — verify and realign to the canonical
      Linux numeric value `0x80000` before any userspace shipping).
      Addresses reviewer US-A2. (~20 LOC + test)
- [ ] Pick the `mode_t` / `dev_t` widths for the syscall ABI boundary
      (Linux uses `u32` `mode_t`, `u64` `dev_t` on x86_64). Pin the
      choice in a small `abi/posix_types.rs` module and use those
      aliases everywhere the Stat/openat ABI touches userspace.
      Addresses reviewer US-A1. (~50 LOC)
