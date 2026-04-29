//! VFS-backed path syscalls: `open`, `openat`, `stat`, `fstat`, `lstat`,
//! `newfstatat`.
//!
//! Scope (RFC 0002 item 11/15, issue #238, read-path subset):
//!
//! - No `O_CREAT` — any `open` that would create returns `-EPERM` via
//!   the default `InodeOps::create` trait body. `open` on a non-existent
//!   path returns `-ENOENT`.
//! - No `chdir` / per-process cwd yet (tracked in #239) — relative paths
//!   resolve against the namespace root until that lands.
//! - Legacy compat: `/dev/stdin`, `/dev/stdout`, `/dev/stderr`,
//!   `/dev/serial` still short-circuit to [`SerialBackend`] so the
//!   boot-time init binary keeps working until a real `/dev/serial`
//!   character device is wired up.
//!
//! All handlers share:
//! - `copy_path_from_user` for bounded user-path copy-in.
//! - `resolve_inode` / `resolve_and_open` for path_walk + SB pinning.
//! - `write_stat` for the userspace `struct stat` copy-out.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::super::syscall::copy_path_from_user_pub;
use super::super::uaccess;
use crate::fs::vfs::dentry::{DFlags, Dentry};
use crate::fs::vfs::ops::{meta_into_stat, Stat};
use crate::fs::vfs::ops::{SetAttr, SetAttrMask};
use crate::fs::vfs::path_walk::{path_walk, LookupFlags, MountResolver, NameIdata, PATH_MAX};
use crate::fs::vfs::super_block::{SbActiveGuard, SuperBlock};
use crate::fs::vfs::{
    root as vfs_root, GlobalMountResolver, Inode, InodeKind, OpenFile, VfsBackend,
};
use crate::fs::vfs::{Access, Credential, Timespec};
use crate::fs::{
    flags as oflags, FileBackend, FileDescription, EBADF, EBUSY, EEXIST, EFAULT, EFBIG, EINVAL,
    EISDIR, ENAMETOOLONG, ENODEV, ENOENT, ENOMEM, ENOTDIR, EPERM, EROFS, EXDEV,
};

/// Linux x86_64 value of the "use the current working directory"
/// sentinel for `*at` syscalls. Sign-extended as an `i32`, negative,
/// so it never collides with a live fd number.
pub const AT_FDCWD: i32 = -100;

/// `AT_SYMLINK_NOFOLLOW` — the `*at` flag that asks the resolver to
/// stop on a trailing symlink rather than following it.
pub const AT_SYMLINK_NOFOLLOW: u32 = 0x100;

/// `AT_EMPTY_PATH` — treat an empty `path` as a reference to the file
/// behind `dfd` (used by `fstatat(fd, "", &st, AT_EMPTY_PATH)`).
pub const AT_EMPTY_PATH: u32 = 0x1000;

/// `AT_REMOVEDIR` — flag to `unlinkat(2)` that dispatches to `rmdir`
/// semantics instead of `unlink`. Mirrors Linux's value.
pub const AT_REMOVEDIR: u32 = 0x200;

/// `AT_SYMLINK_FOLLOW` — flag to `linkat(2)` that asks the resolver to
/// follow a terminal symlink on the *source* path. Default (no flag)
/// is to hard-link the symlink itself, per POSIX. Mirrors Linux's
/// value (RFC 0002 §flags).
pub const AT_SYMLINK_FOLLOW: u32 = 0x400;

/// `AT_EACCESS` — flag to `faccessat(2)` that asks the kernel to use
/// the *effective* uid/gid for the permission check instead of the
/// POSIX-default *real* uid/gid. Linux value 0x200; shares its bit
/// pattern with `AT_REMOVEDIR` (the `unlinkat(2)` flag) — the two
/// belong to disjoint syscall flag namespaces and the value collision
/// is harmless in practice.
pub const AT_EACCESS: u32 = 0x200;

/// `F_OK` — `access(2)` mode meaning "test for existence only" (no
/// permission bit checked). When `mode == F_OK` (i.e. `0`), a
/// successful path resolve is itself the answer; no `permission()`
/// callback is invoked.
pub const F_OK: u32 = 0;
/// `R_OK` — `access(2)` mode bit asking "is read permission granted?"
pub const R_OK: u32 = 4;
/// `W_OK` — `access(2)` mode bit asking "is write permission granted?"
pub const W_OK: u32 = 2;
/// `X_OK` — `access(2)` mode bit asking "is execute (or search, on a
/// directory) permission granted?"
pub const X_OK: u32 = 1;

/// `S_ISVTX` — the POSIX "sticky bit" in `InodeMeta.mode`. When set on
/// a directory, `unlink`/`rename` require the caller to own either the
/// target file or the directory (or be root). Linux value 0o1000.
const S_ISVTX: u16 = 0o1000;

/// Copy a user path into a heap buffer sized at `PATH_MAX + 1`. The
/// `+1` lets `copy_path_from_user_pub` observe the terminating NUL
/// within the buffer for paths of exactly `PATH_MAX` user bytes;
/// anything longer returns `-ENAMETOOLONG`. A heap buffer avoids a
/// 4 KiB stack frame on every VFS syscall.
///
/// Uses fallible allocation (`try_reserve_exact`) so a heap-pressure
/// situation surfaces as `-ENOMEM` to userspace instead of tripping
/// the kernel-wide `panic = "abort"` handler — a user syscall must
/// never be a DoS vector against the kernel.
fn copy_user_path(path_uva: u64) -> Result<Vec<u8>, i64> {
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(PATH_MAX + 1).map_err(|_| ENOMEM)?;
    buf.resize(PATH_MAX + 1, 0u8);
    let n = unsafe { copy_path_from_user_pub(path_uva as usize, &mut buf) }?;
    buf.truncate(n);
    Ok(buf)
}

/// Resolve a user path to an `Arc<Inode>` via `path_walk`.
///
/// `follow` controls whether a terminal symlink is followed
/// (`stat` vs `lstat`). Returns `(inode, sb_guard_holder)` on success —
/// the holder is an `Arc<SbActiveGuard>`-equivalent: we return the
/// `NameIdata`'s `edges` vector so the caller's `Arc<SuperBlock>`
/// references keep the SB alive for the duration of the `getattr` call.
fn resolve_inode(path: &[u8], follow: bool) -> Result<(Arc<Inode>, NameIdata), i64> {
    // RFC 0004 Workstream B: every userspace-driven VFS path walk runs
    // under the caller's per-task credential snapshot. The previous
    // `Credential::kernel()` fallback existed only while the syscall
    // arms were feature-gated off; with `vfs_creds` flipped on, every
    // dispatch arm reaches the impl with a real task in `current`, so
    // `current_credentials()` is the right (and only) source.
    let cred = (*crate::task::current_credentials()).clone();
    resolve_inode_as(path, follow, cred)
}

/// Like [`resolve_inode`] but walks the path using `cred` for
/// every intermediate `may_lookup` (search-permission) check.
///
/// Syscalls that make DAC decisions about the resolved inode —
/// `chmod`/`chown` and friends — pass the caller's per-task credential
/// here so that a non-root caller is rejected with `-EACCES` on an
/// unsearchable ancestor, instead of silently resolving as root and
/// then failing the subsequent ownership check with a misleading
/// errno. Read-only syscalls (`stat`/`open`) keep using the root
/// placeholder until Workstream B plumbs per-task credentials through
/// every call site in one go.
fn resolve_inode_as(
    path: &[u8],
    follow: bool,
    cred: Credential,
) -> Result<(Arc<Inode>, NameIdata), i64> {
    let root = vfs_root().ok_or(ENOENT)?;
    // For relative paths, walk from the per-process cwd. For absolute
    // paths, path_walk reseats at root on the first `/` component so
    // the cwd argument is ignored — but we still pass root as cwd for
    // absolute paths since that is the correct sentinel.
    let cwd = if path.first() == Some(&b'/') {
        root.clone()
    } else {
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let mut flags = LookupFlags::default();
    if follow {
        flags = flags | LookupFlags::FOLLOW;
    } else {
        flags = flags | LookupFlags::NOFOLLOW;
    }
    let mut nd = NameIdata::new(root, cwd, cred, flags)?;
    path_walk(&mut nd, path, &GlobalMountResolver)?;
    let inode = nd.path.inode.clone();
    Ok((inode, nd))
}

/// Resolve a `*at` syscall's `dfd` argument to the directory dentry the
/// walk should start from for relative paths.
///
/// Per POSIX `*at(2)`:
/// - `AT_FDCWD` → the caller's per-process cwd is the walk root. We
///   surface this as `Ok(None)` so callers can use their existing
///   `current_cwd()` fallback (matches the behaviour of `resolve_inode`).
/// - any other value → looked up in the current task's fd table. The
///   referenced file must be a directory; non-directory backings return
///   `-ENOTDIR`. Closed or out-of-range fds return `-EBADF`. Backends
///   that don't expose a VFS dentry (e.g. `SerialBackend`) also yield
///   `-ENOTDIR` because they have no directory inode to walk under.
///
/// The returned dentry is reference-counted (`Arc`), so it remains
/// alive across the subsequent `path_walk` even if the fd is closed
/// concurrently. Absolute paths ignore `dfd` entirely (per POSIX) — the
/// helper is still safe to call on them, and callers that know the
/// path is absolute may skip the call to save the fd-table round trip.
fn resolve_dirfd(dfd: i32) -> Result<Option<Arc<Dentry>>, i64> {
    if dfd == AT_FDCWD {
        return Ok(None);
    }
    if dfd < 0 {
        // Negative fds other than AT_FDCWD are never valid.
        return Err(EBADF);
    }
    let fd = dfd as u32;
    let tbl = crate::task::current_fd_table();
    let backend = tbl.lock().get(fd).map_err(|_| EBADF)?;
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        // Non-VFS backends (e.g. SerialBackend before execve) don't
        // refer to any directory in the namespace.
        None => return Err(ENOTDIR),
    };
    if vfs.open_file.inode.kind != InodeKind::Dir {
        return Err(ENOTDIR);
    }
    Ok(Some(vfs.open_file.dentry.clone()))
}

/// Like [`resolve_inode_as`] but seeds the path walk from `start` when
/// the path is relative. `start = None` falls back to the caller's cwd
/// (the `*at(AT_FDCWD)` and plain-path cases). Absolute paths reseat to
/// the namespace root inside `path_walk` regardless of `start`.
fn resolve_inode_at(
    start: Option<Arc<Dentry>>,
    path: &[u8],
    follow: bool,
    cred: Credential,
) -> Result<(Arc<Inode>, NameIdata), i64> {
    let root = vfs_root().ok_or(ENOENT)?;
    let cwd = if path.first() == Some(&b'/') {
        // Absolute path: cwd is irrelevant — `path_walk` reseats at
        // root on the leading `/`. Pass root as the conventional
        // sentinel.
        root.clone()
    } else if let Some(d) = start {
        // Relative path with a real dirfd: walk from there.
        d
    } else {
        // Relative path with AT_FDCWD (or plain non-`*at` syscall):
        // walk from the caller's cwd.
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let mut flags = LookupFlags::default();
    if follow {
        flags = flags | LookupFlags::FOLLOW;
    } else {
        flags = flags | LookupFlags::NOFOLLOW;
    }
    let mut nd = NameIdata::new(root, cwd, cred, flags)?;
    path_walk(&mut nd, path, &GlobalMountResolver)?;
    let inode = nd.path.inode.clone();
    Ok((inode, nd))
}

/// Fill `out` from `inode.ops.getattr`, then copy out to user.
fn stat_into_user(inode: &Arc<Inode>, user_statbuf: u64) -> i64 {
    if user_statbuf == 0 {
        return EINVAL;
    }
    if let Err(e) = uaccess::check_user_range(user_statbuf as usize, core::mem::size_of::<Stat>()) {
        return e.as_errno();
    }
    // Zero-init to avoid padding infoleak (Sec-B4 per RFC 0002).
    let mut st = Stat::default();
    if let Err(e) = inode.ops.getattr(inode, &mut st) {
        return e;
    }
    // Drivers that don't fill fs_id/ino should get sane defaults from
    // `meta_into_stat` — but any driver implementing its own getattr is
    // expected to set them. We re-apply from the inode as a safety net
    // so a stubbed getattr that returned Ok without touching `out`
    // still emits a coherent stat.
    if st.st_ino == 0 {
        let meta = inode.meta.read();
        let fs_id = inode.sb.upgrade().map(|s| s.fs_id.0).unwrap_or(0);
        meta_into_stat(&meta, inode.kind, fs_id, inode.ino, &mut st);
    }
    let bytes = unsafe {
        core::slice::from_raw_parts(
            &st as *const Stat as *const u8,
            core::mem::size_of::<Stat>(),
        )
    };
    match unsafe { uaccess::copy_to_user(user_statbuf as usize, bytes) } {
        Ok(()) => 0,
        Err(e) => e.as_errno(),
    }
}

/// Install `backend` into the current fd table. `flags` contains the
/// caller's `O_*` flags; access-mode bits go into `FileDescription.flags`
/// and `O_CLOEXEC` is split into the per-fd slot via `alloc_fd_with_flags`.
fn install_fd(backend: Arc<dyn FileBackend>, flags: u32) -> i64 {
    // Preserve every status flag the caller passed (access mode, O_APPEND,
    // O_NONBLOCK, etc.) on the open-file description so fcntl(F_GETFL)
    // returns the full set. The per-fd O_CLOEXEC bit is split out into the
    // slot's fd_flags — dup'd fds must not inherit it.
    let fd_flags = flags & oflags::O_CLOEXEC;
    // Only POSIX file-status flags persist on the open-file description.
    // Creation-time / path-resolution bits (O_CREAT, O_EXCL, O_TRUNC,
    // O_DIRECTORY, O_NOFOLLOW) affect open() only and must not surface
    // via fcntl(F_GETFL).
    let status_flags =
        flags & (oflags::O_ACCMODE | oflags::O_APPEND | oflags::O_NONBLOCK | oflags::O_ASYNC);
    let desc = Arc::new(FileDescription::new(backend, status_flags));
    let tbl = crate::task::current_fd_table();
    let result = tbl.lock().alloc_fd_with_flags(desc, fd_flags);
    match result {
        Ok(fd) => fd as i64,
        Err(e) => e,
    }
}

/// Split `path` into its parent directory and final component for
/// `O_CREAT`-style dispatch. Rejects inputs with no nameable leaf — an
/// empty path, a bare `/`, or anything whose final component is `.` /
/// `..` / empty (trailing slash) — since `create(parent, leaf)` cannot
/// act on them.
fn split_parent(path: &[u8]) -> Result<(&[u8], &[u8]), i64> {
    if path.is_empty() {
        return Err(ENOENT);
    }
    // Strip a trailing slash for "/foo/" but keep bare "/" as-is so the
    // rejection below triggers.
    let trimmed = if path.len() > 1 && *path.last().unwrap() == b'/' {
        &path[..path.len() - 1]
    } else {
        path
    };
    let (parent, leaf) = match trimmed.iter().rposition(|&b| b == b'/') {
        Some(0) => (&b"/"[..], &trimmed[1..]),
        Some(i) => (&trimmed[..i], &trimmed[i + 1..]),
        None => (&b"."[..], trimmed),
    };
    if leaf.is_empty() || leaf == b"." || leaf == b".." {
        return Err(ENOENT);
    }
    Ok((parent, leaf))
}

/// `/dev/{stdin,stdout,stderr,serial}` legacy compat: returns a
/// `SerialBackend`-backed description when path matches. None otherwise.
fn legacy_dev_backend(path: &[u8], flags: u64) -> Option<i64> {
    let is_special = matches!(
        path,
        b"/dev/stdin" | b"/dev/stdout" | b"/dev/stderr" | b"/dev/serial"
    );
    if !is_special {
        return None;
    }
    let safe_flags =
        (flags as u32) & (oflags::O_RDONLY | oflags::O_WRONLY | oflags::O_RDWR | oflags::O_CLOEXEC);
    let backend: Arc<dyn FileBackend> = Arc::new(crate::fs::SerialBackend::new());
    let rc = install_fd(backend, safe_flags);
    // Linux `open(tty, !O_NOCTTY)` on a session leader with no existing
    // ctty acquires the tty as the session's controlling terminal. Every
    // legacy /dev/* path points at the same console tty until multi-tty
    // support lands (#374).
    if rc >= 0 && (flags as u32) & oflags::O_NOCTTY == 0 {
        let caller = crate::process::current_pid();
        let tty = crate::tty::console_tty();
        let _ = crate::tty::acquire_ctty_on_open(caller, &tty);
    }
    Some(rc)
}

/// Shared `open` body: used by `sys_open` (dfd == AT_FDCWD) and
/// `sys_openat`.
///
/// `dfd` is accepted but only `AT_FDCWD` is honored today — passing a
/// real fd for a relative path returns `-EINVAL` because per-process
/// cwd / fd-rooted walks don't exist yet (#239).
pub unsafe fn sys_openat_impl(dfd: i32, path_uva: u64, flags: u64, mode: u64) -> i64 {
    // 1. Copy the user path.
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();
    let flags32 = flags as u32;

    // 2. Legacy /dev/{stdin,stdout,stderr,serial} fast path. Bypasses
    //    the VFS so a smoke boot that opens these before the devfs
    //    character devices exist keeps working.
    if let Some(r) = legacy_dev_backend(path, flags) {
        return r;
    }

    // 3. `*at` resolution. `AT_FDCWD` falls through to the caller's
    //    cwd; a real dirfd seeds the walk from that directory. Absolute
    //    paths ignore `dfd` per POSIX — `path_walk` reseats at root on
    //    the leading `/` regardless of the start dentry.
    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // 4. Walk. If O_CREAT is set and the leaf does not exist, try to
    //    create it in the parent directory, then re-walk.
    let follow = flags32 & oflags::O_NOFOLLOW == 0;
    let cred = (*crate::task::current_credentials()).clone();
    let (inode, nd) = match resolve_inode_at(start.clone(), path, follow, cred.clone()) {
        Ok(v) => {
            // File exists. With O_CREAT|O_EXCL this is an error.
            if flags32 & oflags::O_CREAT != 0 && flags32 & oflags::O_EXCL != 0 {
                return EEXIST;
            }
            v
        }
        Err(e) if e == ENOENT && flags32 & oflags::O_CREAT != 0 => {
            let (parent_path, leaf) = match split_parent(path) {
                Ok(v) => v,
                Err(e) => return e,
            };
            let (parent_inode, _pnd) = match resolve_inode_at(
                start.clone(),
                parent_path,
                /* follow */ true,
                cred.clone(),
            ) {
                Ok(v) => v,
                Err(e) => return e,
            };
            if parent_inode.kind != InodeKind::Dir {
                return ENOTDIR;
            }
            let create_mode = (mode as u16) & 0o7777;
            if let Err(e) = parent_inode.ops.create(&parent_inode, leaf, create_mode) {
                return e;
            }
            // Re-resolve to pick up the freshly created dentry+inode.
            match resolve_inode_at(start.clone(), path, follow, cred.clone()) {
                Ok(v) => v,
                Err(e) => return e,
            }
        }
        Err(e) => return e,
    };

    // 5. O_DIRECTORY check.
    if flags32 & oflags::O_DIRECTORY != 0 && inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // 6. O_TRUNC: zero the file length for a writable open on a regular
    //    file. Silently ignored on a read-only open (Linux semantics);
    //    rejected with EISDIR on a directory.
    if flags32 & oflags::O_TRUNC != 0 {
        if inode.kind == InodeKind::Dir {
            return EISDIR;
        }
        let access = flags32 & oflags::O_ACCMODE;
        if inode.kind == InodeKind::Reg && (access == oflags::O_WRONLY || access == oflags::O_RDWR)
        {
            let attr = SetAttr {
                mask: SetAttrMask::SIZE,
                size: 0,
                ..SetAttr::default()
            };
            if let Err(e) = inode.ops.setattr(&inode, &attr) {
                return e;
            }
        }
    }

    // 7a. FIFO detour: on an `InodeKind::Fifo`, `open(2)` rendezvous
    //     semantics (POSIX §open) take over. The fd gets a
    //     `FifoOpenBackend` that wraps the pipe end(s) alongside an
    //     `Arc<OpenFile>` — the latter pins the inode + SB (via a
    //     transferred `SbActiveGuard`) and lets fd-keyed inode syscalls
    //     (`fstat` etc.) route through `as_vfs`.
    if inode.kind == InodeKind::Fifo {
        let pipe = match inode.ops.fifo_pipe() {
            Some(p) => p,
            // A FIFO inode must always carry a pipe — surface the bug
            // as ENXIO (same errno used for a write-side rendezvous
            // failure) rather than panic.
            None => return crate::fs::ENXIO,
        };
        let nonblocking = flags32 & oflags::O_NONBLOCK != 0;
        let access = flags32 & oflags::O_ACCMODE;
        // Acquire the pipe end(s) first — O_WRONLY-without-reader
        // returns ENXIO here, and we do not want to have acquired an
        // SbActiveGuard only to immediately drop it on that failure.
        let (read_end, write_end) = match access {
            oflags::O_RDONLY => match pipe.open_read(nonblocking) {
                Ok(r) => (Some(r), None),
                Err(e) => return e,
            },
            oflags::O_WRONLY => match pipe.open_write(nonblocking) {
                Ok(w) => (None, Some(w)),
                Err(e) => return e,
            },
            oflags::O_RDWR => {
                // Linux extension: `O_RDWR` on a FIFO always succeeds.
                // Both ends hang off the same `Arc<Pipe>`, so a write
                // through the fd is observable on a later read.
                let (r, w) = pipe.open_rdwr(nonblocking);
                (Some(r), Some(w))
            }
            _ => return EINVAL,
        };
        // Pin the inode + superblock for the fd's lifetime by building
        // an `OpenFile` around them, the same dance every other
        // path-opened fd goes through (see step 7 below). `OpenFile`'s
        // `Drop` releases the `sb_active` pin.
        let sb = match inode.sb.upgrade() {
            Some(s) => s,
            None => return ENOENT,
        };
        let guard = match SbActiveGuard::try_acquire(&sb) {
            Ok(g) => g,
            Err(e) => return e,
        };
        let of = OpenFile::new(
            nd.path.dentry.clone(),
            inode.clone(),
            inode.file_ops.clone(),
            sb.clone(),
            flags as u32,
            guard,
        );
        let backend: Arc<dyn FileBackend> = Arc::new(FifoOpenBackend {
            vfs: VfsBackend { open_file: of },
            read_end,
            write_end,
        });
        return install_fd(backend, flags as u32);
    }

    // 7. Build the OpenFile. The edge list in `nd` keeps the SB alive
    //    until we've successfully acquired our own `SbActiveGuard`.
    let sb = match inode.sb.upgrade() {
        Some(s) => s,
        None => return ENOENT,
    };
    let guard = match SbActiveGuard::try_acquire(&sb) {
        Ok(g) => g,
        Err(e) => return e,
    };
    // `OpenFile::new` takes `sb: Arc<SuperBlock>` by value and
    // `guard: SbActiveGuard<'_>` also by value. Cloning the `Arc` for
    // the `sb` argument keeps `sb` live for the `guard`'s lifetime.
    let sb_for_of = sb.clone();
    let of = OpenFile::new(
        nd.path.dentry.clone(),
        inode.clone(),
        inode.file_ops.clone(),
        sb_for_of,
        flags as u32,
        guard,
    );
    let backend: Arc<dyn FileBackend> = Arc::new(VfsBackend { open_file: of });
    install_fd(backend, flags as u32)
}

/// FileBackend for a path-opened FIFO fd.
///
/// Holds the pipe end(s) matching the open's access mode alongside an
/// inner [`VfsBackend`] over the FIFO's inode. The `VfsBackend` pins
/// the inode + superblock (via the `SbActiveGuard` transferred into
/// its `OpenFile`), and `as_vfs` returns `Some(&self.vfs)` so fd-keyed
/// inode syscalls (`fstat`, `fstatat` with `AT_EMPTY_PATH`, etc.) see
/// the FIFO's inode rather than falling through to `-EINVAL`.
///
/// `read`/`write` bypass the inner `VfsBackend` and route directly to
/// the pipe ends — FIFO I/O is ring-based rendezvous, not an offset-
/// tracked inode body. `read` on a write-only open returns `EBADF`
/// (mirroring `PipeWriteEnd::read`), and vice versa.
struct FifoOpenBackend {
    /// Inner VFS backend — purely for `as_vfs`/SB pinning. Its `read`/
    /// `write` are never called through this outer backend.
    vfs: VfsBackend,
    read_end: Option<Arc<crate::ipc::pipe::PipeReadEnd>>,
    write_end: Option<Arc<crate::ipc::pipe::PipeWriteEnd>>,
}

impl FileBackend for FifoOpenBackend {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        match self.read_end.as_ref() {
            Some(r) => r.read(buf),
            None => Err(EBADF),
        }
    }
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        match self.write_end.as_ref() {
            Some(w) => w.write(buf),
            None => Err(EBADF),
        }
    }
    fn poll(&self, pt: &mut crate::poll::PollTable) -> crate::poll::PollMask {
        let mut mask: crate::poll::PollMask = 0;
        if let Some(r) = self.read_end.as_ref() {
            mask |= r.poll(pt);
        }
        if let Some(w) = self.write_end.as_ref() {
            mask |= w.poll(pt);
        }
        mask
    }
    fn set_flags(&self, new_flags: u32) {
        if let Some(r) = self.read_end.as_ref() {
            r.set_flags(new_flags);
        }
        if let Some(w) = self.write_end.as_ref() {
            w.set_flags(new_flags);
        }
    }
    fn as_vfs(&self) -> Option<&VfsBackend> {
        Some(&self.vfs)
    }
}

/// `stat(path, *statbuf)` (follow=true) / `lstat(path, *statbuf)`
/// (follow=false — `nofollow=true` here flips the sense).
pub unsafe fn sys_stat_impl(path_uva: u64, statbuf_uva: u64, nofollow: bool) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let (inode, _nd) = match resolve_inode(path, !nofollow) {
        Ok(v) => v,
        Err(e) => return e,
    };
    stat_into_user(&inode, statbuf_uva)
}

/// `fstat(fd, *statbuf)` — read `struct stat` of the file behind an
/// already-open fd.
pub unsafe fn sys_fstat_impl(fd_raw: u64, statbuf_uva: u64) -> i64 {
    // Linux fd space fits in u32; values above that are always invalid.
    if fd_raw > u32::MAX as u64 {
        return EBADF;
    }
    let fd = fd_raw as u32;
    let tbl = crate::task::current_fd_table();
    let backend = match tbl.lock().get(fd) {
        Ok(b) => b,
        Err(_) => return EBADF,
    };
    // Non-VFS backends (SerialBackend on fds 0/1/2 before execve) have
    // no Inode; fstat on them yields -EINVAL per POSIX for "no such
    // attribute". This matches Linux's `generic_file_fstat` on a
    // pipe/socket fd whose inode lookup returns nothing useful.
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        None => return EINVAL,
    };
    stat_into_user(&vfs.open_file.inode, statbuf_uva)
}

/// `newfstatat(dfd, path, *statbuf, flags)` — the `*at` form of stat.
///
/// Supports `AT_SYMLINK_NOFOLLOW` and `AT_EMPTY_PATH`. Rejects any
/// other flag bit with `-EINVAL` so future additions (`AT_NO_AUTOMOUNT`
/// etc.) have to be whitelisted explicitly.
pub unsafe fn sys_newfstatat_impl(dfd: i32, path_uva: u64, statbuf_uva: u64, flags: u32) -> i64 {
    let known = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !known != 0 {
        return EINVAL;
    }

    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // AT_EMPTY_PATH + empty path + real fd: stat the file behind dfd.
    // AT_FDCWD (-100) is not a valid fd for this purpose — reject it
    // until per-process cwd semantics land (#239).
    if flags & AT_EMPTY_PATH != 0 && path.is_empty() {
        if dfd == AT_FDCWD {
            return EINVAL;
        }
        return sys_fstat_impl(dfd as u64, statbuf_uva);
    }

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let cred = (*crate::task::current_credentials()).clone();
    let (inode, _nd) = match resolve_inode_at(start, path, follow, cred) {
        Ok(v) => v,
        Err(e) => return e,
    };
    stat_into_user(&inode, statbuf_uva)
}

/// `chdir(path)` — set the per-process current working directory.
///
/// Resolves `path` (following symlinks), checks the target is a
/// directory, then stores its dentry as the task's cwd via
/// [`crate::task::set_current_cwd`].
pub unsafe fn sys_chdir(path_uva: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let (inode, nd) = match resolve_inode(path, /* follow */ true) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    crate::task::set_current_cwd(nd.path.dentry.clone());
    0
}

/// `getcwd(buf, len)` — copy the absolute path of the current working
/// directory into the user buffer.
///
/// Walks the dentry parent chain from the cwd (or VFS root if no cwd
/// is set) up to the root, collecting component names, then assembles
/// and copies out `"/component/…\0"`.
///
/// Returns the number of bytes written (including the terminating NUL)
/// on success, or a negative errno:
/// - `-ENOENT` if the VFS root is not yet initialised.
/// - `-EINVAL` if `buf` is NULL or `len` is 0.
/// - `-ENAMETOOLONG` if the path does not fit in `len` bytes.
/// - `-EFAULT` if `buf` is not a valid user-space range.
pub unsafe fn sys_getcwd(buf_uva: u64, len: u64) -> i64 {
    if buf_uva == 0 || len == 0 {
        return EINVAL;
    }
    let len = len as usize;

    // Resolve the cwd: fall back to VFS root.
    let cwd = match crate::task::current_cwd().or_else(vfs_root) {
        Some(d) => d,
        None => return ENOENT,
    };

    // Walk the parent chain. We hold strong Arcs in `chain` to keep
    // dentries alive while assembling the path string.
    //
    // Mount crossings: when we land on an `IS_ROOT` dentry, query
    // `MOUNT_TABLE` for the edge whose `root_dentry` is this dentry. If
    // found, the mountpoint in the parent FS is the next step upward and
    // its name is what belongs in the path. If not found (we are at the
    // VFS namespace root), stop.
    let mut chain: Vec<Arc<Dentry>> = Vec::new();
    let resolver = GlobalMountResolver;

    let mut cur = cwd.clone();
    loop {
        if cur.flags.contains(DFlags::IS_ROOT) {
            // Check if this is a mounted root (has a parent FS above it).
            match resolver.mount_above(&cur) {
                Some(edge) => {
                    // Cross back up to the mountpoint in the parent FS.
                    // The mountpoint's name is the directory name in the
                    // parent (e.g. "dev" for /dev).
                    match edge.mountpoint.upgrade() {
                        Some(mp) => {
                            chain.push(mp.clone());
                            match mp.parent.upgrade() {
                                Some(parent) => cur = parent,
                                None => break,
                            }
                        }
                        None => break, // mountpoint dropped — treat as root
                    }
                }
                None => break, // namespace root — stop
            }
        } else {
            chain.push(cur.clone());
            match cur.parent.upgrade() {
                Some(parent) => cur = parent,
                None => break,
            }
        }
    }

    // Build "/comp1/comp2/…\0".
    // Total length: 1 ('/') + sum(name_len + 1 per component) + 1 (NUL).
    // For root cwd the chain is empty → path is "/\0".
    let mut path_len = 1usize; // leading '/'
    for d in chain.iter().rev() {
        path_len += d.name.as_bytes().len() + 1; // '/' + name
    }
    path_len += 1; // NUL

    if path_len > len {
        return ENAMETOOLONG;
    }

    if let Err(e) = uaccess::check_user_range(buf_uva as usize, path_len) {
        return e.as_errno();
    }

    // Assemble into a kernel buffer.
    let mut out: Vec<u8> = Vec::with_capacity(path_len);
    // If cwd is root, chain is empty.
    if chain.is_empty() {
        out.push(b'/');
    } else {
        for d in chain.iter().rev() {
            out.push(b'/');
            out.extend_from_slice(d.name.as_bytes());
        }
    }
    out.push(0); // NUL terminator

    match uaccess::copy_to_user(buf_uva as usize, &out) {
        Ok(()) => out.len() as i64,
        Err(e) => e.as_errno(),
    }
}

/// POSIX file-type bits (mask: `S_IFMT`). Only the values we act on are
/// spelled out — the full Linux set is larger, but `mknod` in this
/// kernel only accepts FIFO and regular files today.
const S_IFMT: u32 = 0o170_000;
const S_IFREG: u32 = 0o100_000;
const S_IFIFO: u32 = 0o010_000;

/// Shared body for `mknod(2)` / `mknodat(2)`.
///
/// Resolves the parent directory, splits off the leaf name, then dispatches
/// to `InodeOps::mkfifo` (for `S_IFIFO`) or `InodeOps::create` (for
/// `S_IFREG`). Any other type — character/block/socket nodes — returns
/// `-EPERM` since this kernel has no devtmpfs or unix-socket support yet.
fn mknod_impl(dfd: i32, path_uva: u64, mode: u32, _dev: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // mknod never names a directory — a trailing slash on the leaf is
    // invalid. split_parent strips it silently, so the check has to
    // happen here.
    if path.len() > 1 && path.last() == Some(&b'/') {
        return ENOTDIR;
    }

    let cred = (*crate::task::current_credentials()).clone();
    // Refuse if the target already exists. Matches Linux mknod semantics
    // (EEXIST on pre-existing path).
    if resolve_inode_at(start.clone(), path, /* follow */ false, cred.clone()).is_ok() {
        return EEXIST;
    }

    let (parent_path, leaf) = match split_parent(path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent_inode, _pnd) =
        match resolve_inode_at(start, parent_path, /* follow */ true, cred) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    let perm = (mode & 0o7777) as u16;
    let typ = mode & S_IFMT;
    // A zero type field means "regular file" per POSIX.
    let typ = if typ == 0 { S_IFREG } else { typ };

    match typ {
        S_IFIFO => match parent_inode.ops.mkfifo(&parent_inode, leaf, perm) {
            Ok(_) => 0,
            Err(e) => e,
        },
        S_IFREG => match parent_inode.ops.create(&parent_inode, leaf, perm) {
            Ok(_) => 0,
            Err(e) => e,
        },
        _ => crate::fs::EPERM,
    }
}

/// `mknod(path, mode, dev)` — create a FIFO or regular file at `path`.
pub unsafe fn sys_mknod_impl(path_uva: u64, mode: u64, dev: u64) -> i64 {
    mknod_impl(AT_FDCWD, path_uva, mode as u32, dev)
}

/// `mknodat(dfd, path, mode, dev)` — like `mknod` but relative to `dfd`.
/// Only `AT_FDCWD` and absolute paths are honored today.
pub unsafe fn sys_mknodat_impl(dfd: i32, path_uva: u64, mode: u64, dev: u64) -> i64 {
    mknod_impl(dfd, path_uva, mode as u32, dev)
}

/// Shared body for `mkdir(2)` / `mkdirat(2)`.
///
/// Resolves the parent directory, checks the caller holds `W|X` on it,
/// then dispatches to [`crate::fs::vfs::ops::InodeOps::mkdir`]. Errors
/// are surfaced per RFC 0004 §Kernel-Userspace Interface:
///
/// - `EEXIST` — final component already exists.
/// - `ENOTDIR` — a non-terminal path component is not a directory, or
///   the final component has a trailing slash and the parent isn't one.
/// - `ENOENT` — a path component doesn't exist.
/// - `EACCES` — caller lacks `W|X` on the parent directory.
/// - `ENAMETOOLONG` — path or a component exceeds POSIX caps.
///
/// `ENOTEMPTY` and `EBUSY` are emitted by sibling write-syscalls
/// (rmdir / unlink) that operate on populated / pinned directories;
/// they are mentioned in the errno table for completeness of the
/// POSIX mkdir(2) + rmdir(2) surface but do not arise from mkdir
/// itself.
///
/// Per-process umask application is deferred: this kernel has no
/// umask field on the task struct yet (tracked as a follow-up to
/// RFC 0004 Workstream B). The mode is therefore passed through
/// after masking off non-permission bits (`& 0o7777`), matching
/// how `mknod_impl` handles `mode` today. When umask plumbing lands,
/// the masked mode becomes `mode & ~umask & 0o7777` — a mechanical
/// one-line change here.
fn mkdir_impl(dfd: i32, path_uva: u64, mode: u32) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // `*at` resolution: AT_FDCWD → cwd, real fd → its dentry.
    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // `split_parent` strips a trailing slash from the leaf. Directories
    // are the one kind of thing where a trailing slash on the path is
    // legitimate — `mkdir("/foo/")` is the same as `mkdir("/foo")` per
    // POSIX — so no equivalent of `mknod_impl`'s trailing-slash rejection
    // is needed here.

    // Normalize the leaf first so that invalid leaves (".", "..", "") are
    // rejected with ENOENT (per the PR contract) before any EEXIST fast
    // path gets a chance to classify them. Running `resolve_inode` first
    // would let `/tmp/.` map to the existing `/tmp` inode and return
    // EEXIST, which is the wrong errno.
    let (parent_path, leaf) = match split_parent(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let cred = (*crate::task::current_credentials()).clone();
    // Refuse if the target already exists. The pre-check races with a
    // concurrent creator, but the authoritative check is the FS driver's
    // own duplicate-insert path — RamFs returns EEXIST under the dir
    // rwsem (see `ramfs::InodeOps::mkdir`). The pre-walk just avoids
    // the more expensive permission-check + parent-resolution round-trip
    // when we already know the answer.
    if resolve_inode_at(start.clone(), path, /* follow */ false, cred.clone()).is_ok() {
        return EEXIST;
    }
    let (parent_inode, _pnd) =
        match resolve_inode_at(start, parent_path, /* follow */ true, cred.clone()) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // DAC check: POSIX `mkdir(2)` requires write + search (execute bit
    // on a directory) on the parent. Goes through `InodeOps::permission`
    // so ACL-style overrides can take effect once an FS driver implements
    // them. RFC 0004 Workstream B: caller's per-task credential snapshot
    // drives the check — root bypass falls out of `default_permission`
    // when `cred.euid == 0`.
    let access = Access::WRITE | Access::EXECUTE;
    if let Err(e) = parent_inode.ops.permission(&parent_inode, &cred, access) {
        return e;
    }

    // Strip non-permission bits from `mode` (caller may have spuriously
    // OR'd in S_IF* constants per some libc idioms). The driver is
    // responsible for setting the `S_IFDIR` type bit on the new inode.
    let perm = (mode & 0o7777) as u16;
    match parent_inode.ops.mkdir(&parent_inode, leaf, perm) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `mkdir(path, mode)` — create a directory at `path`.
///
/// Dispatches through [`mkdir_impl`] with `dfd = AT_FDCWD`.
pub unsafe fn sys_mkdir_impl(path_uva: u64, mode: u64) -> i64 {
    mkdir_impl(AT_FDCWD, path_uva, mode as u32)
}

/// `mkdirat(dfd, path, mode)` — like `mkdir` but relative to `dfd`.
///
/// Honors `AT_FDCWD` (use the current working directory) and absolute
/// paths; a real fd with a relative path returns `EINVAL` until
/// per-process fd-rooted walks land (issue #239).
pub unsafe fn sys_mkdirat_impl(dfd: i32, path_uva: u64, mode: u64) -> i64 {
    mkdir_impl(dfd, path_uva, mode as u32)
}

/// `rmdir(path)` — remove an empty directory.
///
/// RFC 0004 — Workstream A: wires the syscall to
/// [`crate::fs::vfs::ops::InodeOps::rmdir`] on the parent directory's
/// inode. The trait implementation is responsible for verifying the
/// target is a directory, that it is empty (non-empty → `-ENOTEMPTY`),
/// taking `dir_rwsem` for the parent, and decrementing the parent's
/// `nlink` for the removed `..` backlink.
///
/// Shaping done here (POSIX deltas that the per-FS op can't see):
/// - Empty path → `-ENOENT`.
/// - Bare `/` → `-EBUSY` (removing the mount root is always refused).
/// - Leaf of `.` (e.g. `rmdir(".")` or `rmdir("foo/.")`) → `-EINVAL`.
/// - Leaf of `..` (e.g. `rmdir("..")` or `rmdir("foo/..")`) →
///   `-ENOTEMPTY`, matching Linux. Kept separate from `.` so callers
///   can tell "current directory" from "parent of".
/// - Parent not a directory → `-ENOTDIR`.
///
/// Credential is the caller's per-task snapshot via
/// [`crate::task::current_credentials`] (RFC 0004 Workstream B, #550).
pub unsafe fn sys_rmdir_impl(path_uva: u64) -> i64 {
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    if path.is_empty() {
        return ENOENT;
    }

    // Collapse *all* trailing slashes so "/foo", "/foo/", and "/foo//"
    // share the leaf check and the parent split. Bare "/" survives as
    // "/" because the loop only strips while `len > 1`.
    let mut trimmed: &[u8] = path;
    while trimmed.len() > 1 && *trimmed.last().unwrap() == b'/' {
        trimmed = &trimmed[..trimmed.len() - 1];
    }

    // `rmdir("/")` never succeeds — the FS root is a mountpoint that
    // cannot be removed. Return EBUSY per Linux's root-removal errno.
    if trimmed == b"/" {
        return crate::fs::EBUSY;
    }

    // Locate the leaf to enforce POSIX's `.` / `..` rejection before
    // committing to a full path walk. The resolver below would
    // otherwise resolve `.` / `..` silently and mis-target an ancestor.
    let leaf_after_slash = trimmed
        .iter()
        .rposition(|&b| b == b'/')
        .map(|i| &trimmed[i + 1..])
        .unwrap_or(trimmed);
    if leaf_after_slash == b"." {
        // POSIX: rmdir(".") is always EINVAL.
        return EINVAL;
    }
    if leaf_after_slash == b".." {
        // Linux: rmdir("..") returns ENOTEMPTY because the parent
        // directory has `.` and children referring back.
        return crate::fs::ENOTEMPTY;
    }

    // Pass the trailing-slash-collapsed path to `split_parent` so the
    // inner strip logic sees a clean leaf (it only peels one slash
    // itself, so multi-slash inputs would otherwise come back with an
    // empty leaf → ENOENT).
    let (parent_path, leaf) = match split_parent(trimmed) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent_inode, _pnd) = match resolve_inode(parent_path, /* follow */ true) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    match parent_inode.ops.rmdir(&parent_inode, leaf) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Shared body for `unlink(2)` / `unlinkat(2)`.
///
/// Resolves the parent directory, splits off the leaf name, then
/// dispatches to `InodeOps::unlink` (default) or `InodeOps::rmdir`
/// (when `AT_REMOVEDIR` is set in `flags`). Enforces the common POSIX
/// pre-checks the trait impls must not each reinvent:
///
/// - Trailing-slash leaf forces directory semantics: non-`AT_REMOVEDIR`
///   `unlink("foo/")` returns `EISDIR` since the caller named a
///   directory explicitly.
/// - A `.` / `..` / empty leaf is rejected upfront via `split_parent`.
/// - The leaf may not itself be a mountpoint — `EBUSY` per POSIX
///   (rmdir/unlink on a mount root is always refused).
/// - Sticky-bit (`S_ISVTX`) on the parent directory forces the caller
///   to own the parent or the target file; root bypasses.
///
/// The body is always compiled — only the syscall *dispatch arms*
/// upstream are gated behind `#[cfg(feature = "vfs_creds")]`. Tests
/// reach this impl directly through `sys_unlink_impl` /
/// `sys_unlinkat_impl`, mirroring the convention `sys_mkdir_impl`
/// established in #585. Until Workstream B flips `vfs_creds` on,
/// ring-3 callers see `-ENOSYS` because the dispatcher's default
/// arm catches the syscall numbers.
fn unlinkat_impl(dfd: i32, path_uva: u64, flags: u32) -> i64 {
    // Only AT_REMOVEDIR is recognised today. Everything else must be
    // whitelisted explicitly so a silent-accept never masks a future
    // flag bit.
    if flags & !AT_REMOVEDIR != 0 {
        return EINVAL;
    }
    let remove_dir = flags & AT_REMOVEDIR != 0;

    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    // `*at` resolution: AT_FDCWD → cwd, real fd → its dentry.
    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Trailing-slash means the caller explicitly named a directory.
    // POSIX unlink(2) on a trailing-slash path returns EISDIR (or
    // ENOTDIR if the final component does not resolve to a directory);
    // Linux picks EISDIR when the named leaf itself is a directory and
    // we mirror that here. `rmdir`/`AT_REMOVEDIR` accepts a trailing
    // slash since that's the POSIX-preferred spelling for directories.
    let trailing_slash = path.len() > 1 && path.last() == Some(&b'/');

    let (parent_path, leaf) = match split_parent(path) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // Resolve the parent (follow symlinks on every intermediate
    // component — standard POSIX behaviour).
    let walk_cred = (*crate::task::current_credentials()).clone();
    let (parent_inode, pnd) =
        match resolve_inode_at(start, parent_path, /* follow */ true, walk_cred) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if parent_inode.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // Resolve the leaf via lookup on the parent so we can run the
    // mountpoint + sticky checks before calling into the FS driver.
    // We intentionally do NOT go back through `path_walk` for the
    // leaf — that would cross a symlink on a symlinked leaf and delete
    // the wrong thing. `unlink`/`rmdir` always act on the name itself.
    let leaf_inode = match parent_inode.ops.lookup(&parent_inode, leaf) {
        Ok(i) => i,
        Err(e) => return e,
    };

    // Mountpoint check: we need the leaf's dentry to inspect `.mount`.
    // `pnd.path.dentry` is the parent-directory dentry after the walk.
    // Look the leaf up in the parent's child cache — if a mount edge
    // is attached to the leaf dentry, refuse with `EBUSY` per POSIX.
    // A miss in the child cache (or a negative entry) means nothing
    // is mounted on the leaf, so there is no mountpoint to refuse.
    if let Ok(leaf_dstr) = crate::fs::vfs::DString::try_from_bytes(leaf) {
        let parent_dentry = pnd.path.dentry.clone();
        let children = parent_dentry.children.read();
        if let Some(crate::fs::vfs::ChildState::Resolved(child)) = children.get(&leaf_dstr) {
            if child.mount.read().is_some() {
                return EBUSY;
            }
        }
    }

    // Kind-based dispatch. `unlink` on a directory is EISDIR; `rmdir`
    // on a non-directory is ENOTDIR. Drivers can still reject on their
    // own, but catching it up front gives a consistent errno across
    // backends.
    if remove_dir {
        if leaf_inode.kind != InodeKind::Dir {
            return ENOTDIR;
        }
    } else {
        if leaf_inode.kind == InodeKind::Dir {
            return EISDIR;
        }
        if trailing_slash {
            // unlink("foo/") where foo is a symlink to a directory is
            // still refused (ENOTDIR on Linux). Here the leaf isn't a
            // directory but the caller named a directory explicitly,
            // so ENOTDIR best describes the mismatch. Unreachable for
            // regular files via split_parent today, but kept as a
            // defensive guard for future resolver behaviour.
            return ENOTDIR;
        }
    }

    // Sticky-bit check. When S_ISVTX is set on the parent, POSIX
    // requires the caller to own either the parent or the target
    // file, or be the super-user. RFC 0004 Workstream B: driven by
    // the caller's per-task credential snapshot. Effective uid is the
    // identity POSIX consults for DAC ownership comparisons.
    let cred = crate::task::current_credentials();
    let parent_meta = parent_inode.meta.read();
    if parent_meta.mode & S_ISVTX != 0 && cred.euid != 0 {
        let leaf_uid = leaf_inode.meta.read().uid;
        if cred.euid != parent_meta.uid && cred.euid != leaf_uid {
            return EPERM;
        }
    }
    drop(parent_meta);

    let r = if remove_dir {
        parent_inode.ops.rmdir(&parent_inode, leaf)
    } else {
        parent_inode.ops.unlink(&parent_inode, leaf)
    };
    match r {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `unlink(path)` — remove a non-directory from its parent. Thin
/// wrapper over [`unlinkat_impl`] with `dfd = AT_FDCWD` and no flags.
///
/// Reachable from ring-3 only when the `vfs_creds` feature is on
/// (the dispatch arm is gated). Tests call this entry point directly
/// to exercise the impl regardless of feature state, mirroring the
/// `sys_mkdir_impl` convention from #585.
pub unsafe fn sys_unlink_impl(path_uva: u64) -> i64 {
    unlinkat_impl(AT_FDCWD, path_uva, 0)
}

/// `unlinkat(dfd, path, flags)` — `unlink` or `rmdir` (when `flags`
/// sets `AT_REMOVEDIR`) relative to `dfd`. `AT_FDCWD` and absolute
/// paths only; a real fd with a relative path returns `EINVAL` until
/// per-fd cwd semantics land (#239).
///
/// Reachable from ring-3 only when `vfs_creds` is on (gated dispatch
/// arm). See [`sys_unlink_impl`] for the test-path convention.
pub unsafe fn sys_unlinkat_impl(dfd: i32, path_uva: u64, flags: u32) -> i64 {
    unlinkat_impl(dfd, path_uva, flags)
}

// ---------------------------------------------------------------------------
// chmod / fchmod / fchmodat + chown / fchown / fchownat / lchown (issue #541)
//
// Wires the POSIX metadata-mutation syscalls to `InodeOps::setattr`. The
// permission model lives here rather than in the per-FS driver so every
// backend (RamFs, TarFs, ext2 when it lands) inherits the same rules —
// drivers only decide how to persist the requested mutation.
//
// Rules (RFC 0004 §Permission model, POSIX.1-2017 §chmod/§chown):
//   - `chmod`: only the file's owner (`euid == meta.uid`) or root
//     (`euid == 0`) may change mode. Anyone else gets `-EPERM`.
//   - `chown`: only root may change `uid`. The owner may change `gid`
//     but only to a group they are a member of (`egid` or
//     `supplementary groups`). Anyone else gets `-EPERM`.
//   - `fchown(fd, -1, -1)` (no-op) returns 0.
//   - `chown` on a regular file by a non-root caller *clears*
//     `S_ISUID` / `S_ISGID` (when exec-group is set) on success, per
//     POSIX and Linux. Root-initiated chown preserves the bits.
//   - `fchmodat(AT_SYMLINK_NOFOLLOW)` is unsupported on Linux for the
//     mode mutation; we accept the flag and ignore it (chmod always
//     follows the symlink) to match Linux's de-facto behaviour.
//   - `fchownat(AT_SYMLINK_NOFOLLOW)` operates on the symlink itself —
//     this is the primitive `lchown` is built on.
// ---------------------------------------------------------------------------

/// `S_ISUID` — set-user-ID bit on a file's mode word. Cleared on a
/// non-root `chown` per POSIX.
const S_ISUID: u16 = 0o4000;
/// `S_ISGID` — set-group-ID bit on a file's mode word. Cleared on a
/// non-root `chown` **only** when the group-exec bit is set (the usual
/// idiom: `S_ISGID` without `S_IXGRP` signals mandatory locking on
/// Linux, not a setgid binary, and must be preserved).
const S_ISGID: u16 = 0o2000;
/// `S_IXGRP` — group-execute bit. Used alongside `S_ISGID` to
/// distinguish a setgid binary (`S_ISGID | S_IXGRP`) from a mandatory-
/// locking marker (`S_ISGID` alone).
const S_IXGRP: u16 = 0o0010;

/// Shared chmod body. Applies `mode & 0o7777` to `inode`'s metadata
/// via `InodeOps::setattr`, after checking the caller owns the file
/// or is root.
///
/// `inode` is the resolved target (post-path-walk for path-based
/// callers, post-fd-lookup for `fchmod`). `cred` is the caller's
/// per-task credential snapshot.
fn do_chmod(inode: &Arc<Inode>, mode: u16, cred: &Credential) -> i64 {
    // Ownership gate. POSIX: only the owner or a process with
    // appropriate privileges (root) may change mode.
    let owner_uid = inode.meta.read().uid;
    if cred.euid != 0 && cred.euid != owner_uid {
        return EPERM;
    }
    let attr = SetAttr {
        mask: SetAttrMask::MODE,
        mode: mode & 0o7777,
        ..SetAttr::default()
    };
    match inode.ops.setattr(inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Shared chown body. Applies `uid` / `gid` changes (when they are not
/// the "don't change" sentinel `u32::MAX`, matching the C `-1` cast)
/// via `InodeOps::setattr`, enforcing POSIX's narrow ownership /
/// group-membership rules.
///
/// Clears the set-user-ID bit (and the set-group-ID bit when group-exec
/// is set) on a regular file whenever the chown is performed by a
/// non-root caller — POSIX §chown. A root-initiated chown preserves
/// the bits.
fn do_chown(inode: &Arc<Inode>, uid: u32, gid: u32, cred: &Credential) -> i64 {
    // Linux / POSIX: -1 (interpreted as u32::MAX) means "don't change".
    let change_uid = uid != u32::MAX;
    let change_gid = gid != u32::MAX;
    if !change_uid && !change_gid {
        // Nothing to do. Per POSIX fchown(2) §Application Usage: this
        // is a success no-op (matches `fchown(fd, -1, -1)`).
        return 0;
    }

    let (cur_uid, cur_gid, cur_mode) = {
        let meta = inode.meta.read();
        (meta.uid, meta.gid, meta.mode)
    };

    // uid-side rules.
    if change_uid {
        // Only root may change the owning uid. An owner is not allowed
        // to "give away" their file to another user.
        if cred.euid != 0 {
            return EPERM;
        }
    }

    // gid-side rules.
    if change_gid {
        if cred.euid != 0 {
            // Non-root: must own the file AND the target gid must be
            // in the caller's group set (egid or supplementary).
            if cred.euid != cur_uid {
                return EPERM;
            }
            let in_group = cred.egid == gid || cred.groups.iter().any(|&g| g == gid);
            if !in_group {
                return EPERM;
            }
        }
    }

    // Compute the post-chown mode. POSIX: a successful chown by a
    // non-root caller clears S_ISUID and (conditionally) S_ISGID on
    // a regular file. The S_ISGID-without-S_IXGRP case is the
    // mandatory-locking marker on Linux and must be preserved.
    let mut new_mode = cur_mode;
    let mut clear_setid = false;
    if inode.kind == InodeKind::Reg && cred.euid != 0 {
        if new_mode & S_ISUID != 0 {
            new_mode &= !S_ISUID;
            clear_setid = true;
        }
        if new_mode & S_ISGID != 0 && new_mode & S_IXGRP != 0 {
            new_mode &= !S_ISGID;
            clear_setid = true;
        }
    }

    let mut mask = SetAttrMask::default();
    if change_uid {
        mask = mask | SetAttrMask::UID;
    }
    if change_gid {
        mask = mask | SetAttrMask::GID;
    }
    if clear_setid {
        mask = mask | SetAttrMask::MODE;
    }
    let attr = SetAttr {
        mask,
        mode: new_mode,
        uid: if change_uid { uid } else { cur_uid },
        gid: if change_gid { gid } else { cur_gid },
        ..SetAttr::default()
    };
    match inode.ops.setattr(inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `fsync(fd)` / `fdatasync(fd)` syscall body. Routed from the dispatch
/// table at `arch::x86_64::syscall::syscall_dispatch` (numbers 74 and 75
/// respectively) and kept in `vfs.rs` because the work is purely
/// VFS-layer plumbing: route the fd to its `OpenFile`, then call
/// [`OpenFile::do_fsync`] which performs the RFC 0007 two-stage flush
/// (page cache writeback then `BlockCache::sync_fs`) and the errseq
/// EIO comparison.
///
/// `data_only=true` is `fdatasync(2)`; `data_only=false` is `fsync(2)`.
/// The full RFC contract (including the `fdatasync` skip-inode-table
/// rule) lives in [`OpenFile::do_fsync`] and the SuperOps `sync_fs`
/// trait body. This wrapper only owns the syscall ABI: validate the
/// fd, fetch the backend, downcast through `as_vfs`, and translate
/// the `Result<(), i64>` to a syscall return value (negated errno on
/// error, zero on success).
///
/// Errno table (matches Linux `fsync(2)`):
///
/// - `EBADF` — `fd` is not an open descriptor in this task's table.
/// - `EINVAL` — `fd` refers to a non-VFS backend (e.g. `SerialBackend`
///   for stdin/stdout/stderr before the userspace init has reopened
///   them through devfs). Linux returns `EINVAL` for `fsync` on a
///   special file that doesn't support synchronisation; we mirror
///   that.
/// - `EIO` — sticky writeback error; the inode's page-cache
///   `wb_err` counter advanced since this `OpenFile`'s last
///   snapshot. Once consumed, the snapshot is caught up so the next
///   call only surfaces *new* errors.
/// - Any errno propagated from `FileOps::fsync` or
///   `SuperOps::sync_fs`.
pub fn sys_fsync_impl(fd_raw: u64, data_only: bool) -> i64 {
    // Reject userspace fds whose high 32 bits are set rather than
    // silently truncating to a low-32-bit fd. `fsync(0x1_0000_0003)`
    // must not collapse to `fsync(3)`; mirroring Linux's `EBADF`
    // behaviour for out-of-range fd arguments.
    if fd_raw > u32::MAX as u64 {
        return EBADF;
    }
    let fd = fd_raw as u32;
    let tbl = crate::task::current_fd_table();
    let backend = match tbl.lock().get(fd) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let vfs = match backend.as_vfs() {
        Some(v) => v,
        // Non-VFS backends (e.g. the legacy SerialBackend hooked up
        // for early-boot stdin/stdout) have nothing to sync. Linux
        // returns `EINVAL` for `fsync(2)` on file descriptors that
        // don't support synchronisation.
        None => return EINVAL,
    };
    match vfs.open_file.do_fsync(data_only) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// Resolve the inode behind an fd for the fchmod/fchown family. Returns
/// `EBADF` on an out-of-range fd, or on any backend that doesn't expose
/// a VFS inode (e.g. a pure `SerialBackend`) since there is nothing to
/// mutate there.
fn fd_to_inode(fd_raw: u64) -> Result<Arc<Inode>, i64> {
    if fd_raw > u32::MAX as u64 {
        return Err(EBADF);
    }
    let fd = fd_raw as u32;
    let tbl = crate::task::current_fd_table();
    let backend = tbl.lock().get(fd).map_err(|_| EBADF)?;
    match backend.as_vfs() {
        Some(v) => Ok(v.open_file.inode.clone()),
        None => Err(EBADF),
    }
}

/// Shared path-mode chmod body. Used by `sys_chmod_impl` and
/// `sys_fchmodat_impl`; `dfd` is honored only for `AT_FDCWD` /
/// absolute paths until per-fd walks land (#239).
fn chmodat_impl(dfd: i32, path_uva: u64, mode: u32, flags: u32) -> i64 {
    // Only `AT_SYMLINK_NOFOLLOW` is a recognised flag for fchmodat on
    // Linux, and even there it is not supported — Linux returns
    // `EOPNOTSUPP`. We mirror Linux's de-facto behaviour: accept the
    // flag bit, but the trailing-symlink semantics are always "follow"
    // (`chmod` on a symlink chases it). Any other bit is rejected so
    // future additions are whitelisted explicitly.
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return EINVAL;
    }
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let cred = crate::task::current_credentials();
    // chmod always resolves through a trailing symlink — the target
    // file is what gets its mode updated. `AT_SYMLINK_NOFOLLOW` on
    // Linux returns EOPNOTSUPP; we accept-and-ignore it for simplicity
    // since the only sensible answer on an in-memory symlink is to
    // follow (there's nothing on a symlink inode to chmod).
    let (inode, _nd) = match resolve_inode_at(start, path, /* follow */ true, (*cred).clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_chmod(&inode, mode as u16, &cred)
}

/// `chmod(path, mode)` — change the mode bits of `path`.
pub unsafe fn sys_chmod_impl(path_uva: u64, mode: u64) -> i64 {
    chmodat_impl(AT_FDCWD, path_uva, mode as u32, 0)
}

/// `fchmod(fd, mode)` — change the mode bits of the file behind an
/// already-open fd.
pub unsafe fn sys_fchmod_impl(fd_raw: u64, mode: u64) -> i64 {
    let inode = match fd_to_inode(fd_raw) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let cred = crate::task::current_credentials();
    do_chmod(&inode, mode as u16, &cred)
}

/// `fchmodat(dfd, path, mode, flags)` — `*at` form of chmod.
pub unsafe fn sys_fchmodat_impl(dfd: i32, path_uva: u64, mode: u64, flags: u32) -> i64 {
    chmodat_impl(dfd, path_uva, mode as u32, flags)
}

/// Shared path-mode chown body. Used by `sys_chown_impl`, `sys_lchown_impl`,
/// and `sys_fchownat_impl`. `follow` controls whether a terminal
/// symlink is chased (chown vs lchown).
fn chownat_impl(dfd: i32, path_uva: u64, uid: u32, gid: u32, flags: u32) -> i64 {
    // `fchownat` only recognises `AT_SYMLINK_NOFOLLOW` today. Future
    // additions like `AT_EMPTY_PATH` need to be whitelisted explicitly.
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return EINVAL;
    }
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let cred = crate::task::current_credentials();
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (inode, _nd) = match resolve_inode_at(start, path, follow, (*cred).clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_chown(&inode, uid, gid, &cred)
}

/// `chown(path, uid, gid)` — change owner/group; follows symlinks.
pub unsafe fn sys_chown_impl(path_uva: u64, uid: u64, gid: u64) -> i64 {
    chownat_impl(AT_FDCWD, path_uva, uid as u32, gid as u32, 0)
}

/// `fchown(fd, uid, gid)` — change owner/group of an open fd's file.
pub unsafe fn sys_fchown_impl(fd_raw: u64, uid: u64, gid: u64) -> i64 {
    let inode = match fd_to_inode(fd_raw) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let cred = crate::task::current_credentials();
    do_chown(&inode, uid as u32, gid as u32, &cred)
}

/// `lchown(path, uid, gid)` — change owner/group; does **not** follow a
/// terminal symlink. Equivalent to
/// `fchownat(AT_FDCWD, path, uid, gid, AT_SYMLINK_NOFOLLOW)`.
pub unsafe fn sys_lchown_impl(path_uva: u64, uid: u64, gid: u64) -> i64 {
    chownat_impl(
        AT_FDCWD,
        path_uva,
        uid as u32,
        gid as u32,
        AT_SYMLINK_NOFOLLOW,
    )
}

/// `fchownat(dfd, path, uid, gid, flags)` — `*at` form of chown.
pub unsafe fn sys_fchownat_impl(dfd: i32, path_uva: u64, uid: u64, gid: u64, flags: u32) -> i64 {
    chownat_impl(dfd, path_uva, uid as u32, gid as u32, flags)
}

// ---------------------------------------------------------------------------
// access / faccessat / faccessat2 (issue #545, RFC 0004 Workstream A wave 1)
//
// `access(2)` lets a caller probe whether they would be permitted to
// open/read/write/execute `path` without actually doing so. The
// distinguishing feature vs. the normal permission path is the use of
// the **real** uid/gid (not effective) — historically intended for
// setuid binaries asking "what could the real user have done?".
//
// `faccessat(dirfd, path, mode, flags)` is the *at form. `AT_EACCESS`
// flips the check back to the effective uid/gid; `AT_SYMLINK_NOFOLLOW`
// stops on a trailing symlink (in which case the resolution naturally
// fails on most callers' use cases — kept for POSIX completeness).
//
// `faccessat2(dirfd, path, mode, flags)` is the Linux extension that
// validates flag bits strictly (rejecting unknown bits with `EINVAL`
// rather than silently masking them). Both implementations here reject
// unknown bits — the codebase's other `*at` syscalls (`fchmodat`,
// `fchownat`, `unlinkat`) follow the same explicit-whitelist
// convention, and matching it keeps a future flag addition from
// silently being a no-op.
// ---------------------------------------------------------------------------

/// Build the credential snapshot the access-check should consult.
///
/// POSIX `access(2)` (and `faccessat(.., 0)`) checks against the
/// caller's **real** uid/gid, not effective. We model that by cloning
/// the per-task credential and overriding the effective IDs — including
/// `euid` and `egid`, which is what `default_permission` actually
/// reads — to mirror the real IDs. The `AT_EACCESS` flag short-circuits
/// this and returns the snapshot unchanged so the effective IDs apply.
///
/// `suid`/`sgid` are intentionally left at their original values: they
/// don't participate in `default_permission` and POSIX never asks the
/// access check to consult them.
fn access_check_credential(cur: &Credential, use_effective: bool) -> Credential {
    if use_effective {
        cur.clone()
    } else {
        Credential::from_task_ids(
            cur.uid,
            cur.uid,
            cur.suid,
            cur.gid,
            cur.gid,
            cur.sgid,
            cur.groups.clone(),
        )
    }
}

/// Translate an `access(2)` mode bitmask into [`Access`] flags.
///
/// Returns `Access::NONE` for `F_OK` (0) — the caller treats that as
/// "skip the permission callback, the path resolve was sufficient".
fn access_mode_to_access(mode: u32) -> Access {
    let mut a = Access::NONE;
    if mode & R_OK != 0 {
        a = a | Access::READ;
    }
    if mode & W_OK != 0 {
        a = a | Access::WRITE;
    }
    if mode & X_OK != 0 {
        a = a | Access::EXECUTE;
    }
    a
}

/// Shared body for `access`, `faccessat`, and `faccessat2`. Returns 0
/// on permitted, negative errno otherwise. Both `faccessat` and
/// `faccessat2` reject unknown flag bits (see module-level comment),
/// so a single body suffices.
fn faccessat_impl(dfd: i32, path_uva: u64, mode: u32, flags: u32) -> i64 {
    // Mode validation: only the low three bits are valid, plus F_OK==0.
    if mode & !(R_OK | W_OK | X_OK) != 0 {
        return EINVAL;
    }
    // Flag validation: only AT_EACCESS, AT_SYMLINK_NOFOLLOW, and
    // AT_EMPTY_PATH are recognised. Any other bit is rejected so a
    // future addition is whitelisted explicitly.
    let allowed = AT_EACCESS | AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if flags & !allowed != 0 {
        return EINVAL;
    }

    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let cur = crate::task::current_credentials();
    let use_effective = flags & AT_EACCESS != 0;
    let check_cred = access_check_credential(&cur, use_effective);

    // The path walk must run under the same credential that will later
    // gate the permission check, so an unsearchable ancestor returns
    // `EACCES` (real ID's view) rather than silently resolving as the
    // effective ID and then failing the leaf check with the wrong
    // errno. `AT_SYMLINK_NOFOLLOW` selects the lstat-style walk — on a
    // terminal symlink the resolved inode *is* the symlink, and
    // `default_permission` against link bits (typically 0o777) makes
    // the answer almost always "yes"; that mirrors Linux.
    let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
    let (inode, _nd) = match resolve_inode_at(start, path, follow, check_cred.clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };

    // F_OK: existence is the answer. Skip the permission callback.
    let access = access_mode_to_access(mode);
    if access == Access::NONE {
        return 0;
    }

    // EROFS short-circuit for W_OK on a read-only mount. Linux does
    // this even when the file's mode bits would grant write — the
    // syscall reports the answer the *next* write would actually get,
    // which is EROFS, not EACCES. Matches `do_faccessat` in the Linux
    // kernel.
    if access.contains(Access::WRITE) {
        if let Some(sb) = inode.sb.upgrade() {
            if sb.flags.contains(crate::fs::vfs::SbFlags::RDONLY) {
                // Per Linux: only block writes to regular files /
                // directories — character devices on a RO mount are
                // still writeable through the device backend, so
                // `access(W_OK)` should not lie about that. RamFs
                // doesn't yet model writable devices on a RO SB so
                // this branch is conservative; revisit if a driver
                // ever needs the carve-out.
                match inode.kind {
                    InodeKind::Reg | InodeKind::Dir | InodeKind::Link => return EROFS,
                    _ => {}
                }
            }
        }
    }

    match inode.ops.permission(&inode, &check_cred, access) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `access(path, mode)` — POSIX.1-2017 §access. Equivalent to
/// `faccessat(AT_FDCWD, path, mode, 0)`. The check uses the caller's
/// **real** uid/gid (not effective).
pub unsafe fn sys_access_impl(path_uva: u64, mode: u64) -> i64 {
    faccessat_impl(AT_FDCWD, path_uva, mode as u32, 0)
}

/// `faccessat(dirfd, path, mode, flags)` — POSIX.1-2017 §faccessat.
///
/// `flags` honors `AT_EACCESS` (use effective IDs),
/// `AT_SYMLINK_NOFOLLOW`, and `AT_EMPTY_PATH`. Unknown bits are
/// rejected with `EINVAL`.
pub unsafe fn sys_faccessat_impl(dfd: i32, path_uva: u64, mode: u64, flags: u32) -> i64 {
    faccessat_impl(dfd, path_uva, mode as u32, flags)
}

/// `faccessat2(dirfd, path, mode, flags)` — Linux extension that adds
/// strict flag-bit validation on top of `faccessat`. Our `faccessat`
/// already rejects unknown flag bits (see module-level comment), so
/// the bodies are identical — the separate entry point exists to give
/// `glibc`'s `faccessat2` shim a stable syscall number.
pub unsafe fn sys_faccessat2_impl(dfd: i32, path_uva: u64, mode: u64, flags: u32) -> i64 {
    faccessat_impl(dfd, path_uva, mode as u32, flags)
}

// ---------------------------------------------------------------------------
// truncate / ftruncate (issue #543)
//
// Wires the POSIX file-length-mutation syscalls to `InodeOps::setattr`
// with `SetAttrMask::SIZE`. Both forms share the same body after path
// vs fd resolution — the shared `do_truncate` enforces common POSIX
// rules (directory → EISDIR, RO mount → EROFS, size > max → EFBIG,
// caller needs `W_OK` on the inode) and then hands off to the driver.
//
// Rules (POSIX.1-2017 §truncate, §ftruncate):
//   - Negative `length` → EINVAL (caller passes a signed off_t).
//   - Target is a directory → EISDIR.
//   - Filesystem is read-only → EROFS.
//   - Caller lacks W_OK on the inode → EACCES (via `InodeOps::permission`).
//     For `truncate`, path-walk intermediates also need search (X_OK);
//     that is enforced by `resolve_inode_as` under the caller's creds.
//   - `length` exceeds the filesystem's maximum → EFBIG.
//   - POSIX: growing a file creates a sparse hole that reads as zero.
//     RamFs fulfils this by zero-filling in `setattr`; ext2 will do the
//     same when it implements `setattr(size)` in Workstream E.
//
// ETXTBSY is not enforced here: the target-is-a-busy-exec-image check
// belongs alongside execve's image pinning, which is #578 territory.
// Leaving a TODO here documents the omission for future work.
// ---------------------------------------------------------------------------

/// Upper bound we accept for a `length` argument, derived from the
/// target inode's superblock.
///
/// The ext2 block-map formula for a 4 KiB-block filesystem tops out at
/// ~2 TiB (direct + single + double + triple indirect). Rather than
/// hard-coding that, we compute it from `sb.block_size`:
///
/// ```text
///   ptrs_per_block = block_size / 4
///   max = (12 + n + n*n + n*n*n) * block_size
/// ```
///
/// where 12 is the ext2 direct-block count. Filesystems whose block
/// size is zero (or otherwise unusable as a divisor) fall back to
/// `i64::MAX as u64`, matching POSIX's "no explicit limit". RamFs sets
/// its block_size to 4096, so the formula still produces a sane cap.
fn max_file_size_for(sb: &SuperBlock) -> u64 {
    let bs = sb.block_size as u64;
    if bs == 0 {
        return i64::MAX as u64;
    }
    let n = bs / 4;
    // Use checked arithmetic end-to-end so an overflow simply saturates
    // to i64::MAX, which is the POSIX `off_t` ceiling we'd clamp against
    // anyway. The branches below keep the formula readable.
    let direct = 12u64.saturating_mul(bs);
    let single = n.saturating_mul(bs);
    let double = n.saturating_mul(n).saturating_mul(bs);
    let triple = n.saturating_mul(n).saturating_mul(n).saturating_mul(bs);
    let total = direct
        .saturating_add(single)
        .saturating_add(double)
        .saturating_add(triple);
    // Cap at i64::MAX so callers who pass the result back through a
    // signed off_t never see it flip negative.
    total.min(i64::MAX as u64)
}

/// Shared truncate body. Takes a resolved inode, a signed `length` (so
/// the caller's EINVAL gate can fire before we get here), and the
/// caller's credential snapshot.
///
/// Callers are responsible for resolving the target — `truncate` walks
/// a path under the caller's creds; `ftruncate` looks up an fd. Once
/// we have the inode, the rules are identical.
fn do_truncate(inode: &Arc<Inode>, length: i64, cred: &Credential) -> i64 {
    // POSIX: negative length is EINVAL. The caller passes `length` as a
    // signed `i64` (x86_64 off_t) so the check lives here, not at the
    // syscall boundary where the raw u64 would hide the sign bit.
    if length < 0 {
        return EINVAL;
    }
    let length = length as u64;

    // Directory target is always EISDIR — POSIX says `truncate` on a
    // directory is undefined, Linux returns EISDIR, and we do too.
    if inode.kind == InodeKind::Dir {
        return EISDIR;
    }

    // Read-only mount: fail early. Drivers on a RO SB also reject via
    // their own setattr (tarfs::setattr returns EROFS unconditionally),
    // but catching it here gives every backend consistent behaviour
    // without the driver round-trip.
    let sb = match inode.sb.upgrade() {
        Some(s) => s,
        None => return ENOENT,
    };
    if sb.flags.contains(crate::fs::vfs::SbFlags::RDONLY) {
        return EROFS;
    }

    // Clamp against the filesystem's maximum file size. Using checked
    // arithmetic: any overflow during the computation saturates to
    // i64::MAX inside `max_file_size_for`, so this comparison never
    // produces a false pass on a pathological block_size.
    let max = max_file_size_for(&sb);
    if length > max {
        return EFBIG;
    }

    // DAC: caller needs W_OK on the inode itself. Goes through
    // `InodeOps::permission` so a driver-level ACL override (when one
    // ever exists) applies uniformly. Path-walk has already verified
    // X_OK on each ancestor under the caller's creds.
    if let Err(e) = inode.ops.permission(inode, cred, Access::WRITE) {
        return e;
    }

    // TODO(#578): ETXTBSY when the target is a currently-executing
    // image. This check lives alongside execve's image pinning, which
    // RamFs cannot detect today. Wire it here once execve exposes a
    // per-inode busy flag.

    let attr = SetAttr {
        mask: SetAttrMask::SIZE,
        size: length,
        ..SetAttr::default()
    };
    match inode.ops.setattr(inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// utimensat / futimens (issue #544, RFC 0004 §Kernel-Userspace Interface)
//
// POSIX.1-2017 §utimensat. The semantics are subtle enough that every
// case is spelled out — see RFC 0004 §"utimensat(2) semantics" for the
// spec we implement.
//
// - `times == NULL` → set atime+mtime to the current wall-clock (same
//   as both-UTIME_NOW).
// - `times[i].tv_nsec == UTIME_NOW`  → set that field to now.
// - `times[i].tv_nsec == UTIME_OMIT` → leave that field unchanged.
// - `flags & AT_SYMLINK_NOFOLLOW`    → do not follow a trailing symlink.
// - ctime is always bumped on a successful update.
//
// Permission matrix (POSIX-required — see RFC 0004 §Permission model):
// - Explicit timestamps (any tv_nsec outside [UTIME_NOW, UTIME_OMIT]):
//   caller must be the file owner or root. Write permission alone is
//   *insufficient* — backdating mtime is an anti-forensics primitive.
//   Non-owner → `EPERM`.
// - UTIME_NOW / `times == NULL`: owner / root always allowed; anyone
//   else needs write permission on the file. Missing both → `EACCES`.
// - UTIME_OMIT on both fields with no other change: permit-and-skip
//   (POSIX lets implementations no-op; we do, and bump ctime only if
//   any real change was requested).
//
// futimens(fd, times) is expressed via the same core helper: the
// standard idiom on Linux is `utimensat(fd, NULL, times, 0)` and our
// dispatcher maps SYS_utimensat with `path_uva == 0` onto `fd`-rooted
// behaviour. A dedicated `sys_futimens_impl` is provided for tests /
// future inline callers.
// ---------------------------------------------------------------------------

/// Linux x86_64 syscall number for `utimensat(2)`. Exposed so integration
/// tests can reach the dispatcher directly without re-hardcoding it.
pub const SYS_UTIMENSAT_NR: u64 = 280;

/// `UTIME_NOW` sentinel for `timespec.tv_nsec`. Matches the Linux /
/// POSIX value: `(1 << 30) - 1`.
pub const UTIME_NOW: u32 = (1 << 30) - 1;

/// `UTIME_OMIT` sentinel for `timespec.tv_nsec`. Matches the Linux /
/// POSIX value: `(1 << 30) - 2`.
pub const UTIME_OMIT: u32 = (1 << 30) - 2;

/// Userspace-visible layout of `struct timespec` on x86_64 Linux: two
/// 8-byte words, `tv_sec` then `tv_nsec`. We copy pairs of these in
/// raw bytes through `uaccess::copy_from_user`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
struct UserTimespec {
    tv_sec: i64,
    tv_nsec: i64,
}

const _: () = {
    assert!(core::mem::size_of::<UserTimespec>() == 16);
    assert!(core::mem::align_of::<UserTimespec>() == 8);
};

/// Resolved per-field request after sentinel classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TimeReq {
    /// Set to the given Timespec.
    Set(Timespec),
    /// Set to current wall-clock ("now").
    Now,
    /// Leave the field unchanged.
    Omit,
}

/// Classify a single user-supplied `timespec` into a [`TimeReq`].
///
/// Rejects out-of-range `tv_nsec` (outside `[0, 1e9)`) unless it is
/// one of the two sentinels — matches Linux's `EINVAL` behaviour.
fn classify_timespec(ts: &UserTimespec) -> Result<TimeReq, i64> {
    // The sentinels use the tv_nsec slot; tv_sec is ignored for them.
    let nsec = ts.tv_nsec as u32;
    if ts.tv_nsec == UTIME_NOW as i64 || nsec == UTIME_NOW {
        return Ok(TimeReq::Now);
    }
    if ts.tv_nsec == UTIME_OMIT as i64 || nsec == UTIME_OMIT {
        return Ok(TimeReq::Omit);
    }
    if ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(EINVAL);
    }
    Ok(TimeReq::Set(Timespec {
        sec: ts.tv_sec,
        nsec: ts.tv_nsec as u32,
    }))
}

/// Copy the two-entry `times[2]` array from user memory. Returns
/// `(TimeReq, TimeReq)` on success; `(Now, Now)` if `times_uva == 0`
/// (the POSIX `times == NULL` spelling).
fn read_times(times_uva: u64) -> Result<(TimeReq, TimeReq), i64> {
    if times_uva == 0 {
        return Ok((TimeReq::Now, TimeReq::Now));
    }
    let mut buf = [0u8; core::mem::size_of::<UserTimespec>() * 2];
    match unsafe { uaccess::copy_from_user(&mut buf, times_uva as usize) } {
        Ok(()) => {}
        Err(e) => return Err(e.as_errno()),
    }
    let a = unsafe { core::ptr::read_unaligned(buf.as_ptr() as *const UserTimespec) };
    let m = unsafe {
        core::ptr::read_unaligned(
            buf.as_ptr().add(core::mem::size_of::<UserTimespec>()) as *const UserTimespec
        )
    };
    Ok((classify_timespec(&a)?, classify_timespec(&m)?))
}

/// True if the caller owns `inode` or is root. Matches the POSIX
/// "appropriate privileges" predicate used by every non-write-perm
/// timestamp path.
fn is_owner_or_root(inode: &Inode, cred: &Credential) -> bool {
    cred.euid == 0 || cred.euid == inode.meta.read().uid
}

/// Enforce the utimensat permission matrix and compute the final
/// `SetAttr` to hand to the FS driver.
///
/// - `atime_req` / `mtime_req` describe what the caller wants for each
///   field (from [`classify_timespec`]).
/// - Explicit-time on either side requires owner/root (`EPERM` else).
/// - UTIME_NOW on either side (including `times == NULL`, surfaced as
///   `(Now, Now)` upstream) is permitted for owner/root OR anyone with
///   write permission on the file (`EACCES` else).
///
/// On a successful call, ctime is always bumped to "now" — POSIX
/// requires it whenever *any* field actually changes. A call whose
/// effect reduces to `(OMIT, OMIT)` returns `Ok(None)`: the caller
/// should short-circuit to success without touching the inode.
fn build_utime_setattr(
    inode: &Inode,
    cred: &Credential,
    atime_req: TimeReq,
    mtime_req: TimeReq,
) -> Result<Option<SetAttr>, i64> {
    let has_explicit = matches!(atime_req, TimeReq::Set(_)) || matches!(mtime_req, TimeReq::Set(_));
    let has_any_write = atime_req != TimeReq::Omit || mtime_req != TimeReq::Omit;

    if !has_any_write {
        // Both fields OMIT — nothing to do, permit unconditionally.
        return Ok(None);
    }

    if has_explicit {
        // Anti-forensics rule: explicit timestamps require ownership.
        // Write permission alone is NOT sufficient.
        if !is_owner_or_root(inode, cred) {
            return Err(EPERM);
        }
    } else {
        // Every non-omit request is UTIME_NOW. Owner/root always OK;
        // otherwise caller needs write permission on the file.
        if !is_owner_or_root(inode, cred) {
            // default_permission (or the driver's override) maps a
            // missing W bit to EACCES.
            if let Err(e) = inode.ops.permission(inode, cred, Access::WRITE) {
                // default_permission returns EACCES for write denial;
                // surface that directly so the errno table holds.
                return Err(e);
            }
        }
    }

    // Resolve each field to a concrete Timespec (or leave it alone).
    let mut mask = SetAttrMask::default();
    let mut attr = SetAttr::default();
    let now = Timespec::now();
    match atime_req {
        TimeReq::Omit => {}
        TimeReq::Now => {
            mask = mask | SetAttrMask::ATIME;
            attr.atime = now;
        }
        TimeReq::Set(ts) => {
            mask = mask | SetAttrMask::ATIME;
            attr.atime = ts;
        }
    }
    match mtime_req {
        TimeReq::Omit => {}
        TimeReq::Now => {
            mask = mask | SetAttrMask::MTIME;
            attr.mtime = now;
        }
        TimeReq::Set(ts) => {
            mask = mask | SetAttrMask::MTIME;
            attr.mtime = ts;
        }
    }
    // ctime always bumped when any field actually changes (POSIX).
    mask = mask | SetAttrMask::CTIME;
    attr.ctime = now;
    attr.mask = mask;
    Ok(Some(attr))
}

/// Core utimensat body. `path_uva == 0` with a real `dfd` means
/// "operate on the file behind `dfd`" — this is how futimens is
/// expressed (glibc: `futimens(fd, times) == utimensat(fd, NULL,
/// times, 0)`). `dfd == AT_FDCWD` with a zero path is rejected with
/// `EFAULT` (no path and no fd).
fn utimensat_impl(dfd: i32, path_uva: u64, times_uva: u64, flags: u32) -> i64 {
    if flags & !AT_SYMLINK_NOFOLLOW != 0 {
        return EINVAL;
    }
    let (atime_req, mtime_req) = match read_times(times_uva) {
        Ok(v) => v,
        Err(e) => return e,
    };

    let cred = crate::task::current_credentials();

    // Resolve the target inode. Two paths:
    //   - `path_uva == 0` with `dfd >= 0`: futimens style — look up by fd.
    //   - otherwise: path-walk under the given dfd.
    let inode: Arc<Inode> = if path_uva == 0 {
        if dfd == AT_FDCWD {
            // POSIX says EFAULT here (null path without a fd).
            return crate::fs::EFAULT;
        }
        match fd_to_inode(dfd as u64) {
            Ok(i) => i,
            Err(e) => return e,
        }
    } else {
        let buf = match copy_user_path(path_uva) {
            Ok(b) => b,
            Err(e) => return e,
        };
        let path = buf.as_slice();
        let start = match resolve_dirfd(dfd) {
            Ok(s) => s,
            Err(e) => return e,
        };
        let follow = flags & AT_SYMLINK_NOFOLLOW == 0;
        let (i, _nd) = match resolve_inode_at(start, path, follow, (*cred).clone()) {
            Ok(v) => v,
            Err(e) => return e,
        };
        i
    };

    let attr = match build_utime_setattr(&inode, &cred, atime_req, mtime_req) {
        Ok(Some(a)) => a,
        // (OMIT, OMIT): POSIX-allowed no-op; return success.
        Ok(None) => return 0,
        Err(e) => return e,
    };

    match inode.ops.setattr(&inode, &attr) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `truncate(path, length)` — set the file at `path` to `length` bytes.
///
/// Follows a trailing symlink (POSIX defines no `AT_SYMLINK_NOFOLLOW`
/// variant for `truncate`). Every path component is walked under the
/// caller's credentials so an unsearchable ancestor surfaces as EACCES
/// from `path_walk` rather than leaking through as a DAC failure on
/// the final inode.
///
/// Reachable from ring-3 only when `vfs_creds` is on (gated dispatch
/// arm). Integration tests exercise the impl directly via
/// `sys_truncate_impl`, mirroring the mkdir/chmod convention.
pub unsafe fn sys_truncate_impl(path_uva: u64, length: i64) -> i64 {
    // Reject the obvious bad args before any path-walk work.
    if length < 0 {
        return EINVAL;
    }
    let buf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = buf.as_slice();

    let cred = crate::task::current_credentials();
    // truncate(2) always follows a trailing symlink.
    let (inode, _nd) = match resolve_inode_as(path, /* follow */ true, (*cred).clone()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    do_truncate(&inode, length, &cred)
}

/// `ftruncate(fd, length)` — set the file behind an open fd to
/// `length` bytes. The fd form skips path-walk entirely; the DAC gate
/// still runs so a read-only fd whose backing inode denies `W_OK` to
/// the caller fails closed.
///
/// Reachable from ring-3 only when `vfs_creds` is on (gated dispatch
/// arm). Integration tests exercise the impl directly.
pub unsafe fn sys_ftruncate_impl(fd_raw: u64, length: i64) -> i64 {
    if length < 0 {
        return EINVAL;
    }
    let inode = match fd_to_inode(fd_raw) {
        Ok(i) => i,
        Err(e) => return e,
    };
    let cred = crate::task::current_credentials();
    do_truncate(&inode, length, &cred)
}

/// `utimensat(dirfd, path, times, flags)` — update atime/mtime on
/// `path` (or on the file behind `dirfd` when `path` is NULL, a.k.a.
/// the futimens idiom).
pub unsafe fn sys_utimensat_impl(dfd: i32, path_uva: u64, times_uva: u64, flags: u32) -> i64 {
    utimensat_impl(dfd, path_uva, times_uva, flags)
}

/// `futimens(fd, times)` — update atime/mtime on an already-open fd.
/// Equivalent to `utimensat(fd, NULL, times, 0)` per POSIX; provided
/// as a standalone entry for tests and future inline callers.
pub unsafe fn sys_futimens_impl(fd_raw: u64, times_uva: u64) -> i64 {
    if fd_raw > i32::MAX as u64 {
        return EBADF;
    }
    utimensat_impl(fd_raw as i32, 0, times_uva, 0)
}

// ---------------------------------------------------------------------
// link / linkat / symlink / symlinkat / readlink / readlinkat
//
// Issue #540, RFC 0004 Workstream A wave 1. Each syscall wires through
// to the existing `InodeOps::link` / `InodeOps::symlink` /
// `InodeOps::readlink` trait method; the per-FS side is already
// implemented for RamFs (ext2 is #570, separate workstream). The
// dispatcher arms in `syscall.rs` are gated behind `vfs_creds` per the
// A-before-B convention established by mkdir/unlink; tests call the
// `sys_*_impl` entry points directly.
// ---------------------------------------------------------------------

/// Shared body for `link(2)` / `linkat(2)`.
///
/// Resolves the source inode (following a terminal symlink only when
/// `AT_SYMLINK_FOLLOW` is set — POSIX defaults to *not* following),
/// splits the new path into parent + leaf, and dispatches to
/// [`crate::fs::vfs::ops::InodeOps::link`] on the new parent.
///
/// Shaping done here (POSIX deltas the per-FS op can't see):
/// - `EPERM` if the source inode is a directory (hard-linking
///   directories is forbidden to all users on every modern POSIX).
/// - `EXDEV` if the source and new-parent live on different
///   superblocks (cross-mount hard-link rejection).
/// - `EEXIST` if the new path already exists (pre-check before the
///   driver re-validates under its own dir-rwsem).
/// - `ENOTDIR` if the new parent is not a directory.
/// - `EINVAL` if unknown flag bits are set in `flags`.
///
/// `EMLINK` (nlink already at `LINK_MAX`), `ENOSPC`, `EIO`, and
/// `EACCES` are surfaced by the FS driver's `link` body. The RFC 0004
/// errno table is therefore fully covered jointly by this arm and
/// the driver.
fn linkat_impl(
    old_dfd: i32,
    old_path_uva: u64,
    new_dfd: i32,
    new_path_uva: u64,
    flags: u32,
) -> i64 {
    // AT_EMPTY_PATH turns `linkat(olddfd, "", newdfd, new, AT_EMPTY_PATH)`
    // into "hard-link the file behind `olddfd`" — we don't support that
    // until fd-rooted walks land (#239), but we still accept the flag in
    // `flags` for forward compatibility. AT_SYMLINK_FOLLOW is the only
    // other recognised bit. Silent-accept of unknown bits would mask
    // future ABI surface, so whitelist strictly.
    if flags & !(AT_SYMLINK_FOLLOW | AT_EMPTY_PATH) != 0 {
        return EINVAL;
    }
    let follow_source = flags & AT_SYMLINK_FOLLOW != 0;
    let empty_path = flags & AT_EMPTY_PATH != 0;

    let old_buf = match copy_user_path(old_path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let old_path = old_buf.as_slice();
    let new_buf = match copy_user_path(new_path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let new_path = new_buf.as_slice();

    // AT_EMPTY_PATH would need fd-as-source semantics that aren't wired
    // here yet — reject with EINVAL until that path lands. Real dirfds
    // for relative paths are now honoured via `resolve_dirfd`.
    if empty_path {
        return EINVAL;
    }
    let old_start = match resolve_dirfd(old_dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };
    let new_start = match resolve_dirfd(new_dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // Resolve the source. Hard-linking names the underlying inode, not
    // the link, so the default is NOT to follow a terminal symlink —
    // but we must NOT error on a terminal symlink either: POSIX default
    // `link(2)` hard-links the symlink itself. `resolve_inode(path,
    // false)` sets `LookupFlags::NOFOLLOW` which returns `ELOOP` on a
    // terminal symlink (correct for `O_NOFOLLOW`, wrong here), so we
    // walk with default flags when the caller asked for the default.
    // `AT_SYMLINK_FOLLOW` flips to POSIX-`link`-style following.
    let walk_cred = (*crate::task::current_credentials()).clone();
    let src_inode = if follow_source {
        match resolve_inode_at(
            old_start.clone(),
            old_path,
            /* follow */ true,
            walk_cred.clone(),
        ) {
            Ok((i, _)) => i,
            Err(e) => return e,
        }
    } else {
        // Manual walk with `LookupFlags::default()` — intermediates still
        // chase through symlinks (so a link under `/var` works when
        // `/var` is itself a symlink), but the terminal component is
        // returned as-is without the NOFOLLOW ELOOP trap.
        let root = match vfs_root() {
            Some(r) => r,
            None => return ENOENT,
        };
        let cwd = if old_path.first() == Some(&b'/') {
            root.clone()
        } else if let Some(d) = old_start.clone() {
            d
        } else {
            crate::task::current_cwd().unwrap_or_else(|| root.clone())
        };
        let flags = LookupFlags::default();
        let mut nd = match NameIdata::new(root, cwd, walk_cred.clone(), flags) {
            Ok(n) => n,
            Err(e) => return e,
        };
        if let Err(e) = path_walk(&mut nd, old_path, &GlobalMountResolver) {
            return e;
        }
        nd.path.inode.clone()
    };

    // Directories are never hard-linkable (EPERM). Check here so every
    // FS backend gets the same errno without each reimplementing it.
    if src_inode.kind == InodeKind::Dir {
        return EPERM;
    }

    // Reject if the new path already exists. This races with a
    // concurrent creator, but the driver re-validates under dir-rwsem
    // and surfaces EEXIST on the losing side either way. Pre-checking
    // lets us skip the parent-resolve round-trip when the answer is
    // already known.
    if resolve_inode_at(
        new_start.clone(),
        new_path,
        /* follow */ false,
        walk_cred.clone(),
    )
    .is_ok()
    {
        return EEXIST;
    }

    let (new_parent_path, new_leaf) = match split_parent(new_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (new_parent, _pnd) = match resolve_inode_at(
        new_start,
        new_parent_path,
        /* follow */ true,
        walk_cred.clone(),
    ) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if new_parent.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // Cross-superblock hard-link rejection (EXDEV). The driver also
    // checks this (see ramfs::link), but catching it here guarantees
    // the errno for every backend and saves the dir-rwsem round-trip.
    let src_sb = src_inode.sb.upgrade();
    let new_sb = new_parent.sb.upgrade();
    match (src_sb, new_sb) {
        (Some(a), Some(b)) if !Arc::ptr_eq(&a, &b) => return EXDEV,
        (None, _) | (_, None) => return ENOENT,
        _ => {}
    }

    // DAC check: writer needs W|X on the new parent directory.
    // RFC 0004 Workstream B: caller's per-task credential snapshot
    // drives the check.
    let cred = (*crate::task::current_credentials()).clone();
    if let Err(e) = new_parent
        .ops
        .permission(&new_parent, &cred, Access::WRITE | Access::EXECUTE)
    {
        return e;
    }

    match new_parent.ops.link(&new_parent, new_leaf, &src_inode) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `link(oldpath, newpath)` — create a hard link `newpath` to the file
/// named by `oldpath`. Source symlinks are **not** followed (POSIX).
///
/// Reachable from ring-3 only when `vfs_creds` is on (the dispatch arm
/// in `syscall.rs` is gated). Tests call this entry point directly.
pub unsafe fn sys_link_impl(old_path_uva: u64, new_path_uva: u64) -> i64 {
    linkat_impl(AT_FDCWD, old_path_uva, AT_FDCWD, new_path_uva, 0)
}

/// `linkat(olddfd, oldpath, newdfd, newpath, flags)` — `*at` form of
/// link. Honors `AT_SYMLINK_FOLLOW` (follow a terminal symlink on
/// `oldpath`) and `AT_EMPTY_PATH` (reserved for fd-rooted walks,
/// rejected today). Only `AT_FDCWD` and absolute paths are honored
/// for the dfd arguments until #239 lands.
pub unsafe fn sys_linkat_impl(
    old_dfd: i32,
    old_path_uva: u64,
    new_dfd: i32,
    new_path_uva: u64,
    flags: u32,
) -> i64 {
    linkat_impl(old_dfd, old_path_uva, new_dfd, new_path_uva, flags)
}

/// Shared body for `symlink(2)` / `symlinkat(2)`.
///
/// The `target` argument is a C string in user memory — **not** a
/// path to be resolved. Per POSIX we store the exact bytes the caller
/// passed (minus the terminating NUL) so `readlink` round-trips them
/// verbatim; intermediate-component resolution happens at
/// path-walk time.
///
/// Shaping done here:
/// - `EEXIST` if the link path already exists.
/// - `ENOTDIR` if the containing directory isn't one.
/// - `ENOENT` on an empty `target` (POSIX behaviour is implementation-
///   defined but Linux returns `ENOENT`).
/// - `ENAMETOOLONG` if `target` exceeds `PATH_MAX`.
fn symlinkat_impl(target_uva: u64, new_dfd: i32, link_path_uva: u64) -> i64 {
    let target_buf = match copy_user_path(target_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let target = target_buf.as_slice();
    if target.is_empty() {
        return ENOENT;
    }

    let link_buf = match copy_user_path(link_path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let link_path = link_buf.as_slice();

    let start = match resolve_dirfd(new_dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    let walk_cred = (*crate::task::current_credentials()).clone();
    if resolve_inode_at(
        start.clone(),
        link_path,
        /* follow */ false,
        walk_cred.clone(),
    )
    .is_ok()
    {
        return EEXIST;
    }

    let (parent_path, leaf) = match split_parent(link_path) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (parent, _pnd) =
        match resolve_inode_at(start, parent_path, /* follow */ true, walk_cred) {
            Ok(v) => v,
            Err(e) => return e,
        };
    if parent.kind != InodeKind::Dir {
        return ENOTDIR;
    }

    // DAC: writer needs W|X on the new parent directory. Caller's
    // per-task credential snapshot drives the check (RFC 0004 §B).
    let cred = (*crate::task::current_credentials()).clone();
    if let Err(e) = parent
        .ops
        .permission(&parent, &cred, Access::WRITE | Access::EXECUTE)
    {
        return e;
    }

    match parent.ops.symlink(&parent, leaf, target) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// `symlink(target, linkpath)` — create a symbolic link `linkpath`
/// whose contents are the bytes of `target`. Target is stored
/// verbatim; it is *not* path-resolved at creation time.
pub unsafe fn sys_symlink_impl(target_uva: u64, link_path_uva: u64) -> i64 {
    symlinkat_impl(target_uva, AT_FDCWD, link_path_uva)
}

/// `symlinkat(target, newdfd, linkpath)` — `*at` form of symlink.
/// Only `AT_FDCWD` and absolute paths are honored until #239 lands.
pub unsafe fn sys_symlinkat_impl(target_uva: u64, new_dfd: i32, link_path_uva: u64) -> i64 {
    symlinkat_impl(target_uva, new_dfd, link_path_uva)
}

/// Shared body for `readlink(2)` / `readlinkat(2)`.
///
/// Resolves `path` **without** following the terminal symlink
/// (`lstat`-style walk), calls `InodeOps::readlink` to copy the
/// target bytes into a kernel staging buffer, then copies at most
/// `bufsize` bytes to the user `buf`.
///
/// POSIX specifics enforced here:
/// - The output is **not** NUL-terminated. The returned length
///   counts bytes written; the caller appends `\0` if it wants a
///   C string.
/// - `EINVAL` if the terminal inode is not a symlink (the default
///   `InodeOps::readlink` body also returns `EINVAL` for non-links,
///   but catching it up front is clearer and skips the trait call).
/// - `EINVAL` if `bufsize` is zero. POSIX allows either `EINVAL` or
///   `0`; Linux returns `EINVAL` and we follow that.
/// - `EFAULT` if the user buffer is not mapped.
/// - `ENAMETOOLONG` is *not* a readlink error — the output is
///   truncated to `bufsize` bytes silently, matching POSIX/Linux.
fn readlinkat_impl(dfd: i32, path_uva: u64, buf_uva: u64, bufsize: u64) -> i64 {
    if bufsize == 0 {
        return EINVAL;
    }
    // Clamp kernel staging to PATH_MAX — any symlink longer than that
    // is already out of spec. `bufsize` can exceed PATH_MAX (userspace
    // convention: pass a generous buffer), we just never stage more
    // than PATH_MAX bytes because no on-disk target can be larger.
    let staging_len = core::cmp::min(bufsize as usize, PATH_MAX);

    let pbuf = match copy_user_path(path_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let path = pbuf.as_slice();

    let start = match resolve_dirfd(dfd) {
        Ok(s) => s,
        Err(e) => return e,
    };

    // readlink(2) / readlinkat(2) operate on the symlink itself, so
    // the terminal component must NOT be followed. `resolve_inode`'s
    // `follow=false` mode sets `LookupFlags::NOFOLLOW`, which makes a
    // terminal symlink return `ELOOP` — that's the right behaviour for
    // `O_NOFOLLOW` but wrong for `readlink`, which must succeed on a
    // terminal symlink. Walk with default flags instead: path_walk
    // only follows a symlink when it is NOT final, so a terminal
    // symlink falls through to the final-checks arm with its own
    // inode on the cursor.
    let root = match vfs_root() {
        Some(r) => r,
        None => return ENOENT,
    };
    let cwd = if path.first() == Some(&b'/') {
        root.clone()
    } else if let Some(d) = start {
        d
    } else {
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let cred = (*crate::task::current_credentials()).clone();
    let flags = LookupFlags::default();
    let mut nd = match NameIdata::new(root, cwd, cred, flags) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = path_walk(&mut nd, path, &GlobalMountResolver) {
        return e;
    }
    let inode = nd.path.inode.clone();
    if inode.kind != InodeKind::Link {
        return EINVAL;
    }

    // Stage into a heap buffer; the user buffer may be unaligned /
    // unmapped, and we must only cross the user/kernel boundary via
    // `copy_to_user`. Fallible allocation → ENOMEM so syscall pressure
    // never panics the kernel.
    let mut staging: Vec<u8> = Vec::new();
    if staging.try_reserve_exact(staging_len).is_err() {
        return ENOMEM;
    }
    staging.resize(staging_len, 0u8);

    let n = match inode.ops.readlink(&inode, &mut staging[..]) {
        Ok(n) => n,
        Err(e) => return e,
    };
    // Defensive clamp: a misbehaving driver might claim it wrote more
    // than the staging buffer. Truncate to the smaller of the reported
    // length and the staging-buffer length.
    let n = core::cmp::min(n, staging.len());

    // Copy exactly `n` bytes to userspace. No NUL terminator — POSIX
    // `readlink` returns the byte count and leaves termination to the
    // caller. Treating the user buffer as "write exactly these bytes"
    // preserves the invariant that a short symlink does not clobber
    // bytes past the returned length.
    if n > 0 {
        if let Err(e) = unsafe { uaccess::copy_to_user(buf_uva as usize, &staging[..n]) } {
            let _ = e;
            return EFAULT;
        }
    }
    n as i64
}

/// `readlink(path, buf, bufsize)` — read the contents of a symlink.
/// Output is **not** NUL-terminated.
pub unsafe fn sys_readlink_impl(path_uva: u64, buf_uva: u64, bufsize: u64) -> i64 {
    readlinkat_impl(AT_FDCWD, path_uva, buf_uva, bufsize)
}

/// `readlinkat(dfd, path, buf, bufsize)` — `*at` form of readlink.
/// Only `AT_FDCWD` and absolute paths are honored until #239 lands.
pub unsafe fn sys_readlinkat_impl(dfd: i32, path_uva: u64, buf_uva: u64, bufsize: u64) -> i64 {
    readlinkat_impl(dfd, path_uva, buf_uva, bufsize)
}

// ---------------------------------------------------------------------------
// mount(2) — issue #575, RFC 0004 §Mount API.
//
// Signature: `mount(source, target, fstype, flags, data)`
//   a0 = source   : *const u8 (may be NULL for pseudo-FSes)
//   a1 = target   : *const u8
//   a2 = fstype   : *const u8
//   a3 = flags    : u64 (MS_RDONLY=0x01, MS_NOSUID=0x02, MS_NODEV=0x04,
//                         MS_NOEXEC=0x08)
//   a4 = data     : *const u8 (ignored — per-FS options not plumbed yet)
// ---------------------------------------------------------------------------

/// Linux `MS_*` bits that `mount(2)` honours in this vibix revision. Any
/// other bit in the flags argument is rejected with `-EINVAL` so a future
/// caller can tell "v1 doesn't support this yet" from "flags ignored".
pub const MS_RDONLY: u64 = 0x0001;
pub const MS_NOSUID: u64 = 0x0002;
pub const MS_NODEV: u64 = 0x0004;
pub const MS_NOEXEC: u64 = 0x0008;
const MS_SUPPORTED: u64 = MS_RDONLY | MS_NOSUID | MS_NODEV | MS_NOEXEC;

/// Copy a NUL-terminated user string at `uva` into a heap buffer. Sized
/// at [`PATH_MAX`]+1 so paths at the boundary still see their NUL. An
/// empty `uva` (0) returns an empty vector — callers map that to
/// [`crate::fs::vfs::MountSource::None`] for source-less FSes.
fn copy_optional_user_string(uva: u64) -> Result<Vec<u8>, i64> {
    if uva == 0 {
        return Ok(Vec::new());
    }
    copy_user_path(uva)
}

/// Max length of the `fstype` name. Linux caps at `PAGE_SIZE`; we use a
/// much tighter bound because the registry is a linear scan over <10
/// entries and a legitimate caller never passes more than a handful of
/// bytes.
const FSTYPE_MAX: usize = 64;

/// Copy the fstype name. Rejects oversized (`-EINVAL`, matching Linux's
/// `mount_fs_str` path for over-long names) and empty names.
fn copy_fstype(uva: u64) -> Result<Vec<u8>, i64> {
    if uva == 0 {
        return Err(EINVAL);
    }
    let mut buf: Vec<u8> = Vec::new();
    buf.try_reserve_exact(FSTYPE_MAX + 1).map_err(|_| ENOMEM)?;
    buf.resize(FSTYPE_MAX + 1, 0u8);
    let n = unsafe { copy_path_from_user_pub(uva as usize, &mut buf) }?;
    buf.truncate(n);
    if buf.is_empty() {
        return Err(EINVAL);
    }
    Ok(buf)
}

/// `mount(source, target, fstype, flags, data)` — RFC 0004 §Mount API.
///
/// Contract:
/// - `euid == 0` only. Non-root callers receive `-EPERM` **before** any
///   path walk or string copy that could leak kernel state.
/// - Unknown flag bits (outside [`MS_SUPPORTED`]) → `-EINVAL`.
/// - Unknown fstype → `-EINVAL` (Linux-conformant).
/// - Target path cannot be resolved → the walk's errno (typically
///   `-ENOENT`).
/// - Target is not a positive directory → `-ENOTDIR`.
/// - Target already has something mounted on it → `-EBUSY` (race-safe:
///   mount_table's own EBUSY path fires if another caller beats us
///   between our pre-check and the publish).
/// - Source resolution failed inside the factory (ext2 wants a block
///   device, none is registered) → factory-returned errno, typically
///   `-ENODEV`.
///
/// `data` is accepted for ABI compatibility but ignored — vibix does
/// not parse per-FS mount options yet.
pub unsafe fn sys_mount_impl(
    source_uva: u64,
    target_uva: u64,
    fstype_uva: u64,
    flags: u64,
    _data_uva: u64,
) -> i64 {
    // 1. Superuser-only. Reject early so a bogus caller cannot even
    //    probe which fstype names exist. Mirrors Linux's CAP_SYS_ADMIN
    //    check at the entry of `ksys_mount`.
    let cred = crate::task::current_credentials();
    if cred.euid != 0 {
        return EPERM;
    }

    // 2. Reject unknown flag bits. A caller that sets `MS_BIND` or
    //    `MS_SHARED` today gets a clean EINVAL rather than a silently
    //    ignored bit that causes divergence when the bit ships later.
    if flags & !MS_SUPPORTED != 0 {
        return EINVAL;
    }
    let mut mflags = crate::fs::vfs::MountFlags::default();
    if flags & MS_RDONLY != 0 {
        mflags = mflags | crate::fs::vfs::MountFlags::RDONLY;
    }
    if flags & MS_NOSUID != 0 {
        mflags = mflags | crate::fs::vfs::MountFlags::NOSUID;
    }
    if flags & MS_NODEV != 0 {
        mflags = mflags | crate::fs::vfs::MountFlags::NODEV;
    }
    if flags & MS_NOEXEC != 0 {
        mflags = mflags | crate::fs::vfs::MountFlags::NOEXEC;
    }

    // 3. Copy the three user strings. `target` and `fstype` are
    //    mandatory; `source` may be NULL for pseudo-filesystems.
    let fstype_buf = match copy_fstype(fstype_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let fstype = match core::str::from_utf8(&fstype_buf) {
        Ok(s) => s,
        Err(_) => return EINVAL,
    };

    // Early-reject unknown fstype before walking the target path. Saves a
    // heap allocation on the common misspelled-name failure path.
    if !crate::fs::vfs::is_registered(fstype) {
        return EINVAL;
    }

    let target_buf = match copy_user_path(target_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if target_buf.is_empty() {
        return ENOENT;
    }

    let source_buf = match copy_optional_user_string(source_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };

    // 4. Resolve the target path to a positive-directory dentry. The
    //    walk uses the caller's credentials so an unsearchable ancestor
    //    fails with `-EACCES`. Root reaches every directory via its
    //    kernel.euid==0 bypass — we've already checked euid==0 above —
    //    so the cred argument is primarily a defensive measure against
    //    a future change that moves the euid gate elsewhere.
    let root = match vfs_root() {
        Some(r) => r,
        None => return ENOENT,
    };
    let cwd = if target_buf.first() == Some(&b'/') {
        root.clone()
    } else {
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let mut nd = match NameIdata::new(
        root,
        cwd,
        (*cred).clone(),
        LookupFlags::default() | LookupFlags::FOLLOW,
    ) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = path_walk(&mut nd, &target_buf, &GlobalMountResolver) {
        return e;
    }
    let target_dentry = nd.path.dentry.clone();

    // Must be a positive directory. `mount_table::mount` checks the same
    // thing under its write lock, but doing it here means the diagnostic
    // `ENOTDIR` fires before the factory allocates driver state.
    {
        let inode_slot = target_dentry.inode.read();
        let inode = match inode_slot.as_ref() {
            Some(i) => i,
            None => return ENOENT,
        };
        if inode.kind != InodeKind::Dir {
            return ENOTDIR;
        }
    }
    if target_dentry.mount.read().is_some() {
        return EBUSY;
    }

    // 5. Build the `MountSource`. `source` may be empty (pseudo-FS) or a
    //    path to a block-device node. Until devfs carries first-class
    //    block-device inodes, a non-empty `source` is just forwarded to
    //    the factory as a `MountSource::Path`; factories that need a
    //    block device (ext2) reach for `block::default_device()` and
    //    return `-ENODEV` if none is registered.
    let msrc = if source_buf.is_empty() {
        crate::fs::vfs::MountSource::None
    } else {
        crate::fs::vfs::MountSource::Path(&source_buf)
    };

    // 6. Build the FS via the registry and mount it.
    let fs = match crate::fs::vfs::lookup_and_build(fstype, msrc) {
        Ok(f) => f,
        Err(e) => return e,
    };
    // Re-materialise the source so `FileSystem::mount` sees the same
    // bytes. Using a second borrow of `source_buf` is fine — the factory
    // call above has returned and the previous borrow is released.
    let msrc2 = if source_buf.is_empty() {
        crate::fs::vfs::MountSource::None
    } else {
        crate::fs::vfs::MountSource::Path(&source_buf)
    };
    match crate::fs::vfs::mount(msrc2, &target_dentry, fs, mflags) {
        Ok(_edge) => 0,
        // Surface `ENODEV` through unchanged (e.g. ext2 factory returned
        // it; fs-side mount could also bubble the same errno for a
        // missing device on the slow path).
        Err(e) if e == ENODEV => ENODEV,
        Err(e) => e,
    }
}

// ---------------------------------------------------------------------------
// umount2(2) — issue #576, RFC 0004 §umount2.
//
// Signature: `umount2(target, flags)`
//   a0 = target : *const u8
//   a1 = flags  : u32 (MNT_FORCE=0x1, MNT_DETACH=0x2, MNT_EXPIRE=0x4
//                      is rejected, UMOUNT_NOFOLLOW=0x8 rejected too)
// ---------------------------------------------------------------------------

/// `MNT_FORCE` — abort in-flight I/O and detach immediately.
pub const MNT_FORCE: u32 = 0x0000_0001;
/// `MNT_DETACH` — lazy unmount. Unlink now, finalize when the last
/// [`SbActiveGuard`] drops.
pub const MNT_DETACH: u32 = 0x0000_0002;

/// Mask of `MNT_*` bits this revision accepts. Unknown bits are
/// rejected with `-EINVAL` so future additions (`MNT_EXPIRE`,
/// `UMOUNT_NOFOLLOW`) can't sneak through as a silently-ignored bit.
const MNT_SUPPORTED: u32 = MNT_FORCE | MNT_DETACH;

/// `umount2(target, flags)` — tear down a mounted filesystem.
///
/// Contract (mirrors Linux `umount2(2)` for the subset vibix
/// implements):
/// - `euid == 0` only — non-root callers see `-EPERM` before any
///   user pointer is dereferenced.
/// - Unknown flag bits → `-EINVAL`.
/// - `MNT_FORCE | MNT_DETACH` is accepted (lazy wins; Phase-B is
///   deferred and the FORCE nested-mount refusal is skipped).
/// - `target` fails to resolve → walk's errno (typically `-ENOENT`).
/// - `target` is not itself the mountpoint of a live mount →
///   `-EINVAL`.
/// - Default flags, SB still pinned → `-EBUSY`.
/// - `MNT_FORCE` without `MNT_DETACH`, nested child mount still
///   present → `-EBUSY`.
///
/// The success path always detaches; Phase-B flush + driver
/// teardown is synchronous for the default / FORCE cases and
/// deferred for DETACH.
/// Walk up parent links from `resolved` until a dentry with a covering
/// mount edge is found, returning that edge's mountpoint dentry.
///
/// This mirrors Linux's `umount2(2)` behaviour where the target may be
/// any path inside a mounted filesystem (e.g. `/mnt/sub/dir`) — the
/// kernel canonicalizes it to the nearest enclosing mount root, then
/// peels back one step via the mount edge to obtain the mountpoint
/// dentry in the parent filesystem (which is what
/// [`crate::fs::vfs::unmount`] needs).
///
/// Errors:
/// - `EBUSY` if the walk reaches `ns_root` without finding a covering
///   edge — that means the caller asked to unmount `/`. Linux mirrors
///   this until `pivot_root` is implemented; vibix follows suit.
/// - `EINVAL` if the covering edge's mountpoint weak-ref is dead
///   (mount is racing a teardown on another thread).
/// - `EINVAL` if a parent link cannot be upgraded, or if a self-parenting
///   non-namespace dentry is reached without a covering edge — neither
///   is reachable in normal operation but both are guarded so the loop
///   cannot spin.
pub fn canonicalize_umount_target(
    resolved: Arc<Dentry>,
    ns_root: &Arc<Dentry>,
    resolver: &dyn MountResolver,
) -> Result<Arc<Dentry>, i64> {
    let mut cur = resolved;
    loop {
        if let Some(edge) = resolver.mount_above(&cur) {
            return edge.mountpoint.upgrade().ok_or(EINVAL);
        }
        if Arc::ptr_eq(&cur, ns_root) {
            return Err(EBUSY);
        }
        let parent = cur.parent.upgrade().ok_or(EINVAL)?;
        if Arc::ptr_eq(&parent, &cur) {
            // Self-parenting dentry that is not `ns_root` — disconnected
            // root with no covering mount edge. Surface as EINVAL rather
            // than looping.
            return Err(EINVAL);
        }
        cur = parent;
    }
}

pub unsafe fn sys_umount2_impl(target_uva: u64, flags: u32) -> i64 {
    // 1. Superuser-only. Mirrors Linux's CAP_SYS_ADMIN gate at the
    //    entry of `path_umount`.
    let cred = crate::task::current_credentials();
    if cred.euid != 0 {
        return EPERM;
    }

    // 2. Reject unknown flag bits.
    if flags & !MNT_SUPPORTED != 0 {
        return EINVAL;
    }

    // 3. Copy the target path. Empty path is -ENOENT, matching the
    //    rest of the VFS surface.
    let target_buf = match copy_user_path(target_uva) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if target_buf.is_empty() {
        return ENOENT;
    }

    // 4. Resolve the target path. We want the mountpoint *dentry*
    //    (the one the mount edge is installed on), not the root of
    //    the mounted filesystem, so the resolver must not cross the
    //    mount into the new filesystem. `path_walk` follows mounts
    //    by default; for umount we walk to the parent directory
    //    and look up the final component without mount-following.
    //
    //    However, Linux `umount2` actually *does* accept a path
    //    that lands on the mounted root and then peels back one
    //    level via `follow_down`. For the vibix subset — where
    //    only one mount currently lives on any given dentry — we
    //    mirror the simpler semantic: walk the path, then look
    //    for `dentry.mount`. If absent, check whether the dentry
    //    is itself a mount root and walk up to its mountpoint via
    //    the global table.
    let root = match vfs_root() {
        Some(r) => r,
        None => return ENOENT,
    };
    let cwd = if target_buf.first() == Some(&b'/') {
        root.clone()
    } else {
        crate::task::current_cwd().unwrap_or_else(|| root.clone())
    };
    let mut nd = match NameIdata::new(
        root,
        cwd,
        (*cred).clone(),
        LookupFlags::default() | LookupFlags::FOLLOW,
    ) {
        Ok(n) => n,
        Err(e) => return e,
    };
    if let Err(e) = path_walk(&mut nd, &target_buf, &GlobalMountResolver) {
        return e;
    }
    let resolved = nd.path.dentry.clone();
    let ns_root = nd.root.clone();

    // 5. Canonicalize the resolved dentry to the dentry that owns the
    //    covering mount edge (issue #636). Pulled into a helper so
    //    host unit tests can exercise the walk without staging a full
    //    `path_walk` + mount table.
    let target_dentry = match canonicalize_umount_target(resolved, &ns_root, &GlobalMountResolver) {
        Ok(d) => d,
        Err(e) => return e,
    };

    // 6. Translate MNT_* to UmountFlags and hand off to the VFS.
    let mut uflags = crate::fs::vfs::UmountFlags::default();
    if flags & MNT_FORCE != 0 {
        uflags = uflags | crate::fs::vfs::UmountFlags::FORCE;
    }
    if flags & MNT_DETACH != 0 {
        uflags = uflags | crate::fs::vfs::UmountFlags::DETACH;
    }

    match crate::fs::vfs::unmount(&target_dentry, uflags) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

#[cfg(test)]
mod mount_tests {
    use super::*;
    use crate::fs::vfs::ops::{FileSystem, MountSource};
    use crate::fs::vfs::registry::{register_filesystem, reset_for_tests};
    use crate::fs::vfs::super_block::{SbFlags, SuperBlock};
    use crate::fs::vfs::{
        alloc_fs_id, FileOps, InodeOps, MountFlags, SetAttr, Stat, StatFs, SuperOps,
    };
    use alloc::boxed::Box;
    use alloc::sync::Arc;

    struct T;
    impl InodeOps for T {
        fn getattr(&self, _i: &crate::fs::vfs::Inode, _o: &mut Stat) -> Result<(), i64> {
            Ok(())
        }
        fn setattr(&self, _i: &crate::fs::vfs::Inode, _a: &SetAttr) -> Result<(), i64> {
            Ok(())
        }
    }
    struct TF;
    impl FileOps for TF {}
    struct TSB;
    impl SuperOps for TSB {
        fn root_inode(&self) -> Arc<crate::fs::vfs::Inode> {
            unreachable!()
        }
        fn statfs(&self) -> Result<StatFs, i64> {
            Ok(Default::default())
        }
        fn unmount(&self) {}
    }

    struct MockFs;
    impl FileSystem for MockFs {
        fn name(&self) -> &'static str {
            "mockfs"
        }
        fn mount(&self, _s: MountSource<'_>, _f: MountFlags) -> Result<Arc<SuperBlock>, i64> {
            let sb = Arc::new(SuperBlock::new(
                alloc_fs_id(),
                Arc::new(TSB),
                "mockfs",
                512,
                SbFlags::default(),
            ));
            let root = Arc::new(crate::fs::vfs::Inode::new(
                1,
                Arc::downgrade(&sb),
                Arc::new(T),
                Arc::new(TF),
                crate::fs::vfs::InodeKind::Dir,
                crate::fs::vfs::InodeMeta {
                    mode: 0o755,
                    nlink: 2,
                    ..Default::default()
                },
            ));
            sb.root.call_once(|| root);
            Ok(sb)
        }
    }

    #[test]
    fn flag_mask_round_trip() {
        // Every supported MS_* bit maps to its MountFlags equivalent.
        assert_eq!(MS_RDONLY, 0x0001);
        assert_eq!(MS_NOSUID, 0x0002);
        assert_eq!(MS_NODEV, 0x0004);
        assert_eq!(MS_NOEXEC, 0x0008);
        assert_eq!(MS_SUPPORTED, 0x000F);
    }

    #[test]
    fn registry_lookup_unknown_returns_einval() {
        reset_for_tests();
        // Pre-condition: nothing registered under this name.
        assert!(!crate::fs::vfs::is_registered("nosuch"));
        let r = crate::fs::vfs::lookup_and_build("nosuch", MountSource::None);
        assert_eq!(r.err(), Some(EINVAL));
    }

    #[test]
    fn registry_lookup_registered_builds_fs() {
        reset_for_tests();
        register_filesystem(
            "mockfs",
            Box::new(|_src| Ok(Arc::new(MockFs) as Arc<dyn FileSystem>)),
        );
        let fs = crate::fs::vfs::lookup_and_build("mockfs", MountSource::None).expect("registered");
        assert_eq!(fs.name(), "mockfs");
    }
}
