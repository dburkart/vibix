//! Per-process file-descriptor table and file-backend abstraction.
//!
//! This module is a thin adapter between syscalls and the filesystem layer
//! that lives in [`vfs`]. The real name→inode lookup, mount table, dentry
//! cache, and concrete filesystems (`ramfs`, `tarfs`, `devfs`) are implemented
//! there; everything in this file is just the per-process fd array plus the
//! small [`FileBackend`] trait that hides whether a given fd is path-opened
//! (VFS-backed via [`vfs::VfsBackend`]) or synthetic (`SerialBackend` for
//! stdio, test stubs in unit tests).
//!
//! See [`docs/RFC/0002-virtual-filesystem.md`] for the overall design.
//!
//! The module is split into:
//! - Core types (`FileBackend`, `FileDescription`, `FileDescTable`) — compiled
//!   for both `target_os = "none"` and host unit tests.
//! - `SerialBackend` + `FileDescTable::new_with_stdio()` — compiled for
//!   `target_os = "none"` only (require port I/O and the serial subsystem).
//! - [`vfs`] — the real filesystem layer, compiled for `target_os = "none"`.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::poll::{PollMask, PollTable, DEFAULT_POLLMASK};

#[cfg(target_os = "none")]
pub mod vfs;

/// ext2 filesystem driver — on-disk types today; trait impls land in
/// sibling Workstream D/E issues per RFC 0004.
///
/// Compiled for both `target_os = "none"` (kernel) and host unit tests
/// so `cargo test --lib` can round-trip the on-disk types against the
/// `mkfs.ext2` golden fixture.
#[cfg(any(test, target_os = "none"))]
pub mod ext2;

/// I/O dispatch interface for a single open file description.
///
/// Implementations must be `Send + Sync` so that `Arc<dyn FileBackend>` can
/// be shared across the process fd table.
pub trait FileBackend: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64>;
    fn write(&self, buf: &[u8]) -> Result<usize, i64>;

    /// Device-specific control. `cmd` follows Linux's `_IOC` encoding; `arg`
    /// is the third `ioctl(2)` argument, typically a userspace pointer. The
    /// default returns `-ENOTTY`, which POSIX defines as "inappropriate ioctl
    /// for device" — the correct error for fds that expose no `ioctl` surface.
    fn ioctl(&self, _cmd: u32, _arg: usize) -> Result<i64, i64> {
        Err(ENOTTY)
    }

    /// Report the backend's current readiness for `sys_poll`/`select`.
    ///
    /// Called in both passes of RFC 0003's two-pass poll (see
    /// `docs/RFC/0003-pipes-poll-tty.md` §"Poll table"). The default
    /// implementation returns [`DEFAULT_POLLMASK`] — read and write both
    /// ready — matching Linux's `DEFAULT_POLLMASK` for drivers that lack
    /// a `.poll` file-op. Backends that own a `WaitQueue`
    /// (pipes, ttys, sockets) override this to publish real readiness
    /// and to register the passed-in `PollTable` on their wait queues
    /// during the Wait pass.
    ///
    /// Today `PollTable::register` does not yet exist — it lands with
    /// `WaitQueue` in issue #369 — so this hook currently has no
    /// behavioural effect beyond reporting the default mask.
    fn poll(&self, _pt: &mut PollTable) -> PollMask {
        DEFAULT_POLLMASK
    }

    /// Reposition the shared file offset per POSIX `lseek(2)`.
    ///
    /// `whence` follows the Linux ABI (`SEEK_SET`=0, `SEEK_CUR`=1,
    /// `SEEK_END`=2). The default returns `ESPIPE`, which is the correct
    /// answer for pipes, FIFOs, sockets, and any other backend that has
    /// no random-access offset — matching the Linux behaviour for drivers
    /// without a `.llseek` file-op. Backends over seekable objects
    /// (VFS-backed regular files) override this.
    fn lseek(&self, _off: i64, _whence: i32) -> Result<i64, i64> {
        Err(ESPIPE)
    }

    /// Read directory entries into `buf` in Linux `linux_dirent64` format.
    ///
    /// Each call appends as many whole records as fit and advances the
    /// backend's internal cursor (for VFS-backed dirs, the shared
    /// `OpenFile.offset`). Returns the number of bytes written, or `0` at
    /// end-of-directory. The default returns `ENOTDIR` — the correct error
    /// for any backend that is not a directory.
    fn getdents64(&self, _buf: &mut [u8]) -> Result<usize, i64> {
        Err(ENOTDIR)
    }

    /// Downcast to [`vfs::VfsBackend`] for fd-keyed syscalls that need the
    /// underlying `OpenFile` (e.g. `fstat`, `fstatat` with `AT_EMPTY_PATH`).
    /// Non-VFS backends (`SerialBackend`, test stubs) return `None` and
    /// trigger the caller's `-EINVAL`/`-ENOTTY` path.
    #[cfg(target_os = "none")]
    fn as_vfs(&self) -> Option<&vfs::VfsBackend> {
        None
    }

    /// Propagate mutable open-file status flags into backend-local state.
    ///
    /// Called from [`FileDescTable::set_status_flags`] after the
    /// `FileDescription.flags` CAS succeeds. `new_flags` is the full
    /// post-update flag word (the description's canonical value) so that
    /// backends holding a duplicate atomic (e.g. pipes' `nonblocking`) can
    /// synchronise their own bits without re-deriving them.
    ///
    /// Only `O_APPEND`, `O_NONBLOCK`, and `O_ASYNC` will ever change here —
    /// POSIX pins the other bits. The default is a no-op, which is correct
    /// for backends that either read the description's flags directly on
    /// every I/O (regular files snap `O_APPEND` from `OpenFile.flags`) or
    /// that simply don't care about status flags (serial stdio).
    fn set_flags(&self, _new_flags: u32) {}
}

/// Open-file flags. Values match the Linux x86_64 ABI exactly so userspace
/// binaries built against Linux headers link against vibix without shims.
///
/// The canonical table lives in `docs/RFC/0002-virtual-filesystem.md`
/// §Kernel–Userspace Interface. Each constant below carries a `0o…` octal
/// literal in the same form Linux uses in `<asm-generic/fcntl.h>`.
pub mod flags {
    /// Open for reading only. (Access-mode bits occupy the low two bits.)
    pub const O_RDONLY: u32 = 0o0;
    /// Open for writing only.
    pub const O_WRONLY: u32 = 0o1;
    /// Open for reading and writing.
    pub const O_RDWR: u32 = 0o2;
    /// Mask for the two low access-mode bits.
    pub const O_ACCMODE: u32 = 0o3;
    /// Create the file if it does not exist.
    pub const O_CREAT: u32 = 0o100;
    /// With `O_CREAT`: fail with `EEXIST` if the file already exists.
    pub const O_EXCL: u32 = 0o200;
    /// Truncate a regular file to zero length on open.
    pub const O_TRUNC: u32 = 0o1000;
    /// Write offset is seeked to end-of-file atomically before each write.
    pub const O_APPEND: u32 = 0o2000;
    /// Non-blocking I/O on fifos, sockets, and character devices.
    pub const O_NONBLOCK: u32 = 0o4000;
    /// 0o20000 = 0x2000 = 8192
    pub const O_ASYNC: u32 = 0o20000;
    /// Require the resolved path to refer to a directory (`ENOTDIR` if not).
    pub const O_DIRECTORY: u32 = 0o200000;
    /// Do not follow a symlink in the final path component (`ELOOP`).
    pub const O_NOFOLLOW: u32 = 0o400000;
    /// Do not acquire the opened tty as the caller session's controlling
    /// terminal. Linux convention: `open(tty, !O_NOCTTY)` on a session
    /// leader with no ctty implicitly attaches; `O_NOCTTY` suppresses.
    pub const O_NOCTTY: u32 = 0o400;
    /// Close this fd on the next `exec()`.
    pub const O_CLOEXEC: u32 = 0o2000000;
    /// Open a stat-only fd (no I/O permitted).
    pub const O_PATH: u32 = 0o10000000;
    /// Create an unnamed temporary file (defined for Linux ABI parity; not
    /// yet honored by `sys_open`, which currently masks unsupported bits).
    pub const O_TMPFILE: u32 = 0o20200000;

    // Compile-time pins against the Linux x86_64 numeric values. If any of
    // these change the syscall ABI silently diverges, so we fail to build.
    const _: () = assert!(O_RDONLY == 0);
    const _: () = assert!(O_WRONLY == 1);
    const _: () = assert!(O_RDWR == 2);
    const _: () = assert!(O_ACCMODE == 3);
    const _: () = assert!(O_CREAT == 0x40);
    const _: () = assert!(O_EXCL == 0x80);
    const _: () = assert!(O_TRUNC == 0x200);
    const _: () = assert!(O_APPEND == 0x400);
    const _: () = assert!(O_NONBLOCK == 0x800);
    const _: () = assert!(O_DIRECTORY == 0x10000);
    const _: () = assert!(O_NOFOLLOW == 0x20000);
    const _: () = assert!(O_CLOEXEC == 0x80000);
    const _: () = assert!(O_PATH == 0x200000);
    const _: () = assert!(O_TMPFILE == 0x410000);
}

/// Kernel-side open-file description.
///
/// Shared across duplicate fds (via `Arc` refcounting) — `dup()` bumps the
/// count; the last `close()` drops it.
pub struct FileDescription {
    pub backend: Arc<dyn FileBackend>,
    /// OFD status flags (access mode + mutable bits like `O_APPEND`,
    /// `O_NONBLOCK`, `O_ASYNC`). Interior-mutable so `fcntl(F_SETFL)` can
    /// mutate them through the `Arc` shared by dup'd fds — POSIX requires
    /// the change to be visible on every fd that aliases this description.
    pub flags: AtomicU32,
}

impl FileDescription {
    /// Construct a new description with initial status `flags`.
    pub fn new(backend: Arc<dyn FileBackend>, flags: u32) -> Self {
        Self {
            backend,
            flags: AtomicU32::new(flags),
        }
    }
}

/// Maximum number of simultaneously open fds per process.
const MAX_FD: usize = 1024;

/// `fcntl(2)` commands. Numeric values match the Linux x86_64 ABI
/// (`<asm-generic/fcntl.h>`). `F_DUPFD_CLOEXEC` is Linux-only (since 2.6.24)
/// but widely relied on.
pub const F_DUPFD: u32 = 0;
pub const F_GETFD: u32 = 1;
pub const F_SETFD: u32 = 2;
pub const F_GETFL: u32 = 3;
pub const F_SETFL: u32 = 4;
pub const F_DUPFD_CLOEXEC: u32 = 1030;

/// Per-fd flag returned by `F_GETFD` / accepted by `F_SETFD`. Internally
/// stored as `flags::O_CLOEXEC`.
pub const FD_CLOEXEC: u32 = 1;

/// Linux errno constants (negated so they match syscall return values).
pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const EINTR: i64 = -4;
pub const EIO: i64 = -5;
pub const ENXIO: i64 = -6;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EBUSY: i64 = -16;
pub const EEXIST: i64 = -17;
pub const EXDEV: i64 = -18;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const EISDIR: i64 = -21;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENOTTY: i64 = -25;
pub const EFBIG: i64 = -27;
pub const ENOSPC: i64 = -28;
pub const ESPIPE: i64 = -29;
pub const EROFS: i64 = -30;
pub const EPIPE: i64 = -32;
pub const ENAMETOOLONG: i64 = -36;
pub const ENOTEMPTY: i64 = -39;
pub const ELOOP: i64 = -40;
pub const EOVERFLOW: i64 = -75;

/// Per-process file-descriptor array.
///
/// Each open slot holds `(description, fd_flags)`:
/// - `description` — the shared open-file description (backend + access mode).
/// - `fd_flags` — **per-fd** flags, currently only `O_CLOEXEC` / `FD_CLOEXEC`.
///   These must NOT live on `FileDescription` because `dup()` clones the
///   `Arc<FileDescription>`, but POSIX requires `dup()`-created fds to start
///   with `FD_CLOEXEC` cleared.
///
/// `slots[fd]` is `Some((Arc<FileDescription>, u32))` when `fd` is open, `None`
/// otherwise. The array grows lazily; unallocated entries past the current
/// length are implicitly closed.
pub struct FileDescTable {
    slots: Vec<Option<(Arc<FileDescription>, u32)>>,
}

impl FileDescTable {
    /// Create an empty table with no open fds.
    pub fn new() -> Self {
        FileDescTable { slots: Vec::new() }
    }

    /// Create a table with fds 0 (stdin), 1 (stdout), 2 (stderr) pre-wired
    /// to the supplied backends.
    pub fn new_with_backends(
        stdin: Arc<dyn FileBackend>,
        stdout: Arc<dyn FileBackend>,
        stderr: Arc<dyn FileBackend>,
    ) -> Self {
        let mut t = Self::new();
        t.slots.push(Some((
            Arc::new(FileDescription::new(stdin, flags::O_RDONLY)),
            0,
        )));
        t.slots.push(Some((
            Arc::new(FileDescription::new(stdout, flags::O_WRONLY)),
            0,
        )));
        t.slots.push(Some((
            Arc::new(FileDescription::new(stderr, flags::O_WRONLY)),
            0,
        )));
        t
    }

    /// Shallow-clone the fd table for `fork()`.
    ///
    /// The child's slots hold `Arc` clones of the parent's open-file
    /// descriptions, so they share the same backend. Closing an fd in one
    /// process does not affect the other.
    pub fn clone_for_fork(&self) -> Self {
        FileDescTable {
            slots: self.slots.clone(),
        }
    }

    /// Close every fd whose per-fd `FD_CLOEXEC` flag is set. Called by the
    /// `exec()` path.
    ///
    /// `FD_CLOEXEC` is a per-fd attribute stored in the slot's `fd_flags`,
    /// not in `FileDescription.flags`, so `dup()`-created fds (which share
    /// the same `Arc<FileDescription>`) are not affected.
    pub fn close_cloexec(&mut self) {
        for slot in self.slots.iter_mut() {
            if let Some((_, fd_flags)) = slot {
                if *fd_flags & flags::O_CLOEXEC != 0 {
                    *slot = None;
                }
            }
        }
    }

    /// Allocate the lowest free fd slot and return its number.
    ///
    /// `fd_flags` holds per-fd flags (e.g. `O_CLOEXEC`). These are stored
    /// separately from `FileDescription.flags` so that `dup()` can clear
    /// `FD_CLOEXEC` on the new fd without affecting the original.
    ///
    /// Returns `EMFILE` if all `MAX_FD` slots are occupied.
    pub fn alloc_fd_with_flags(
        &mut self,
        desc: Arc<FileDescription>,
        fd_flags: u32,
    ) -> Result<u32, i64> {
        for (i, slot) in self.slots.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some((desc, fd_flags));
                return Ok(i as u32);
            }
        }
        if self.slots.len() >= MAX_FD {
            return Err(EMFILE);
        }
        let fd = self.slots.len() as u32;
        self.slots.push(Some((desc, fd_flags)));
        Ok(fd)
    }

    /// Allocate with no per-fd flags. Convenience wrapper for callers that
    /// do not need `O_CLOEXEC` on the new fd.
    pub fn alloc_fd(&mut self, desc: Arc<FileDescription>) -> Result<u32, i64> {
        self.alloc_fd_with_flags(desc, 0)
    }

    /// Release fd `fd`. Returns `EBADF` if the fd was not open.
    pub fn close_fd(&mut self, fd: u32) -> Result<(), i64> {
        match self.slots.get_mut(fd as usize) {
            Some(slot @ Some(_)) => {
                *slot = None;
                Ok(())
            }
            _ => Err(EBADF),
        }
    }

    /// Return a clone of the backend for `fd`, or `EBADF` if not open.
    pub fn get(&self, fd: u32) -> Result<Arc<dyn FileBackend>, i64> {
        self.slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .map(|(d, _)| d.backend.clone())
            .ok_or(EBADF)
    }

    /// Return `true` if `fd` is currently open.
    pub fn is_open(&self, fd: u32) -> bool {
        self.slots
            .get(fd as usize)
            .map(Option::is_some)
            .unwrap_or(false)
    }

    fn get_desc(&self, fd: u32) -> Result<Arc<FileDescription>, i64> {
        self.slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .map(|(d, _)| d.clone())
            .ok_or(EBADF)
    }

    /// Duplicate `oldfd` to the lowest free fd. Returns the new fd number.
    ///
    /// The new fd starts with `FD_CLOEXEC` cleared, as required by POSIX
    /// (dup-created fds do not inherit the close-on-exec flag).
    pub fn dup(&mut self, oldfd: u32) -> Result<u32, i64> {
        let desc = self.get_desc(oldfd)?;
        // fd_flags = 0: new fd has FD_CLOEXEC cleared (POSIX dup semantics).
        self.alloc_fd_with_flags(desc, 0)
    }

    /// Return the open-file description's status flags for `fd`
    /// (`fcntl(fd, F_GETFL)`).
    pub fn get_status_flags(&self, fd: u32) -> Result<u32, i64> {
        let desc = self.get_desc(fd)?;
        Ok(desc.flags.load(Ordering::Relaxed))
    }

    /// Mutate the open-file description's status flags for `fd`
    /// (`fcntl(fd, F_SETFL, flags)`).
    ///
    /// Per POSIX only `O_APPEND`, `O_NONBLOCK`, and `O_ASYNC` are writable;
    /// other bits in `new_flags` are silently ignored, and the access-mode
    /// plus creation-time bits already on the description are preserved.
    pub fn set_status_flags(&mut self, fd: u32, new_flags: u32) -> Result<(), i64> {
        let desc = self.get_desc(fd)?;
        let mutable = flags::O_APPEND | flags::O_NONBLOCK | flags::O_ASYNC;
        // Atomic swap under a tight loop so concurrent `F_SETFL` callers on
        // dup'd fds can't lose each other's edits.
        let mut cur = desc.flags.load(Ordering::Relaxed);
        let mut desired = loop {
            let next = (cur & !mutable) | (new_flags & mutable);
            match desc
                .flags
                .compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break next,
                Err(observed) => cur = observed,
            }
        };
        // POSIX requires the status-flag change to take effect on live I/O
        // through the description — backends that cache flag state (pipes'
        // `nonblocking`, VFS files' `OpenFile.flags`) need to observe the
        // edit before the next read/write, not only after the next dup or
        // fork. Hand the post-update flag word to the backend's hook now.
        //
        // Winning the CAS does not guarantee our `backend.set_flags(desired)`
        // runs before a later, concurrent `F_SETFL` also wins its CAS and
        // mirrors — if thread A wins the CAS with `desired_A`, is preempted,
        // and thread B wins with `desired_B` and mirrors, A resuming here
        // would overwrite the backend with the stale `desired_A`. Re-check
        // the live atomic after mirroring and, if a newer edit has landed,
        // re-mirror with that value. The loop converges because each
        // iteration's mirror reflects the flag word observed after the
        // previous CAS, so the final mirror always matches the winning
        // atomic state regardless of scheduler order.
        loop {
            desc.backend.set_flags(desired);
            let observed = desc.flags.load(Ordering::Relaxed);
            if observed == desired {
                break;
            }
            desired = observed;
        }
        Ok(())
    }

    /// Return the per-fd flags for `fd` (`fcntl(fd, F_GETFD)`).
    ///
    /// Today the only defined per-fd flag is `FD_CLOEXEC` (bit 0). Internally
    /// we store it as `flags::O_CLOEXEC` in the slot's `fd_flags`; this
    /// method translates it to the userspace `FD_CLOEXEC` bit.
    pub fn get_fd_flags(&self, fd: u32) -> Result<u32, i64> {
        let (_, fd_flags) = self
            .slots
            .get(fd as usize)
            .and_then(Option::as_ref)
            .ok_or(EBADF)?;
        if *fd_flags & flags::O_CLOEXEC != 0 {
            Ok(FD_CLOEXEC)
        } else {
            Ok(0)
        }
    }

    /// Mutate the per-fd flags for `fd` (`fcntl(fd, F_SETFD, flags)`).
    ///
    /// Accepts the userspace `FD_CLOEXEC` bit and translates it to the
    /// internal `O_CLOEXEC` storage. Other bits in `new_flags` are silently
    /// ignored (Linux behaviour).
    pub fn set_fd_flags(&mut self, fd: u32, new_flags: u32) -> Result<(), i64> {
        let slot = self
            .slots
            .get_mut(fd as usize)
            .and_then(Option::as_mut)
            .ok_or(EBADF)?;
        if new_flags & FD_CLOEXEC != 0 {
            slot.1 |= flags::O_CLOEXEC;
        } else {
            slot.1 &= !flags::O_CLOEXEC;
        }
        Ok(())
    }

    /// Allocate the lowest free fd `>= min_fd` and duplicate `oldfd` into
    /// it. Backs `fcntl(oldfd, F_DUPFD, min_fd)` and
    /// `fcntl(oldfd, F_DUPFD_CLOEXEC, min_fd)`.
    ///
    /// Returns `EINVAL` if `min_fd >= MAX_FD`, `EMFILE` when the table is
    /// full, and `EBADF` if `oldfd` is not open.
    pub fn dupfd_from(&mut self, oldfd: u32, min_fd: u32, cloexec: bool) -> Result<u32, i64> {
        if min_fd as usize >= MAX_FD {
            return Err(EINVAL);
        }
        let desc = self.get_desc(oldfd)?;
        let fd_flags = if cloexec { flags::O_CLOEXEC } else { 0 };
        // Search existing slots from `min_fd` upward for a hole.
        if (min_fd as usize) < self.slots.len() {
            for (i, slot) in self.slots.iter_mut().enumerate().skip(min_fd as usize) {
                if slot.is_none() {
                    *slot = Some((desc, fd_flags));
                    return Ok(i as u32);
                }
            }
        }
        // No hole at or after `min_fd`; extend the vec, padding with holes
        // from the current end up to `min_fd`, then push.
        if self.slots.len() >= MAX_FD {
            return Err(EMFILE);
        }
        while self.slots.len() < min_fd as usize {
            self.slots.push(None);
        }
        let fd = self.slots.len() as u32;
        self.slots.push(Some((desc, fd_flags)));
        Ok(fd)
    }

    /// Make `newfd` an alias for `oldfd`'s description. Returns `newfd`.
    ///
    /// - If `newfd == oldfd` and it is open, returns `newfd` without any
    ///   change.
    /// - If `newfd` was already open, it is closed silently before
    ///   reassignment (POSIX `dup2` semantics).
    /// - Returns `EBADF` if `oldfd` is not open.
    /// - Returns `EINVAL` if `newfd >= MAX_FD`.
    ///
    /// The new fd starts with `FD_CLOEXEC` cleared (POSIX `dup2` semantics).
    pub fn dup2(&mut self, oldfd: u32, newfd: u32) -> Result<u32, i64> {
        if newfd as usize >= MAX_FD {
            return Err(EINVAL);
        }
        if oldfd == newfd {
            // Verify oldfd is open (return EBADF if not).
            self.get_desc(oldfd)?;
            return Ok(newfd);
        }
        let desc = self.get_desc(oldfd)?;
        // Extend the slot vector if `newfd` is beyond the current length.
        while self.slots.len() <= newfd as usize {
            self.slots.push(None);
        }
        // fd_flags = 0: new fd has FD_CLOEXEC cleared (POSIX dup2 semantics).
        self.slots[newfd as usize] = Some((desc, 0));
        Ok(newfd)
    }

    /// Like [`dup2`], but:
    /// - Returns `EINVAL` if `oldfd == newfd` (POSIX `dup3`).
    /// - Accepts a `flags` argument; only `O_CLOEXEC` is legal. Any other
    ///   bit returns `EINVAL`. When `O_CLOEXEC` is set, `newfd` is created
    ///   with `FD_CLOEXEC`; the source fd's per-fd flags are untouched.
    ///
    /// Returns `EBADF` if `oldfd` is not open, `EINVAL` if
    /// `newfd >= MAX_FD`.
    pub fn dup3(&mut self, oldfd: u32, newfd: u32, flags: u32) -> Result<u32, i64> {
        if oldfd == newfd {
            return Err(EINVAL);
        }
        if flags & !flags::O_CLOEXEC != 0 {
            return Err(EINVAL);
        }
        if newfd as usize >= MAX_FD {
            return Err(EINVAL);
        }
        let desc = self.get_desc(oldfd)?;
        while self.slots.len() <= newfd as usize {
            self.slots.push(None);
        }
        let fd_flags = if flags & flags::O_CLOEXEC != 0 {
            flags::O_CLOEXEC
        } else {
            0
        };
        self.slots[newfd as usize] = Some((desc, fd_flags));
        Ok(newfd)
    }
}

// ---------------------------------------------------------------------------
// SerialBackend — only compiled for the kernel target (requires port I/O).
// ---------------------------------------------------------------------------

/// Serial (COM1) backend.
///
/// Used as the backend for fds 0/1/2. Stdio bypasses the VFS on purpose:
/// every task gets a direct [`SerialBackend`] so console I/O works even
/// before `/dev/console` is wired up in `devfs`.
///
/// Holds a per-backend [`tty::termios::Termios`] so userspace
/// `tcgetattr`/`tcsetattr` (via `TCGETS`/`TCSETS` ioctls) have something
/// to read and write. Semantically the stored struct is a shim until the
/// real `Tty` wrapper lands (issue #374): N_TTY is not yet consulting it
/// for canonical-mode or echo processing, but the ABI is in place so
/// userspace can start calling `tcgetattr` without `-ENOTTY`.
#[cfg(target_os = "none")]
pub struct SerialBackend {
    termios: spin::Mutex<crate::tty::termios::Termios>,
}

#[cfg(target_os = "none")]
impl SerialBackend {
    pub const fn new() -> Self {
        Self {
            termios: spin::Mutex::new(crate::tty::termios::Termios::sane()),
        }
    }
}

#[cfg(target_os = "none")]
impl Default for SerialBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "none")]
impl FileBackend for SerialBackend {
    /// Non-blocking read: drains whatever bytes are currently in the RX ring.
    ///
    /// Returns `EAGAIN` (`-11`) if no bytes are available. Callers that need
    /// blocking semantics must re-try in a loop (the blocking wait-queue path
    /// lives in a future `read` syscall extension).
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        let caller = crate::process::current_pid();
        let tty = crate::tty::console_tty();
        if let Some(rc) = crate::tty::tty_check_sigttin(&tty, caller) {
            // KERN_ERESTARTSYS is honoured by the syscall trampoline
            // (see `signal::check_and_deliver_signals`): restart on
            // SA_RESTART, otherwise -EINTR.
            return Err(rc);
        }
        for (i, byte) in buf.iter_mut().enumerate() {
            match crate::serial::try_read_byte() {
                Some(b) => *byte = b,
                None => {
                    return if i == 0 { Err(EAGAIN) } else { Ok(i) };
                }
            }
        }
        Ok(buf.len())
    }

    /// Write path acquires `COM1.lock()` inside `without_interrupts` via
    /// `crate::serial::write_bytes`. No deadlock risk: this call chain
    /// never calls `serial_println!` or re-enters the COM1 mutex.
    ///
    /// Job-control gate: if the caller's pgrp is not the console tty's
    /// foreground pgrp and `TOSTOP` is set, raise `SIGTTOU` and return
    /// `KERN_ERESTARTSYS`. The syscall trampoline then either rewinds
    /// `rip` to restart the write (SA_RESTART) or converts the return
    /// to `-EINTR`.
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        let caller = crate::process::current_pid();
        let tty = crate::tty::console_tty();
        if let Some(rc) = crate::tty::tty_check_tostop(&tty, caller) {
            return Err(rc);
        }
        crate::serial::write_bytes(buf);
        Ok(buf.len())
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<i64, i64> {
        use crate::tty::termios::{
            Termios, TCGETS, TCSETS, TCSETSF, TCSETSW, TIOCGPGRP, TIOCGSID, TIOCNOTTY, TIOCSCTTY,
            TIOCSPGRP,
        };
        // Job-control ioctls act on the shared console tty. #374/#403 will
        // replace this with a per-driver Tty lookup; until then every legacy
        // /dev/{tty,console,serial,std*} fd shares one tty identity.
        let caller = crate::process::current_pid();
        match cmd {
            TIOCSCTTY => {
                let force = arg != 0;
                // No credentials subsystem yet → treat all callers as root.
                // Once UIDs land, this `true` becomes `uid == 0`.
                let is_root = true;
                let tty = crate::tty::console_tty();
                return Ok(crate::tty::tiocsctty_for(caller, &tty, force, is_root));
            }
            TIOCSPGRP => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let mut pgid_bytes = [0u8; 4];
                unsafe { crate::arch::x86_64::uaccess::copy_from_user(&mut pgid_bytes, arg) }
                    .map_err(|e| e.as_errno())?;
                let pgid = u32::from_ne_bytes(pgid_bytes);
                let tty = crate::tty::console_tty();
                return Ok(crate::tty::tiocspgrp_for(caller, &tty, pgid));
            }
            TIOCGPGRP => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let tty = crate::tty::console_tty();
                let rc = crate::tty::tiocgpgrp_for(&tty);
                if rc < 0 {
                    return Ok(rc);
                }
                let pgid = rc as u32;
                unsafe { crate::arch::x86_64::uaccess::copy_to_user(arg, &pgid.to_ne_bytes()) }
                    .map_err(|e| e.as_errno())?;
                return Ok(0);
            }
            TIOCGSID => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let tty = crate::tty::console_tty();
                let rc = crate::tty::tiocgsid_for(&tty);
                if rc < 0 {
                    return Ok(rc);
                }
                let sid = rc as u32;
                unsafe { crate::arch::x86_64::uaccess::copy_to_user(arg, &sid.to_ne_bytes()) }
                    .map_err(|e| e.as_errno())?;
                return Ok(0);
            }
            TIOCNOTTY => {
                return Ok(crate::tty::tiocnotty_for(caller));
            }
            _ => {}
        }
        match cmd {
            TCGETS => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let snapshot = *self.termios.lock();
                // SAFETY: `arg` is a userspace VA. `copy_to_user` validates
                // the range against USER_VA_END and brackets the write with
                // STAC/CLAC so SMAP enforces the user mapping.
                unsafe { crate::arch::x86_64::uaccess::copy_to_user(arg, snapshot.as_bytes()) }
                    .map_err(|e| e.as_errno())?;
                Ok(0)
            }
            // Drain (TCSETSW) and flush (TCSETSF) reduce to "apply now" until
            // the output ring and raw-input buffer introduced by #374 exist —
            // at that point this arm splits and acquires the relevant queues.
            TCSETS | TCSETSW | TCSETSF => {
                if arg == 0 {
                    return Err(EFAULT);
                }
                let mut bytes = [0u8; 44];
                // SAFETY: see TCGETS.
                unsafe { crate::arch::x86_64::uaccess::copy_from_user(&mut bytes, arg) }
                    .map_err(|e| e.as_errno())?;
                *self.termios.lock() = Termios::from_bytes(&bytes);
                Ok(0)
            }
            _ => Err(ENOTTY),
        }
    }
}

#[cfg(target_os = "none")]
impl FileDescTable {
    /// Create a table with fds 0/1/2 wired to the COM1 serial port.
    ///
    /// This is the standard starting point for every new task: stdin, stdout,
    /// and stderr all map to the same [`SerialBackend`], bypassing the VFS
    /// so console I/O works before any filesystem is mounted.
    pub fn new_with_stdio() -> Self {
        let serial = Arc::new(SerialBackend::new()) as Arc<dyn FileBackend>;
        Self::new_with_backends(serial.clone(), serial.clone(), serial.clone())
    }
}

// ---------------------------------------------------------------------------
// Host unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;

    struct NullBackend;
    impl FileBackend for NullBackend {
        fn read(&self, _: &mut [u8]) -> Result<usize, i64> {
            Ok(0)
        }
        fn write(&self, buf: &[u8]) -> Result<usize, i64> {
            Ok(buf.len())
        }
    }

    fn null() -> Arc<dyn FileBackend> {
        Arc::new(NullBackend)
    }

    fn null_desc() -> Arc<FileDescription> {
        Arc::new(FileDescription::new(null(), 0))
    }

    fn make_table() -> FileDescTable {
        FileDescTable::new_with_backends(null(), null(), null())
    }

    #[test]
    fn alloc_fd_lowest_free() {
        let mut t = make_table();
        // fds 0, 1, 2 occupied — next should be 3
        assert_eq!(t.alloc_fd(null_desc()).unwrap(), 3);
        // Close fd 1; re-alloc should return 1 (lowest free)
        t.close_fd(1).unwrap();
        assert_eq!(t.alloc_fd(null_desc()).unwrap(), 1);
    }

    #[test]
    fn close_fd_ebadf_on_already_closed() {
        let mut t = make_table();
        t.close_fd(1).unwrap();
        assert_eq!(t.close_fd(1), Err(EBADF));
    }

    #[test]
    fn close_fd_ebadf_on_out_of_range() {
        let mut t = make_table();
        assert_eq!(t.close_fd(100), Err(EBADF));
    }

    #[test]
    fn get_ebadf_on_closed() {
        let t = make_table();
        assert_eq!(t.get(99).err(), Some(EBADF));
    }

    #[test]
    fn dup_creates_alias() {
        let mut t = make_table();
        let new_fd = t.dup(1).unwrap();
        assert_eq!(new_fd, 3); // lowest free after 0,1,2
        assert!(t.get(1).is_ok());
        assert!(t.get(3).is_ok());
    }

    #[test]
    fn dup_ebadf_on_closed_fd() {
        let mut t = make_table();
        t.close_fd(2).unwrap();
        assert_eq!(t.dup(2), Err(EBADF));
    }

    #[test]
    fn dup2_replaces_target() {
        let mut t = make_table();
        let r = t.dup2(1, 5).unwrap();
        assert_eq!(r, 5);
        assert!(t.get(5).is_ok());
        // Holes 3 and 4 should still be closed
        assert_eq!(t.get(3).err(), Some(EBADF));
        assert_eq!(t.get(4).err(), Some(EBADF));
    }

    #[test]
    fn dup2_same_fd_noop() {
        let mut t = make_table();
        assert_eq!(t.dup2(1, 1).unwrap(), 1);
        assert!(t.get(1).is_ok());
    }

    #[test]
    fn dup2_same_fd_ebadf_if_not_open() {
        let mut t = make_table();
        t.close_fd(2).unwrap();
        assert_eq!(t.dup2(2, 2), Err(EBADF));
    }

    #[test]
    fn dup2_ebadf_on_closed_oldfd() {
        let mut t = make_table();
        t.close_fd(2).unwrap();
        assert_eq!(t.dup2(2, 5), Err(EBADF));
    }

    #[test]
    fn dup2_einval_newfd_too_large() {
        let mut t = make_table();
        assert_eq!(t.dup2(1, MAX_FD as u32), Err(EINVAL));
    }

    #[test]
    fn dup3_einval_on_equal_fd() {
        let mut t = make_table();
        assert_eq!(t.dup3(1, 1, 0), Err(EINVAL));
        // Even with O_CLOEXEC: dup3(fd, fd, _) is always EINVAL.
        assert_eq!(t.dup3(1, 1, flags::O_CLOEXEC), Err(EINVAL));
    }

    #[test]
    fn dup3_sets_cloexec_only_on_new_fd() {
        let mut t = make_table();
        // dup3(1, 5, O_CLOEXEC): fd 5 gets FD_CLOEXEC, fd 1 does not.
        assert_eq!(t.dup3(1, 5, flags::O_CLOEXEC).unwrap(), 5);
        assert_eq!(t.get_fd_flags(5).unwrap(), FD_CLOEXEC);
        assert_eq!(t.get_fd_flags(1).unwrap(), 0);
    }

    #[test]
    fn dup3_without_cloexec_clears_fd_flags() {
        let mut t = make_table();
        assert_eq!(t.dup3(1, 5, 0).unwrap(), 5);
        assert_eq!(t.get_fd_flags(5).unwrap(), 0);
    }

    #[test]
    fn dup3_einval_on_unknown_flag() {
        let mut t = make_table();
        // O_NONBLOCK is valid on pipe2 but not on dup3.
        assert_eq!(t.dup3(1, 5, flags::O_NONBLOCK), Err(EINVAL));
        // An entirely unknown bit also returns EINVAL.
        assert_eq!(t.dup3(1, 5, 0x1), Err(EINVAL));
    }

    #[test]
    fn dup3_closes_newfd_if_open() {
        let mut t = make_table();
        // fd 2 is open; dup3(1, 2, _) silently replaces it.
        assert_eq!(t.dup3(1, 2, 0).unwrap(), 2);
        assert!(t.get(2).is_ok());
    }

    #[test]
    fn dup3_ebadf_on_closed_oldfd() {
        let mut t = make_table();
        t.close_fd(2).unwrap();
        assert_eq!(t.dup3(2, 5, 0), Err(EBADF));
    }

    #[test]
    fn dup3_einval_newfd_too_large() {
        let mut t = make_table();
        assert_eq!(t.dup3(1, MAX_FD as u32, 0), Err(EINVAL));
    }

    #[test]
    fn clone_for_fork_independent_slots() {
        let mut t = make_table();
        let mut child = t.clone_for_fork();
        // Close fd 1 in parent; child should still have it
        t.close_fd(1).unwrap();
        assert_eq!(t.get(1).err(), Some(EBADF));
        assert!(child.get(1).is_ok());
        // Close fd 2 in child; parent should still have it
        child.close_fd(2).unwrap();
        assert!(t.get(2).is_ok());
    }

    #[test]
    fn o_flag_numeric_values_match_linux() {
        use flags::*;
        // (constant, decimal, hex, octal-as-decimal) — all three widely-cited
        // Linux x86_64 representations. Any drift here breaks the ABI.
        let cases: &[(u32, u32, u32, u32)] = &[
            (O_RDONLY, 0, 0x0, 0o0),
            (O_WRONLY, 1, 0x1, 0o1),
            (O_RDWR, 2, 0x2, 0o2),
            (O_ACCMODE, 3, 0x3, 0o3),
            (O_CREAT, 64, 0x40, 0o100),
            (O_EXCL, 128, 0x80, 0o200),
            (O_TRUNC, 512, 0x200, 0o1000),
            (O_APPEND, 1024, 0x400, 0o2000),
            (O_NONBLOCK, 2048, 0x800, 0o4000),
            (O_DIRECTORY, 65536, 0x10000, 0o200000),
            (O_NOFOLLOW, 131072, 0x20000, 0o400000),
            (O_CLOEXEC, 524288, 0x80000, 0o2000000),
            (O_PATH, 2097152, 0x200000, 0o10000000),
            (O_TMPFILE, 4259840, 0x410000, 0o20200000),
        ];
        for &(v, dec, hex, oct) in cases {
            assert_eq!(v, dec);
            assert_eq!(v, hex);
            assert_eq!(v, oct);
        }
    }

    #[test]
    fn close_cloexec_only_closes_flagged() {
        let mut t = make_table();
        // Allocate fd 3 with FD_CLOEXEC set in per-fd flags (not in FileDescription.flags).
        t.alloc_fd_with_flags(null_desc(), flags::O_CLOEXEC)
            .unwrap();
        // Allocate fd 4 without FD_CLOEXEC.
        t.alloc_fd(null_desc()).unwrap();
        t.close_cloexec();
        // fd 3 (FD_CLOEXEC set) should be gone.
        assert_eq!(t.get(3).err(), Some(EBADF));
        // fd 4 (no FD_CLOEXEC) should survive.
        assert!(t.get(4).is_ok());
        // fd 0/1/2 (stdio, no FD_CLOEXEC) should survive.
        assert!(t.get(0).is_ok());
        assert!(t.get(1).is_ok());
        assert!(t.get(2).is_ok());
    }

    #[test]
    fn default_lseek_returns_espipe() {
        // Backends that do not override lseek (pipes, sockets, synthetic
        // stdio) must surface ESPIPE — matching Linux's behaviour for
        // drivers without a .llseek file-op.
        let backend = NullBackend;
        assert_eq!(backend.lseek(0, 0), Err(ESPIPE));
        assert_eq!(backend.lseek(42, 1), Err(ESPIPE));
    }

    #[test]
    fn default_poll_returns_default_pollmask() {
        let backend = NullBackend;
        let mut pt = PollTable::probe();
        assert_eq!(backend.poll(&mut pt), DEFAULT_POLLMASK);
    }

    #[test]
    fn dup_clears_cloexec() {
        let mut t = make_table();
        // Open fd 3 with FD_CLOEXEC set.
        t.alloc_fd_with_flags(null_desc(), flags::O_CLOEXEC)
            .unwrap();
        // dup(3) → fd 4; the dup'd fd must NOT inherit FD_CLOEXEC.
        let new_fd = t.dup(3).unwrap();
        assert_eq!(new_fd, 4);
        // After close_cloexec: fd 3 closed, fd 4 survives.
        t.close_cloexec();
        assert_eq!(t.get(3).err(), Some(EBADF));
        assert!(t.get(4).is_ok());
    }

    /// Errno ABI matrix — pins each constant to its Linux x86_64 value
    /// (negated). Any divergence from these numbers is an ABI break for
    /// userspace and must fail here before shipping.
    #[test]
    fn errno_constants_match_linux_abi() {
        assert_eq!(EPERM, -1);
        assert_eq!(ENOENT, -2);
        assert_eq!(EINTR, -4);
        assert_eq!(ENXIO, -6);
        assert_eq!(EBADF, -9);
        assert_eq!(EAGAIN, -11);
        assert_eq!(ENOMEM, -12);
        assert_eq!(EACCES, -13);
        assert_eq!(EFAULT, -14);
        assert_eq!(EBUSY, -16);
        assert_eq!(EEXIST, -17);
        assert_eq!(EXDEV, -18);
        assert_eq!(ENODEV, -19);
        assert_eq!(ENOTDIR, -20);
        assert_eq!(EISDIR, -21);
        assert_eq!(EINVAL, -22);
        assert_eq!(EMFILE, -24);
        assert_eq!(ENOTTY, -25);
        assert_eq!(EFBIG, -27);
        assert_eq!(ENOSPC, -28);
        assert_eq!(ESPIPE, -29);
        assert_eq!(EROFS, -30);
        assert_eq!(EPIPE, -32);
        assert_eq!(ENAMETOOLONG, -36);
        assert_eq!(ENOTEMPTY, -39);
        assert_eq!(ELOOP, -40);
        assert_eq!(EOVERFLOW, -75);
    }
}
