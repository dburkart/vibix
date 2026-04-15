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

use crate::poll::{PollMask, PollTable, DEFAULT_POLLMASK};

#[cfg(target_os = "none")]
pub mod vfs;

/// I/O dispatch interface for a single open file description.
///
/// Implementations must be `Send + Sync` so that `Arc<dyn FileBackend>` can
/// be shared across the process fd table.
pub trait FileBackend: Send + Sync {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64>;
    fn write(&self, buf: &[u8]) -> Result<usize, i64>;

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

    /// Downcast to [`vfs::VfsBackend`] for fd-keyed syscalls that need the
    /// underlying `OpenFile` (e.g. `fstat`, `fstatat` with `AT_EMPTY_PATH`).
    /// Non-VFS backends (`SerialBackend`, test stubs) return `None` and
    /// trigger the caller's `-EINVAL`/`-ENOTTY` path.
    #[cfg(target_os = "none")]
    fn as_vfs(&self) -> Option<&vfs::VfsBackend> {
        None
    }
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
    /// Require the resolved path to refer to a directory (`ENOTDIR` if not).
    pub const O_DIRECTORY: u32 = 0o200000;
    /// Do not follow a symlink in the final path component (`ELOOP`).
    pub const O_NOFOLLOW: u32 = 0o400000;
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
    pub flags: u32,
}

/// Maximum number of simultaneously open fds per process.
const MAX_FD: usize = 1024;

/// Linux errno constants (negated so they match syscall return values).
pub const ENOENT: i64 = -2;
pub const EBADF: i64 = -9;
pub const ENOMEM: i64 = -12;
pub const EAGAIN: i64 = -11;
pub const EINVAL: i64 = -22;
pub const EMFILE: i64 = -24;
pub const ENAMETOOLONG: i64 = -36;
pub const EEXIST: i64 = -17;
pub const ENODEV: i64 = -19;
pub const ENOTDIR: i64 = -20;
pub const ELOOP: i64 = -40;
pub const EACCES: i64 = -13;
pub const EBUSY: i64 = -16;
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
            Arc::new(FileDescription {
                backend: stdin,
                flags: flags::O_RDONLY,
            }),
            0,
        )));
        t.slots.push(Some((
            Arc::new(FileDescription {
                backend: stdout,
                flags: flags::O_WRONLY,
            }),
            0,
        )));
        t.slots.push(Some((
            Arc::new(FileDescription {
                backend: stderr,
                flags: flags::O_WRONLY,
            }),
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
}

// ---------------------------------------------------------------------------
// SerialBackend — only compiled for the kernel target (requires port I/O).
// ---------------------------------------------------------------------------

/// Serial (COM1) backend.
///
/// Used as the backend for fds 0/1/2. Stdio bypasses the VFS on purpose:
/// every task gets a direct [`SerialBackend`] so console I/O works even
/// before `/dev/console` is wired up in `devfs`.
#[cfg(target_os = "none")]
pub struct SerialBackend;

#[cfg(target_os = "none")]
impl FileBackend for SerialBackend {
    /// Non-blocking read: drains whatever bytes are currently in the RX ring.
    ///
    /// Returns `EAGAIN` (`-11`) if no bytes are available. Callers that need
    /// blocking semantics must re-try in a loop (the blocking wait-queue path
    /// lives in a future `read` syscall extension).
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
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
    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        crate::serial::write_bytes(buf);
        Ok(buf.len())
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
        let serial = Arc::new(SerialBackend) as Arc<dyn FileBackend>;
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
        Arc::new(FileDescription {
            backend: null(),
            flags: 0,
        })
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
}
