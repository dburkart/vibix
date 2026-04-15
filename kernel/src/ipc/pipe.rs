//! Anonymous pipes — `pipe(2)` / `pipe2(2)`.
//!
//! Implements RFC 0003 §"Pipe (anonymous + FIFO)":
//!
//! - [`PipeRing`]: lock-protected byte ring with cache-line-separated
//!   head/tail atomics for a lock-free poll fast-path.
//! - [`Pipe`]: the shared state between read and write ends, plus two
//!   [`WaitQueue`]s so blocked readers/writers wake each other.
//! - [`PipeReadEnd`] / [`PipeWriteEnd`]: [`FileBackend`] implementations
//!   that dec-ref their side's count on drop and call `wake_all` so the
//!   other side observes EOF / EPIPE.
//!
//! # Blocking model
//!
//! The `read`/`write` implementations use the wait-latching protocol
//! from `sync::WaitQueue`: register a wait token, snapshot state, decide
//! whether to park.  Any wake that fires after `register_wait` but before
//! `block_current` sets `wake_pending` so `block_current` returns
//! immediately without losing the notification.
//!
//! # O_NONBLOCK
//!
//! `FileBackend::read/write` don't receive the open-file flags, so each
//! backend stores its own `nonblocking` flag at construction time.
//! A future `fcntl(F_SETFL)` implementation must update both the
//! `FileDescription.flags` field and `PipeReadEnd/PipeWriteEnd.nonblocking`.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::fs::{FileBackend, FileDescription, EBADF, EAGAIN, EINVAL, EPIPE};
use crate::poll::{PollMask, PollTable, POLLHUP, POLLIN, POLLOUT, POLLRDNORM, POLLWRNORM};

// On the kernel target use IrqLock (which saves/restores RFLAGS.IF).
// In host-side unit tests fall back to a plain spin::Mutex — same external
// API but without the RFLAGS manipulation that would panic in ring-3.
#[cfg(target_os = "none")]
use crate::sync::irqlock::IrqLock;
#[cfg(not(target_os = "none"))]
use spin::Mutex as IrqLock;

// ── Constants ──────────────────────────────────────────────────────────────

/// POSIX `PIPE_BUF`: writes of at most this many bytes are atomic (no
/// interleaving with other writers).  Linux uses 4096; we match it.
pub const PIPE_BUF: usize = 4096;

/// Default pipe ring capacity.  Power-of-two so head/tail wrap by mask.
/// 64 KiB matches Linux's default (16 pages × 4096).
pub const PIPE_CAPACITY: usize = 64 * 1024;

// ── CachePadded ────────────────────────────────────────────────────────────

/// Wrapper that ensures `T` occupies its own cache line (64 bytes on x86-64).
///
/// `#[repr(align(64))]` is only valid on type definitions, not on struct
/// fields, so we use a newtype following the crossbeam-utils pattern.
/// This prevents false sharing between the head (updated by readers) and the
/// tail (updated by writers) in `PipeRing`.
#[repr(C, align(64))]
struct CachePadded<T>(T);

// ── PipeRing ───────────────────────────────────────────────────────────────

/// SPSC-ish byte ring protected by an IRQ-safe lock.
///
/// The ring is "SPSC-ish" — head and tail are separate `AtomicUsize`s
/// on separate cache lines so a lock-free *poll* fast-path can snapshot
/// `len = (tail - head) & MASK` without taking the lock.  Actual reads
/// and writes take the lock so that multiple readers/writers (POSIX
/// allows this) are serialised.
struct PipeRing {
    /// Heap-allocated zero-initialised buffer.  Zero-init is mandatory:
    /// a kernel ring must not leak uninitialised memory to userspace.
    buf: Box<[u8; PIPE_CAPACITY]>,
    /// Byte count consumed so far (read index).  Written by readers.
    head: CachePadded<AtomicUsize>,
    /// Byte count produced so far (write index).  Written by writers.
    tail: CachePadded<AtomicUsize>,
    /// Mutual-exclusion lock for read/write critical sections.
    lock: IrqLock<()>,
}

impl PipeRing {
    fn new() -> Self {
        PipeRing {
            buf: Box::new([0u8; PIPE_CAPACITY]),
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
            lock: IrqLock::new(()),
        }
    }

    /// Number of bytes available to read (lock-free snapshot).
    #[inline]
    fn len(&self) -> usize {
        let tail = self.tail.0.load(Ordering::Acquire);
        let head = self.head.0.load(Ordering::Acquire);
        tail.wrapping_sub(head) & (PIPE_CAPACITY - 1)
    }

    /// Number of bytes free for writing (lock-free snapshot).
    #[inline]
    fn free(&self) -> usize {
        // We reserve one slot so that `head == tail` always means empty.
        PIPE_CAPACITY - 1 - self.len()
    }

    /// Copy up to `out.len()` bytes out of the ring.
    ///
    /// **Must be called with `self.lock` held.**
    /// Returns the number of bytes actually copied.
    fn read_bytes_locked(&self, out: &mut [u8]) -> usize {
        let avail = self.len();
        let n = core::cmp::min(out.len(), avail);
        if n == 0 {
            return 0;
        }
        let head = self.head.0.load(Ordering::Relaxed) & (PIPE_CAPACITY - 1);
        let first = core::cmp::min(n, PIPE_CAPACITY - head);
        // SAFETY: buf is valid for the entire ring; indices are within bounds.
        out[..first].copy_from_slice(&self.buf[head..head + first]);
        if first < n {
            out[first..n].copy_from_slice(&self.buf[..n - first]);
        }
        // Publish the new head with Release so subsequent writers see the
        // freed space on their next Acquire load.
        self.head
            .0
            .fetch_add(n, Ordering::Release);
        n
    }

    /// Copy exactly `data.len()` bytes into the ring.
    ///
    /// **Must be called with `self.lock` held and after verifying
    /// `self.free() >= data.len()`.**
    fn write_bytes_locked(&self, data: &[u8]) {
        let n = data.len();
        debug_assert!(n <= self.free(), "write_bytes_locked called without enough free space");
        let tail = self.tail.0.load(Ordering::Relaxed) & (PIPE_CAPACITY - 1);
        let first = core::cmp::min(n, PIPE_CAPACITY - tail);
        // SAFETY: buf is valid for the entire ring; indices are within bounds.
        // Using unsafe ptr writes to bypass the shared-reference aliasing
        // check — the lock guarantees exclusive write access at this point.
        unsafe {
            let ptr = self.buf.as_ptr().add(tail) as *mut u8;
            core::ptr::copy_nonoverlapping(data.as_ptr(), ptr, first);
            if first < n {
                let ptr2 = self.buf.as_ptr() as *mut u8;
                core::ptr::copy_nonoverlapping(data.as_ptr().add(first), ptr2, n - first);
            }
        }
        self.tail
            .0
            .fetch_add(n, Ordering::Release);
    }
}

// SAFETY: PipeRing is guarded by an IrqLock; raw-pointer access only
// happens under that lock, so cross-thread access is serialised.
unsafe impl Send for PipeRing {}
unsafe impl Sync for PipeRing {}

// ── Pipe ───────────────────────────────────────────────────────────────────

/// The shared state between a pipe's read end and write end.
///
/// Both ends hold an `Arc<Pipe>`.  When the last read end drops,
/// `readers` hits zero and the write end observes EPIPE.  When the last
/// write end drops, `writers` hits zero and the read end drains then
/// returns EOF.
pub struct Pipe {
    ring: PipeRing,
    /// WaitQueue for blocked readers (waiting for data or EOF).
    rd_wait: Arc<crate::poll::WaitQueue>,
    /// WaitQueue for blocked writers (waiting for free space).
    wr_wait: Arc<crate::poll::WaitQueue>,
    /// Number of live read ends (decremented by `PipeReadEnd::drop`).
    readers: AtomicUsize,
    /// Number of live write ends (decremented by `PipeWriteEnd::drop`).
    writers: AtomicUsize,
}

impl Pipe {
    /// Allocate a new, empty pipe with one reader and one writer.
    pub fn new() -> Arc<Self> {
        Arc::new(Pipe {
            ring: PipeRing::new(),
            rd_wait: crate::poll::WaitQueue::new(),
            wr_wait: crate::poll::WaitQueue::new(),
            readers: AtomicUsize::new(1),
            writers: AtomicUsize::new(1),
        })
    }
}

// ── PipeReadEnd ────────────────────────────────────────────────────────────

/// The read end of an anonymous pipe.
///
/// Implements `FileBackend`; `write` returns `EBADF`.
pub struct PipeReadEnd {
    pipe: Arc<Pipe>,
    /// Tracks O_NONBLOCK so `read` can return EAGAIN instead of blocking.
    nonblocking: AtomicBool,
}

impl PipeReadEnd {
    pub fn new(pipe: Arc<Pipe>, nonblocking: bool) -> Self {
        PipeReadEnd {
            pipe,
            nonblocking: AtomicBool::new(nonblocking),
        }
    }
}

impl Drop for PipeReadEnd {
    fn drop(&mut self) {
        let prev = self.pipe.readers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last reader closed — wake all blocked writers so they
            // observe EPIPE on their next loop iteration.
            self.pipe.wr_wait.wake_all();
        }
    }
}

impl FileBackend for PipeReadEnd {
    fn read(&self, buf: &mut [u8]) -> Result<usize, i64> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            // Fast path: data already in ring.
            {
                let _guard = self.pipe.ring.lock.lock();
                if self.pipe.ring.len() > 0 {
                    let n = self.pipe.ring.read_bytes_locked(buf);
                    drop(_guard);
                    self.pipe.wr_wait.wake_poll_then_one();
                    return Ok(n);
                }
                // Ring is empty — check for EOF.
                if self.pipe.writers.load(Ordering::Acquire) == 0 {
                    return Ok(0); // EOF
                }
            }
            // Non-blocking: bail out.
            if self.nonblocking.load(Ordering::Relaxed) {
                return Err(EAGAIN);
            }
            // Blocking: park until a writer signals rd_wait.
            #[cfg(target_os = "none")]
            {
                let tid = crate::task::current_id();
                let tok = self.pipe.rd_wait.register_wait(tid);
                // Re-check under lock before parking (wait-latching invariant).
                {
                    let _guard = self.pipe.ring.lock.lock();
                    if self.pipe.ring.len() > 0
                        || self.pipe.writers.load(Ordering::Acquire) == 0
                    {
                        self.pipe.rd_wait.cancel(tok);
                        // Loop back — will take fast path or return EOF.
                        continue;
                    }
                }
                crate::task::block_current();
                self.pipe.rd_wait.cancel(tok);
            }
            #[cfg(not(target_os = "none"))]
            {
                // Host unit tests never reach the blocking path because
                // they always call with data in the ring or with writers==0.
                return Err(EAGAIN);
            }
        }
    }

    fn write(&self, _buf: &[u8]) -> Result<usize, i64> {
        Err(EBADF)
    }

    fn poll(&self, pt: &mut PollTable) -> PollMask {
        pt.register(&self.pipe.rd_wait);
        let mut mask: PollMask = 0;
        if self.pipe.ring.len() > 0 {
            mask |= POLLIN | POLLRDNORM;
        }
        if self.pipe.writers.load(Ordering::Acquire) == 0 {
            mask |= POLLHUP;
        }
        mask
    }
}

// ── PipeWriteEnd ───────────────────────────────────────────────────────────

/// The write end of an anonymous pipe.
///
/// Implements `FileBackend`; `read` returns `EBADF`.
pub struct PipeWriteEnd {
    pipe: Arc<Pipe>,
    nonblocking: AtomicBool,
}

impl PipeWriteEnd {
    pub fn new(pipe: Arc<Pipe>, nonblocking: bool) -> Self {
        PipeWriteEnd {
            pipe,
            nonblocking: AtomicBool::new(nonblocking),
        }
    }
}

impl Drop for PipeWriteEnd {
    fn drop(&mut self) {
        let prev = self.pipe.writers.fetch_sub(1, Ordering::AcqRel);
        if prev == 1 {
            // Last writer closed — wake all blocked readers so they drain
            // the ring and then observe EOF.
            self.pipe.rd_wait.wake_all();
        }
    }
}

impl FileBackend for PipeWriteEnd {
    fn read(&self, _buf: &mut [u8]) -> Result<usize, i64> {
        Err(EBADF)
    }

    fn write(&self, buf: &[u8]) -> Result<usize, i64> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut written = 0usize;
        let mut remaining = buf;

        while !remaining.is_empty() {
            // Check for broken pipe (no readers).
            if self.pipe.readers.load(Ordering::Acquire) == 0 {
                // Raise SIGPIPE on the current task and return EPIPE.
                #[cfg(target_os = "none")]
                {
                    let tid = crate::task::current_id();
                    crate::signal::raise_signal_on_task(tid, crate::signal::SIGPIPE);
                }
                return Err(EPIPE);
            }

            // Determine how many bytes to write in this chunk.
            // For writes ≤ PIPE_BUF, we must be atomic: wait until
            // there is room for the entire chunk before writing.
            // For writes > PIPE_BUF, split into PIPE_BUF-sized pieces.
            let chunk_len = core::cmp::min(remaining.len(), PIPE_BUF);
            let chunk = &remaining[..chunk_len];

            // Wait until there is room for this atomic chunk.
            loop {
                {
                    let _guard = self.pipe.ring.lock.lock();
                    if self.pipe.ring.free() >= chunk_len {
                        self.pipe.ring.write_bytes_locked(chunk);
                        drop(_guard);
                        self.pipe.rd_wait.wake_poll_then_one();
                        break;
                    }
                }
                // Not enough space.
                if self.nonblocking.load(Ordering::Relaxed) {
                    if written == 0 {
                        return Err(EAGAIN);
                    } else {
                        return Ok(written);
                    }
                }
                // Block until a reader frees some space.
                #[cfg(target_os = "none")]
                {
                    let tid = crate::task::current_id();
                    let tok = self.pipe.wr_wait.register_wait(tid);
                    // Re-check before parking.
                    {
                        let _guard = self.pipe.ring.lock.lock();
                        if self.pipe.ring.free() >= chunk_len
                            || self.pipe.readers.load(Ordering::Acquire) == 0
                        {
                            self.pipe.wr_wait.cancel(tok);
                            continue;
                        }
                    }
                    crate::task::block_current();
                    self.pipe.wr_wait.cancel(tok);
                }
                #[cfg(not(target_os = "none"))]
                {
                    // Host tests don't reach blocking paths.
                    if written == 0 {
                        return Err(EAGAIN);
                    } else {
                        return Ok(written);
                    }
                }
            }

            written += chunk_len;
            remaining = &remaining[chunk_len..];
        }
        Ok(written)
    }

    fn poll(&self, pt: &mut PollTable) -> PollMask {
        pt.register(&self.pipe.wr_wait);
        let mut mask: PollMask = 0;
        if self.pipe.readers.load(Ordering::Acquire) == 0 {
            return mask | POLLHUP | POLLOUT; // EPIPE path; ready for write (will return EPIPE)
        }
        if self.pipe.ring.free() > 0 {
            mask |= POLLOUT | POLLWRNORM;
        }
        mask
    }
}

// ── Syscall implementations ────────────────────────────────────────────────

/// `pipe(pipefd)` — create an anonymous pipe.
///
/// `pipefd_uva` is a userspace pointer to a `[i32; 2]` array that
/// receives `[read_fd, write_fd]`.  Both fds start with `O_NONBLOCK`
/// and `FD_CLOEXEC` **clear** (POSIX XSH §pipe).
///
/// Returns 0 on success or a negated errno on failure.
#[cfg(target_os = "none")]
pub unsafe fn sys_pipe(pipefd_uva: u64) -> i64 {
    sys_pipe2(pipefd_uva, 0)
}

/// `pipe2(pipefd, flags)` — create an anonymous pipe with flags.
///
/// `flags` may be `O_NONBLOCK` (0o4000 / 0x800) and/or `O_CLOEXEC`
/// (0o2000000 / 0x80000).  Any other bit returns `EINVAL`.
#[cfg(target_os = "none")]
pub unsafe fn sys_pipe2(pipefd_uva: u64, flags: u32) -> i64 {
    use crate::arch::x86_64::uaccess;
    use crate::fs::flags::{O_CLOEXEC, O_NONBLOCK};

    // Validate flags — reject anything we don't know about.
    let known = O_NONBLOCK | O_CLOEXEC;
    if flags & !known != 0 {
        return EINVAL;
    }

    let nonblocking = flags & O_NONBLOCK != 0;
    let cloexec = flags & O_CLOEXEC != 0;
    let fd_flags: u32 = if cloexec { O_CLOEXEC } else { 0 };

    let pipe = Pipe::new();

    let read_desc = Arc::new(FileDescription {
        backend: Arc::new(PipeReadEnd::new(pipe.clone(), nonblocking)),
        flags: if nonblocking { O_NONBLOCK } else { 0 },
    });
    let write_desc = Arc::new(FileDescription {
        backend: Arc::new(PipeWriteEnd::new(pipe, nonblocking)),
        flags: if nonblocking { O_NONBLOCK } else { 0 },
    });

    let fd_table_arc = crate::task::current_fd_table();
    let mut fd_table = fd_table_arc.lock();

    let read_fd = match fd_table.alloc_fd_with_flags(read_desc, fd_flags) {
        Ok(fd) => fd,
        Err(e) => return e,
    };
    let write_fd = match fd_table.alloc_fd_with_flags(write_desc, fd_flags) {
        Ok(fd) => fd,
        Err(e) => {
            // Roll back the read fd allocation.
            let _ = fd_table.close_fd(read_fd);
            return e;
        }
    };
    drop(fd_table);

    // Write [read_fd, write_fd] as two i32s to userspace.
    let fds: [i32; 2] = [read_fd as i32, write_fd as i32];
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(fds.as_ptr() as *const u8, 8)
    };
    match uaccess::copy_to_user(pipefd_uva as usize, bytes) {
        Ok(()) => 0,
        Err(e) => {
            // Roll back both fds if the copy fails.
            let tbl = crate::task::current_fd_table();
            let mut tbl = tbl.lock();
            let _ = tbl.close_fd(read_fd);
            let _ = tbl.close_fd(write_fd);
            e.as_errno()
        }
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poll::{PollMode, PollTable};

    /// Helper: probe-mode table (register is a no-op).
    fn probe() -> PollTable {
        PollTable::probe()
    }

    // ── PipeRing ──────────────────────────────────────────────────────────

    #[test]
    fn pipe_ring_basic_rw() {
        let ring = PipeRing::new();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.free(), PIPE_CAPACITY - 1);

        let data = b"hello, pipe!";
        {
            let _g = ring.lock.lock();
            ring.write_bytes_locked(data);
        }
        assert_eq!(ring.len(), data.len());

        let mut buf = [0u8; 32];
        {
            let _g = ring.lock.lock();
            let n = ring.read_bytes_locked(&mut buf);
            assert_eq!(n, data.len());
        }
        assert_eq!(&buf[..data.len()], data);
        assert_eq!(ring.len(), 0);
    }

    #[test]
    fn pipe_ring_wrap() {
        // Fill the ring almost to capacity, then drain, then write again
        // to exercise the wrap-around path.
        let ring = PipeRing::new();
        // Write PIPE_CAPACITY - 1 bytes (maximum).
        let big = vec![0xAAu8; PIPE_CAPACITY - 1];
        {
            let _g = ring.lock.lock();
            ring.write_bytes_locked(&big);
        }
        assert_eq!(ring.len(), PIPE_CAPACITY - 1);

        // Drain all.
        let mut drain = vec![0u8; PIPE_CAPACITY - 1];
        {
            let _g = ring.lock.lock();
            let n = ring.read_bytes_locked(&mut drain);
            assert_eq!(n, PIPE_CAPACITY - 1);
        }
        assert_eq!(ring.len(), 0);

        // Write a small amount that will wrap (tail started at 0, advanced
        // to 0 mod CAPACITY after wrap, but next_tail wraps).
        let small = b"wrap!";
        {
            let _g = ring.lock.lock();
            ring.write_bytes_locked(small);
        }
        let mut out = [0u8; 8];
        {
            let _g = ring.lock.lock();
            let n = ring.read_bytes_locked(&mut out);
            assert_eq!(n, small.len());
        }
        assert_eq!(&out[..small.len()], small);
    }

    // ── PipeReadEnd ───────────────────────────────────────────────────────

    #[test]
    fn pipe_read_eof_on_writer_drop() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe.clone(), false);
        drop(write); // writers → 0
        let mut buf = [0u8; 16];
        // Should return Ok(0) (EOF) immediately — no blocking.
        assert_eq!(read.read(&mut buf), Ok(0));
    }

    #[test]
    fn pipe_eagain_empty_nonblocking() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), true);
        // Keep write end alive so it's not EOF.
        let _write = PipeWriteEnd::new(pipe, false);
        let mut buf = [0u8; 16];
        assert_eq!(read.read(&mut buf), Err(EAGAIN));
    }

    #[test]
    fn pipe_epipe_no_readers() {
        let pipe = Pipe::new();
        let write = PipeWriteEnd::new(pipe.clone(), false);
        drop(PipeReadEnd::new(pipe, false)); // readers → 0
        assert_eq!(write.write(b"hello"), Err(EPIPE));
    }

    #[test]
    fn pipe_read_after_write() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        assert_eq!(write.write(b"hello"), Ok(5));
        let mut buf = [0u8; 16];
        let n = read.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    // ── Poll ──────────────────────────────────────────────────────────────

    #[test]
    fn pipe_poll_read_reports_pollin() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        // No data yet — POLLIN should be clear, no POLLHUP.
        let mask = read.poll(&mut probe());
        assert_eq!(mask & POLLIN, 0);
        assert_eq!(mask & POLLHUP, 0);
        // Write data.
        write.write(b"x").unwrap();
        let mask = read.poll(&mut probe());
        assert_ne!(mask & POLLIN, 0);
    }

    #[test]
    fn pipe_poll_write_reports_pollout() {
        let pipe = Pipe::new();
        let _read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        let mask = write.poll(&mut probe());
        assert_ne!(mask & POLLOUT, 0);
    }

    #[test]
    fn pipe_poll_hup_on_writer_drop() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        drop(write);
        let mask = read.poll(&mut probe());
        assert_ne!(mask & POLLHUP, 0);
    }

    #[test]
    fn pipe_poll_err_on_reader_drop() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        drop(read);
        // Write end observes POLLHUP when readers == 0.
        let mask = write.poll(&mut probe());
        assert_ne!(mask & POLLHUP, 0);
    }

    #[test]
    fn pipe_buf_atomicity_boundary() {
        // Write exactly PIPE_BUF bytes, confirm they land as one chunk.
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        let data = vec![0x5Au8; PIPE_BUF];
        assert_eq!(write.write(&data), Ok(PIPE_BUF));
        assert_eq!(read.pipe.ring.len(), PIPE_BUF);
        let mut out = vec![0u8; PIPE_BUF];
        assert_eq!(read.read(&mut out), Ok(PIPE_BUF));
        assert_eq!(out, data);
    }

    #[test]
    fn pipe_write_zero_is_noop() {
        let pipe = Pipe::new();
        let _read = PipeReadEnd::new(pipe.clone(), false);
        let write = PipeWriteEnd::new(pipe, false);
        assert_eq!(write.write(b""), Ok(0));
    }

    #[test]
    fn pipe_read_zero_is_noop() {
        let pipe = Pipe::new();
        let read = PipeReadEnd::new(pipe.clone(), false);
        let _write = PipeWriteEnd::new(pipe, false);
        assert_eq!(read.read(&mut []), Ok(0));
    }
}
