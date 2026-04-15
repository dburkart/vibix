//! TTY subsystem.
//!
//! This module defines the generic [`Tty`] container, the [`TtyDriver`]
//! and [`LineDiscipline`] traits, and the allocation-free
//! [`DeferredByteRing`](ring::DeferredByteRing) byte buffer used to hand
//! decoded bytes off from a device ISR to a soft-IRQ drain context.
//!
//! Actual device wiring (16550 serial UART rx, PS/2 keyboard rx) lands
//! in follow-ups (#405, #406) once the soft-IRQ bottom-half primitive
//! from #404 is available. The stub [`PassthroughLdisc`] preserves the
//! current raw-byte behavior until the N_TTY skeleton (#428/#375) is
//! wired in.
//!
//! See `docs/RFC/0003-pipes-poll-tty.md` for the design rationale.

pub mod ntty;
pub mod ps2;
pub mod ring;
pub mod termios;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::poll::WaitQueue;
#[cfg(target_os = "none")]
use crate::sync::IrqLock;
#[cfg(target_os = "none")]
use spin::Lazy;
use termios::Termios;

// Host tests can't use IrqLock (it touches RFLAGS.IF) — fall back to a
// plain spin mutex, which has the same external API for our purposes.
#[cfg(all(test, not(target_os = "none")))]
use spin::Mutex as IrqLock;

#[cfg(target_os = "none")]
use crate::process;

/// POSIX session identifier. `0` is reserved for "no session" (bootstrap
/// kernel tasks before the process table is populated).
pub type SessionId = u32;

/// POSIX process-group identifier. `0` is reserved for "no foreground pgrp".
pub type ProcessGroupId = u32;

/// Lock-free pgrp snapshot.
///
/// Used by the N_TTY ISIG fast path (#375) so a character arriving on the
/// serial ISR can read the foreground pgrp without acquiring
/// `tty.ctrl.lock()` — see RFC 0003 §Lock order.
pub struct AtomicPid(AtomicU32);

impl AtomicPid {
    pub const fn new(v: u32) -> Self {
        Self(AtomicU32::new(v))
    }

    pub fn load(&self) -> u32 {
        self.0.load(Ordering::Acquire)
    }

    pub fn store(&self, v: u32) {
        self.0.store(v, Ordering::Release);
    }
}

/// Controlling-terminal job-control state.
///
/// Stored under `Tty.ctrl`. The `pgrp_snapshot` field mirrors `pgrp` so
/// ISR-context code can read it without taking `ctrl.lock()`. Mutators
/// (`TIOCSPGRP`, ctty acquisition) must update both fields under the lock
/// to keep them in sync.
pub struct JobControl {
    pub session: Option<SessionId>,
    pub pgrp: Option<ProcessGroupId>,
    pub pgrp_snapshot: AtomicPid,
}

impl JobControl {
    pub const fn new() -> Self {
        Self {
            session: None,
            pgrp: None,
            pgrp_snapshot: AtomicPid::new(0),
        }
    }

    /// Set the foreground pgrp and update the lock-free snapshot atomically
    /// from the writer's perspective. Caller must hold `Tty.ctrl.lock()`.
    pub fn set_pgrp(&mut self, pgrp: Option<ProcessGroupId>) {
        self.pgrp = pgrp;
        self.pgrp_snapshot.store(pgrp.unwrap_or(0));
    }
}

impl Default for JobControl {
    fn default() -> Self {
        Self::new()
    }
}

/// Bottom-half device driver abstraction.
///
/// Implementations own the hardware-specific tx path (`write`/`flush`).
/// Rx runs on the hardware ISR, which pushes decoded bytes into a
/// [`DeferredByteRing`](ring::DeferredByteRing) and raises a soft-IRQ;
/// the registered drain handler then feeds bytes into
/// [`LineDiscipline::receive_byte`]. Rx is therefore not part of this
/// trait — a driver only needs to publish a tx surface.
pub trait TtyDriver: Send + Sync {
    /// Synchronously push `buf` toward the device. Returns the number of
    /// bytes accepted. May be called from process context only — the
    /// ISR-side "queue a decoded byte" path goes through the driver's
    /// own `DeferredByteRing`, not through this method.
    fn write(&self, buf: &[u8]) -> usize;

    /// Block until any hardware tx queue has drained. Best-effort;
    /// drivers with no tx queue may implement as a no-op.
    fn flush(&self) {}
}

/// Line-discipline dispatch surface.
///
/// A line discipline consumes bytes arriving from a driver and decides
/// what to do with them: echo, canonicalize, signal-dispatch, and
/// eventually deliver into the `Tty`'s read buffer. [`PassthroughLdisc`]
/// is the minimum implementation (no-op `open`/`close`, `receive_byte`
/// defers to a test sink or hard-sinks to the console).
pub trait LineDiscipline: Send + Sync {
    /// Called once per byte arriving from the driver's rx path. Runs in
    /// soft-IRQ context — must not allocate and must not take any lock
    /// that the process-context path holds across a preemption.
    fn receive_byte(&self, tty: &Tty, byte: u8);

    /// Called when a tty first attaches this discipline. Returns an
    /// errno on failure.
    fn open(&self, tty: &Tty) -> Result<(), i64>;

    /// Called when the discipline is being torn down or swapped out.
    fn close(&self, tty: &Tty);
}

/// Trivial passthrough line discipline — a no-op placeholder.
///
/// `receive_byte` appends incoming bytes into an optional test sink and
/// otherwise drops them on the floor. Used as the default ldisc for a
/// tty until N_TTY (#428/#375) lands, and as the harness for host unit
/// tests in this file.
pub struct PassthroughLdisc {
    sink: IrqLock<Option<alloc::vec::Vec<u8>>>,
}

impl PassthroughLdisc {
    pub const fn new() -> Self {
        Self {
            sink: IrqLock::new(None),
        }
    }

    /// Install an empty collector vec so tests can observe the byte
    /// stream arriving from the driver. Returns a handle that tests
    /// drain via [`drain_sink`](Self::drain_sink).
    pub fn with_sink() -> Self {
        Self {
            sink: IrqLock::new(Some(alloc::vec::Vec::new())),
        }
    }

    /// Take the currently-collected bytes, leaving an empty vec in place
    /// if a sink is installed, or returning an empty vec if there isn't.
    pub fn drain_sink(&self) -> alloc::vec::Vec<u8> {
        let mut g = self.sink.lock();
        match g.as_mut() {
            Some(v) => core::mem::take(v),
            None => alloc::vec::Vec::new(),
        }
    }
}

impl Default for PassthroughLdisc {
    fn default() -> Self {
        Self::new()
    }
}

impl LineDiscipline for PassthroughLdisc {
    fn receive_byte(&self, _tty: &Tty, byte: u8) {
        let mut g = self.sink.lock();
        if let Some(v) = g.as_mut() {
            v.push(byte);
        }
    }

    fn open(&self, _tty: &Tty) -> Result<(), i64> {
        Ok(())
    }

    fn close(&self, _tty: &Tty) {}
}

/// Trivial driver stub used as the default for a [`Tty`] until a real
/// hardware driver is attached. `write` discards bytes; `flush` is a
/// no-op. Allocated once per [`Tty`] via `Arc::new(NullDriver)`.
pub struct NullDriver;

impl TtyDriver for NullDriver {
    fn write(&self, buf: &[u8]) -> usize {
        buf.len()
    }
}

/// Generic TTY container.
///
/// Holds a device driver (`driver`), an active line discipline
/// (`ldisc`), the termios settings (`termios`), job-control state
/// (`ctrl`), and two wait-queues (`read_wait`, `write_wait`) for
/// blocking readers/writers. Ownership is `Arc<Tty>` so the same
/// controlling terminal can be shared across a session's processes.
pub struct Tty {
    pub driver: Arc<dyn TtyDriver>,
    pub ldisc: Arc<dyn LineDiscipline>,
    pub termios: IrqLock<Termios>,
    pub ctrl: IrqLock<JobControl>,
    pub read_wait: Arc<WaitQueue>,
    pub write_wait: Arc<WaitQueue>,
}

impl Tty {
    /// Build a tty with an explicit driver and line discipline.
    pub fn with_driver(driver: Arc<dyn TtyDriver>, ldisc: Arc<dyn LineDiscipline>) -> Self {
        Self {
            driver,
            ldisc,
            termios: IrqLock::new(Termios::sane()),
            ctrl: IrqLock::new(JobControl::new()),
            read_wait: WaitQueue::new(),
            write_wait: WaitQueue::new(),
        }
    }

    /// Build a stub tty with no hardware wiring. Used by the PCB for
    /// controlling-terminal job-control state (#372) before any real
    /// tty has been attached.
    pub fn new() -> Self {
        Self::with_driver(Arc::new(NullDriver), Arc::new(PassthroughLdisc::new()))
    }
}

impl Default for Tty {
    fn default() -> Self {
        Self::new()
    }
}

/// The single system-wide console tty backing `/dev/{tty,console,serial,std*}`.
/// A real multi-tty world (pty, serial[N], vt[N]) arrives with #374/#403 —
/// until then every legacy `/dev/*` open refers to the same `Arc<Tty>` so
/// session/pgrp identity is shared across fds as POSIX expects.
#[cfg(target_os = "none")]
pub static CONSOLE_TTY: Lazy<Arc<Tty>> = Lazy::new(|| Arc::new(Tty::new()));

/// Return the shared console tty.
#[cfg(target_os = "none")]
pub fn console_tty() -> Arc<Tty> {
    Arc::clone(&CONSOLE_TTY)
}

// ── Job-control ioctl helpers ─────────────────────────────────────────────
//
// Each `*_for` function takes the caller pid explicitly so host unit tests
// can drive them without going through the scheduler. They return a POSIX
// errno as `i64` (0 or positive on success), matching the `setsid_for` /
// `setpgid_for` convention in `process::mod`.
//
// Lock order: TABLE (via `process::*`) → `tty.ctrl`. Every helper releases
// TABLE before taking `tty.ctrl.lock()`. Do not invert.

/// POSIX errno constants, shared with `process::mod`.
#[cfg(target_os = "none")]
const EPERM: i64 = -1;
#[cfg(target_os = "none")]
const ENOTTY: i64 = -25;

/// Linux-internal "restart this syscall" sentinel. Not user-visible: the
/// syscall trampoline either restarts the call transparently (SA_RESTART)
/// or converts it to `EINTR` (-4). Until the trampoline lands (tracked as
/// a follow-up to #434), callers translate this to `EINTR` directly.
pub const KERN_ERESTARTSYS: i64 = -512;

/// `TIOCSCTTY(force)` — acquire `tty` as the caller session's controlling
/// terminal. Only a session leader may acquire a ctty. If `tty` already
/// has a session, `force && is_root` steals it (clearing the old session's
/// ctty on every member).
#[cfg(target_os = "none")]
pub fn tiocsctty_for(caller_pid: u32, tty: &Arc<Tty>, force: bool, is_root: bool) -> i64 {
    if caller_pid == 0 {
        return EPERM;
    }
    if !process::is_session_leader(caller_pid) {
        return EPERM;
    }
    if let Some(existing_tty) = process::ctty_of(caller_pid) {
        if Arc::ptr_eq(&existing_tty, tty) {
            return 0;
        }
        return EPERM;
    }
    let caller_sid = match process::session_of(caller_pid) {
        Some(s) => s,
        None => return EPERM,
    };
    if let Some(existing) = process::session_using_tty(tty) {
        if existing == caller_sid {
            return 0;
        }
        if !force || !is_root {
            return EPERM;
        }
        process::clear_ctty_for_session(existing);
    }
    // Attach tty to the caller; pgrp snapshot mirrors caller's pgrp.
    process::set_ctty(caller_pid, Some(Arc::clone(tty)));
    let mut ctrl = tty.ctrl.lock();
    ctrl.session = Some(caller_sid);
    ctrl.set_pgrp(Some(caller_pid));
    0
}

/// `TIOCSPGRP(pgid)` — set `pgid` as `tty`'s foreground pgrp. Caller must
/// be in the same session as `tty`, and `pgid` must name an existing pgrp
/// in that session.
#[cfg(target_os = "none")]
pub fn tiocspgrp_for(caller_pid: u32, tty: &Tty, pgid: ProcessGroupId) -> i64 {
    if caller_pid == 0 {
        return EPERM;
    }
    let tty_sid = match tty.ctrl.lock().session {
        Some(s) => s,
        None => return ENOTTY,
    };
    match process::session_of(caller_pid) {
        Some(s) if s == tty_sid => {}
        _ => return EPERM,
    }
    if !process::pgrp_is_in_session(pgid, tty_sid) {
        return EPERM;
    }
    tty.ctrl.lock().set_pgrp(Some(pgid));
    0
}

/// `TIOCGPGRP` — return `tty`'s foreground pgrp, or `ENOTTY` if none.
#[cfg(target_os = "none")]
pub fn tiocgpgrp_for(tty: &Tty) -> i64 {
    match tty.ctrl.lock().pgrp {
        Some(p) => p as i64,
        None => ENOTTY,
    }
}

/// `TIOCGSID` — return `tty`'s session id, or `ENOTTY` if none.
#[cfg(target_os = "none")]
pub fn tiocgsid_for(tty: &Tty) -> i64 {
    match tty.ctrl.lock().session {
        Some(s) => s as i64,
        None => ENOTTY,
    }
}

/// `TIOCNOTTY` — detach the caller's session from its controlling
/// terminal. If the caller is the session leader, every session member
/// loses its ctty and the tty's `session`/`pgrp` clear. Non-leaders only
/// drop their own reference. Wait-queue wakeup for blocked readers/writers
/// lands with #429/#430 — TODO below is deliberate.
#[cfg(target_os = "none")]
pub fn tiocnotty_for(caller_pid: u32) -> i64 {
    if caller_pid == 0 {
        return EPERM;
    }
    let tty = match process::ctty_of(caller_pid) {
        Some(t) => t,
        None => return ENOTTY,
    };
    if process::is_session_leader(caller_pid) {
        let sid = match process::session_of(caller_pid) {
            Some(s) => s,
            None => return EPERM,
        };
        process::clear_ctty_for_session(sid);
        let mut ctrl = tty.ctrl.lock();
        ctrl.session = None;
        ctrl.set_pgrp(None);
        // TODO(#429/#430): wake blocked readers/writers once wait queues land.
    } else {
        process::set_ctty(caller_pid, None);
    }
    0
}

/// Open-path hook: `open(tty, !O_NOCTTY)` on a session leader with no
/// existing ctty implicitly acquires `tty` as the ctty. No-op in every
/// other case (non-leader, already-attached, or the tty already has a
/// session). Returns `true` if a ctty was acquired. Errors are swallowed
/// because this is a best-effort side-effect of `open`, not a gate on it.
#[cfg(target_os = "none")]
pub fn acquire_ctty_on_open(caller_pid: u32, tty: &Arc<Tty>) -> bool {
    process::try_acquire_ctty_atomic(caller_pid, tty)
}

/// POSIX background-pgrp write gate for `write(tty, ...)`.
///
/// If `TOSTOP` is set in `tty.termios.c_lflag`, the tty has a foreground
/// pgrp, and `caller_pid` is in a different pgrp, raise `SIGTTOU` on the
/// caller's pgrp and return `Some(KERN_ERESTARTSYS)` — the caller (syscall
/// path) either restarts the write or converts to `EINTR`. Returns `None`
/// when the write should proceed: TOSTOP clear, no foreground pgrp, caller
/// unattached (`pid == 0`) or caller pgrp matches.
///
/// The pgrp identity check reads `ctrl.pgrp_snapshot` without taking
/// `ctrl.lock()` (RFC 0003 §Lock order, fast path).
#[cfg(target_os = "none")]
pub fn tty_check_tostop(tty: &Tty, caller_pid: u32) -> Option<i64> {
    if caller_pid == 0 {
        return None;
    }
    if tty.termios.lock().c_lflag & termios::TOSTOP == 0 {
        return None;
    }
    let fg = tty.ctrl.lock().pgrp_snapshot.load();
    if fg == 0 {
        return None;
    }
    let caller_pgrp = match process::pgrp_of(caller_pid) {
        Some(p) => p,
        None => return None,
    };
    if caller_pgrp == fg {
        return None;
    }
    process::raise_signal_on_pgrp(caller_pgrp, crate::signal::SIGTTOU);
    Some(KERN_ERESTARTSYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_pid_round_trip() {
        let p = AtomicPid::new(0);
        assert_eq!(p.load(), 0);
        p.store(42);
        assert_eq!(p.load(), 42);
        p.store(0);
        assert_eq!(p.load(), 0);
    }

    #[test]
    fn set_pgrp_updates_snapshot() {
        let mut jc = JobControl::new();
        assert_eq!(jc.pgrp, None);
        assert_eq!(jc.pgrp_snapshot.load(), 0);

        jc.set_pgrp(Some(7));
        assert_eq!(jc.pgrp, Some(7));
        assert_eq!(jc.pgrp_snapshot.load(), 7);

        jc.set_pgrp(None);
        assert_eq!(jc.pgrp, None);
        assert_eq!(jc.pgrp_snapshot.load(), 0);
    }

    #[test]
    fn tty_default_has_no_session_or_pgrp() {
        let tty = Tty::new();
        let ctrl = tty.ctrl.lock();
        assert!(ctrl.session.is_none());
        assert!(ctrl.pgrp.is_none());
        assert_eq!(ctrl.pgrp_snapshot.load(), 0);
    }

    #[test]
    fn passthrough_ldisc_appends_bytes_in_order() {
        let ldisc = Arc::new(PassthroughLdisc::with_sink());
        let tty = Tty::with_driver(
            Arc::new(NullDriver),
            ldisc.clone() as Arc<dyn LineDiscipline>,
        );
        for b in b"hello" {
            tty.ldisc.receive_byte(&tty, *b);
        }
        assert_eq!(ldisc.drain_sink(), b"hello");
        // Second drain after take yields empty.
        assert!(ldisc.drain_sink().is_empty());
    }

    #[test]
    fn null_driver_reports_all_bytes_written() {
        let d = NullDriver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"hi"), 2);
    }
}
