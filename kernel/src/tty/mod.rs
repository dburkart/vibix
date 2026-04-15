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
pub mod ring;
pub mod termios;

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::poll::WaitQueue;
#[cfg(target_os = "none")]
use crate::sync::IrqLock;
use termios::Termios;

// Host tests can't use IrqLock (it touches RFLAGS.IF) — fall back to a
// plain spin mutex, which has the same external API for our purposes.
#[cfg(all(test, not(target_os = "none")))]
use spin::Mutex as IrqLock;

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
        let tty = Tty::with_driver(
            Arc::new(NullDriver),
            Arc::new(PassthroughLdisc::with_sink()),
        );
        let ldisc = tty.ldisc.clone();
        for b in b"hello" {
            ldisc.receive_byte(&tty, *b);
        }
        // Downcast via a concrete clone for test drain.
        let probe = PassthroughLdisc::with_sink();
        for b in b"hello" {
            probe.receive_byte(&tty, *b);
        }
        assert_eq!(probe.drain_sink(), b"hello");
        // Second drain after take yields empty.
        assert!(probe.drain_sink().is_empty());
    }

    #[test]
    fn null_driver_reports_all_bytes_written() {
        let d = NullDriver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"hi"), 2);
    }
}
