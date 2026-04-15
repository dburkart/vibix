//! TTY subsystem.
//!
//! Today this module is [`termios`] plus a minimal [`Tty`] stub with the
//! job-control fields the PCB needs for `setsid`/`setpgid` (#372). The
//! `LineDiscipline`, `TtyDriver`, and `DeferredByteRing` arrive with
//! #374–#376.

pub mod termios;

use core::sync::atomic::{AtomicU32, Ordering};

use spin::Mutex;

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

/// Minimal TTY stub.
///
/// #372 needs `Option<Arc<Tty>>` in the PCB to hold the controlling
/// terminal, and the N_TTY ISIG path needs a place to publish the pgrp
/// snapshot. #374 extends this with `driver`, `ldisc`, `termios`, and
/// `read_wait`/`write_wait` wait-queues — additive changes that don't
/// touch the PCB wiring landed here.
pub struct Tty {
    pub ctrl: Mutex<JobControl>,
}

impl Tty {
    pub fn new() -> Self {
        Self {
            ctrl: Mutex::new(JobControl::new()),
        }
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
}
