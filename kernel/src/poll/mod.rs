//! Poll primitive types — readiness masks and the `PollTable` scratch.
//!
//! RFC 0003 (`docs/RFC/0003-pipes-poll-tty.md` §"Poll table") defines a
//! two-pass `sys_poll`: a **Probe** pass that reads readiness without
//! registering on any WaitQueue, and a **Wait** pass that registers
//! `PollEntry` records before the task parks. Every `FileBackend` gains a
//! `poll` method that drivers specialize (e.g. `PipeBackend`, `Tty`) and
//! default-implementers inherit.
//!
//! This module is the *foundation* of that system. It defines:
//!
//! - [`PollMask`] — a bitmask of `POLL*` readiness bits, sized to match
//!   Linux's `short revents` (`u16`) so the `sys_poll` ABI lines up later.
//! - The Linux-numbered `POLL*` constants.
//! - [`DEFAULT_POLLMASK`] — the readiness advertised by any backend that
//!   has not yet learned how to publish real waitability. Matches Linux's
//!   `DEFAULT_POLLMASK` in `fs/select.c`: read/write both ready, no HUP,
//!   no ERR.
//! - A stub [`PollTable`] with a single `probe()` constructor. Registering
//!   waits is intentionally not implemented here — `WaitQueue` lands in
//!   issue #369, and `PollTable::register` (plus `Wait` mode and
//!   `PollEntry` storage) lands with it. Until then, calling `.poll()` in
//!   Probe mode is a no-op wrt registration, exactly as RFC 0003 specifies.

/// Readiness bitmask. Matches Linux's `revents` width (`short`, 16 bits).
pub type PollMask = u16;

/// Normal data available to read (matches Linux `POLLIN`).
pub const POLLIN: PollMask = 0x0001;
/// Priority data available (matches Linux `POLLPRI`).
pub const POLLPRI: PollMask = 0x0002;
/// Normal data can be written without blocking (matches Linux `POLLOUT`).
pub const POLLOUT: PollMask = 0x0004;
/// Error condition (always reported if set, even if not requested).
pub const POLLERR: PollMask = 0x0008;
/// Peer closed its end (always reported if set, even if not requested).
pub const POLLHUP: PollMask = 0x0010;
/// Invalid request (fd not open; always reported if set).
pub const POLLNVAL: PollMask = 0x0020;
/// Normal-priority data available (synonym of `POLLIN` on Linux).
pub const POLLRDNORM: PollMask = 0x0040;
/// Normal-priority data can be written (synonym of `POLLOUT` on Linux).
pub const POLLWRNORM: PollMask = 0x0100;

/// Advertised readiness for a backend that has not overridden `poll`.
///
/// Matches Linux's `DEFAULT_POLLMASK` (`fs/select.c`): read/write both
/// ready, no error, no hangup. This is what `select(2)` historically
/// returned for any fd that lacked a `.poll` file-op — a safe default
/// because it degrades to spurious wakeups rather than missed ones.
pub const DEFAULT_POLLMASK: PollMask = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM;

/// Per-syscall scratch used by `sys_poll` to track registered waits.
///
/// This is a **stub** — the real `PollTable` (with `PollEntry` storage,
/// `Probe`/`Wait` modes, and a `register(&WaitQueue)` method) lands with
/// issue #369 and the `WaitQueue` primitive. Today the only operation is
/// constructing a probe-mode table, which every `FileBackend::poll`
/// default gets passed. Drivers that override `poll` call
/// `pt.register(...)` — which, in Probe mode, is a no-op by design.
pub struct PollTable {
    _priv: (),
}

impl PollTable {
    /// Construct a probe-mode poll table. In the RFC's two-pass model this
    /// is the first pass: no waits are registered, drivers only report
    /// their current readiness.
    pub const fn probe() -> Self {
        Self { _priv: () }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pollmask_has_expected_bits() {
        assert_eq!(DEFAULT_POLLMASK, POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM);
    }

    #[test]
    fn pollmask_bit_values_match_linux() {
        // Pinned against the Linux x86_64 numeric values from
        // <asm-generic/poll.h>. Same ABI discipline as the O_* flags in
        // `fs/mod.rs`: any drift breaks the `sys_poll` syscall ABI.
        assert_eq!(POLLIN, 0x0001);
        assert_eq!(POLLPRI, 0x0002);
        assert_eq!(POLLOUT, 0x0004);
        assert_eq!(POLLERR, 0x0008);
        assert_eq!(POLLHUP, 0x0010);
        assert_eq!(POLLNVAL, 0x0020);
        assert_eq!(POLLRDNORM, 0x0040);
        assert_eq!(POLLWRNORM, 0x0100);
    }
}
