//! N_TTY line discipline (RFC 0003 §N_TTY input).
//!
//! Layers implemented so far:
//! - `c_iflag` input transforms (ISTRIP / IGNCR / ICRNL / INLCR).
//! - ISIG signal generation (SIGINT / SIGQUIT / SIGTSTP).
//! - `c_oflag` output transforms + echo (OPOST / ONLCR / OCRNL / ECHO / ECHOE / ECHONL).
//! - ICANON line buffering: VERASE / VKILL / VEOF / VEOL / newline commit.

use spin::Mutex;

use super::termios::{
    Termios, ECHO, ECHOE, ECHONL, ICANON, ICRNL, IGNCR, INLCR, ISIG, ISTRIP, OCRNL, ONLCR, OPOST,
    VEOF, VEOL, VERASE, VINTR, VKILL, VQUIT, VSUSP,
};
use super::JobControl;

// Signal numbers mirrored here to keep `tty` buildable on host (the
// real `crate::signal` module is gated on `target_os = "none"`). These
// values must match `kernel/src/signal/mod.rs`.
const SIGHUP: u8 = 1;
const SIGINT: u8 = 2;
const SIGQUIT: u8 = 3;
const SIGTSTP: u8 = 20;
const SIGCONT: u8 = 18;

/// Byte sink used by the output path. `process_output` and `queue_echo`
/// push transformed bytes into a sink rather than allocating a buffer so
/// callers can target either a ring (future `DeferredByteRing` from #376)
/// or a test-local `Vec<u8>`.
pub trait OutSink {
    fn push(&mut self, b: u8);
}

/// Signal dispatcher used by the N_TTY ISIG path. Decouples `receive_signal_or_byte`
/// from `crate::signal` / `crate::process`, which are gated on
/// `target_os = "none"` and unavailable to host unit tests. Production
/// code wires [`KernelSignalDispatch`] (defined only for
/// `target_os = "none"`); tests supply their own.
pub trait SignalDispatch {
    /// True when the pgrp has no live members. When this returns true,
    /// the ISIG path delivers `SIGHUP` + `SIGCONT` via [`Self::send_to_pgrp`]
    /// instead of the originally-requested signal — mirrors Linux's
    /// background-pgrp-read behaviour.
    fn is_orphaned(&self, pgid: u32) -> bool;

    /// Fan-out signal `sig` to every live member of `pgid`. No-op when
    /// `pgid == 0`.
    fn send_to_pgrp(&self, pgid: u32, sig: u8);
}

/// Production dispatcher that routes through `crate::signal` and
/// `crate::process`. Only compiled in a full kernel build.
#[cfg(target_os = "none")]
pub struct KernelSignalDispatch;

#[cfg(target_os = "none")]
impl SignalDispatch for KernelSignalDispatch {
    fn is_orphaned(&self, pgid: u32) -> bool {
        crate::process::pgrp_is_orphaned(pgid)
    }

    fn send_to_pgrp(&self, pgid: u32, sig: u8) {
        crate::signal::send_to_pgrp(pgid, sig);
    }
}

/// Readers waiting on committed data in the raw ring. Decouples the
/// N_TTY line discipline from the `Tty`-level waitqueue — production
/// wiring supplies a real implementation; tests use [`NullWake`].
pub trait ReaderWake {
    fn wake(&self);
}

pub struct NullWake;

impl ReaderWake for NullWake {
    fn wake(&self) {}
}

fn matches_cc(termios: &Termios, cc_idx: usize, c: u8) -> bool {
    let cc = termios.c_cc[cc_idx];
    cc != 0 && c == cc
}

const LINE_BUF_CAP: usize = 4096;
const RAW_RING_CAP: usize = 4096;

struct LineBuffer {
    buf: [u8; LINE_BUF_CAP],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; LINE_BUF_CAP],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len >= LINE_BUF_CAP {
            return false;
        }
        self.buf[self.len] = b;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        Some(self.buf[self.len])
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    #[allow(dead_code)]
    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }

}

struct RawRing {
    buf: [u8; RAW_RING_CAP],
    head: usize,
    tail: usize,
    eof_pos: Option<usize>,
}

impl RawRing {
    const fn new() -> Self {
        Self {
            buf: [0; RAW_RING_CAP],
            head: 0,
            tail: 0,
            eof_pos: None,
        }
    }

    fn len(&self) -> usize {
        self.tail.wrapping_sub(self.head)
    }

    #[allow(dead_code)]
    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len() >= RAW_RING_CAP {
            return false;
        }
        self.buf[self.tail & (RAW_RING_CAP - 1)] = b;
        self.tail = self.tail.wrapping_add(1);
        true
    }

    fn commit_line(&mut self, src: &[u8], is_eof: bool) {
        for &b in src {
            if !self.push(b) {
                break;
            }
        }
        if is_eof {
            self.eof_pos = Some(self.tail);
        }
    }
}

struct NTtyState {
    line: LineBuffer,
    raw: RawRing,
}

impl NTtyState {
    fn commit_line(&mut self, is_eof: bool) {
        self.raw
            .commit_line(&self.line.buf[..self.line.len], is_eof);
        self.line.len = 0;
    }
}

pub struct NTty {
    state: Mutex<NTtyState>,
}

impl NTty {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NTtyState {
                line: LineBuffer::new(),
                raw: RawRing::new(),
            }),
        }
    }

    /// Signal-aware entry point. Must be called before the hot
    /// `receive_byte` path when a [`JobControl`] is available (i.e. for
    /// any tty that has a controlling session) so Ctrl-C / Ctrl-\ /
    /// Ctrl-Z generate the right signals before ICANON buffering.
    ///
    /// With `ISIG` clear or the byte not matching VINTR/VQUIT/VSUSP,
    /// behavior is identical to [`NTty::receive_byte`]. With a match:
    /// the foreground pgrp is read lock-free from
    /// `ctrl.pgrp_snapshot`; if the pgrp is orphaned (no live members),
    /// `SIGHUP` + `SIGCONT` are delivered instead of the intended
    /// signal, matching Linux's background-pgrp read behavior. The
    /// signal byte is then consumed — the caller does **not** commit
    /// it to the line buffer.
    pub fn receive_signal_or_byte(
        &self,
        termios: &Termios,
        ctrl: &JobControl,
        dispatch: &dyn SignalDispatch,
        b: u8,
    ) -> Option<u8> {
        if termios.c_lflag & ISIG != 0 {
            let sig = if b == termios.c_cc[VINTR] {
                Some(SIGINT)
            } else if b == termios.c_cc[VQUIT] {
                Some(SIGQUIT)
            } else if b == termios.c_cc[VSUSP] {
                Some(SIGTSTP)
            } else {
                None
            };
            if let Some(sig) = sig {
                let pgrp = ctrl.pgrp_snapshot.load();
                if pgrp != 0 {
                    if dispatch.is_orphaned(pgrp) {
                        dispatch.send_to_pgrp(pgrp, SIGHUP);
                        dispatch.send_to_pgrp(pgrp, SIGCONT);
                    } else {
                        dispatch.send_to_pgrp(pgrp, sig);
                    }
                }
                return None;
            }
        }
        self.receive_byte(termios, b)
    }

    /// ICANON-aware input path. Routes a post-iflag byte into either the
    /// line editor (canonical mode) or straight into the raw ring (raw
    /// mode). Callers should feed the result of `receive_byte` (or
    /// `receive_signal_or_byte`) into this method.
    ///
    /// In canonical mode: VERASE pops the last byte, VKILL clears the
    /// line, VEOF commits the line without appending the EOF byte itself
    /// (and records a positional EOF boundary on the raw ring), `\n` and
    /// VEOL append and commit. All other bytes are appended to the
    /// line-in-progress; overflow silently drops the newest byte
    /// (matching Linux behavior).
    ///
    /// In raw mode (`ICANON` clear): every byte is pushed directly into
    /// the raw ring and the reader is woken immediately.
    pub fn canon_input(&self, termios: &Termios, c: u8, wake: &dyn ReaderWake) {
        let mut st = self.state.lock();
        if termios.c_lflag & ICANON == 0 {
            st.raw.push(c);
            wake.wake();
            return;
        }
        if matches_cc(termios, VEOF, c) {
            st.commit_line(true);
            wake.wake();
            return;
        }
        if c == b'\n' || matches_cc(termios, VEOL, c) {
            st.commit_line(false);
            st.raw.push(c);
            wake.wake();
            return;
        }
        if matches_cc(termios, VERASE, c) {
            st.line.pop();
            return;
        }
        if matches_cc(termios, VKILL, c) {
            st.line.clear();
            return;
        }
        st.line.push(c);
    }

    /// Apply the `c_iflag` input transforms to one raw byte.
    ///
    /// Returns `None` when the byte is consumed (IGNCR drop). Processing
    /// order mirrors Linux `drivers/tty/n_tty.c` `n_tty_receive_char`:
    ///
    /// 1. `ISTRIP` — clear the high bit.
    /// 2. `IGNCR` on `\r` — drop the byte.
    /// 3. `ICRNL` on `\r` — remap to `\n`.
    /// 4. `INLCR` on `\n` — remap to `\r`.
    ///
    /// IGNCR wins over ICRNL; the CR rewrite happens before the NL check
    /// so a single byte is never ping-ponged when both `ICRNL` and `INLCR`
    /// are set.
    pub fn receive_byte(&self, termios: &Termios, b: u8) -> Option<u8> {
        let iflag = termios.c_iflag;
        let mut b = b;
        if iflag & ISTRIP != 0 {
            b &= 0x7f;
        }
        if b == b'\r' {
            if iflag & IGNCR != 0 {
                return None;
            }
            if iflag & ICRNL != 0 {
                return Some(b'\n');
            }
        } else if b == b'\n' && iflag & INLCR != 0 {
            return Some(b'\r');
        }
        Some(b)
    }

    /// Apply `c_oflag` output transforms to `buf`, pushing each emitted
    /// byte into `out`. With `OPOST` clear, every byte passes through
    /// unchanged; with `OPOST` set, `ONLCR` remaps `\n` to `\r\n` and
    /// `OCRNL` remaps `\r` to `\n`. Transforms are per-input-byte: a `\r`
    /// rewritten to `\n` by OCRNL is not then re-expanded by ONLCR.
    pub fn process_output(&self, termios: &Termios, buf: &[u8], out: &mut dyn OutSink) {
        let oflag = termios.c_oflag;
        if oflag & OPOST == 0 {
            for &b in buf {
                out.push(b);
            }
            return;
        }
        for &b in buf {
            match b {
                b'\n' if oflag & ONLCR != 0 => {
                    out.push(b'\r');
                    out.push(b'\n');
                }
                b'\r' if oflag & OCRNL != 0 => {
                    out.push(b'\n');
                }
                _ => out.push(b),
            }
        }
    }

    /// Push one echoed character through the OPOST-aware output path.
    ///
    /// With `ECHO` clear, produces nothing — except that `ECHONL` forces
    /// `\n` through regardless, matching the `-echo echonl` termios
    /// mode. With `ECHOE` set and `c` equal to `VERASE`, emits the
    /// visual-erase sequence `"\b \b"`. Otherwise echoes `c` literally.
    /// All emitted bytes flow through `process_output` so OPOST still
    /// governs the wire format.
    pub fn queue_echo(&self, termios: &Termios, c: u8, out: &mut dyn OutSink) {
        let lflag = termios.c_lflag;
        if lflag & ECHO == 0 && !(lflag & ECHONL != 0 && c == b'\n') {
            return;
        }
        if lflag & ECHOE != 0 && c == termios.c_cc[VERASE] {
            self.process_output(termios, &[0x08, b' ', 0x08], out);
            return;
        }
        self.process_output(termios, &[c], out);
    }
}

impl Default for NTty {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tty::termios::Termios;
    use alloc::vec::Vec;

    impl OutSink for Vec<u8> {
        fn push(&mut self, b: u8) {
            Vec::push(self, b);
        }
    }

    fn termios_with(iflag: u32) -> Termios {
        let mut t = Termios::sane();
        t.c_iflag = iflag;
        t
    }

    fn termios_with_oflag(oflag: u32) -> Termios {
        let mut t = Termios::sane();
        t.c_oflag = oflag;
        t
    }

    fn termios_with_lflag(lflag: u32) -> Termios {
        let mut t = Termios::sane();
        t.c_lflag = lflag;
        t
    }

    #[test]
    fn passthrough_when_iflag_zero() {
        let n = NTty::new();
        let t = termios_with(0);
        assert_eq!(n.receive_byte(&t, 0x41), Some(0x41));
        assert_eq!(n.receive_byte(&t, b'\r'), Some(b'\r'));
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\n'));
        assert_eq!(n.receive_byte(&t, 0xFF), Some(0xFF));
    }

    #[test]
    fn istrip_clears_high_bit() {
        let n = NTty::new();
        let t = termios_with(ISTRIP);
        assert_eq!(n.receive_byte(&t, 0xE1), Some(0x61));
        assert_eq!(n.receive_byte(&t, b'\r'), Some(b'\r'));
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\n'));
    }

    #[test]
    fn inlcr_maps_nl_to_cr() {
        let n = NTty::new();
        let t = termios_with(INLCR);
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\r'));
        assert_eq!(n.receive_byte(&t, b'\r'), Some(b'\r'));
    }

    #[test]
    fn igncr_drops_cr() {
        let n = NTty::new();
        let t = termios_with(IGNCR);
        assert_eq!(n.receive_byte(&t, b'\r'), None);
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\n'));
    }

    #[test]
    fn icrnl_maps_cr_to_nl() {
        let n = NTty::new();
        let t = termios_with(ICRNL);
        assert_eq!(n.receive_byte(&t, b'\r'), Some(b'\n'));
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\n'));
    }

    #[test]
    fn igncr_wins_over_icrnl() {
        let n = NTty::new();
        let t = termios_with(IGNCR | ICRNL);
        assert_eq!(n.receive_byte(&t, b'\r'), None);
    }

    #[test]
    fn icrnl_plus_inlcr_no_pingpong() {
        let n = NTty::new();
        let t = termios_with(ICRNL | INLCR);
        assert_eq!(n.receive_byte(&t, b'\r'), Some(b'\n'));
        assert_eq!(n.receive_byte(&t, b'\n'), Some(b'\r'));
    }

    #[test]
    fn istrip_then_icrnl() {
        let n = NTty::new();
        let t = termios_with(ISTRIP | ICRNL);
        assert_eq!(n.receive_byte(&t, 0x8D), Some(b'\n'));
    }

    #[test]
    fn istrip_then_igncr() {
        let n = NTty::new();
        let t = termios_with(ISTRIP | IGNCR);
        assert_eq!(n.receive_byte(&t, 0x8D), None);
    }

    #[test]
    fn opost_off_is_passthrough() {
        let n = NTty::new();
        let t = termios_with_oflag(ONLCR | OCRNL);
        let mut out = Vec::new();
        n.process_output(&t, b"a\nb\rc", &mut out);
        assert_eq!(out, b"a\nb\rc");
    }

    #[test]
    fn onlcr_maps_nl_to_crnl() {
        let n = NTty::new();
        let t = termios_with_oflag(OPOST | ONLCR);
        let mut out = Vec::new();
        n.process_output(&t, b"a\nb", &mut out);
        assert_eq!(out, b"a\r\nb");
    }

    #[test]
    fn ocrnl_maps_cr_to_nl() {
        let n = NTty::new();
        let t = termios_with_oflag(OPOST | OCRNL);
        let mut out = Vec::new();
        n.process_output(&t, b"\r", &mut out);
        assert_eq!(out, b"\n");
    }

    #[test]
    fn onlcr_plus_ocrnl_no_pingpong() {
        // CR is rewritten to NL (not re-expanded to CRNL); the following
        // NL is independently expanded to CRNL.
        let n = NTty::new();
        let t = termios_with_oflag(OPOST | ONLCR | OCRNL);
        let mut out = Vec::new();
        n.process_output(&t, b"\r\n", &mut out);
        assert_eq!(out, b"\n\r\n");
    }

    #[test]
    fn queue_echo_off_is_noop() {
        let n = NTty::new();
        let t = termios_with_lflag(0);
        let mut out = Vec::new();
        n.queue_echo(&t, b'a', &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn queue_echo_plain_char_via_opost() {
        let mut t = Termios::sane();
        t.c_oflag = OPOST | ONLCR;
        t.c_lflag = ECHO;
        let n = NTty::new();
        let mut out = Vec::new();
        n.queue_echo(&t, b'\n', &mut out);
        assert_eq!(out, b"\r\n");
    }

    #[test]
    fn queue_echo_erase_emits_bs_sp_bs() {
        let mut t = Termios::sane();
        t.c_oflag = 0;
        t.c_lflag = ECHO | ECHOE;
        let n = NTty::new();
        let mut out = Vec::new();
        n.queue_echo(&t, t.c_cc[VERASE], &mut out);
        assert_eq!(out, &[0x08, b' ', 0x08]);
    }

    #[test]
    fn queue_echo_echoe_without_echo_is_noop() {
        let mut t = Termios::sane();
        t.c_lflag = ECHOE;
        let n = NTty::new();
        let mut out = Vec::new();
        n.queue_echo(&t, t.c_cc[VERASE], &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn queue_echo_echonl_emits_nl_with_echo_off() {
        // `-echo echonl` forces newlines through the echo path even with
        // ECHO clear. OPOST | ONLCR still expands the \n to \r\n.
        let mut t = Termios::sane();
        t.c_oflag = OPOST | ONLCR;
        t.c_lflag = ECHONL;
        let n = NTty::new();
        let mut out = Vec::new();
        n.queue_echo(&t, b'\n', &mut out);
        assert_eq!(out, b"\r\n");
        // Non-newline bytes are still suppressed.
        let mut out = Vec::new();
        n.queue_echo(&t, b'a', &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn queue_echo_erase_without_echoe_echoes_literal() {
        let mut t = Termios::sane();
        t.c_oflag = 0;
        t.c_lflag = ECHO;
        let n = NTty::new();
        let mut out = Vec::new();
        n.queue_echo(&t, t.c_cc[VERASE], &mut out);
        assert_eq!(out, &[0x7f]);
    }

    // ── ISIG tests (#431) ────────────────────────────────────────────

    use crate::tty::JobControl;
    use core::cell::RefCell;

    /// Test dispatcher: records every (pgid, sig) call and answers
    /// `is_orphaned` from a pre-seeded set.
    struct CapturingDispatch {
        orphaned_pgrps: &'static [u32],
        captures: RefCell<Vec<(u32, u8)>>,
    }

    impl CapturingDispatch {
        fn new(orphaned: &'static [u32]) -> Self {
            Self {
                orphaned_pgrps: orphaned,
                captures: RefCell::new(Vec::new()),
            }
        }
        fn captures(&self) -> Vec<(u32, u8)> {
            self.captures.borrow().clone()
        }
    }

    impl SignalDispatch for CapturingDispatch {
        fn is_orphaned(&self, pgid: u32) -> bool {
            self.orphaned_pgrps.contains(&pgid)
        }
        fn send_to_pgrp(&self, pgid: u32, sig: u8) {
            self.captures.borrow_mut().push((pgid, sig));
        }
    }

    fn termios_isig() -> Termios {
        let mut t = Termios::sane();
        t.c_lflag = ISIG;
        t
    }

    fn ctrl_with_pgrp(pgid: u32) -> JobControl {
        let jc = JobControl::new();
        jc.pgrp_snapshot.store(pgid);
        jc
    }

    #[test]
    fn isig_ctrl_c_raises_sigint_and_consumes_byte() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(50);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, t.c_cc[VINTR]), None);
        assert_eq!(d.captures(), alloc::vec![(50u32, SIGINT)]);
    }

    #[test]
    fn isig_ctrl_backslash_raises_sigquit() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(51);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, t.c_cc[VQUIT]), None);
        assert_eq!(d.captures(), alloc::vec![(51u32, SIGQUIT)]);
    }

    #[test]
    fn isig_ctrl_z_raises_sigtstp() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(52);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, t.c_cc[VSUSP]), None);
        assert_eq!(d.captures(), alloc::vec![(52u32, SIGTSTP)]);
    }

    #[test]
    fn isig_off_passes_through_to_receive_byte() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        // ISIG cleared; termios still has ICRNL so \r becomes \n.
        let mut t = Termios::sane();
        t.c_lflag = 0;
        t.c_iflag = ICRNL;
        let ctrl = ctrl_with_pgrp(42);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, b'\r'), Some(b'\n'));
        assert!(d.captures().is_empty());
    }

    #[test]
    fn isig_on_non_signal_byte_passes_through() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(53);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, b'a'), Some(b'a'));
        assert!(d.captures().is_empty());
    }

    #[test]
    fn isig_orphaned_pgrp_raises_sighup_sigcont_not_sigint() {
        // Pgrp 99 is orphaned — SIGINT should be replaced by
        // SIGHUP + SIGCONT per Linux background-pgrp semantics.
        let d = CapturingDispatch::new(&[99]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(99);
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, t.c_cc[VINTR]), None);
        assert_eq!(d.captures(), alloc::vec![(99u32, SIGHUP), (99u32, SIGCONT)]);
    }

    #[test]
    fn isig_pgrp_zero_drops_silently() {
        let d = CapturingDispatch::new(&[]);
        let n = NTty::new();
        let t = termios_isig();
        let ctrl = ctrl_with_pgrp(0);
        // Byte is still consumed (matched a signal control char) but
        // no delivery occurs when there's no foreground pgrp.
        assert_eq!(n.receive_signal_or_byte(&t, &ctrl, &d, t.c_cc[VINTR]), None);
        assert!(d.captures().is_empty());
    }

    // ── ICANON tests (#429) ─────────────────────────────────────────

    use core::cell::Cell;

    struct CountingWake(Cell<usize>);

    impl CountingWake {
        fn new() -> Self {
            Self(Cell::new(0))
        }
        fn count(&self) -> usize {
            self.0.get()
        }
    }

    impl ReaderWake for CountingWake {
        fn wake(&self) {
            self.0.set(self.0.get() + 1);
        }
    }

    fn termios_canon() -> Termios {
        let mut t = Termios::sane();
        t.c_lflag = ICANON;
        t
    }

    fn termios_raw() -> Termios {
        let mut t = Termios::sane();
        t.c_lflag = 0;
        t
    }

    fn raw_contents(n: &NTty) -> Vec<u8> {
        let st = n.state.lock();
        let mut out = Vec::new();
        let mut i = st.raw.head;
        while i != st.raw.tail {
            out.push(st.raw.buf[i & (RAW_RING_CAP - 1)]);
            i = i.wrapping_add(1);
        }
        out
    }

    #[test]
    fn raw_mode_pushes_directly_to_ring() {
        let n = NTty::new();
        let t = termios_raw();
        let w = CountingWake::new();
        n.canon_input(&t, b'a', &w);
        n.canon_input(&t, b'b', &w);
        assert_eq!(raw_contents(&n), b"ab");
        assert_eq!(w.count(), 2);
    }

    #[test]
    fn canon_newline_commits_line() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        for &b in b"abc" {
            n.canon_input(&t, b, &w);
        }
        assert!(raw_contents(&n).is_empty());
        assert_eq!(w.count(), 0);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(raw_contents(&n), b"abc\n");
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn canon_veol_commits_line() {
        let mut t = termios_canon();
        t.c_cc[VEOL] = b'|';
        let n = NTty::new();
        let w = CountingWake::new();
        for &b in b"xy" {
            n.canon_input(&t, b, &w);
        }
        n.canon_input(&t, b'|', &w);
        assert_eq!(raw_contents(&n), b"xy|");
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn canon_veof_commits_without_char() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        for &b in b"hi" {
            n.canon_input(&t, b, &w);
        }
        n.canon_input(&t, t.c_cc[VEOF], &w);
        assert_eq!(raw_contents(&n), b"hi");
        assert!(n.state.lock().raw.eof_pos.is_some());
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn canon_verase_pops_last() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        n.canon_input(&t, b'a', &w);
        n.canon_input(&t, b'b', &w);
        n.canon_input(&t, t.c_cc[VERASE], &w);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(raw_contents(&n), b"a\n");
    }

    #[test]
    fn canon_verase_on_empty_is_noop() {
        let n = NTty::new();
        let t = termios_canon();
        let w = NullWake;
        n.canon_input(&t, t.c_cc[VERASE], &w);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(raw_contents(&n), b"\n");
    }

    #[test]
    fn canon_vkill_clears_line() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        for &b in b"abc" {
            n.canon_input(&t, b, &w);
        }
        n.canon_input(&t, t.c_cc[VKILL], &w);
        n.canon_input(&t, b'd', &w);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(raw_contents(&n), b"d\n");
    }

    #[test]
    fn canon_line_overflow_drops_newest() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        for _ in 0..LINE_BUF_CAP {
            n.canon_input(&t, b'x', &w);
        }
        // 4097th byte silently dropped — line buffer is full.
        n.canon_input(&t, b'y', &w);
        assert_eq!(w.count(), 0);
        // Newline commits the full line (all x's).
        n.canon_input(&t, b'\n', &w);
        assert_eq!(w.count(), 1);
        let data = raw_contents(&n);
        assert_eq!(data.len(), LINE_BUF_CAP);
        assert!(data.iter().all(|&b| b == b'x'));
    }

    #[test]
    fn cc_disabled_zero_not_matched() {
        let mut t = termios_canon();
        t.c_cc[VEOF] = 0;
        let n = NTty::new();
        let w = NullWake;
        n.canon_input(&t, 0x04, &w);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(raw_contents(&n), &[0x04, b'\n']);
    }

    #[test]
    fn raw_ring_wraps_correctly() {
        let n = NTty::new();
        let t = termios_raw();
        let w = NullWake;
        for i in 0u8..128 {
            n.canon_input(&t, i, &w);
        }
        {
            let mut st = n.state.lock();
            st.raw.head = st.raw.head.wrapping_add(64);
        }
        for i in 0u8..64 {
            n.canon_input(&t, i, &w);
        }
        assert_eq!(n.state.lock().raw.len(), 128);
    }

    #[test]
    fn eof_pos_is_positional_not_sticky() {
        let n = NTty::new();
        let t = termios_canon();
        let w = NullWake;
        n.canon_input(&t, b'a', &w);
        n.canon_input(&t, t.c_cc[VEOF], &w);
        assert!(n.state.lock().raw.eof_pos.is_some());
        {
            let mut st = n.state.lock();
            st.raw.head = st.raw.tail;
            st.raw.eof_pos = None;
        }
        n.canon_input(&t, b'b', &w);
        n.canon_input(&t, b'\n', &w);
        assert!(n.state.lock().raw.eof_pos.is_none());
    }

    #[test]
    fn wake_called_on_commit() {
        let n = NTty::new();
        let t = termios_canon();
        let w = CountingWake::new();
        n.canon_input(&t, b'a', &w);
        assert_eq!(w.count(), 0);
        n.canon_input(&t, b'\n', &w);
        assert_eq!(w.count(), 1);
        n.canon_input(&t, t.c_cc[VEOF], &w);
        assert_eq!(w.count(), 2);
    }

    #[test]
    fn multi_line_concatenation() {
        let n = NTty::new();
        let t = termios_canon();
        let w = NullWake;
        for &b in b"abc\n" {
            n.canon_input(&t, b, &w);
        }
        for &b in b"def\n" {
            n.canon_input(&t, b, &w);
        }
        assert_eq!(raw_contents(&n), b"abc\ndef\n");
    }
}
