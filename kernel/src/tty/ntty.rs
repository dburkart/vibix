//! N_TTY line-discipline skeleton (RFC 0003 §N_TTY input).
//!
//! This slice implements only the byte-level `c_iflag` input transforms —
//! pure functions of `Termios.c_iflag` with no signal generation, line
//! buffering, or output path. ICANON / ISIG / OPOST / echo arrive in later
//! sub-issues of #375.

use spin::Mutex;

use super::termios::{Termios, ICANON, ICRNL, IGNCR, INLCR, ISTRIP, VEOF, VEOL, VERASE, VKILL};

/// Maximum bytes held in the unfinished line edit buffer. Sized per RFC
/// 0003 §N_TTY ring sizing; matches Linux `N_TTY_BUF_SIZE`.
const LINE_MAX: usize = 4096;

/// Maximum bytes buffered in the committed read ring.
const RAW_MAX: usize = 4096;

/// Readers waiting on `state.raw`. Implemented as a trait so this slice is
/// independently unit-testable before the `Tty`-level waitqueue lands
/// (#374). The `Tty` wiring PR will supply a real impl that calls the
/// equivalent of Linux's `wake_up_poll`.
pub trait ReaderWake {
    fn wake(&self);
}

impl ReaderWake for () {
    fn wake(&self) {}
}

/// Unfinished line being edited by VERASE/VKILL. Committed to `RawRing`
/// on `\n`, VEOL, or VEOF.
struct LineBuffer {
    buf: [u8; LINE_MAX],
    len: usize,
}

impl LineBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; LINE_MAX],
            len: 0,
        }
    }

    /// Append one byte. Returns `false` if the buffer is full (RFC
    /// "drop-newest" on overflow).
    fn push(&mut self, b: u8) -> bool {
        if self.len >= LINE_MAX {
            return false;
        }
        self.buf[self.len] = b;
        self.len += 1;
        true
    }

    fn pop(&mut self) {
        if self.len > 0 {
            self.len -= 1;
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn drain_into(&mut self, dst: &mut RawRing) {
        for i in 0..self.len {
            if !dst.push(self.buf[i]) {
                break;
            }
        }
        self.len = 0;
    }
}

/// Committed read ring. Readers (post-#374) drain this; ICANON commits
/// whole lines at a time, raw mode pushes each byte directly.
///
/// `eof_at` records VEOF as a **positional boundary** rather than a
/// sticky flag: the value is the number of bytes (counted from `head`)
/// that precede the EOF marker, so `ab\x04cd\n` produces a ring of
/// `abcd\n` with `eof_at = Some(2)` — the read path returns `ab`, then
/// EOF, then `cd\n` on subsequent reads. A sticky bool would collapse
/// this to "EOF happened somewhere" and lose the split.
struct RawRing {
    buf: [u8; RAW_MAX],
    head: usize,
    tail: usize,
    len: usize,
    eof_at: Option<usize>,
}

impl RawRing {
    const fn new() -> Self {
        Self {
            buf: [0; RAW_MAX],
            head: 0,
            tail: 0,
            len: 0,
            eof_at: None,
        }
    }

    /// Push one byte. Returns `false` on full (RFC "drop-newest").
    fn push(&mut self, b: u8) -> bool {
        if self.len >= RAW_MAX {
            return false;
        }
        self.buf[self.tail] = b;
        self.tail = (self.tail + 1) % RAW_MAX;
        self.len += 1;
        true
    }

    /// Record EOF at the current tail position. An existing `eof_at`
    /// is not overwritten — the earlier boundary is still pending for
    /// the reader and must be honoured before a new one is recorded.
    /// The later VEOF collapses into the existing boundary (matching
    /// Linux's "two ^D with no data between" behaviour, where the
    /// second VEOF is a no-op until the first has been consumed).
    fn set_eof(&mut self) {
        if self.eof_at.is_none() {
            self.eof_at = Some(self.len);
        }
    }
}

/// Interior N_TTY state. Guarded by lock class "2d" per RFC 0003 §Lock
/// order. Holds the line-in-progress (ICANON edit buffer) and the
/// committed raw ring readers consume.
struct NTtyState {
    line: LineBuffer,
    raw: RawRing,
}

impl NTtyState {
    const fn new() -> Self {
        Self {
            line: LineBuffer::new(),
            raw: RawRing::new(),
        }
    }
}

pub struct NTty {
    state: Mutex<NTtyState>,
}

/// `_POSIX_VDISABLE`: a `c_cc[i]` of `0` means the control is disabled
/// and the corresponding byte should be treated as plain data. Match
/// against `c_cc` via this helper so a disabled slot never eats `\0`.
fn matches_cc(c: u8, cc: u8) -> bool {
    cc != 0 && c == cc
}

impl NTty {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NTtyState::new()),
        }
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

    /// Line-discipline canonicalisation. Called by the `Tty` rx path on
    /// each post-`receive_byte` byte. With `ICANON` clear the byte goes
    /// straight into the raw ring; with `ICANON` set, VERASE / VKILL /
    /// VEOF / `\n` / VEOL drive line editing and commit boundaries.
    ///
    /// A commit wakes the reader waitqueue via `waker`; edits (VERASE,
    /// VKILL, plain character while mid-line) do not wake — readers in
    /// canonical mode are only interested in completed lines.
    pub fn canon_input(&self, termios: &Termios, c: u8, waker: &impl ReaderWake) {
        let mut commit = false;
        let mut wake_for_push = false;
        {
            let mut st = self.state.lock();
            if termios.c_lflag & ICANON == 0 {
                if st.raw.push(c) {
                    wake_for_push = true;
                }
            } else if matches_cc(c, termios.c_cc[VERASE]) {
                st.line.pop();
            } else if matches_cc(c, termios.c_cc[VKILL]) {
                st.line.clear();
            } else if matches_cc(c, termios.c_cc[VEOF]) {
                commit = true;
                let NTtyState { line, raw } = &mut *st;
                line.drain_into(raw);
                st.raw.set_eof();
            } else if c == b'\n' || matches_cc(c, termios.c_cc[VEOL]) {
                let _ = st.line.push(c);
                commit = true;
                let NTtyState { line, raw } = &mut *st;
                line.drain_into(raw);
            } else {
                let _ = st.line.push(c);
            }
        }
        if commit || wake_for_push {
            waker.wake();
        }
    }

    #[cfg(test)]
    fn snapshot(&self) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>, Option<usize>) {
        use alloc::vec::Vec;
        let st = self.state.lock();
        let line: Vec<u8> = st.line.buf[..st.line.len].to_vec();
        let mut raw: Vec<u8> = Vec::with_capacity(st.raw.len);
        let mut idx = st.raw.head;
        for _ in 0..st.raw.len {
            raw.push(st.raw.buf[idx]);
            idx = (idx + 1) % RAW_MAX;
        }
        (line, raw, st.raw.eof_at)
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
    use crate::tty::termios::{Termios, ICANON, VEOF, VEOL, VERASE, VKILL};
    use core::sync::atomic::{AtomicUsize, Ordering};

    fn termios_with(iflag: u32) -> Termios {
        let mut t = Termios::sane();
        t.c_iflag = iflag;
        t
    }

    /// Clear ICANON on an otherwise-sane termios. Used by the raw-mode
    /// canon_input tests.
    fn termios_noncanon() -> Termios {
        let mut t = Termios::sane();
        t.c_lflag &= !ICANON;
        t
    }

    struct CountingWake(AtomicUsize);
    impl CountingWake {
        const fn new() -> Self {
            Self(AtomicUsize::new(0))
        }
        fn count(&self) -> usize {
            self.0.load(Ordering::Relaxed)
        }
    }
    impl ReaderWake for CountingWake {
        fn wake(&self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn feed(n: &NTty, t: &Termios, w: &impl ReaderWake, s: &[u8]) {
        for &b in s {
            n.canon_input(t, b, w);
        }
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
    fn icanon_off_passes_raw() {
        let n = NTty::new();
        let t = termios_noncanon();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"abc");
        let (line, raw, eof_at) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"abc");
        assert_eq!(eof_at, None);
        assert_eq!(w.count(), 3);
    }

    #[test]
    fn icanon_commits_on_newline() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"hi\n");
        let (line, raw, eof_at) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"hi\n");
        assert_eq!(eof_at, None);
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn verase_pops_last() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"ab\x7f");
        let (line, raw, _) = n.snapshot();
        assert_eq!(line, b"a");
        assert_eq!(raw, b"");
        assert_eq!(w.count(), 0);
    }

    #[test]
    fn verase_empty_is_noop() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"\x7f\x7f");
        let (line, raw, _) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"");
        assert_eq!(w.count(), 0);
    }

    #[test]
    fn vkill_clears_line() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"abc\x15");
        let (line, raw, _) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"");
        assert_eq!(w.count(), 0);
    }

    #[test]
    fn veof_commits_pending() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"ab\x04");
        let (line, raw, eof_at) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"ab");
        // EOF falls after the two committed bytes.
        assert_eq!(eof_at, Some(2));
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn veof_alone_sets_eof() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"\x04");
        let (line, raw, eof_at) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"");
        // EOF at position 0: the reader should see EOF immediately.
        assert_eq!(eof_at, Some(0));
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn veof_between_lines_preserves_boundary() {
        // Regression for the sticky-bool collapse: `ab\x04cd\n` must
        // record EOF between `b` and `c`, not as "EOF somewhere in
        // this stream". The first read should return `ab`, then EOF,
        // then `cd\n` — impossible if `eof` were just a bool.
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"ab\x04cd\n");
        let (line, raw, eof_at) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"abcd\n");
        assert_eq!(eof_at, Some(2));
        // Two commits: one on VEOF, one on newline.
        assert_eq!(w.count(), 2);
    }

    #[test]
    fn long_line_drops_newest() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        let overflow = [b'x'; LINE_MAX + 32];
        feed(&n, &t, &w, &overflow);
        n.canon_input(&t, b'\n', &w);
        let (_, raw, _) = n.snapshot();
        // The \n is drop-newest against the full line buffer, so the
        // committed raw ring holds exactly LINE_MAX 'x' bytes and no
        // terminator. A real producer would see VERASE/VKILL feedback
        // well before hitting LINE_MAX.
        assert_eq!(raw.len(), LINE_MAX);
        assert!(raw.iter().all(|&b| b == b'x'));
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn veol_alt_terminator() {
        let n = NTty::new();
        let mut t = Termios::sane();
        t.c_cc[VEOL] = b';';
        let w = CountingWake::new();
        feed(&n, &t, &w, b"x;");
        let (line, raw, _) = n.snapshot();
        assert_eq!(line, b"");
        assert_eq!(raw, b"x;");
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn disabled_cc_is_inert() {
        let n = NTty::new();
        let mut t = Termios::sane();
        t.c_cc[VERASE] = 0; // _POSIX_VDISABLE
        let w = CountingWake::new();
        feed(&n, &t, &w, b"a\x7f");
        let (line, raw, _) = n.snapshot();
        assert_eq!(line, b"a\x7f");
        assert_eq!(raw, b"");
        assert_eq!(w.count(), 0);
    }

    #[test]
    fn wake_fires_on_commit_not_on_edit() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        // Plain chars and VERASE/VKILL do not wake.
        feed(&n, &t, &w, b"ab\x7f\x15cd");
        assert_eq!(w.count(), 0);
        // Commit once on newline.
        n.canon_input(&t, b'\n', &w);
        assert_eq!(w.count(), 1);
    }

    #[test]
    fn multiple_commits_concatenate() {
        let n = NTty::new();
        let t = Termios::sane();
        let w = CountingWake::new();
        feed(&n, &t, &w, b"one\n");
        feed(&n, &t, &w, b"two\n");
        let (_, raw, _) = n.snapshot();
        assert_eq!(raw, b"one\ntwo\n");
        assert_eq!(w.count(), 2);
    }
}
