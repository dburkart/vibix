//! N_TTY line-discipline skeleton (RFC 0003 §N_TTY input).
//!
//! This slice implements only the byte-level `c_iflag` input transforms —
//! pure functions of `Termios.c_iflag` with no signal generation, line
//! buffering, or output path. ICANON / ISIG / OPOST / echo arrive in later
//! sub-issues of #375.

use spin::Mutex;

use super::termios::{
    Termios, ECHO, ECHOE, ECHONL, ICRNL, IGNCR, INLCR, ISTRIP, OCRNL, ONLCR, OPOST, VERASE,
};

/// Byte sink used by the output path. `process_output` and `queue_echo`
/// push transformed bytes into a sink rather than allocating a buffer so
/// callers can target either a ring (future `DeferredByteRing` from #376)
/// or a test-local `Vec<u8>`.
pub trait OutSink {
    fn push(&mut self, b: u8);
}

/// Interior N_TTY state. Guarded by lock class "2d" per RFC 0003 §Lock
/// order. Kept a unit placeholder until the `DeferredByteRing` primitive
/// (#376) lands; receive_byte does not currently need the lock but the
/// public `NTty` type is stabilised here so follow-up PRs extend state in
/// place without churning callers.
#[allow(dead_code)]
struct NTtyState;

pub struct NTty {
    #[allow(dead_code)]
    state: Mutex<NTtyState>,
}

impl NTty {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NTtyState),
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
}
