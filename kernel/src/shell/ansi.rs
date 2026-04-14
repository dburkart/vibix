//! ANSI CSI state machine for the shell's serial input path.
//!
//! Serial keyboards send arrow keys and other editing keys as escape
//! sequences: plain arrows arrive as three bytes (`ESC [ A`..`D`, or
//! `ESC O A`..`D` from some xterm modes), and modified arrows like
//! Ctrl+Up arrive as longer sequences with parameter bytes — xterm's
//! Ctrl+Up is `ESC [ 1 ; 5 A`. The state machine here walks those
//! sequences byte-by-byte so the shell can route each completed CSI to
//! an editor event without the caller having to buffer escape bytes.
//!
//! Kept as a pure submodule (no kernel imports, no I/O) so it compiles
//! and tests on the host like `line_editor`.
//!
//! Byte-range vocabulary (per ECMA-48 / VT100):
//! - `0x20..=0x2F` — intermediate bytes (e.g. `!`, space).
//! - `0x30..=0x3F` — parameter bytes (digits, `;`, `?`, etc.).
//! - `0x40..=0x7E` — final byte that terminates the CSI.

/// Current position in the escape-sequence grammar. Stored outside the
/// state machine because serial bytes are consumed across many calls
/// (each one is a fresh [`step`]).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum State {
    /// No escape in progress.
    #[default]
    Ground,
    /// Saw `ESC`, waiting for `[` or `O`.
    Esc,
    /// In a CSI body, no parameter / intermediate bytes seen yet.
    Csi,
    /// In a CSI body, at least one parameter or intermediate byte
    /// accumulated. Treated identically to [`State::Csi`] for
    /// dispatch — we only care about the final byte today — but kept
    /// distinct so a future richer decoder can attach a small param
    /// buffer without touching callers.
    CsiParam,
}

/// Final byte of a CSI sequence, classified for the caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CsiFinal {
    /// `A` — up arrow (with or without modifiers).
    Up,
    /// `B` — down arrow.
    Down,
    /// `C` — right arrow.
    Right,
    /// `D` — left arrow.
    Left,
    /// Any other final byte in `0x40..=0x7E`. Surfaced so callers can
    /// extend routing later without another state-machine revision.
    Other(u8),
}

/// Result of feeding one byte to the state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// A ground-state byte the caller should interpret as literal
    /// input. Not emitted for bytes consumed inside an escape.
    Byte(u8),
    /// A CSI sequence terminated on this byte.
    Csi(CsiFinal),
}

/// Feed one serial byte into the state machine. Returns `Some(event)`
/// when the byte completes a dispatchable input; returns `None` when
/// the byte was consumed mid-sequence (or a malformed sequence was
/// dropped) and the caller should wait for more bytes.
pub fn step(state: &mut State, b: u8) -> Option<Event> {
    match (*state, b) {
        (State::Ground, 0x1b) => {
            *state = State::Esc;
            None
        }
        (State::Ground, _) => Some(Event::Byte(b)),

        (State::Esc, b'[') | (State::Esc, b'O') => {
            *state = State::Csi;
            None
        }
        // A fresh ESC mid-recovery restarts parsing rather than
        // dropping the new introducer along with the stale one.
        (State::Esc, 0x1b) => None,
        (State::Esc, _) => {
            // Bare ESC followed by something that isn't the CSI
            // introducer: drop and resync.
            *state = State::Ground;
            None
        }

        (State::Csi, _) | (State::CsiParam, _) => csi_byte(state, b),
    }
}

/// Inner CSI handler. Split out so the two in-CSI states share the
/// param / intermediate / final classification in one place.
fn csi_byte(state: &mut State, b: u8) -> Option<Event> {
    match b {
        // A fresh ESC inside a CSI body abandons the in-progress
        // sequence and starts a new one — the next byte is treated as
        // the introducer.
        0x1b => {
            *state = State::Esc;
            None
        }
        // Parameter or intermediate byte: keep accumulating. Upgrades
        // the state to `CsiParam` so future callers can tell a "plain"
        // CSI from a parameterised one without re-scanning.
        0x20..=0x3F => {
            *state = State::CsiParam;
            None
        }
        // Final byte: dispatch and reset.
        0x40..=0x7E => {
            *state = State::Ground;
            Some(Event::Csi(classify_final(b)))
        }
        // Anything else (C0 control char mid-sequence, 8-bit byte):
        // malformed, drop and resync to Ground.
        _ => {
            *state = State::Ground;
            None
        }
    }
}

fn classify_final(b: u8) -> CsiFinal {
    match b {
        b'A' => CsiFinal::Up,
        b'B' => CsiFinal::Down,
        b'C' => CsiFinal::Right,
        b'D' => CsiFinal::Left,
        _ => CsiFinal::Other(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(state: &mut State, bytes: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        for &b in bytes {
            if let Some(ev) = step(state, b) {
                out.push(ev);
            }
        }
        out
    }

    #[test]
    fn printable_ascii_passthrough() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"hi!"),
            vec![Event::Byte(b'h'), Event::Byte(b'i'), Event::Byte(b'!'),]
        );
        assert_eq!(s, State::Ground);
    }

    #[test]
    fn plain_up_arrow_dispatches_up() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[A"), vec![Event::Csi(CsiFinal::Up)],);
        assert_eq!(s, State::Ground);
    }

    #[test]
    fn plain_down_arrow_dispatches_down() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[B"), vec![Event::Csi(CsiFinal::Down)],);
    }

    #[test]
    fn xterm_o_introducer_accepted() {
        // Some xterm modes use `ESC O A` for arrows.
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1bOA"), vec![Event::Csi(CsiFinal::Up)],);
    }

    #[test]
    fn ctrl_up_with_params_dispatches_up() {
        // xterm Ctrl+Up: ESC [ 1 ; 5 A. Issue #310 policy is to map
        // modified arrows onto the same final-byte classification as
        // plain arrows for now.
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[1;5A"), vec![Event::Csi(CsiFinal::Up)],);
        assert_eq!(s, State::Ground);
    }

    #[test]
    fn intermediate_byte_does_not_drop_sequence() {
        // `ESC [ ! p` is a valid DECSTR soft reset; we don't act on
        // it, but the state machine must consume it without stranding
        // the next arrow.
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[!p"),
            vec![Event::Csi(CsiFinal::Other(b'p'))],
        );
        assert_eq!(feed(&mut s, b"\x1b[A"), vec![Event::Csi(CsiFinal::Up)],);
    }

    #[test]
    fn csi_with_control_byte_mid_sequence_resyncs() {
        // A stray control byte inside a CSI body is malformed; drop
        // the in-progress sequence and resync. The following plain
        // arrow must still dispatch.
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[1\x07"), Vec::<Event>::new());
        assert_eq!(s, State::Ground);
        assert_eq!(feed(&mut s, b"\x1b[B"), vec![Event::Csi(CsiFinal::Down)],);
    }

    #[test]
    fn fresh_esc_after_bare_esc_starts_new_sequence() {
        // `ESC ESC [ A` should dispatch Up, not lose the second ESC
        // along with the first as "bare ESC + non-introducer".
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b\x1b[A"), vec![Event::Csi(CsiFinal::Up)],);
        assert_eq!(s, State::Ground);
    }

    #[test]
    fn fresh_esc_inside_csi_starts_new_sequence() {
        // `ESC [ 1 ESC [ A` should dispatch Up: the new ESC abandons
        // the in-progress CSI and re-enters Esc so `[ A` completes.
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[1\x1b[A"),
            vec![Event::Csi(CsiFinal::Up)],
        );
        assert_eq!(s, State::Ground);
    }

    #[test]
    fn bare_esc_followed_by_letter_resets() {
        // ESC followed by a non-CSI-introducer byte: drop and resync;
        // the trailing letter is not delivered as a ground byte
        // (matches the pre-existing Esc/_ behaviour).
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1bX"), Vec::<Event>::new());
        assert_eq!(s, State::Ground);
        // Next printable byte passes through normally.
        assert_eq!(feed(&mut s, b"y"), vec![Event::Byte(b'y')]);
    }

    #[test]
    fn high_bit_byte_in_ground_surfaces_as_byte() {
        // The state machine itself passes 8-bit bytes through; it's
        // the shell's caller that guards against `b as char`
        // producing replacement chars.
        let mut s = State::default();
        assert_eq!(feed(&mut s, &[0xC3]), vec![Event::Byte(0xC3)]);
    }

    #[test]
    fn left_right_finals_classified() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[C"), vec![Event::Csi(CsiFinal::Right)],);
        assert_eq!(feed(&mut s, b"\x1b[D"), vec![Event::Csi(CsiFinal::Left)],);
    }

    #[test]
    fn unknown_final_reported_as_other() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[H"),
            vec![Event::Csi(CsiFinal::Other(b'H'))],
        );
    }
}
