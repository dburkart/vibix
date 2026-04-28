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

/// Maximum number of `;`-separated numeric parameters retained per CSI
/// sequence. xterm's modified-key encoding only ever uses two
/// (`ESC [ 1 ; <mod> <final>`); a small cap keeps the state struct
/// `Copy`-cheap and bounds work per byte.
pub const MAX_PARAMS: usize = 4;

/// xterm parameter byte encoding for keyboard modifiers (bit-flags
/// applied to a base of 1). E.g. Shift = 2, Alt = 3, Shift+Alt = 4,
/// Ctrl = 5. We decode this into a flat [`Modifiers`] for the caller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Modifiers {
    pub shift: bool,
    pub alt: bool,
    pub ctrl: bool,
}

impl Modifiers {
    /// `true` when no modifier keys were held.
    pub fn is_none(&self) -> bool {
        !self.shift && !self.alt && !self.ctrl
    }

    /// Decode an xterm parameter value (1 = none, 2 = shift, 3 = alt,
    /// 5 = ctrl, etc.) into modifier flags. Values that don't map to a
    /// known modifier yield [`Modifiers::default`] — callers treating an
    /// unknown modifier as "no modifier" preserves the pre-#336
    /// behaviour where modified arrows degraded to plain arrows.
    fn from_xterm_param(p: u16) -> Self {
        if p < 2 {
            return Modifiers::default();
        }
        let bits = p - 1;
        Self {
            shift: bits & 0b001 != 0,
            alt: bits & 0b010 != 0,
            ctrl: bits & 0b100 != 0,
        }
    }
}

/// Current position in the escape-sequence grammar plus a small param
/// buffer used while a CSI is in flight. Stored outside the dispatch
/// loop because serial bytes are consumed across many calls (each one
/// is a fresh [`step`]).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    phase: Phase,
    /// Numeric `;`-separated parameter values seen so far. Entries past
    /// `params_len` are stale.
    params: [u16; MAX_PARAMS],
    /// Number of populated entries in `params`.
    params_len: usize,
    /// `true` once the current parameter slot has accepted at least one
    /// digit. Distinguishes "empty" from "0", and lets `;` terminate a
    /// slot (advancing `params_len`) without inserting a phantom value
    /// for a leading separator.
    cur_started: bool,
    /// `true` once we've seen any parameter byte that exceeds the
    /// retained capacity (param overflow, individual value overflow, or
    /// an unknown param byte like `?`). The sequence is still consumed
    /// to its final byte; modifiers are reported as default and the
    /// caller can act on the bare final.
    overflow: bool,
}

impl Default for State {
    fn default() -> Self {
        Self {
            phase: Phase::Ground,
            params: [0; MAX_PARAMS],
            params_len: 0,
            cur_started: false,
            overflow: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// No escape in progress.
    Ground,
    /// Saw `ESC`, waiting for `[` or `O`.
    Esc,
    /// Inside a CSI body. The param buffer on [`State`] tells us
    /// whether anything has been accumulated yet — we don't need a
    /// separate `CsiParam` phase the way the pre-#336 enum did.
    Csi,
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
    /// A CSI sequence terminated on this byte. The [`Modifiers`] are
    /// decoded from xterm's `ESC [ 1 ; <mod> <final>` convention; for
    /// unparameterised sequences (or when overflow forced us to drop
    /// the param buffer) every flag is `false`.
    Csi(CsiFinal, Modifiers),
}

/// Feed one serial byte into the state machine. Returns `Some(event)`
/// when the byte completes a dispatchable input; returns `None` when
/// the byte was consumed mid-sequence (or a malformed sequence was
/// dropped) and the caller should wait for more bytes.
pub fn step(state: &mut State, b: u8) -> Option<Event> {
    match (state.phase, b) {
        (Phase::Ground, 0x1b) => {
            state.phase = Phase::Esc;
            None
        }
        (Phase::Ground, _) => Some(Event::Byte(b)),

        (Phase::Esc, b'[') | (Phase::Esc, b'O') => {
            enter_csi(state);
            None
        }
        // A fresh ESC mid-recovery restarts parsing rather than
        // dropping the new introducer along with the stale one.
        (Phase::Esc, 0x1b) => None,
        (Phase::Esc, _) => {
            // Bare ESC followed by something that isn't the CSI
            // introducer: drop and resync.
            reset(state);
            None
        }

        (Phase::Csi, _) => csi_byte(state, b),
    }
}

/// Reset to ground and wipe the param buffer.
fn reset(state: &mut State) {
    *state = State::default();
}

/// Transition into the CSI body, clearing any prior param accumulator.
fn enter_csi(state: &mut State) {
    state.phase = Phase::Csi;
    state.params = [0; MAX_PARAMS];
    state.params_len = 0;
    state.cur_started = false;
    state.overflow = false;
}

/// Inner CSI handler. Splits each in-CSI byte into param accumulation,
/// intermediate bytes, final-byte dispatch, or malformed-byte resync.
fn csi_byte(state: &mut State, b: u8) -> Option<Event> {
    match b {
        // A fresh ESC inside a CSI body abandons the in-progress
        // sequence and starts a new one — the next byte is treated as
        // the introducer.
        0x1b => {
            state.params = [0; MAX_PARAMS];
            state.params_len = 0;
            state.cur_started = false;
            state.overflow = false;
            state.phase = Phase::Esc;
            None
        }
        // Numeric parameter digit: fold into the current slot.
        b'0'..=b'9' => {
            accumulate_digit(state, b - b'0');
            None
        }
        // `;` separator: advance to the next slot (or mark overflow if
        // we've already filled the buffer). A leading or repeated `;`
        // commits a default-zero entry, matching ECMA-48 semantics.
        b';' => {
            commit_param(state);
            None
        }
        // Other parameter bytes (`:`, `<`, `=`, `>`, `?`) and any
        // intermediate byte (`0x20..=0x2F`): we don't decode them, but
        // they don't malform the sequence — keep accumulating and let
        // the final byte still dispatch with default modifiers.
        0x20..=0x2F | 0x3A | 0x3C..=0x3F => {
            state.overflow = true;
            None
        }
        // Final byte: dispatch and reset.
        0x40..=0x7E => {
            let modifiers = decode_modifiers(state);
            let final_byte = b;
            reset(state);
            Some(Event::Csi(classify_final(final_byte), modifiers))
        }
        // Anything else (C0 control char mid-sequence, 8-bit byte):
        // malformed, drop and resync to Ground.
        _ => {
            reset(state);
            None
        }
    }
}

/// Fold a decimal digit into the current parameter slot, capping at
/// `u16::MAX` to keep arithmetic infallible. Slots beyond `MAX_PARAMS`
/// trip the overflow flag so the caller still gets the final byte.
fn accumulate_digit(state: &mut State, digit: u8) {
    if state.params_len >= MAX_PARAMS {
        state.overflow = true;
        return;
    }
    let slot = &mut state.params[state.params_len];
    *slot = slot.saturating_mul(10).saturating_add(u16::from(digit));
    state.cur_started = true;
}

/// Close out the current parameter slot on a `;` separator. Empty
/// slots commit a 0 (per ECMA-48) so positions stay aligned with the
/// caller's expectations (e.g. `ESC [ ; 5 A` → `[0, 5]`). Once the
/// buffer is full, further separators count as overflow but don't
/// abort the sequence.
fn commit_param(state: &mut State) {
    if state.params_len < MAX_PARAMS {
        state.params_len += 1;
        state.cur_started = false;
    } else {
        state.overflow = true;
    }
}

/// Snapshot the modifier value out of the param buffer at dispatch
/// time. xterm encodes modified keys as `ESC [ 1 ; <mod> <final>`, so
/// we read the second slot. Overflowed sequences degrade to default
/// modifiers — preserves the pre-#336 behaviour where weird parameter
/// shapes still let the final byte route as a plain key.
fn decode_modifiers(state: &State) -> Modifiers {
    if state.overflow {
        return Modifiers::default();
    }
    // Number of populated slots: every `;` advances `params_len`, plus
    // one for the in-progress slot if it accumulated digits.
    let total = state.params_len + usize::from(state.cur_started);
    if total < 2 {
        return Modifiers::default();
    }
    // The second slot lives at index 1 regardless of whether it's
    // closed off (params_len >= 2) or still in progress (cur_started
    // with params_len == 1) — `accumulate_digit` writes into
    // `params[params_len]` either way.
    let raw = state.params[1];
    Modifiers::from_xterm_param(raw)
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

    const NOMOD: Modifiers = Modifiers {
        shift: false,
        alt: false,
        ctrl: false,
    };

    #[test]
    fn printable_ascii_passthrough() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"hi!"),
            vec![Event::Byte(b'h'), Event::Byte(b'i'), Event::Byte(b'!'),]
        );
        assert_eq!(s, State::default());
    }

    #[test]
    fn plain_up_arrow_dispatches_up_no_mod() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
        assert_eq!(s, State::default());
    }

    #[test]
    fn plain_down_arrow_dispatches_down_no_mod() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[B"),
            vec![Event::Csi(CsiFinal::Down, NOMOD)],
        );
    }

    #[test]
    fn xterm_o_introducer_accepted() {
        // Some xterm modes use `ESC O A` for arrows.
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1bOA"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
    }

    #[test]
    fn ctrl_up_carries_ctrl_modifier() {
        // xterm Ctrl+Up: ESC [ 1 ; 5 A.
        let mut s = State::default();
        let ctrl = Modifiers {
            ctrl: true,
            ..Modifiers::default()
        };
        assert_eq!(
            feed(&mut s, b"\x1b[1;5A"),
            vec![Event::Csi(CsiFinal::Up, ctrl)],
        );
        assert_eq!(s, State::default());
    }

    #[test]
    fn shift_left_carries_shift_modifier() {
        let mut s = State::default();
        let shift = Modifiers {
            shift: true,
            ..Modifiers::default()
        };
        assert_eq!(
            feed(&mut s, b"\x1b[1;2D"),
            vec![Event::Csi(CsiFinal::Left, shift)],
        );
    }

    #[test]
    fn alt_right_carries_alt_modifier() {
        let mut s = State::default();
        let alt = Modifiers {
            alt: true,
            ..Modifiers::default()
        };
        assert_eq!(
            feed(&mut s, b"\x1b[1;3C"),
            vec![Event::Csi(CsiFinal::Right, alt)],
        );
    }

    #[test]
    fn shift_alt_combo_decodes_both() {
        // xterm encodes Shift+Alt as modifier value 4 (1 + 0b011).
        let mut s = State::default();
        let m = Modifiers {
            shift: true,
            alt: true,
            ctrl: false,
        };
        assert_eq!(
            feed(&mut s, b"\x1b[1;4A"),
            vec![Event::Csi(CsiFinal::Up, m)],
        );
    }

    #[test]
    fn intermediate_byte_does_not_drop_sequence() {
        // `ESC [ ! p` is a valid DECSTR soft reset; we don't act on
        // it, but the state machine must consume it without stranding
        // the next arrow. Intermediate bytes set the overflow flag, so
        // the dispatched event reports default modifiers.
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[!p"),
            vec![Event::Csi(CsiFinal::Other(b'p'), NOMOD)],
        );
        assert_eq!(
            feed(&mut s, b"\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
    }

    #[test]
    fn csi_with_control_byte_mid_sequence_resyncs() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1b[1\x07"), Vec::<Event>::new());
        assert_eq!(s, State::default());
        assert_eq!(
            feed(&mut s, b"\x1b[B"),
            vec![Event::Csi(CsiFinal::Down, NOMOD)],
        );
    }

    #[test]
    fn fresh_esc_after_bare_esc_starts_new_sequence() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
        assert_eq!(s, State::default());
    }

    #[test]
    fn fresh_esc_inside_csi_starts_new_sequence() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[1\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
        assert_eq!(s, State::default());
    }

    #[test]
    fn bare_esc_followed_by_letter_resets() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, b"\x1bX"), Vec::<Event>::new());
        assert_eq!(s, State::default());
        assert_eq!(feed(&mut s, b"y"), vec![Event::Byte(b'y')]);
    }

    #[test]
    fn high_bit_byte_in_ground_surfaces_as_byte() {
        let mut s = State::default();
        assert_eq!(feed(&mut s, &[0xC3]), vec![Event::Byte(0xC3)]);
    }

    #[test]
    fn left_right_finals_classified() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[C"),
            vec![Event::Csi(CsiFinal::Right, NOMOD)],
        );
        assert_eq!(
            feed(&mut s, b"\x1b[D"),
            vec![Event::Csi(CsiFinal::Left, NOMOD)],
        );
    }

    #[test]
    fn unknown_final_reported_as_other() {
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[H"),
            vec![Event::Csi(CsiFinal::Other(b'H'), NOMOD)],
        );
    }

    #[test]
    fn excess_params_drop_cleanly_with_default_modifiers() {
        // Five params overflow the four-slot buffer; the sequence is
        // still consumed and the final byte still classified, but the
        // modifier decode reports default (no modifiers held) so the
        // caller behaves as if it were a plain arrow.
        let mut s = State::default();
        assert_eq!(
            feed(&mut s, b"\x1b[1;2;3;4;5A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
        assert_eq!(s, State::default());
        // The state machine recovers — a follow-up plain arrow still
        // dispatches.
        assert_eq!(
            feed(&mut s, b"\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
    }

    #[test]
    fn very_long_param_value_saturates_without_panic() {
        let mut s = State::default();
        // 10 digits would overflow u16 mid-multiply; saturating math
        // keeps the parser honest. Modifier slot is empty so we still
        // get default modifiers.
        let evs = feed(&mut s, b"\x1b[9999999999A");
        assert_eq!(evs, vec![Event::Csi(CsiFinal::Up, NOMOD)]);
        // And we can still parse a normal sequence afterwards.
        assert_eq!(
            feed(&mut s, b"\x1b[A"),
            vec![Event::Csi(CsiFinal::Up, NOMOD)],
        );
    }

    #[test]
    fn modifiers_is_none_helper() {
        assert!(NOMOD.is_none());
        assert!(!Modifiers {
            ctrl: true,
            ..Modifiers::default()
        }
        .is_none());
    }
}
