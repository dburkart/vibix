//! PS/2 keyboard rx path routed through [`Tty`] + [`LineDiscipline`].
//!
//! Issue #405. The hardware ISR in
//! [`crate::arch::x86_64::interrupts::keyboard_interrupt`] calls
//! [`push_scancode_from_isr`], which pushes the raw scancode byte into a
//! [`DeferredByteRing`] and latches `SoftIrq::PS2Rx`. On the next
//! [`crate::task::softirq::drain`] tick the registered handler drains the
//! ring, feeds each scancode through a `pc_keyboard` state machine, and
//! forwards every decoded Unicode byte (UTF-8) into
//! `tty.ldisc.receive_byte(&tty, b)`.
//!
//! The default line discipline is [`NTtyLdisc::new_kernel`], which runs
//! each decoded byte through the full N_TTY pipeline (ISIG / ICANON /
//! OPOST / ECHO). The shell still reads keystrokes via [`crate::input`]'s
//! untouched SCANCODES ring until a second consumer migrates to the
//! ldisc's raw ring in a follow-up.
//!
//! A second `pc_keyboard::Keyboard` instance lives here rather than
//! sharing the one in [`crate::input`]; the shell-side consumer and the
//! softirq drainer must not contend on a single decoder's modifier
//! state. This duplication goes away when N_TTY replaces the shell's
//! direct `input::read_key` consumer.

use crate::tty::ring::DeferredByteRing;
use crate::tty::TtyDriver;

#[cfg(target_os = "none")]
use crate::task::softirq::{self, SoftIrq};
#[cfg(target_os = "none")]
use crate::tty::ntty::NTtyLdisc;
#[cfg(target_os = "none")]
use crate::tty::{LineDiscipline, Tty};
#[cfg(target_os = "none")]
use alloc::sync::Arc;
#[cfg(target_os = "none")]
use pc_keyboard::{layouts::Us104Key, DecodedKey, HandleControl, Keyboard, ScancodeSet1};
#[cfg(target_os = "none")]
use spin::{Lazy, Mutex};

/// ISR→softirq handoff ring for PS/2 rx. Producer is the keyboard ISR
/// (exclusive via hardware vectoring); consumer is [`ps2_softirq_drain`].
pub static PS2_RX_RING: DeferredByteRing = DeferredByteRing::new();

/// Trivial [`TtyDriver`] stub for the PS/2 keyboard.
///
/// A keyboard has no tx surface of interest — writes to the tty go to
/// the attached output device (framebuffer/serial), not back to the
/// keyboard. `write` therefore reports all bytes consumed without side
/// effects, matching [`NullDriver`](super::NullDriver).
pub struct Ps2Driver;

impl TtyDriver for Ps2Driver {
    fn write(&self, buf: &[u8]) -> usize {
        buf.len()
    }
}

#[cfg(target_os = "none")]
static PS2_TTY: Lazy<Arc<Tty>> = Lazy::new(|| {
    Arc::new(Tty::with_driver(
        Arc::new(Ps2Driver),
        Arc::new(NTtyLdisc::new_kernel()) as Arc<dyn LineDiscipline>,
    ))
});

#[cfg(target_os = "none")]
static DECODER: Lazy<Mutex<Keyboard<Us104Key, ScancodeSet1>>> = Lazy::new(|| {
    Mutex::new(Keyboard::new(
        ScancodeSet1::new(),
        Us104Key,
        HandleControl::MapLettersToUnicode,
    ))
});

/// Accessor for the global PS/2 tty. Lazy-initialised; safe to call
/// after [`init`] has run, and tolerable before (tests may touch it).
#[cfg(target_os = "none")]
pub fn tty() -> Arc<Tty> {
    PS2_TTY.clone()
}

/// Called from the keyboard ISR after
/// [`crate::input::push_scancode_from_isr`]. Pushes the raw scancode
/// byte into [`PS2_RX_RING`] and latches `SoftIrq::PS2Rx`; any subsequent
/// `softirq::drain` tick picks it up. Scancodes that can't fit are
/// silently dropped — this is a best-effort observation path. The
/// authoritative rx buffer for the shell is still `input::SCANCODES`.
#[cfg(target_os = "none")]
pub fn push_scancode_from_isr(code: u8) {
    let _ = PS2_RX_RING.push(code);
    softirq::raise(SoftIrq::PS2Rx);
}

/// Soft-IRQ drain handler for PS/2 rx. Registered by [`init`]; must not
/// allocate or block — it runs with IRQs masked off the tail of
/// [`crate::task::preempt_tick`].
#[cfg(target_os = "none")]
fn ps2_softirq_drain() {
    while let Some(code) = PS2_RX_RING.pop() {
        decode_and_forward(code);
    }
}

#[cfg(target_os = "none")]
fn decode_and_forward(code: u8) {
    let key = {
        let mut kbd = DECODER.lock();
        match kbd.add_byte(code) {
            Ok(Some(event)) => kbd.process_keyevent(event),
            _ => None,
        }
    };
    let Some(DecodedKey::Unicode(c)) = key else {
        return;
    };
    let tty = PS2_TTY.clone();
    let mut buf = [0u8; 4];
    for &b in c.encode_utf8(&mut buf).as_bytes() {
        tty.ldisc.receive_byte(&tty, b);
    }
}

/// Boot-time wiring. Forces [`PS2_TTY`] initialisation and registers the
/// soft-IRQ drain handler. Must be called before the PS/2 IRQ is
/// unmasked (see [`softirq::register`] docs for the "register before
/// enabling the IRQ" convention).
#[cfg(target_os = "none")]
pub fn init() {
    Lazy::force(&PS2_TTY);
    Lazy::force(&DECODER);
    softirq::register(SoftIrq::PS2Rx, ps2_softirq_drain);
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // Host-side tests can't use Lazy<Arc<Tty>> with target-only state.
    // Exercise the moving parts we can test: the ring + Ps2Driver stub.
    #[test]
    fn ps2_driver_write_reports_all_bytes() {
        let d = Ps2Driver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"abc"), 3);
    }

    #[test]
    fn ring_isr_push_and_drain_preserves_order() {
        while PS2_RX_RING.pop().is_some() {}

        PS2_RX_RING.push(0x1e); // scancode 'a' make
        PS2_RX_RING.push(0xab);
        let mut out = Vec::new();
        while let Some(b) = PS2_RX_RING.pop() {
            out.push(b);
        }
        assert_eq!(out, alloc::vec![0x1e, 0xab]);
    }
}
