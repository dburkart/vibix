//! PS/2 keyboard rx path routed through the shared console
//! [`Tty`](super::Tty) + [`NTtyLdisc`](super::ntty::NTtyLdisc).
//!
//! Issue #405 / #898. The hardware ISR in
//! [`crate::arch::x86_64::interrupts::keyboard_interrupt`] calls
//! [`push_scancode_from_isr`], which pushes the raw scancode byte into a
//! [`DeferredByteRing`] and latches `SoftIrq::PS2Rx`. On the next
//! [`crate::task::softirq::drain`] tick the registered handler drains the
//! ring, feeds each scancode through a `pc_keyboard` state machine, and
//! forwards every decoded Unicode byte (UTF-8) into
//! `console_tty().ldisc.receive_byte(...)`.
//!
//! Both PS/2 and serial feed the same [`CONSOLE_TTY`](super::CONSOLE_TTY)
//! so userspace sees a single stdin regardless of input source.
//!
//! A second `pc_keyboard::Keyboard` instance lives here rather than
//! sharing the one in [`crate::input`]; the shell-side consumer and the
//! softirq drainer must not contend on a single decoder's modifier
//! state.

use crate::tty::ring::DeferredByteRing;
use crate::tty::TtyDriver;

#[cfg(target_os = "none")]
use crate::task::softirq::{self, SoftIrq};
#[cfg(target_os = "none")]
use pc_keyboard::{layouts::Us104Key, DecodedKey, HandleControl, KeyCode, Keyboard, ScancodeSet1};
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
static DECODER: Lazy<Mutex<Keyboard<Us104Key, ScancodeSet1>>> = Lazy::new(|| {
    Mutex::new(Keyboard::new(
        ScancodeSet1::new(),
        Us104Key,
        HandleControl::MapLettersToUnicode,
    ))
});

/// Return the console tty that PS/2 keyboard input feeds into.
///
/// This is the same [`CONSOLE_TTY`](super::CONSOLE_TTY) that serial
/// input feeds and that userspace reads from — both input sources
/// share a single N_TTY line discipline.
#[cfg(target_os = "none")]
pub fn tty() -> alloc::sync::Arc<super::Tty> {
    super::console_tty()
}

/// Called from the keyboard ISR after
/// [`crate::input::push_scancode_from_isr`]. Pushes the raw scancode
/// byte into [`PS2_RX_RING`] and latches `SoftIrq::PS2Rx`; any subsequent
/// `softirq::drain` tick picks it up. Scancodes that can't fit are
/// silently dropped. The legacy `input::SCANCODES` ring is still fed in
/// parallel for the kernel shell; see `input.rs` for the dual-consumer
/// note.
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
    let (key, shifted) = {
        let mut kbd = DECODER.lock();
        let k = match kbd.add_byte(code) {
            Ok(Some(event)) => kbd.process_keyevent(event),
            _ => None,
        };
        let s = kbd.get_modifiers().is_shifted();
        (k, s)
    };

    // Shift+PgUp/PgDn scrolls the framebuffer without forwarding to
    // userspace — mirrors the kernel shell's scrollback handling
    // (shell/mod.rs:76-84) so scrollback works even when the shell is
    // not running.
    if let Some(DecodedKey::RawKey(kc @ (KeyCode::PageUp | KeyCode::PageDown))) = key {
        if shifted {
            match kc {
                KeyCode::PageUp => crate::framebuffer::scroll_view_up_page(),
                KeyCode::PageDown => crate::framebuffer::scroll_view_down_page(),
                _ => {}
            }
            return;
        }
    }

    let Some(DecodedKey::Unicode(c)) = key else {
        return;
    };
    let tty = super::console_tty();
    let mut buf = [0u8; 4];
    for &b in c.encode_utf8(&mut buf).as_bytes() {
        tty.ldisc.receive_byte(&tty, b);
    }
}

/// Boot-time wiring. Forces [`CONSOLE_TTY`](super::CONSOLE_TTY) and the
/// scancode decoder, then registers the soft-IRQ drain handler. Must be
/// called before the PS/2 IRQ is unmasked (see [`softirq::register`]
/// docs for the "register before enabling the IRQ" convention).
#[cfg(target_os = "none")]
pub fn init() {
    // Ensure the shared console tty is initialised before the ISR can
    // fire — the drain handler references it on every tick.
    Lazy::force(&super::CONSOLE_TTY);
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
