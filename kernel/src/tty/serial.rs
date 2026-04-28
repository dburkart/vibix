//! 16550 serial UART rx path routed through [`Tty`] + [`LineDiscipline`].
//!
//! Issue #406. The hardware ISR in
//! [`crate::arch::x86_64::interrupts::serial_interrupt`] calls
//! [`crate::serial::drain_rx_hardware`], which pulls bytes out of the
//! UART FIFO into the legacy [`crate::serial::RX_RING`] and, in
//! parallel, into [`SERIAL_RX_RING`] via [`push_byte_from_isr`]. On the
//! next [`crate::task::softirq::drain`] tick the registered handler
//! drains the ring and forwards every byte into
//! `tty.ldisc.receive_byte(&tty, b)`.
//!
//! The default line discipline is [`PassthroughLdisc::new`], which drops
//! bytes on the floor. This keeps behaviour identical to the pre-#406
//! world (shell / kernel consumers still read bytes via
//! [`crate::serial::try_read_byte`]) while establishing the pipe that
//! N_TTY (#375) will hook into once it lands.
//!
//! RTS flow control: when the ring first crosses [`WATERMARK_HIGH`] the
//! ISR-side path clears MCR.RTS to backpressure a peer that honours
//! hardware flow control; the softirq drain re-asserts once the ring
//! drops back below. QEMU's `-serial stdio` backend ignores MCR bits, so
//! this is effectively a no-op in our default test setup — the logic is
//! exercised against real hardware.

use crate::tty::ring::{DeferredByteRing, WATERMARK_HIGH};
use crate::tty::TtyDriver;

#[cfg(target_os = "none")]
use alloc::sync::Arc;
#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "none")]
use x86_64::instructions::port::Port;

#[cfg(target_os = "none")]
use crate::task::softirq::{self, SoftIrq};
#[cfg(target_os = "none")]
use crate::tty::ntty::{KernelSignalDispatch, NTtyLdisc, SignalDispatch};
#[cfg(target_os = "none")]
use crate::tty::{LineDiscipline, Tty};
#[cfg(target_os = "none")]
use spin::Lazy;

/// ISR→softirq handoff ring for serial rx. Producer is the 16550 ISR
/// (exclusive via hardware vectoring); consumer is
/// [`serial_softirq_drain`].
pub static SERIAL_RX_RING: DeferredByteRing = DeferredByteRing::new();

/// Tracks whether we have deasserted RTS due to the ring crossing
/// [`WATERMARK_HIGH`]. Keeps the MCR mutation idempotent — the ISR only
/// clears the bit on the leading edge and the softirq drain only sets
/// it on the trailing edge.
#[cfg(target_os = "none")]
static RTS_DEASSERTED: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "none")]
const COM1_MCR: u16 = crate::serial::COM1_BASE + 4;
#[cfg(target_os = "none")]
const MCR_RTS: u8 = 0x02;

/// TTY driver wrapping the existing COM1 tx path.
///
/// Writes go through [`crate::serial::write_bytes`], which holds
/// `COM1.lock()` for the duration of the transfer — identical to the
/// pre-TTY serial output path.
pub struct SerialDriver;

impl TtyDriver for SerialDriver {
    #[cfg(target_os = "none")]
    fn write(&self, buf: &[u8]) -> usize {
        crate::serial::write_bytes(buf);
        buf.len()
    }

    #[cfg(not(target_os = "none"))]
    fn write(&self, buf: &[u8]) -> usize {
        buf.len()
    }
}

#[cfg(target_os = "none")]
static SERIAL_TTY: Lazy<Arc<Tty>> = Lazy::new(|| {
    let dispatch: Arc<dyn SignalDispatch> = Arc::new(KernelSignalDispatch);
    Arc::new(Tty::with_driver(
        Arc::new(SerialDriver),
        Arc::new(NTtyLdisc::new(dispatch)) as Arc<dyn LineDiscipline>,
    ))
});

/// Accessor for the global serial tty. Lazy-initialised; safe to call
/// after [`init`] has run, and tolerable before.
#[cfg(target_os = "none")]
pub fn tty() -> Arc<Tty> {
    SERIAL_TTY.clone()
}

/// Called from [`crate::serial::drain_rx_hardware`] per FIFO byte.
/// Pushes into [`SERIAL_RX_RING`] and latches `SoftIrq::SerialRx`.
/// Bytes that can't fit are silently dropped — the authoritative rx
/// buffer for the shell is still `serial::RX_RING`.
///
/// When the ring first crosses [`WATERMARK_HIGH`] this also clears
/// MCR.RTS so a flow-controlling peer stops transmitting until the
/// softirq drain catches up.
#[cfg(target_os = "none")]
pub fn push_byte_from_isr(byte: u8) {
    let _ = SERIAL_RX_RING.push(byte);
    softirq::raise(SoftIrq::SerialRx);

    if SERIAL_RX_RING.watermark_high()
        && RTS_DEASSERTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    {
        unsafe {
            let mut mcr: Port<u8> = Port::new(COM1_MCR);
            let cur = mcr.read();
            mcr.write(cur & !MCR_RTS);
        }
    }
}

/// Soft-IRQ drain handler for serial rx. Registered by [`init`]; must
/// not allocate or block.
#[cfg(target_os = "none")]
fn serial_softirq_drain() {
    let tty = SERIAL_TTY.clone();
    while let Some(b) = SERIAL_RX_RING.pop() {
        tty.ldisc.receive_byte(&tty, b);
    }

    if RTS_DEASSERTED.load(Ordering::Acquire) && SERIAL_RX_RING.len() < WATERMARK_HIGH {
        unsafe {
            let mut mcr: Port<u8> = Port::new(COM1_MCR);
            let cur = mcr.read();
            mcr.write(cur | MCR_RTS);
        }
        RTS_DEASSERTED.store(false, Ordering::Release);
    }
}

/// Boot-time wiring. Forces [`SERIAL_TTY`] initialisation and registers
/// the soft-IRQ drain handler. Must be called before IRQ4 is unmasked.
#[cfg(target_os = "none")]
pub fn init() {
    Lazy::force(&SERIAL_TTY);
    softirq::register(SoftIrq::SerialRx, serial_softirq_drain);
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn serial_driver_write_reports_all_bytes() {
        let d = SerialDriver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"hello"), 5);
    }

    #[test]
    fn ring_isr_push_and_drain_preserves_order() {
        while SERIAL_RX_RING.pop().is_some() {}

        SERIAL_RX_RING.push(b'A');
        SERIAL_RX_RING.push(b'B');
        SERIAL_RX_RING.push(b'C');
        let mut out = Vec::new();
        while let Some(b) = SERIAL_RX_RING.pop() {
            out.push(b);
        }
        assert_eq!(out, b"ABC");
    }
}
