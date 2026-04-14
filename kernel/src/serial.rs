//! COM1 16550 UART — our primary log sink during early boot, plus an
//! interrupt-driven RX path that feeds the shell's input loop.
//!
//! Write side uses the `uart_16550` crate's `SerialPort` behind a
//! `Mutex`. RX side runs out of the IRQ4 ISR (`serial_interrupt` in
//! `arch::x86_64::interrupts`): the ISR drains the UART FIFO into
//! `RX_RING`, consumers pop via [`try_read_byte`]. Ring overflow
//! increments [`rx_overflows`] and drops the new byte — mirrors the
//! keyboard scancode path in `input.rs`.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

use spin::Mutex;
use uart_16550::SerialPort;
use x86_64::instructions::interrupts::without_interrupts;
use x86_64::instructions::port::Port;

use crate::input::RingBuffer;

/// COM1 IO base. Individual registers are named offsets off of this.
pub const COM1_BASE: u16 = 0x3F8;

const UART_REG_RBR: u16 = 0; // R: receive buffer (DLAB=0)
const UART_REG_IER: u16 = 1; // R/W: interrupt enable (DLAB=0)
const UART_REG_LCR: u16 = 3; // R/W: line control (bit 7 = DLAB)
const UART_REG_MCR: u16 = 4; // R/W: modem control
const UART_REG_LSR: u16 = 5; // R: line status

/// IER bit 0 — Received Data Available interrupt.
const IER_RDA: u8 = 0x01;
/// MCR bit 3 — OUT2. Required to gate the UART's interrupt line to the
/// IOAPIC; without it, enabling IER alone produces no IRQ.
const MCR_OUT2: u8 = 0x08;
/// LSR bit 0 — Data Ready (one or more bytes in RBR).
const LSR_DR: u8 = 0x01;

static COM1: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(COM1_BASE) });

/// RX bytes pushed here from the IRQ4 ISR. Sized to match the keyboard
/// scancode ring (128) — human typing can't overflow it; the only way
/// it fills is a stuck consumer, which [`rx_overflows`] reports.
static RX_RING: Mutex<RingBuffer<u8, 128>> = Mutex::new(RingBuffer::new());

/// Count of bytes the ISR dropped because `RX_RING` was full.
static RX_OVERFLOWS: AtomicU64 = AtomicU64::new(0);

pub fn init() {
    COM1.lock().init();
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Best-effort: if this fires from an interrupt that preempted a
    // print holding the lock we would deadlock — acceptable for now,
    // all our interrupt handlers halt anyway.
    let _ = COM1.lock().write_fmt(args);
}

/// Write an arbitrary byte slice to COM1, holding the mutex for the
/// entire transfer.
///
/// Uses [`SerialPort::send_raw`] (THRE-spin per byte) inside
/// `without_interrupts` so no IRQ can interleave bytes mid-string and
/// the lock is never contended against the ISR RX path.
///
/// # Deadlock safety
///
/// `without_interrupts` blocks the IRQ4 serial ISR for the duration.
/// No callee on the `SerialBackend::write` → `write_bytes` path calls
/// `serial_println!` or re-acquires `COM1`, so there is no reentrancy
/// hazard.
pub(crate) fn write_bytes(buf: &[u8]) {
    without_interrupts(|| {
        let mut port = COM1.lock();
        for &b in buf {
            port.send_raw(b);
        }
    });
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}

/// Enable the Received-Data-Available interrupt on COM1 and assert
/// MCR.OUT2 so the UART's IRQ line actually reaches the IOAPIC.
///
/// Call *after* `route_legacy_irq(4, ...)` — the ISR vector must exist
/// before an IRQ can fire into it. The `uart_16550` init path leaves
/// IER=0, so enabling it here is safe against double-init.
pub fn enable_rx_interrupts() {
    unsafe {
        let mut lcr: Port<u8> = Port::new(COM1_BASE + UART_REG_LCR);
        // Force DLAB=0 so offset 1 addresses IER (not divisor latch
        // high). `uart_16550::init` already did this, but defend in
        // depth: any future re-entry that toggled DLAB would otherwise
        // silently scribble the baud divisor.
        let cur_lcr = lcr.read() & 0x7F;
        lcr.write(cur_lcr);

        let mut ier: Port<u8> = Port::new(COM1_BASE + UART_REG_IER);
        ier.write(IER_RDA);

        let mut mcr: Port<u8> = Port::new(COM1_BASE + UART_REG_MCR);
        let cur_mcr = mcr.read();
        mcr.write(cur_mcr | MCR_OUT2);
    }
    crate::serial_println!("serial: rx irq enabled");
}

/// Drain the UART receive FIFO into [`RX_RING`]. Called from the IRQ4
/// ISR; also safe to call from test code after TX-loopback.
///
/// Loops while LSR.DR is set so a single IRQ can pull a burst out of
/// the FIFO in one shot, avoiding spurious re-entries on consecutive
/// bytes.
pub(crate) fn drain_rx_hardware() {
    unsafe {
        let mut lsr: Port<u8> = Port::new(COM1_BASE + UART_REG_LSR);
        let mut rbr: Port<u8> = Port::new(COM1_BASE + UART_REG_RBR);
        while lsr.read() & LSR_DR != 0 {
            let b = rbr.read();
            if !RX_RING.lock().push(b) {
                RX_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Pop the next received byte, or `None` if the ring is empty.
pub fn try_read_byte() -> Option<u8> {
    without_interrupts(|| RX_RING.lock().pop())
}

/// Count of bytes dropped by the ISR because `RX_RING` was full.
pub fn rx_overflows() -> u64 {
    RX_OVERFLOWS.load(Ordering::Relaxed)
}
