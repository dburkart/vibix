//! Raw polling transport on COM1 for use while the system is halted
//! under the debugger.
//!
//! The normal `serial::write_bytes` path assumes interrupts are enabled
//! and takes a `Mutex<SerialPort>`. When we're stopped in a fault
//! handler waiting for gdb, interrupts are off and taking the mutex
//! risks deadlocking against a preempted print. This transport reads
//! and writes the UART data register directly with `Port<u8>` and busy-
//! spins on the LSR status bits.
//!
//! # Safety
//!
//! Only use this transport when:
//! - Local interrupts are disabled on the CPU that will call
//!   [`debug_entry`](super::debug_entry).
//! - The IRQ4 serial ISR is not racing with it on this CPU.
//!
//! Meeting both is trivial inside an exception handler (IF=0 on entry)
//! but not during normal kernel execution. The follow-up issue that
//! wires this into `#BP` / `#UD` is responsible for arranging that.

use x86_64::instructions::port::Port;

use super::transport::Transport;
use crate::serial::COM1_BASE;

const UART_REG_DATA: u16 = 0; // RBR on read, THR on write (DLAB=0)
const UART_REG_LSR: u16 = 5; // Line status

const LSR_DR: u8 = 0x01; // Data Ready
const LSR_THRE: u8 = 0x20; // Transmit Holding Register Empty

pub struct Com1PollingTransport {
    data: Port<u8>,
    lsr: Port<u8>,
}

impl Com1PollingTransport {
    pub const fn new() -> Self {
        Self {
            data: Port::new(COM1_BASE + UART_REG_DATA),
            lsr: Port::new(COM1_BASE + UART_REG_LSR),
        }
    }

    fn lsr_bit(&mut self, mask: u8) -> bool {
        unsafe { self.lsr.read() & mask != 0 }
    }
}

impl Default for Com1PollingTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for Com1PollingTransport {
    fn read_byte(&mut self) -> u8 {
        while !self.lsr_bit(LSR_DR) {
            core::hint::spin_loop();
        }
        unsafe { self.data.read() }
    }

    fn try_read_byte(&mut self) -> Option<u8> {
        if self.lsr_bit(LSR_DR) {
            Some(unsafe { self.data.read() })
        } else {
            None
        }
    }

    fn write_byte(&mut self, b: u8) {
        while !self.lsr_bit(LSR_THRE) {
            core::hint::spin_loop();
        }
        unsafe { self.data.write(b) }
    }
}
