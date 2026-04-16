//! Byte transport for the gdbstub packet loop.
//!
//! Two implementations live behind this trait:
//! - [`VecTransport`]: in-memory queue, used by host unit tests and by
//!   the QEMU integration test so the packet loop can run without any
//!   real UART traffic.
//! - `Com1PollingTransport` in [`crate::gdbstub::uart`]: raw polling
//!   reads/writes against COM1. Only exists in kernel builds.
//!
//! The trait is deliberately minimal: blocking [`read_byte`], a non-
//! blocking [`try_read_byte`] for `^C` detection, and [`write_byte`].
//! No framing lives here.

use alloc::collections::VecDeque;
use alloc::vec::Vec;

pub trait Transport {
    /// Block until one byte is available, then return it.
    fn read_byte(&mut self) -> u8;

    /// Non-blocking peek at the next byte; returns `None` if none is
    /// ready. Used by the packet loop to detect `^C` interrupt
    /// requests between packets.
    fn try_read_byte(&mut self) -> Option<u8>;

    /// Block until the UART is ready, then send one byte.
    fn write_byte(&mut self, b: u8);

    /// Write all bytes; default impl calls [`write_byte`] in a loop.
    fn write_all(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_byte(b);
        }
    }
}

/// In-memory transport. `rx` holds bytes the stub will read (host
/// simulates the debugger); `tx` captures bytes the stub wrote (host
/// asserts on the traffic).
pub struct VecTransport {
    pub rx: VecDeque<u8>,
    pub tx: Vec<u8>,
}

impl VecTransport {
    pub fn new() -> Self {
        Self {
            rx: VecDeque::new(),
            tx: Vec::new(),
        }
    }

    pub fn with_rx(bytes: &[u8]) -> Self {
        let mut v = Self::new();
        v.rx.extend(bytes.iter().copied());
        v
    }
}

impl Default for VecTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for VecTransport {
    fn read_byte(&mut self) -> u8 {
        // Host-test contract: callers seed enough bytes before driving
        // the loop. An empty queue here is a test-authoring bug, not a
        // runtime condition — panic with a clear message.
        self.rx
            .pop_front()
            .expect("VecTransport::read_byte: rx underrun")
    }

    fn try_read_byte(&mut self) -> Option<u8> {
        self.rx.pop_front()
    }

    fn write_byte(&mut self, b: u8) {
        self.tx.push(b);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vec_roundtrip() {
        let mut t = VecTransport::with_rx(b"hi");
        assert_eq!(t.read_byte(), b'h');
        assert_eq!(t.try_read_byte(), Some(b'i'));
        assert_eq!(t.try_read_byte(), None);
        t.write_byte(b'x');
        t.write_all(b"yz");
        assert_eq!(t.tx, b"xyz");
    }
}
