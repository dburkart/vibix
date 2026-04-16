//! GDB Remote Serial Protocol stub — transport + packet loop skeleton.
//!
//! First step toward in-kernel `gdb` attach: this module establishes
//! packet framing, a polling UART transport, and a minimal dispatch
//! loop that handles exactly two commands — `?` (stop reason) and
//! `D` (detach). Register, memory, and control-flow commands land in
//! follow-up issues.
//!
//! The entry point [`debug_entry`] is generic over [`Transport`] so
//! host unit tests and QEMU integration tests can drive the same code
//! with a [`VecTransport`](transport::VecTransport). Kernel wiring
//! into the fault handlers is out of scope for this PR — call
//! `debug_entry` directly from a test-only path or (eventually) from
//! a `gdbstub` shell builtin.

pub mod framer;
pub mod transport;

#[cfg(target_os = "none")]
pub mod uart;

use framer::{DecodeError, ACK, EOP, MAX_PACKET, NAK, SOP};
use transport::Transport;

/// The canned `S05` stop reason — SIGTRAP — we hand back on `?` until
/// we wire real exception info through in the follow-up.
const SIG_TRAP: u8 = 0x05;

/// Byte gdb sends outside a packet to request an interrupt. We don't
/// do anything interesting with it yet; noted here for completeness.
#[allow(dead_code)]
const CTRL_C: u8 = 0x03;

/// Drive one gdb session over `t` until the debugger sends a detach
/// packet (`D`). Returns to the caller on detach; any decode failure
/// within a packet is answered with a NAK and the loop continues.
///
/// This is the *only* public entry point in the module for this PR.
/// Follow-ups will add a fault-handler stub that constructs a real
/// [`Com1PollingTransport`](uart::Com1PollingTransport) and calls
/// through here.
pub fn debug_entry<T: Transport>(t: &mut T) {
    let mut inbuf = [0u8; MAX_PACKET + 4];
    loop {
        match read_packet(t, &mut inbuf) {
            Ok(len) => {
                // Parse the framed packet; on success dispatch, on
                // checksum error NAK and loop.
                match framer::decode(&inbuf[..len]) {
                    Ok((pkt, _)) => {
                        t.write_byte(ACK);
                        match dispatch(t, pkt.payload) {
                            Action::Continue => {}
                            Action::Detach => return,
                        }
                    }
                    Err(DecodeError::BadChecksum) => {
                        t.write_byte(NAK);
                    }
                    Err(_) => {
                        // Framing/overflow/incomplete all collapse to
                        // NAK — the debugger will resend.
                        t.write_byte(NAK);
                    }
                }
            }
            Err(ReadErr::Detached) => return,
        }
    }
}

enum Action {
    Continue,
    Detach,
}

enum ReadErr {
    /// Transport returned end-of-input before a packet completed; the
    /// host test drains its queue this way to end the session cleanly.
    Detached,
}

/// Read one `$...#xx` framed packet out of `t`, writing it into `buf`.
/// Returns the number of bytes consumed. Bytes outside a packet (leading
/// ack/nak) are skipped. For [`VecTransport`] a drained queue becomes
/// `Err(Detached)` so the test drives the loop to completion without an
/// explicit detach packet.
fn read_packet<T: Transport>(t: &mut T, buf: &mut [u8]) -> Result<usize, ReadErr> {
    // Skip anything that isn't SOP. For the kernel transport this is
    // where `^C` would be noticed; for now we drop it on the floor.
    loop {
        match try_read(t) {
            Some(b) if b == SOP => {
                buf[0] = SOP;
                break;
            }
            Some(_) => continue,
            None => return Err(ReadErr::Detached),
        }
    }
    let mut i = 1;
    // Read payload until `#`.
    while i < buf.len() {
        match try_read(t) {
            Some(b) => {
                buf[i] = b;
                i += 1;
                if b == EOP {
                    break;
                }
            }
            None => return Err(ReadErr::Detached),
        }
    }
    // Read the two hex checksum bytes.
    for _ in 0..2 {
        match try_read(t) {
            Some(b) => {
                if i >= buf.len() {
                    // Buffer full before checksum — decode will fail
                    // and we'll NAK. Stop here.
                    break;
                }
                buf[i] = b;
                i += 1;
            }
            None => return Err(ReadErr::Detached),
        }
    }
    Ok(i)
}

/// Single byte pull. Returns `None` when the transport has no more
/// input, which in [`VecTransport`] tests means the rx queue is drained
/// and we should end the session. Real kernel callers that need to
/// block across idle periods will grow that behavior alongside the
/// fault-handler wiring in the follow-up.
fn try_read<T: Transport>(t: &mut T) -> Option<u8> {
    t.try_read_byte()
}

/// Handle a single decoded packet payload. Emits the response frame
/// via `t.write_byte` and returns whether the session should continue.
fn dispatch<T: Transport>(t: &mut T, payload: &[u8]) -> Action {
    match payload.first() {
        Some(b'?') => {
            send_packet(t, &stop_reply_buf(SIG_TRAP));
            Action::Continue
        }
        Some(b'D') => {
            send_packet(t, b"OK");
            Action::Detach
        }
        _ => {
            // Unknown command: RSP convention says reply with an empty
            // packet, which the debugger treats as "unsupported".
            send_packet(t, b"");
            Action::Continue
        }
    }
}

/// Build an `Sxx` stop reply payload in a fixed-size buffer.
fn stop_reply_buf(sig: u8) -> [u8; 3] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [b'S', HEX[(sig >> 4) as usize], HEX[(sig & 0xF) as usize]]
}

fn send_packet<T: Transport>(t: &mut T, payload: &[u8]) {
    let mut buf = [0u8; MAX_PACKET + 4];
    let frame = framer::encode(payload, &mut buf);
    t.write_all(frame);
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::VecTransport;

    #[test]
    fn stop_reply_hex() {
        assert_eq!(&stop_reply_buf(0x05), b"S05");
        assert_eq!(&stop_reply_buf(0x0b), b"S0b");
    }

    #[test]
    fn question_then_detach() {
        // Sequence the debugger would send: `?` query, then detach.
        // Leading ack bytes are skipped by the outer loop.
        let mut t = VecTransport::with_rx(b"+$?#3f+$D#44");
        debug_entry(&mut t);

        // Expect: two ACKs from stub (one per accepted packet) and
        // two framed replies: `$S05#b8` then `$OK#9a`.
        let tx = t.tx.as_slice();
        // First three bytes: `+$S...`
        assert_eq!(tx[0], ACK);
        // Look for the expected frames in order.
        let first = find(tx, b"$S05#b8").expect("missing S05 reply");
        let second = find(tx, b"$OK#9a").expect("missing OK detach reply");
        assert!(first < second, "detach reply must follow S05 reply");
    }

    #[test]
    fn bad_checksum_is_nakked() {
        // `?` with wrong checksum, then a correct `D` detach.
        let mut t = VecTransport::with_rx(b"$?#ff$D#44");
        debug_entry(&mut t);
        // First outbound byte should be NAK, not ACK.
        assert_eq!(t.tx[0], NAK);
        assert!(find(&t.tx, b"$OK#9a").is_some());
    }

    #[test]
    fn unknown_command_empty_reply() {
        // `g` = read registers; we don't support it yet → empty reply.
        let mut t = VecTransport::with_rx(b"$g#67$D#44");
        debug_entry(&mut t);
        // Expect: ACK, `$#00`, ACK, `$OK#9a`.
        assert!(find(&t.tx, b"$#00").is_some());
        assert!(find(&t.tx, b"$OK#9a").is_some());
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }
}
