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
pub mod mem;
pub mod regs;
pub mod transport;

#[cfg(target_os = "none")]
pub mod uart;

use core::sync::atomic::{AtomicBool, Ordering};

use framer::{DecodeError, ACK, EOP, MAX_PACKET, NAK, SOP};
use regs::{GdbRegs, GDB_REGS_HEX};
use transport::Transport;

/// The int3 (#BP) handler consults this before diverting into the stub
/// loop. Default-off so every existing kernel `int3` site (panic paths,
/// test-harness markers, speculative breakpoints) keeps its prior
/// behavior until something explicitly arms the stub.
static ARMED: AtomicBool = AtomicBool::new(false);

/// Arm the stub — the next #BP will drop into [`debug_entry_with_regs`].
pub fn arm() {
    ARMED.store(true, Ordering::Release);
}

/// Disarm the stub; #BP returns to normal semantics.
pub fn disarm() {
    ARMED.store(false, Ordering::Release);
}

/// Whether the int3 handler should divert into the stub on the next #BP.
pub fn is_armed() -> bool {
    ARMED.load(Ordering::Acquire)
}

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
    let mut regs = GdbRegs::default();
    debug_entry_with_regs(t, &mut regs);
}

/// Like [`debug_entry`] but with a caller-owned register snapshot.
/// The stub reads `regs` for `g` replies and writes into it on `G` —
/// the caller is responsible for pushing mutated values back into
/// the hardware interrupt frame on resume.
pub fn debug_entry_with_regs<T: Transport>(t: &mut T, regs: &mut GdbRegs) {
    // Wire buffer holds the full escaped packet (worst-case 2x payload
    // plus framing). `scratch` receives the unescaped payload that
    // `framer::decode` hands back as `Packet::payload`.
    let mut inbuf = [0u8; 2 * MAX_PACKET + 4];
    let mut scratch = [0u8; MAX_PACKET];
    loop {
        match read_packet(t, &mut inbuf) {
            Ok(len) => {
                // Parse the framed packet; on success dispatch, on
                // checksum error NAK and loop.
                match framer::decode(&inbuf[..len], &mut scratch) {
                    Ok((pkt, _)) => {
                        t.write_byte(ACK);
                        match dispatch(t, pkt.payload, regs) {
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
/// Returns the number of bytes consumed.
///
/// Scanning for `$` uses the non-blocking [`Transport::try_read_byte`]
/// so that a drained [`VecTransport`] can end a test session and, on
/// the real UART, the packet loop has a place to notice `^C` without
/// deadlocking on idle. Once we've committed to a packet, everything
/// up to and including the checksum is pulled with the *blocking*
/// [`Transport::read_byte`] — the RSP spec guarantees those bytes are
/// coming, and treating a between-byte pause as detach would cause
/// `Com1PollingTransport` to bail out of every packet.
fn read_packet<T: Transport>(t: &mut T, buf: &mut [u8]) -> Result<usize, ReadErr> {
    // Skip anything that isn't SOP. For the kernel transport this is
    // where `^C` would be noticed; for now we drop it on the floor.
    loop {
        match t.try_read_byte() {
            Some(b) if b == SOP => {
                buf[0] = SOP;
                break;
            }
            Some(_) => continue,
            None => return Err(ReadErr::Detached),
        }
    }
    let mut i = 1;
    // Read payload until `#`. Blocking: once SOP is seen, the packet
    // is committed and the remaining bytes must come in.
    while i < buf.len() {
        let b = t.read_byte();
        buf[i] = b;
        i += 1;
        if b == EOP {
            break;
        }
    }
    // Read the two hex checksum bytes (also blocking).
    for _ in 0..2 {
        if i >= buf.len() {
            // Buffer full before checksum — decode will fail and we'll
            // NAK. Stop here rather than overrun.
            break;
        }
        buf[i] = t.read_byte();
        i += 1;
    }
    Ok(i)
}

/// Handle a single decoded packet payload. Emits the response frame
/// via `t.write_byte` and returns whether the session should continue.
fn dispatch<T: Transport>(t: &mut T, payload: &[u8], regs: &mut GdbRegs) -> Action {
    match payload.first() {
        Some(b'?') => {
            send_packet(t, &stop_reply_buf(SIG_TRAP));
            Action::Continue
        }
        Some(b'D') => {
            send_packet(t, b"OK");
            Action::Detach
        }
        Some(b'g') => {
            let mut hex = [0u8; GDB_REGS_HEX];
            let blob = regs::encode_g(regs, &mut hex);
            send_packet(t, blob);
            Action::Continue
        }
        Some(b'G') => {
            // Payload is `G<hex...>`; strip the leading command byte.
            // The int3 trampoline now captures the full GPR set before
            // Rust runs (#482), so `G` writes to rax..r15 + rip/eflags
            // round-trip through the trampoline's saved block on resume.
            // Segment-register writes are still accepted into the in-
            // memory snapshot (a follow-up `g` reads them back) but the
            // trampoline deliberately does not push cs/ss/rsp back into
            // the hardware frame: changing those without a coordinated
            // task switch is unsound. Gdb rarely mutates them.
            let mut tmp = *regs;
            match regs::decode_g(&payload[1..], &mut tmp) {
                Ok(()) => {
                    *regs = tmp;
                    send_packet(t, b"OK");
                }
                Err(_) => send_packet(t, b"E00"),
            }
            Action::Continue
        }
        Some(b'm') => {
            handle_m(t, &payload[1..]);
            Action::Continue
        }
        Some(b'M') => {
            handle_big_m(t, &payload[1..]);
            Action::Continue
        }
        _ => {
            // Unknown command: RSP convention says reply with an empty
            // packet, which the debugger treats as "unsupported".
            send_packet(t, b"");
            Action::Continue
        }
    }
}

/// Handle `m addr,len` — read memory and reply with hex bytes, or
/// `E01` if any byte of the range is unmapped/non-canonical/too big.
fn handle_m<T: Transport>(t: &mut T, args: &[u8]) {
    let parsed = match mem::parse_m(args) {
        Ok(a) => a,
        Err(_) => {
            send_packet(t, b"E01");
            return;
        }
    };
    // Reply buffer: `2 * len` hex bytes, bounded by MAX_MEM_XFER.
    let mut bytes = [0u8; mem::MAX_MEM_XFER];
    let mut hex = [0u8; 2 * mem::MAX_MEM_XFER];
    let n = parsed.len;
    match read_memory(parsed, &mut bytes[..n]) {
        Ok(()) => {
            let out = mem::encode_hex(&bytes[..n], &mut hex[..2 * n]);
            send_packet(t, out);
        }
        Err(()) => send_packet(t, b"E01"),
    }
}

/// Handle `M addr,len:data` — decode hex, write bytes, reply `OK` or
/// `E01` on any parse or access failure.
fn handle_big_m<T: Transport>(t: &mut T, args: &[u8]) {
    let (parsed, data_hex) = match mem::parse_big_m(args) {
        Ok(pair) => pair,
        Err(_) => {
            send_packet(t, b"E01");
            return;
        }
    };
    let mut bytes = [0u8; mem::MAX_MEM_XFER];
    let n = parsed.len;
    if mem::decode_hex(data_hex, &mut bytes[..n]).is_err() {
        send_packet(t, b"E01");
        return;
    }
    match write_memory(parsed, &bytes[..n]) {
        Ok(()) => send_packet(t, b"OK"),
        Err(()) => send_packet(t, b"E01"),
    }
}

/// Kernel-side safe read: routes through the page-walker probe.
#[cfg(target_os = "none")]
fn read_memory(args: mem::MemArgs, out: &mut [u8]) -> Result<(), ()> {
    mem::safe_read(args, out).map_err(|_| ())
}

/// Kernel-side safe write: routes through the page-walker probe.
#[cfg(target_os = "none")]
fn write_memory(args: mem::MemArgs, data: &[u8]) -> Result<(), ()> {
    mem::safe_write(args, data).map_err(|_| ())
}

/// Host-test fallback: no kernel page tables available, so we refuse
/// every access. The existing host tests don't send `m`/`M`, but any
/// future test wanting real access can override this via a test-only
/// transport.
#[cfg(not(target_os = "none"))]
fn read_memory(_args: mem::MemArgs, _out: &mut [u8]) -> Result<(), ()> {
    Err(())
}

#[cfg(not(target_os = "none"))]
fn write_memory(_args: mem::MemArgs, _data: &[u8]) -> Result<(), ()> {
    Err(())
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
        // `q` with no sub-command is not implemented → empty reply.
        // checksum('q') = 0x71.
        let mut t = VecTransport::with_rx(b"$q#71$D#44");
        debug_entry(&mut t);
        // Expect: ACK, `$#00`, ACK, `$OK#9a`.
        assert!(find(&t.tx, b"$#00").is_some());
        assert!(find(&t.tx, b"$OK#9a").is_some());
    }

    fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
        hay.windows(needle.len()).position(|w| w == needle)
    }
}
