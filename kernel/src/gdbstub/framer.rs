//! GDB Remote Serial Protocol packet framing.
//!
//! Pure byte-slice logic so it compiles and runs on the host for
//! `cargo test --lib`. Kernel callers wrap a `Transport` around the
//! framer; nothing here does I/O.
//!
//! Wire format: `$<payload>#<XX>` where `XX` is the two-hex-digit sum
//! of the payload bytes mod 256. `+` and `-` are ack/nak bytes outside
//! a packet. Payload bytes `#`, `$`, `}`, `*` must be escaped as
//! `}` followed by the original byte `^ 0x20`.

/// Cap on decoded payload size. The stub only emits short fixed
/// responses (`S05`, `OK`, empty) in this first cut; 1 KiB leaves
/// headroom for later register dumps without heap allocation.
pub const MAX_PACKET: usize = 1024;

/// Start-of-packet byte.
pub const SOP: u8 = b'$';
/// End-of-payload / start-of-checksum byte.
pub const EOP: u8 = b'#';
/// Escape prefix inside a payload.
pub const ESC: u8 = b'}';
/// Run-length-encoding marker (reserved byte that also needs escaping
/// when it appears as data; we don't emit RLE ourselves yet).
pub const RLE: u8 = b'*';
/// Positive ack.
pub const ACK: u8 = b'+';
/// Negative ack.
pub const NAK: u8 = b'-';

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// Bytes did not start with `$`, or the checksum field was
    /// truncated / non-hex.
    Framing,
    /// Checksum byte(s) did not match the computed sum.
    BadChecksum,
    /// Decoded payload would exceed [`MAX_PACKET`].
    Overflow,
    /// Buffer ended mid-packet; caller should read more bytes.
    Incomplete,
}

/// A borrowed view over a successfully-decoded payload.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub payload: &'a [u8],
}

/// Sum of payload bytes mod 256 — the RSP checksum.
pub fn checksum(payload: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for &b in payload {
        s = s.wrapping_add(b);
    }
    s
}

/// Encode `payload` into `$<payload>#<xx>` in `out`. Caller must size
/// `out` to at least `payload.len() + 4`. Returns the filled slice.
/// Panics only on obvious misuse (undersized buffer) — this is dev-
/// facing kernel code, not untrusted input.
pub fn encode<'b>(payload: &[u8], out: &'b mut [u8]) -> &'b [u8] {
    let need = payload.len() + 4;
    assert!(out.len() >= need, "gdbstub encode: output too small");
    out[0] = SOP;
    out[1..1 + payload.len()].copy_from_slice(payload);
    out[1 + payload.len()] = EOP;
    let [hi, lo] = to_hex(checksum(payload));
    out[2 + payload.len()] = hi;
    out[3 + payload.len()] = lo;
    &out[..need]
}

/// Decode a single packet at the start of `raw`. Returns the packet
/// plus the number of bytes consumed (so callers can advance their
/// input cursor). Leading junk bytes before `$` are *not* skipped —
/// the transport layer peels those off.
pub fn decode<'a>(raw: &'a [u8]) -> Result<(Packet<'a>, usize), DecodeError> {
    if raw.is_empty() {
        return Err(DecodeError::Incomplete);
    }
    if raw[0] != SOP {
        return Err(DecodeError::Framing);
    }
    let mut i = 1;
    while i < raw.len() && raw[i] != EOP {
        i += 1;
    }
    if i >= raw.len() {
        return Err(DecodeError::Incomplete);
    }
    let payload_end = i;
    let payload = &raw[1..payload_end];
    if payload.len() > MAX_PACKET {
        return Err(DecodeError::Overflow);
    }
    if raw.len() < payload_end + 3 {
        return Err(DecodeError::Incomplete);
    }
    let hi = hex_nibble(raw[payload_end + 1]).ok_or(DecodeError::Framing)?;
    let lo = hex_nibble(raw[payload_end + 2]).ok_or(DecodeError::Framing)?;
    let want = (hi << 4) | lo;
    if want != checksum(payload) {
        return Err(DecodeError::BadChecksum);
    }
    Ok((Packet { payload }, payload_end + 3))
}

/// Does this byte need to be escaped inside a payload?
pub fn needs_escape(b: u8) -> bool {
    matches!(b, EOP | SOP | ESC | RLE)
}

/// Copy `src` into `out`, escaping any reserved bytes. Returns the
/// filled slice. Caller sizes `out` to at most `2 * src.len()`.
pub fn escape_into<'b>(src: &[u8], out: &'b mut [u8]) -> &'b [u8] {
    let mut j = 0;
    for &b in src {
        if needs_escape(b) {
            assert!(j + 2 <= out.len(), "gdbstub escape: output too small");
            out[j] = ESC;
            out[j + 1] = b ^ 0x20;
            j += 2;
        } else {
            assert!(j + 1 <= out.len(), "gdbstub escape: output too small");
            out[j] = b;
            j += 1;
        }
    }
    &out[..j]
}

/// Inverse of [`escape_into`].
pub fn unescape_into<'b>(src: &[u8], out: &'b mut [u8]) -> Result<&'b [u8], DecodeError> {
    let mut i = 0;
    let mut j = 0;
    while i < src.len() {
        let b = src[i];
        if b == ESC {
            if i + 1 >= src.len() {
                return Err(DecodeError::Framing);
            }
            if j >= out.len() {
                return Err(DecodeError::Overflow);
            }
            out[j] = src[i + 1] ^ 0x20;
            j += 1;
            i += 2;
        } else {
            if j >= out.len() {
                return Err(DecodeError::Overflow);
            }
            out[j] = b;
            j += 1;
            i += 1;
        }
    }
    Ok(&out[..j])
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        b'A'..=b'F' => Some(10 + b - b'A'),
        _ => None,
    }
}

fn to_hex(n: u8) -> [u8; 2] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [HEX[(n >> 4) as usize], HEX[(n & 0xF) as usize]]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_known() {
        assert_eq!(checksum(b"OK"), 0x9a);
        assert_eq!(checksum(b"?"), 0x3f);
        assert_eq!(checksum(b"S05"), 0xb8);
        assert_eq!(checksum(b""), 0x00);
    }

    #[test]
    fn encode_simple() {
        let mut buf = [0u8; 16];
        let got = encode(b"S05", &mut buf);
        assert_eq!(got, b"$S05#b8");
    }

    #[test]
    fn encode_empty_is_sentinel() {
        let mut buf = [0u8; 8];
        let got = encode(b"", &mut buf);
        // Empty packet is used as the "unknown command" response.
        assert_eq!(got, b"$#00");
    }

    #[test]
    fn decode_valid() {
        let (pkt, used) = decode(b"$OK#9a").unwrap();
        assert_eq!(pkt.payload, b"OK");
        assert_eq!(used, 6);
    }

    #[test]
    fn decode_valid_with_trailing_bytes() {
        let (pkt, used) = decode(b"$?#3f+junk").unwrap();
        assert_eq!(pkt.payload, b"?");
        assert_eq!(used, 5);
    }

    #[test]
    fn decode_bad_checksum() {
        assert_eq!(decode(b"$OK#00"), Err(DecodeError::BadChecksum));
    }

    #[test]
    fn decode_framing_missing_dollar() {
        assert_eq!(decode(b"OK#9a"), Err(DecodeError::Framing));
    }

    #[test]
    fn decode_incomplete_no_hash() {
        assert_eq!(decode(b"$OK"), Err(DecodeError::Incomplete));
    }

    #[test]
    fn decode_incomplete_short_checksum() {
        assert_eq!(decode(b"$OK#9"), Err(DecodeError::Incomplete));
    }

    #[test]
    fn decode_framing_non_hex_checksum() {
        assert_eq!(decode(b"$OK#zz"), Err(DecodeError::Framing));
    }

    #[test]
    fn escape_roundtrip() {
        let payload = b"a$b#c}d*e";
        let mut buf = [0u8; 32];
        let escaped = escape_into(payload, &mut buf);

        // Every reserved byte in the original must have been rewritten
        // as `ESC` + (b ^ 0x20). Walk the escaped buffer and confirm no
        // *unescaped* reserved byte survived.
        let mut i = 0;
        while i < escaped.len() {
            if escaped[i] == ESC {
                i += 2;
                continue;
            }
            assert!(
                !needs_escape(escaped[i]),
                "unescaped reserved byte at {i}: {:#x}",
                escaped[i]
            );
            i += 1;
        }

        let mut back = [0u8; 32];
        let decoded = unescape_into(escaped, &mut back).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn ack_nak_bytes() {
        assert_eq!(ACK, 0x2B);
        assert_eq!(NAK, 0x2D);
    }
}
