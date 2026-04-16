//! `m`/`M` packet support: argument parsing + safe memory access.
//!
//! `m <addr>,<len>` reads `len` bytes at `addr` and sends them back as
//! lowercase hex. `M <addr>,<len>:<data>` takes `2*len` hex characters
//! after the `:` and writes those bytes to `addr`. Both return `E01`
//! if any byte of the range is unreadable/unwritable rather than
//! faulting.
//!
//! Parsing lives here as pure-byte logic so host unit tests can cover
//! the edge cases (non-hex, overflow, missing separators) without
//! pulling in kernel-only code. The safe-access probes are `cfg`-gated
//! to `target_os = "none"` because they rely on the kernel's page
//! walker.

/// Hex alphabet — lowercase to match the wire format our existing
/// `regs::encode_g` produces.
const HEX: &[u8; 16] = b"0123456789abcdef";

/// Cap on `m` reply size. Reply is `2 * len` hex bytes framed in a
/// packet; leaving room for packet framing and escape expansion we
/// bound single-request reads well below `framer::MAX_PACKET`.
pub const MAX_MEM_XFER: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum MemErr {
    /// A hex digit was not in `[0-9a-fA-F]`.
    BadHex,
    /// Missing the `,` between `addr` and `len`.
    MissingComma,
    /// Missing the `:` that precedes `M`'s data block.
    MissingColon,
    /// `addr` or `len` overflowed its target integer type.
    Overflow,
    /// `len` is zero — RSP spec treats this as a no-op but our probe
    /// surface expects at least one byte; the dispatch layer handles
    /// zero by replying empty (for `m`) or `OK` (for `M`) without
    /// touching memory, so parsers reject it and let the caller decide.
    ZeroLen,
    /// Requested length exceeds [`MAX_MEM_XFER`]; gdb retries with a
    /// smaller `len` on `E` responses, so we reject proactively.
    TooBig,
    /// `M` payload has fewer/more hex chars than `2 * len`.
    ShortData,
    /// `addr` is non-canonical — reject up front so the probe layer
    /// doesn't have to handle it.
    NonCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemArgs {
    pub addr: u64,
    pub len: usize,
}

/// Parse an `m addr,len` payload (without the leading `m`).
pub fn parse_m(payload: &[u8]) -> Result<MemArgs, MemErr> {
    let (addr, rest) = parse_hex_u64(payload)?;
    let rest = eat(rest, b',').ok_or(MemErr::MissingComma)?;
    let (len, rest) = parse_hex_usize(rest)?;
    if !rest.is_empty() {
        return Err(MemErr::BadHex);
    }
    validate(addr, len)?;
    Ok(MemArgs { addr, len })
}

/// Parse an `M addr,len:data` payload (without the leading `M`).
/// Returns the parsed args and the raw hex `data` slice.
pub fn parse_big_m(payload: &[u8]) -> Result<(MemArgs, &[u8]), MemErr> {
    let (addr, rest) = parse_hex_u64(payload)?;
    let rest = eat(rest, b',').ok_or(MemErr::MissingComma)?;
    let (len, rest) = parse_hex_usize(rest)?;
    let data = eat(rest, b':').ok_or(MemErr::MissingColon)?;
    validate(addr, len)?;
    if data.len() != len.checked_mul(2).ok_or(MemErr::Overflow)? {
        return Err(MemErr::ShortData);
    }
    for &b in data {
        if hex_nib(b).is_none() {
            return Err(MemErr::BadHex);
        }
    }
    Ok((MemArgs { addr, len }, data))
}

fn validate(addr: u64, len: usize) -> Result<(), MemErr> {
    if len == 0 {
        return Err(MemErr::ZeroLen);
    }
    if len > MAX_MEM_XFER {
        return Err(MemErr::TooBig);
    }
    // Reject non-canonical up front. The leaf probe below dereferences
    // page-table entries indexed off `addr`, which is undefined on a
    // non-canonical pointer; belt-and-braces check here.
    if !is_canonical(addr) {
        return Err(MemErr::NonCanonical);
    }
    // Range must also not wrap past u64::MAX.
    addr.checked_add(len as u64).ok_or(MemErr::Overflow)?;
    Ok(())
}

fn is_canonical(addr: u64) -> bool {
    // x86_64 canonical form: bits [63:48] must all match bit 47.
    let high = addr >> 47;
    high == 0 || high == 0x1_FFFF
}

fn parse_hex_u64(s: &[u8]) -> Result<(u64, &[u8]), MemErr> {
    let mut acc: u64 = 0;
    let mut i = 0;
    while i < s.len() {
        let Some(nib) = hex_nib(s[i]) else { break };
        acc = acc
            .checked_shl(4)
            .and_then(|v| v.checked_add(nib as u64))
            .ok_or(MemErr::Overflow)?;
        i += 1;
    }
    if i == 0 {
        return Err(MemErr::BadHex);
    }
    Ok((acc, &s[i..]))
}

fn parse_hex_usize(s: &[u8]) -> Result<(usize, &[u8]), MemErr> {
    let (v, rest) = parse_hex_u64(s)?;
    let v = usize::try_from(v).map_err(|_| MemErr::Overflow)?;
    Ok((v, rest))
}

fn eat(s: &[u8], b: u8) -> Option<&[u8]> {
    match s.first() {
        Some(&c) if c == b => Some(&s[1..]),
        _ => None,
    }
}

fn hex_nib(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Encode `bytes` as lowercase hex into `out`. Returns the filled
/// slice. `out.len()` must be `>= 2 * bytes.len()`.
pub fn encode_hex<'b>(bytes: &[u8], out: &'b mut [u8]) -> &'b [u8] {
    for (i, &b) in bytes.iter().enumerate() {
        out[2 * i] = HEX[(b >> 4) as usize];
        out[2 * i + 1] = HEX[(b & 0xF) as usize];
    }
    &out[..2 * bytes.len()]
}

/// Decode `2 * out.len()` hex characters from `hex` into `out`.
pub fn decode_hex(hex: &[u8], out: &mut [u8]) -> Result<(), MemErr> {
    if hex.len() != 2 * out.len() {
        return Err(MemErr::ShortData);
    }
    for i in 0..out.len() {
        let hi = hex_nib(hex[2 * i]).ok_or(MemErr::BadHex)?;
        let lo = hex_nib(hex[2 * i + 1]).ok_or(MemErr::BadHex)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

/// Read `args.len` bytes from `args.addr` into `out`. Returns `Err` if
/// any byte of the range is unmapped. Does not fault: the page-walker
/// consults kernel page tables via the HHDM, never dereferences the
/// target VA.
#[cfg(target_os = "none")]
pub fn safe_read(args: MemArgs, out: &mut [u8]) -> Result<(), MemErr> {
    use x86_64::VirtAddr;
    debug_assert_eq!(out.len(), args.len);
    let mut va = args.addr;
    for slot in out.iter_mut() {
        let cur = VirtAddr::try_new(va).map_err(|_| MemErr::NonCanonical)?;
        if !probe_readable(cur) {
            return Err(MemErr::NonCanonical);
        }
        // SAFETY: `probe_readable` returned true → the leaf PTE is
        // present. Reading one byte through a raw volatile load will
        // not fault. Volatile to defeat the optimizer — gdb may be
        // inspecting MMIO.
        unsafe {
            *slot = core::ptr::read_volatile(va as *const u8);
        }
        va = va.wrapping_add(1);
    }
    Ok(())
}

/// Write `data` bytes to `args.addr`. Returns `Err` if any byte is
/// unmapped or read-only. Same fault-safety contract as [`safe_read`].
#[cfg(target_os = "none")]
pub fn safe_write(args: MemArgs, data: &[u8]) -> Result<(), MemErr> {
    use x86_64::VirtAddr;
    debug_assert_eq!(data.len(), args.len);
    let mut va = args.addr;
    for &b in data {
        let cur = VirtAddr::try_new(va).map_err(|_| MemErr::NonCanonical)?;
        if !probe_writable(cur) {
            return Err(MemErr::NonCanonical);
        }
        // SAFETY: leaf PTE is present and writable (CR0.WP respected).
        unsafe {
            core::ptr::write_volatile(va as *mut u8, b);
        }
        va = va.wrapping_add(1);
    }
    Ok(())
}

/// True if the leaf PTE backing `va` has PRESENT set.
#[cfg(target_os = "none")]
fn probe_readable(va: x86_64::VirtAddr) -> bool {
    use x86_64::structures::paging::PageTableFlags as F;
    crate::mem::paging::flags(va)
        .map(|f| f.contains(F::PRESENT))
        .unwrap_or(false)
}

/// True if the leaf PTE backing `va` has PRESENT and WRITABLE set.
#[cfg(target_os = "none")]
fn probe_writable(va: x86_64::VirtAddr) -> bool {
    use x86_64::structures::paging::PageTableFlags as F;
    crate::mem::paging::flags(va)
        .map(|f| f.contains(F::PRESENT | F::WRITABLE))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_m_happy() {
        let a = parse_m(b"1000,10").unwrap();
        assert_eq!(a.addr, 0x1000);
        assert_eq!(a.len, 0x10);
    }

    #[test]
    fn parse_m_missing_comma() {
        assert_eq!(parse_m(b"1000 10"), Err(MemErr::MissingComma));
    }

    #[test]
    fn parse_m_non_hex_addr() {
        assert_eq!(parse_m(b"zz,10"), Err(MemErr::BadHex));
    }

    #[test]
    fn parse_m_zero_len() {
        assert_eq!(parse_m(b"1000,0"), Err(MemErr::ZeroLen));
    }

    #[test]
    fn parse_m_too_big() {
        assert_eq!(parse_m(b"1000,1000"), Err(MemErr::TooBig));
    }

    #[test]
    fn parse_m_non_canonical_rejected() {
        // Bits [63:48] = 0x1 is not 0 or 0x1FFFF → non-canonical.
        assert_eq!(parse_m(b"1000000000000,1"), Err(MemErr::NonCanonical));
    }

    #[test]
    fn parse_m_trailing_junk() {
        assert_eq!(parse_m(b"1000,10;oops"), Err(MemErr::BadHex));
    }

    #[test]
    fn parse_big_m_happy() {
        let (a, data) = parse_big_m(b"2000,2:abcd").unwrap();
        assert_eq!(a.addr, 0x2000);
        assert_eq!(a.len, 2);
        assert_eq!(data, b"abcd");
    }

    #[test]
    fn parse_big_m_missing_colon() {
        assert_eq!(parse_big_m(b"2000,2 abcd"), Err(MemErr::MissingColon));
    }

    #[test]
    fn parse_big_m_short_data() {
        assert_eq!(parse_big_m(b"2000,2:ab"), Err(MemErr::ShortData));
    }

    #[test]
    fn parse_big_m_non_hex_data() {
        assert_eq!(parse_big_m(b"2000,2:abzz"), Err(MemErr::BadHex));
    }

    #[test]
    fn encode_hex_roundtrip() {
        let mut buf = [0u8; 6];
        let out = encode_hex(&[0xde, 0xad, 0xbe], &mut buf);
        assert_eq!(out, b"deadbe");
    }

    #[test]
    fn decode_hex_happy() {
        let mut out = [0u8; 3];
        decode_hex(b"DEADBE", &mut out).unwrap();
        assert_eq!(out, [0xde, 0xad, 0xbe]);
    }

    #[test]
    fn is_canonical_edges() {
        assert!(is_canonical(0));
        assert!(is_canonical(0x0000_7FFF_FFFF_FFFF));
        assert!(is_canonical(0xFFFF_8000_0000_0000));
        assert!(!is_canonical(0x0000_8000_0000_0000));
        assert!(!is_canonical(0x0001_0000_0000_0000));
    }
}
