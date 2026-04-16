//! GDB x86_64 register packet encoding.
//!
//! GDB's `g`/`G` commands serialize registers as one big lowercase hex
//! blob. Field order matches gdb's `i386:x86-64` gdbarch:
//!
//! `rax rbx rcx rdx rsi rdi rbp rsp r8..r15 rip eflags cs ss ds es fs gs`
//!
//! Each GPR is 8 bytes, `rip` is 8 bytes, `eflags` is 4 bytes, and each
//! of the six segment selectors is 4 bytes — 16·8 + 8 + 4 + 6·4 = 164
//! bytes, i.e. 328 hex characters.
//!
//! Per-field bytes are emitted little-endian, each byte as two
//! lowercase hex chars, matching what gdb expects on the wire.

/// Total wire size of a `g` reply in *bytes* (not hex chars).
pub const GDB_REGS_BYTES: usize = 164;

/// The `g` reply is twice as many hex characters as the payload is
/// bytes — exactly `2 * GDB_REGS_BYTES`.
pub const GDB_REGS_HEX: usize = 2 * GDB_REGS_BYTES;

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct GdbRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub eflags: u32,
    pub cs: u32,
    pub ss: u32,
    pub ds: u32,
    pub es: u32,
    pub fs: u32,
    pub gs: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseErr {
    /// Hex input wasn't exactly `GDB_REGS_HEX` characters long.
    WrongLength,
    /// A byte in the hex input wasn't a valid hex nibble.
    BadHex,
}

/// Encode `r` as a lowercase-hex little-endian-per-field blob into
/// `out`. Returns the filled slice (`&out[..GDB_REGS_HEX]`).
pub fn encode_g<'b>(r: &GdbRegs, out: &'b mut [u8; GDB_REGS_HEX]) -> &'b [u8] {
    let mut i = 0;
    let mut put_u64 = |v: u64, i: &mut usize| {
        write_le_hex(v.to_le_bytes().as_slice(), out, i);
    };
    put_u64(r.rax, &mut i);
    put_u64(r.rbx, &mut i);
    put_u64(r.rcx, &mut i);
    put_u64(r.rdx, &mut i);
    put_u64(r.rsi, &mut i);
    put_u64(r.rdi, &mut i);
    put_u64(r.rbp, &mut i);
    put_u64(r.rsp, &mut i);
    put_u64(r.r8, &mut i);
    put_u64(r.r9, &mut i);
    put_u64(r.r10, &mut i);
    put_u64(r.r11, &mut i);
    put_u64(r.r12, &mut i);
    put_u64(r.r13, &mut i);
    put_u64(r.r14, &mut i);
    put_u64(r.r15, &mut i);
    put_u64(r.rip, &mut i);
    let mut put_u32 = |v: u32, i: &mut usize| {
        write_le_hex(v.to_le_bytes().as_slice(), out, i);
    };
    put_u32(r.eflags, &mut i);
    put_u32(r.cs, &mut i);
    put_u32(r.ss, &mut i);
    put_u32(r.ds, &mut i);
    put_u32(r.es, &mut i);
    put_u32(r.fs, &mut i);
    put_u32(r.gs, &mut i);
    debug_assert_eq!(i, GDB_REGS_HEX);
    &out[..]
}

/// Decode a `G` hex blob back into `r`. Input must be exactly
/// `GDB_REGS_HEX` hex characters.
pub fn decode_g(hex: &[u8], r: &mut GdbRegs) -> Result<(), ParseErr> {
    if hex.len() != GDB_REGS_HEX {
        return Err(ParseErr::WrongLength);
    }
    let mut i = 0;
    r.rax = read_le_u64(hex, &mut i)?;
    r.rbx = read_le_u64(hex, &mut i)?;
    r.rcx = read_le_u64(hex, &mut i)?;
    r.rdx = read_le_u64(hex, &mut i)?;
    r.rsi = read_le_u64(hex, &mut i)?;
    r.rdi = read_le_u64(hex, &mut i)?;
    r.rbp = read_le_u64(hex, &mut i)?;
    r.rsp = read_le_u64(hex, &mut i)?;
    r.r8 = read_le_u64(hex, &mut i)?;
    r.r9 = read_le_u64(hex, &mut i)?;
    r.r10 = read_le_u64(hex, &mut i)?;
    r.r11 = read_le_u64(hex, &mut i)?;
    r.r12 = read_le_u64(hex, &mut i)?;
    r.r13 = read_le_u64(hex, &mut i)?;
    r.r14 = read_le_u64(hex, &mut i)?;
    r.r15 = read_le_u64(hex, &mut i)?;
    r.rip = read_le_u64(hex, &mut i)?;
    r.eflags = read_le_u32(hex, &mut i)?;
    r.cs = read_le_u32(hex, &mut i)?;
    r.ss = read_le_u32(hex, &mut i)?;
    r.ds = read_le_u32(hex, &mut i)?;
    r.es = read_le_u32(hex, &mut i)?;
    r.fs = read_le_u32(hex, &mut i)?;
    r.gs = read_le_u32(hex, &mut i)?;
    Ok(())
}

fn write_le_hex(bytes: &[u8], out: &mut [u8], i: &mut usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in bytes {
        out[*i] = HEX[(b >> 4) as usize];
        out[*i + 1] = HEX[(b & 0xF) as usize];
        *i += 2;
    }
}

fn read_le_u64(hex: &[u8], i: &mut usize) -> Result<u64, ParseErr> {
    let mut bytes = [0u8; 8];
    for b in &mut bytes {
        *b = read_byte(hex, i)?;
    }
    Ok(u64::from_le_bytes(bytes))
}

fn read_le_u32(hex: &[u8], i: &mut usize) -> Result<u32, ParseErr> {
    let mut bytes = [0u8; 4];
    for b in &mut bytes {
        *b = read_byte(hex, i)?;
    }
    Ok(u32::from_le_bytes(bytes))
}

fn read_byte(hex: &[u8], i: &mut usize) -> Result<u8, ParseErr> {
    let hi = nibble(hex[*i])?;
    let lo = nibble(hex[*i + 1])?;
    *i += 2;
    Ok((hi << 4) | lo)
}

fn nibble(b: u8) -> Result<u8, ParseErr> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(10 + b - b'a'),
        b'A'..=b'F' => Ok(10 + b - b'A'),
        _ => Err(ParseErr::BadHex),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_zero_roundtrip() {
        let r = GdbRegs::default();
        let mut out = [0u8; GDB_REGS_HEX];
        let enc = encode_g(&r, &mut out);
        assert_eq!(enc.len(), GDB_REGS_HEX);
        assert!(enc.iter().all(|&b| b == b'0'));
        let mut back = GdbRegs {
            rax: 0xDEADBEEF,
            ..Default::default()
        };
        decode_g(enc, &mut back).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn rax_first_bytes_little_endian() {
        // rax is the first field — its bytes should appear at the very
        // start of the hex blob, little-endian. 0x0102030405060708 →
        // bytes [08, 07, 06, 05, 04, 03, 02, 01] → "0807060504030201".
        let r = GdbRegs {
            rax: 0x0102030405060708,
            ..Default::default()
        };
        let mut out = [0u8; GDB_REGS_HEX];
        let enc = encode_g(&r, &mut out);
        assert_eq!(&enc[..16], b"0807060504030201");
    }

    #[test]
    fn field_order_matches_spec() {
        // rip is the 17th u64 (after 16 GPRs), so it starts at byte
        // offset 16*8 = 128 (= 256 hex chars). eflags follows at 136
        // bytes (= 272 hex chars) as a u32.
        let r = GdbRegs {
            rip: 0x00000000aabbccdd,
            eflags: 0x11223344,
            ..Default::default()
        };
        let mut out = [0u8; GDB_REGS_HEX];
        let enc = encode_g(&r, &mut out);
        // rip little-endian: dd cc bb aa 00 00 00 00 → "ddccbbaa00000000"
        assert_eq!(&enc[256..272], b"ddccbbaa00000000");
        // eflags little-endian: 44 33 22 11 → "44332211"
        assert_eq!(&enc[272..280], b"44332211");
    }

    #[test]
    fn roundtrip_nonzero() {
        let r = GdbRegs {
            rax: 0x1111111111111111,
            rbx: 0x2222222222222222,
            rcx: 0x3333333333333333,
            rsp: 0x7fff_ffff_ffff_ff00,
            rip: 0xffff_ffff_8000_1234,
            eflags: 0x202,
            cs: 0x08,
            ss: 0x10,
            ds: 0x10,
            es: 0x10,
            fs: 0x10,
            gs: 0x10,
            ..Default::default()
        };
        let mut out = [0u8; GDB_REGS_HEX];
        let enc = encode_g(&r, &mut out);
        let mut back = GdbRegs::default();
        decode_g(enc, &mut back).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn decode_wrong_length_rejected() {
        let mut r = GdbRegs::default();
        assert_eq!(decode_g(b"abcd", &mut r), Err(ParseErr::WrongLength));
        assert_eq!(
            decode_g(&[b'0'; GDB_REGS_HEX - 2], &mut r),
            Err(ParseErr::WrongLength)
        );
    }

    #[test]
    fn decode_non_hex_rejected() {
        let mut r = GdbRegs::default();
        let mut buf = [b'0'; GDB_REGS_HEX];
        buf[5] = b'z';
        assert_eq!(decode_g(&buf, &mut r), Err(ParseErr::BadHex));
    }

    #[test]
    fn decode_mixed_case_hex_accepted() {
        let mut r = GdbRegs::default();
        let mut buf = [b'0'; GDB_REGS_HEX];
        // rax = 0x00000000000000AB via uppercase 'A','B'
        buf[0] = b'A';
        buf[1] = b'B';
        decode_g(&buf, &mut r).unwrap();
        assert_eq!(r.rax, 0xAB);
    }
}
