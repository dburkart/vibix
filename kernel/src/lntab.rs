//! Kernel line-number table embedded in the final ELF.
//!
//! Mirrors the shape of `ksymtab`: a fixed-size reservation patched in
//! place by xtask after linking. xtask parses `.debug_line` from the
//! kernel's own DWARF, emits a compact `(pc → file:line:col)` blob, and
//! overwrites `LNTAB_RESERVATION`'s bytes. At runtime the backtrace
//! formatter binary-searches the table to annotate each frame.
//!
//! ## Binary format
//!
//! ```text
//! struct Header {
//!     magic:     [u8; 4],   // b"LNTB"
//!     version:   u8,        // 1
//!     _reserved: [u8; 3],
//!     count:     u32 LE,    // number of entries
//!     str_off:   u32 LE,    // byte offset from blob start to strtab
//!     str_len:   u32 LE,    // strtab length
//! }
//! struct Entry {
//!     pc:       u64 LE,
//!     file_off: u32 LE,
//!     file_len: u32 LE,
//!     line:     u32 LE,     // 0 means unknown
//!     col:      u16 LE,     // 0 means unknown; saturated at u16::MAX
//!     _pad:     u16,        // keeps entry 8-aligned
//! }
//! // Entries are sorted ascending by `pc`. Strtab holds raw UTF-8;
//! // entries index into it with (file_off, file_len).
//! ```

use core::mem::size_of;
use core::slice;

const MAGIC: &[u8; 4] = b"LNTB";
const VERSION: u8 = 1;

/// Fixed reservation for the line table. Patched in place by xtask.
/// Integration-test binaries pull in more code paths than the main
/// kernel and produce notably larger line tables — the main kernel
/// lands around ~990 KiB today while the largest test ELF needs
/// ~1.15 MiB. 2 MiB gives both headroom. If it overflows, xtask
/// aborts with a clear "bump LNTAB_BYTES" error.
pub const LNTAB_BYTES: usize = 2 * 1024 * 1024;

/// Fixed-size reservation patched in place by xtask after linking. The
/// explicit non-zero magic in the first four bytes forces LLVM to emit
/// this as SHT_PROGBITS (not NOBITS) so xtask has real file bytes to
/// overwrite. Same trick as `KSYMTAB_RESERVATION`.
#[cfg(target_os = "none")]
#[used]
#[no_mangle]
pub static LNTAB_RESERVATION: LntabReservation = LntabReservation {
    placeholder_magic: *b"____",
    _pad: [0; LNTAB_BYTES - 4],
};

#[repr(C, align(4096))]
pub struct LntabReservation {
    placeholder_magic: [u8; 4],
    _pad: [u8; LNTAB_BYTES - 4],
}

#[repr(C, packed)]
struct Header {
    magic: [u8; 4],
    version: u8,
    _reserved: [u8; 3],
    count: u32,
    str_off: u32,
    str_len: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct Entry {
    pc: u64,
    file_off: u32,
    file_len: u32,
    line: u32,
    col: u16,
    _pad: u16,
}

// Pin on-wire layout. xtask's matching constants must agree; if either
// struct changes, this assert fires and xtask has to be updated too.
const _: () = assert!(size_of::<Header>() == 20);
const _: () = assert!(size_of::<Entry>() == 24);

#[cfg(target_os = "none")]
fn raw_ptr() -> *const u8 {
    let p: *const u8 = &LNTAB_RESERVATION as *const _ as *const u8;
    // SAFETY: reading our own stack slot, which we just initialized.
    // Volatile defeats const-folding against the all-zero initializer
    // so the runtime sees xtask's patched bytes.
    unsafe { core::ptr::read_volatile(&p) }
}

#[cfg(target_os = "none")]
fn raw() -> Option<&'static [u8]> {
    // SAFETY: LNTAB_RESERVATION is a single `'static` object of exactly
    // LNTAB_BYTES bytes.
    unsafe { Some(slice::from_raw_parts(raw_ptr(), LNTAB_BYTES)) }
}

/// Parse a blob into (entries, strtab) slices without touching any
/// `'static` state. Pure function over a byte slice so host unit tests
/// can exercise the decoder directly.
fn parse_blob(blob: &[u8]) -> Option<(&[Entry], &[u8])> {
    if blob.len() < size_of::<Header>() {
        return None;
    }
    // SAFETY: slice is at least header-sized; repr(C, packed) tolerates
    // unaligned reads, and we only read POD bytes.
    let hdr: Header = unsafe { core::ptr::read_unaligned(blob.as_ptr() as *const Header) };
    if &hdr.magic != MAGIC || hdr.version != VERSION {
        return None;
    }
    let count = { hdr.count } as usize;
    let str_off = { hdr.str_off } as usize;
    let str_len = { hdr.str_len } as usize;

    let entries_off = size_of::<Header>();
    let entries_bytes = size_of::<Entry>().checked_mul(count)?;
    let entries_end = entries_off.checked_add(entries_bytes)?;
    if entries_end > blob.len() {
        return None;
    }
    // SAFETY: bounds checked above; Entry is repr(C, packed).
    let ptr = unsafe { blob.as_ptr().add(entries_off) } as *const Entry;
    let entries = unsafe { slice::from_raw_parts(ptr, count) };

    let str_end = str_off.checked_add(str_len)?;
    if str_end > blob.len() {
        return None;
    }
    let strtab = &blob[str_off..str_end];

    Some((entries, strtab))
}

fn resolve_in(blob: &[u8], addr: u64) -> Option<(&str, u32, u16)> {
    let (entries, strtab) = parse_blob(blob)?;
    if entries.is_empty() {
        return None;
    }
    // Binary search for the largest `pc <= addr`.
    let mut lo = 0usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        let mid_pc = { entries[mid].pc };
        if mid_pc <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let e = &entries[lo - 1];
    let off = { e.file_off } as usize;
    let len = { e.file_len } as usize;
    if off.saturating_add(len) > strtab.len() {
        return None;
    }
    let file = core::str::from_utf8(&strtab[off..off + len]).ok()?;
    let line = { e.line };
    let col = { e.col };
    Some((file, line, col))
}

/// Look up source coordinates for an address. Returns `(file, line, col)`
/// where `line == 0` or `col == 0` signal "unknown" for that axis.
#[cfg(target_os = "none")]
pub fn resolve_line(addr: u64) -> Option<(&'static str, u32, u16)> {
    let blob = raw()?;
    // SAFETY: lifetime is tied to `LNTAB_RESERVATION`, which is
    // `'static`; `resolve_in` returns slices into `blob`.
    let (file, line, col) = resolve_in(blob, addr)?;
    let file: &'static str = unsafe { core::mem::transmute(file) };
    Some((file, line, col))
}

/// True when the line table has a valid header. Backtrace callers use
/// this to degrade gracefully on images where xtask didn't patch in a
/// real table (e.g. out-of-tree builds).
#[cfg(target_os = "none")]
pub fn is_populated() -> bool {
    raw().and_then(|b| parse_blob(b).map(|_| ())).is_some()
}

/// Number of line entries in the loaded table (0 if unpopulated).
#[cfg(target_os = "none")]
pub fn len() -> usize {
    raw()
        .and_then(|b| parse_blob(b).map(|(e, _)| e.len()))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_blob(rows: &[(u64, &str, u32, u16)]) -> alloc::vec::Vec<u8> {
        use alloc::vec::Vec;
        const HEADER_SIZE: usize = size_of::<Header>();
        const ENTRY_SIZE: usize = size_of::<Entry>();

        let mut strtab: Vec<u8> = Vec::new();
        let mut entries: Vec<u8> = Vec::new();
        for (pc, file, line, col) in rows {
            let off = strtab.len() as u32;
            let len = file.len() as u32;
            strtab.extend_from_slice(file.as_bytes());
            entries.extend_from_slice(&pc.to_le_bytes());
            entries.extend_from_slice(&off.to_le_bytes());
            entries.extend_from_slice(&len.to_le_bytes());
            entries.extend_from_slice(&line.to_le_bytes());
            entries.extend_from_slice(&col.to_le_bytes());
            entries.extend_from_slice(&0u16.to_le_bytes());
        }
        assert_eq!(entries.len(), rows.len() * ENTRY_SIZE);

        let str_off = (HEADER_SIZE + entries.len()) as u32;
        let str_len = strtab.len() as u32;
        let count = rows.len() as u32;

        let mut blob = Vec::with_capacity(HEADER_SIZE + entries.len() + strtab.len());
        blob.extend_from_slice(MAGIC);
        blob.push(VERSION);
        blob.extend_from_slice(&[0u8; 3]);
        blob.extend_from_slice(&count.to_le_bytes());
        blob.extend_from_slice(&str_off.to_le_bytes());
        blob.extend_from_slice(&str_len.to_le_bytes());
        blob.extend_from_slice(&entries);
        blob.extend_from_slice(&strtab);
        blob
    }

    #[test]
    fn parse_rejects_bad_magic() {
        let mut blob = build_blob(&[(0x1000, "a.rs", 1, 0)]);
        blob[0] = b'X';
        assert!(parse_blob(&blob).is_none());
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut blob = build_blob(&[(0x1000, "a.rs", 1, 0)]);
        blob[4] = 99;
        assert!(parse_blob(&blob).is_none());
    }

    #[test]
    fn parse_rejects_truncated() {
        let blob = build_blob(&[(0x1000, "a.rs", 1, 0)]);
        assert!(parse_blob(&blob[..10]).is_none());
    }

    #[test]
    fn resolve_hits_exact_pc() {
        let blob = build_blob(&[
            (0x1000, "a.rs", 10, 4),
            (0x2000, "b.rs", 20, 8),
            (0x3000, "c.rs", 30, 12),
        ]);
        let (file, line, col) = resolve_in(&blob, 0x2000).unwrap();
        assert_eq!(file, "b.rs");
        assert_eq!(line, 20);
        assert_eq!(col, 8);
    }

    #[test]
    fn resolve_picks_largest_pc_not_exceeding() {
        let blob = build_blob(&[
            (0x1000, "a.rs", 10, 0),
            (0x2000, "b.rs", 20, 0),
            (0x3000, "c.rs", 30, 0),
        ]);
        let (file, line, _) = resolve_in(&blob, 0x2500).unwrap();
        assert_eq!(file, "b.rs");
        assert_eq!(line, 20);
    }

    #[test]
    fn resolve_before_first_returns_none() {
        let blob = build_blob(&[(0x1000, "a.rs", 10, 0)]);
        assert!(resolve_in(&blob, 0x0fff).is_none());
    }

    #[test]
    fn resolve_past_last_returns_last() {
        let blob = build_blob(&[(0x1000, "a.rs", 10, 0), (0x2000, "b.rs", 20, 0)]);
        let (file, _, _) = resolve_in(&blob, u64::MAX).unwrap();
        assert_eq!(file, "b.rs");
    }

    #[test]
    fn resolve_empty_table_returns_none() {
        let blob = build_blob(&[]);
        assert!(resolve_in(&blob, 0x1000).is_none());
    }

    #[test]
    fn resolve_many_rows_binary_search() {
        let mut rows: alloc::vec::Vec<(u64, &str, u32, u16)> = alloc::vec::Vec::new();
        let names = ["a.rs", "b.rs", "c.rs"];
        for i in 0..1000u64 {
            rows.push((0x1000 + i * 16, names[(i % 3) as usize], (i + 1) as u32, 0));
        }
        let blob = build_blob(&rows);
        for i in [0u64, 1, 500, 999] {
            let pc = 0x1000 + i * 16;
            let (file, line, _) = resolve_in(&blob, pc).unwrap();
            assert_eq!(file, names[(i % 3) as usize]);
            assert_eq!(line, (i + 1) as u32);
        }
    }
}
