//! Kernel symbol table embedded in the final ELF.
//!
//! The kernel reserves a fixed-size `.ksymtab` section (zero-filled by
//! the linker). After the normal cargo build finishes, `xtask` parses
//! the ELF's own symbol table, serializes a compact address→name map
//! into this section via `objcopy --update-section`, then ships the
//! patched ELF. At runtime the backtrace resolver reads the section
//! through the linker-provided start/end symbols.
//!
//! ## Binary format
//!
//! ```text
//! struct Header {
//!     magic:      [u8; 4],   // b"KSYM"
//!     version:    u8,        // 1
//!     _reserved:  [u8; 3],
//!     count:      u32 LE,    // number of entries
//!     str_off:    u32 LE,    // byte offset from start of blob to strings
//!     str_len:    u32 LE,    // bytes in string table
//! }
//! struct Entry { addr: u64 LE, name_off: u32 LE, name_len: u32 LE }
//! // Entries are sorted by `addr` ascending.
//! // String table is raw UTF-8 bytes; entries index into it.
//! ```

use core::fmt::{self, Write};
use core::mem::size_of;
use core::slice;

const MAGIC: &[u8; 4] = b"KSYM";
const VERSION: u8 = 1;

/// Fixed reservation for the symbol table. Patched in place by xtask.
/// Sized so a debug kernel's full symbol set fits with headroom; debug
/// builds today come in around 2–3k symbols × ~50 bytes/entry.
pub const KSYMTAB_BYTES: usize = 256 * 1024;

/// Fixed-size reservation patched in place by xtask after linking. We
/// deliberately DO NOT use a custom `#[link_section]` — a separate
/// output section tripped rust-lld into a broken PT_LOAD layout
/// (absorbing `.data`/`.bss` into the rodata segment under a read-only
/// PHDR). Riding in `.rodata` is fine: xtask locates the reservation
/// by symbol address, not by section name.
///
/// The explicit non-zero magic in the first four bytes forces LLVM to
/// emit this as SHT_PROGBITS (not NOBITS), so xtask has real file
/// bytes to overwrite.
#[used]
#[no_mangle]
pub static KSYMTAB_RESERVATION: KsymtabReservation = KsymtabReservation {
    placeholder_magic: *b"____",
    _pad: [0; KSYMTAB_BYTES - 4],
};

#[repr(C, align(4096))]
pub struct KsymtabReservation {
    placeholder_magic: [u8; 4],
    _pad: [u8; KSYMTAB_BYTES - 4],
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
    addr: u64,
    name_off: u32,
    name_len: u32,
}

/// Pointer to the start of the reservation's bytes. Routed through a
/// volatile read of a self-referential constant to defeat rustc's
/// const-folding: without this, LLVM sees `KSYMTAB_RESERVATION`'s
/// compile-time initializer (`"____"` magic, zero payload) and proves
/// every parse attempt unreachable — the post-link patch is invisible
/// to the optimizer.
fn raw_ptr() -> *const u8 {
    let p: *const u8 = &KSYMTAB_RESERVATION as *const _ as *const u8;
    // SAFETY: reading our own stack slot, which we just initialized.
    unsafe { core::ptr::read_volatile(&p) }
}

fn raw() -> Option<&'static [u8]> {
    // SAFETY: KSYMTAB_RESERVATION is a single `'static` object of
    // exactly KSYMTAB_BYTES bytes.
    unsafe { Some(slice::from_raw_parts(raw_ptr(), KSYMTAB_BYTES)) }
}

fn header() -> Option<Header> {
    // SAFETY: pointer is to our own static, which is at least
    // `size_of::<Header>()` bytes. The volatile read forces the load to
    // happen at runtime against the xtask-patched bytes.
    let hdr: Header = unsafe { core::ptr::read_volatile(raw_ptr() as *const Header) };
    if &hdr.magic != MAGIC || hdr.version != VERSION {
        return None;
    }
    Some(hdr)
}

fn entries() -> Option<&'static [Entry]> {
    let blob = raw()?;
    let hdr = header()?;
    let count = { hdr.count } as usize;
    // Checked arithmetic: a malformed blob can't be allowed to overflow
    // the bounds math and trick us into a giant slice.
    let entries_bytes = size_of::<Entry>().checked_mul(count)?;
    let entries_off = size_of::<Header>();
    let end = entries_off.checked_add(entries_bytes)?;
    if end > blob.len() {
        return None;
    }
    // SAFETY: bounds checked above; Entry is repr(C, packed).
    let ptr = unsafe { blob.as_ptr().add(entries_off) } as *const Entry;
    Some(unsafe { slice::from_raw_parts(ptr, count) })
}

fn strtab() -> Option<&'static [u8]> {
    let blob = raw()?;
    let hdr = header()?;
    let off = { hdr.str_off } as usize;
    let len = { hdr.str_len } as usize;
    if off.saturating_add(len) > blob.len() {
        return None;
    }
    Some(&blob[off..off + len])
}

fn name_of(e: &Entry) -> Option<&'static str> {
    let strs = strtab()?;
    let off = e.name_off as usize;
    let len = e.name_len as usize;
    if off.saturating_add(len) > strs.len() {
        return None;
    }
    core::str::from_utf8(&strs[off..off + len]).ok()
}

/// Look up the symbol whose address is the greatest value not exceeding
/// `addr`. Returns `(name, offset_from_symbol_start)` on success.
pub fn resolve(addr: u64) -> Option<(&'static str, u64)> {
    let entries = entries()?;
    if entries.is_empty() {
        return None;
    }
    // Binary search for the largest `addr <= target`.
    let mut lo = 0usize;
    let mut hi = entries.len();
    while lo < hi {
        let mid = (lo + hi) / 2;
        // Copy to a local so we don't take a reference into a packed field.
        let mid_addr = { entries[mid].addr };
        if mid_addr <= addr {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if lo == 0 {
        return None;
    }
    let e = &entries[lo - 1];
    let base = { e.addr };
    let name = name_of(e)?;
    Some((name, addr - base))
}

/// True if the symbol table has been populated with a valid header.
/// Useful for callers that want to degrade gracefully (e.g. print raw
/// addresses if the table wasn't built into this image).
pub fn is_populated() -> bool {
    header().is_some()
}

/// Number of symbols in the loaded table (0 if not populated).
pub fn len() -> usize {
    header().map(|h| { h.count } as usize).unwrap_or(0)
}

/// Format a single return address the way a human wants to read it:
/// `0x<addr> <name>+0x<off>` when a symbol is found, else `0x<addr> ?`.
pub fn format_addr<W: Write>(w: &mut W, addr: u64) -> fmt::Result {
    match resolve(addr) {
        Some((name, off)) => write!(w, "{addr:#018x} {name}+{off:#x}"),
        None => write!(w, "{addr:#018x} ?"),
    }
}
