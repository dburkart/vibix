//! Linux `termios2` / `ktermios` layout and TC* ioctl command numbers.
//!
//! vibix ships Linux's kernel-side `struct termios2` as its canonical
//! termios and exposes it through `TCGETS`/`TCSETS` directly. This is a
//! documented deviation from strict glibc `<termios.h>` compatibility —
//! see RFC 0003 §"Termios layout" for rationale. Userspace built against
//! Linux kernel headers (musl, or glibc with `TCGETS2`/`TCSETS2`) reads
//! the full 44-byte struct including `c_ispeed`/`c_ospeed`.
//!
//! Bit values and `c_cc` indices are pinned against Linux
//! `<asm-generic/termbits.h>` and `<asm-generic/ioctls.h>`.

/// Number of control characters in `c_cc`. Linux `NCCS` on asm-generic
/// architectures is 19.
pub const NCCS: usize = 19;

/// Linux kernel-side `struct termios2` / `ktermios`.
///
/// Laid out so the on-wire representation matches Linux exactly:
/// four `u32` flag words, a one-byte line-discipline selector, the
/// `NCCS`-sized control-character array, then two `u32` baud rates.
/// Total size is 44 bytes; `repr(C)` with `align_of == 4` gives no
/// internal padding because the `[u8; 19]` lands at offset 17 and the
/// next `u32` at offset 36 is 4-aligned.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

// Size/alignment are load-bearing: the syscall ABI passes raw bytes,
// so any drift would silently corrupt userspace termios reads.
const _: () = assert!(core::mem::size_of::<Termios>() == 44);
const _: () = assert!(core::mem::align_of::<Termios>() == 4);

// --- c_iflag bits --------------------------------------------------------

pub const IGNBRK: u32 = 0x0001;
pub const BRKINT: u32 = 0x0002;
pub const ISTRIP: u32 = 0x0020;
pub const INLCR: u32 = 0x0040;
pub const IGNCR: u32 = 0x0080;
pub const ICRNL: u32 = 0x0100;
pub const IXON: u32 = 0x0400;

// --- c_oflag bits --------------------------------------------------------

pub const OPOST: u32 = 0x0001;
pub const ONLCR: u32 = 0x0004;
pub const OCRNL: u32 = 0x0008;

// --- c_lflag bits --------------------------------------------------------

pub const ISIG: u32 = 0x0001;
pub const ICANON: u32 = 0x0002;
pub const ECHO: u32 = 0x0008;
pub const ECHOE: u32 = 0x0010;
pub const ECHOK: u32 = 0x0020;
pub const ECHONL: u32 = 0x0040;
pub const NOFLSH: u32 = 0x0080;
pub const TOSTOP: u32 = 0x0100;
pub const IEXTEN: u32 = 0x8000;

// --- c_cc indices --------------------------------------------------------

pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;

// --- TC* ioctl command numbers (Linux <asm-generic/ioctls.h>) ------------

pub const TCGETS: u32 = 0x5401;
pub const TCSETS: u32 = 0x5402;
pub const TCSETSW: u32 = 0x5403;
pub const TCSETSF: u32 = 0x5404;

impl Termios {
    /// A "sane" default termios suitable for an interactive console:
    /// canonical mode, echo on, input CR→NL, output NL→CRNL, signals
    /// enabled, and the control-character table matching Linux `stty
    /// sane`.
    pub const fn sane() -> Self {
        let mut c_cc = [0u8; NCCS];
        c_cc[VINTR] = 0x03; // Ctrl-C
        c_cc[VQUIT] = 0x1c; // Ctrl-\
        c_cc[VERASE] = 0x7f; // DEL
        c_cc[VKILL] = 0x15; // Ctrl-U
        c_cc[VEOF] = 0x04; // Ctrl-D
        c_cc[VSUSP] = 0x1a; // Ctrl-Z
        c_cc[VSTART] = 0x11; // Ctrl-Q
        c_cc[VSTOP] = 0x13; // Ctrl-S
        Self {
            c_iflag: ICRNL | IXON | BRKINT,
            c_oflag: OPOST | ONLCR,
            c_cflag: 0,
            c_lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN,
            c_line: 0,
            c_cc,
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }

    /// View the struct as a 44-byte buffer for copy-to-user.
    pub fn as_bytes(&self) -> &[u8; 44] {
        // SAFETY: Termios is `#[repr(C)]`, size 44, contains only
        // integer fields — every byte pattern is a valid inhabitant.
        unsafe { &*(self as *const Self as *const [u8; 44]) }
    }

    /// Reinterpret a 44-byte buffer as a termios for copy-from-user.
    pub fn from_bytes(bytes: &[u8; 44]) -> Self {
        // SAFETY: Same as above — all-integer repr(C) layout.
        unsafe { *(bytes.as_ptr() as *const Self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, offset_of, size_of};

    #[test]
    fn layout_matches_linux_termios2() {
        assert_eq!(size_of::<Termios>(), 44);
        assert_eq!(align_of::<Termios>(), 4);
        assert_eq!(offset_of!(Termios, c_iflag), 0);
        assert_eq!(offset_of!(Termios, c_oflag), 4);
        assert_eq!(offset_of!(Termios, c_cflag), 8);
        assert_eq!(offset_of!(Termios, c_lflag), 12);
        assert_eq!(offset_of!(Termios, c_line), 16);
        assert_eq!(offset_of!(Termios, c_cc), 17);
        assert_eq!(offset_of!(Termios, c_ispeed), 36);
        assert_eq!(offset_of!(Termios, c_ospeed), 40);
    }

    #[test]
    fn iflag_bit_values_match_linux() {
        assert_eq!(IGNBRK, 0x0001);
        assert_eq!(BRKINT, 0x0002);
        assert_eq!(ISTRIP, 0x0020);
        assert_eq!(INLCR, 0x0040);
        assert_eq!(IGNCR, 0x0080);
        assert_eq!(ICRNL, 0x0100);
        assert_eq!(IXON, 0x0400);
    }

    #[test]
    fn oflag_bit_values_match_linux() {
        assert_eq!(OPOST, 0x0001);
        assert_eq!(ONLCR, 0x0004);
        assert_eq!(OCRNL, 0x0008);
    }

    #[test]
    fn lflag_bit_values_match_linux() {
        assert_eq!(ISIG, 0x0001);
        assert_eq!(ICANON, 0x0002);
        assert_eq!(ECHO, 0x0008);
        assert_eq!(ECHOE, 0x0010);
        assert_eq!(ECHOK, 0x0020);
        assert_eq!(ECHONL, 0x0040);
        assert_eq!(NOFLSH, 0x0080);
        assert_eq!(TOSTOP, 0x0100);
        assert_eq!(IEXTEN, 0x8000);
    }

    #[test]
    fn cc_indices_match_linux() {
        assert_eq!(VINTR, 0);
        assert_eq!(VQUIT, 1);
        assert_eq!(VERASE, 2);
        assert_eq!(VKILL, 3);
        assert_eq!(VEOF, 4);
        assert_eq!(VTIME, 5);
        assert_eq!(VMIN, 6);
        assert_eq!(VSTART, 8);
        assert_eq!(VSTOP, 9);
        assert_eq!(VSUSP, 10);
        assert_eq!(VEOL, 11);
    }

    #[test]
    fn ioctl_cmd_numbers_match_linux() {
        assert_eq!(TCGETS, 0x5401);
        assert_eq!(TCSETS, 0x5402);
        assert_eq!(TCSETSW, 0x5403);
        assert_eq!(TCSETSF, 0x5404);
    }

    #[test]
    fn sane_defaults_match_stty_sane() {
        let t = Termios::sane();
        assert_eq!(t.c_iflag, ICRNL | IXON | BRKINT);
        assert_eq!(t.c_oflag, OPOST | ONLCR);
        assert_eq!(t.c_lflag, ISIG | ICANON | ECHO | ECHOE | ECHOK | IEXTEN);
        assert_eq!(t.c_cc[VINTR], 0x03);
        assert_eq!(t.c_cc[VQUIT], 0x1c);
        assert_eq!(t.c_cc[VERASE], 0x7f);
        assert_eq!(t.c_cc[VKILL], 0x15);
        assert_eq!(t.c_cc[VEOF], 0x04);
        assert_eq!(t.c_cc[VSUSP], 0x1a);
        assert_eq!(t.c_cc[VSTART], 0x11);
        assert_eq!(t.c_cc[VSTOP], 0x13);
    }

    #[test]
    fn as_bytes_from_bytes_round_trip() {
        let t = Termios::sane();
        let bytes = *t.as_bytes();
        let round = Termios::from_bytes(&bytes);
        assert_eq!(t, round);
    }
}
