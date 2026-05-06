//! Framebuffer TTY driver for console output.
//!
//! Issue #897. [`FramebufferDriver`] implements [`TtyDriver`] by feeding
//! bytes into the framebuffer console's existing ANSI/VT100 terminal
//! emulator ([`crate::framebuffer::CONSOLE`]). This gives userspace
//! processes visible output on the display while keeping the full
//! escape-sequence, scrollback, and alt-screen machinery that the
//! framebuffer module already provides.
//!
//! [`DualDriver`] multiplexes writes to both the serial port (for CI
//! smoke-test markers) and the framebuffer (for on-screen display).

use crate::tty::TtyDriver;

/// TTY driver that writes to the framebuffer console.
///
/// Each byte slice is interpreted as UTF-8 and fed character-by-character
/// into [`crate::framebuffer::_print`], which acquires the `CONSOLE` lock
/// and drives the ANSI parser + glyph renderer.
pub struct FramebufferDriver;

impl TtyDriver for FramebufferDriver {
    #[cfg(target_os = "none")]
    fn write(&self, buf: &[u8]) -> usize {
        // The framebuffer console expects characters via `write_char` /
        // `write_str`. Convert the byte slice to a &str (lossy: invalid
        // UTF-8 is replaced with U+FFFD, which the glyph renderer handles
        // gracefully). Most kernel and userspace output is ASCII or valid
        // UTF-8 so the fast path hits `from_utf8` without copying.
        match core::str::from_utf8(buf) {
            Ok(s) => {
                crate::framebuffer::_print(format_args!("{}", s));
            }
            Err(_) => {
                // Fallback: write byte-by-byte as individual chars.
                // Non-UTF-8 bytes become their Latin-1 code points, which
                // is what a terminal emulator would do.
                if let Some(console) = crate::framebuffer::CONSOLE.lock().as_mut() {
                    for &b in buf {
                        console.write_char(b as char);
                    }
                }
            }
        }
        buf.len()
    }

    #[cfg(not(target_os = "none"))]
    fn write(&self, buf: &[u8]) -> usize {
        buf.len()
    }
}

/// Multiplexing driver that writes to both serial and framebuffer.
///
/// CI smoke tests read serial output for pass/fail markers, so serial
/// must remain active. The framebuffer provides on-screen console output
/// for interactive use. This driver writes to serial first (lower
/// latency, no lock contention with the framebuffer's pixel blitter),
/// then to the framebuffer.
pub struct DualDriver;

impl TtyDriver for DualDriver {
    #[cfg(target_os = "none")]
    fn write(&self, buf: &[u8]) -> usize {
        // Serial first — fast, no pixel work.
        crate::serial::write_bytes(buf);
        // Then framebuffer.
        match core::str::from_utf8(buf) {
            Ok(s) => {
                crate::framebuffer::_print(format_args!("{}", s));
            }
            Err(_) => {
                if let Some(console) = crate::framebuffer::CONSOLE.lock().as_mut() {
                    for &b in buf {
                        console.write_char(b as char);
                    }
                }
            }
        }
        buf.len()
    }

    #[cfg(not(target_os = "none"))]
    fn write(&self, buf: &[u8]) -> usize {
        buf.len()
    }
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn framebuffer_driver_write_reports_all_bytes() {
        let d = FramebufferDriver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"hello"), 5);
    }

    #[test]
    fn dual_driver_write_reports_all_bytes() {
        let d = DualDriver;
        assert_eq!(d.write(b""), 0);
        assert_eq!(d.write(b"hello world"), 11);
    }
}
