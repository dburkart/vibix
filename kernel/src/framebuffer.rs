//! Minimal text console over Limine's linear framebuffer.
//!
//! Uses the `font8x8` crate (8x8 bitmap glyphs). We draw directly into
//! the framebuffer in whatever pixel format Limine reports — assumed
//! 32 bpp little-endian XRGB / BGR variants, which is what every
//! modern UEFI + QEMU combo hands us.

use core::fmt::{self, Write};
use font8x8::UnicodeFonts;
use spin::Mutex;

const GLYPH_W: usize = 8;
const GLYPH_H: usize = 8;
const FG: u32 = 0x00E0_E0E0;
const BG: u32 = 0x0000_0000;

pub struct Console {
    buffer: *mut u32,
    width: usize,  // pixels
    height: usize, // pixels
    pitch: usize,  // u32s per row
    cols: usize,
    rows: usize,
    cx: usize,
    cy: usize,
}

// SAFETY: the framebuffer pointer is stable for the lifetime of the
// kernel; we gate concurrent writes with a Mutex below.
unsafe impl Send for Console {}

impl Console {
    /// Construct a console over a 32-bpp linear framebuffer.
    ///
    /// # Safety
    /// `base` must point to a framebuffer of `height` rows, each `pitch_bytes`
    /// bytes wide, valid for writes for the lifetime of this program.
    pub unsafe fn new(base: *mut u8, width: u64, height: u64, pitch_bytes: u64) -> Self {
        let pitch = (pitch_bytes / 4) as usize;
        let width = width as usize;
        let height = height as usize;
        Self {
            buffer: base as *mut u32,
            width,
            height,
            pitch,
            cols: width / GLYPH_W,
            rows: height / GLYPH_H,
            cx: 0,
            cy: 0,
        }
    }

    pub fn clear(&mut self) {
        for y in 0..self.height {
            for x in 0..self.width {
                unsafe { self.buffer.add(y * self.pitch + x).write_volatile(BG) };
            }
        }
        self.cx = 0;
        self.cy = 0;
    }

    fn put_glyph(&mut self, col: usize, row: usize, glyph: [u8; 8]) {
        let px = col * GLYPH_W;
        let py = row * GLYPH_H;
        for (dy, bits) in glyph.iter().enumerate() {
            for dx in 0..GLYPH_W {
                let lit = (bits >> dx) & 1 != 0;
                let color = if lit { FG } else { BG };
                let x = px + dx;
                let y = py + dy;
                if x < self.width && y < self.height {
                    unsafe { self.buffer.add(y * self.pitch + x).write_volatile(color) };
                }
            }
        }
    }

    fn newline(&mut self) {
        self.cx = 0;
        self.cy += 1;
        if self.cy >= self.rows {
            // Cheap scroll: just wrap. A real scroll would memmove rows up.
            self.cy = 0;
            self.clear();
        }
    }

    pub fn write_char(&mut self, c: char) {
        match c {
            '\n' => self.newline(),
            '\r' => self.cx = 0,
            c => {
                let glyph = font8x8::BASIC_FONTS
                    .get(c)
                    .unwrap_or_else(|| font8x8::BASIC_FONTS.get('?').unwrap());
                self.put_glyph(self.cx, self.cy, glyph);
                self.cx += 1;
                if self.cx >= self.cols {
                    self.newline();
                }
            }
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            self.write_char(c);
        }
        Ok(())
    }
}

pub static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

pub fn init(console: Console) {
    let mut guard = CONSOLE.lock();
    *guard = Some(console);
    if let Some(c) = guard.as_mut() {
        c.clear();
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    if let Some(c) = CONSOLE.lock().as_mut() {
        let _ = c.write_fmt(args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::framebuffer::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
