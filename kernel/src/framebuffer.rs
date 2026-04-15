//! Text console over Limine's linear framebuffer.
//!
//! Backs the display with a character grid (glyph + fg/bg colour per cell)
//! sized to the framebuffer.  When the cursor advances past the last row the
//! screen scrolls up one line and the evicted row is saved to a
//! `SCROLLBACK_ROWS`-deep ring in RAM.
//!
//! A minimal ANSI SGR parser handles:
//! - CSI `n m` with `n` in: 0 (reset), 1 (bold), 22 (bold off),
//!   30-37 (set fg), 39 (default fg), 40-47 (set bg), 49 (default bg).
//! - Control characters `\r`, `\t`, `\n`.
//!
//! A blinking cursor is drawn at the write position.  The blink rate is
//! driven by the kernel task spawned in `main.rs` via [`toggle_cursor`].
//!
//! # Initialization order
//!
//! [`Console::new`] heap-allocates the cell grid via `Vec`, so it **must**
//! be called after `mem::init()`.  Early-boot output before the heap is live
//! uses the serial port only.

use alloc::vec::Vec;
use core::fmt::{self, Write};
use font8x8::UnicodeFonts;
use spin::Mutex;

// ─── glyph geometry ────────────────────────────────────────────────────────

const GLYPH_W: usize = 8;
const GLYPH_H: usize = 8;

// ─── default colours ───────────────────────────────────────────────────────

const DEFAULT_FG: u32 = 0x00E0_E0E0; // near-white
const DEFAULT_BG: u32 = 0x0000_0000; // black

// ─── ANSI 8-colour palettes ────────────────────────────────────────────────

// 0xRRGGBB packed in the low 24 bits.
const ANSI_NORMAL: [u32; 8] = [
    0x00_00_00_00, // 0 black
    0x00_AA_00_00, // 1 red
    0x00_00_AA_00, // 2 green
    0x00_AA_55_00, // 3 yellow (dark)
    0x00_00_00_AA, // 4 blue
    0x00_AA_00_AA, // 5 magenta
    0x00_00_AA_AA, // 6 cyan
    0x00_AA_AA_AA, // 7 white
];

const ANSI_BRIGHT: [u32; 8] = [
    0x00_55_55_55, // 0 bright black
    0x00_FF_55_55, // 1 bright red
    0x00_55_FF_55, // 2 bright green
    0x00_FF_FF_55, // 3 bright yellow
    0x00_55_55_FF, // 4 bright blue
    0x00_FF_55_FF, // 5 bright magenta
    0x00_55_FF_FF, // 6 bright cyan
    0x00_FF_FF_FF, // 7 bright white
];

// ─── scrollback ────────────────────────────────────────────────────────────

/// Off-screen rows kept in the scrollback ring.
pub const SCROLLBACK_ROWS: usize = 200;

use crate::fbview::{clamp_offset_down, clamp_offset_up, split_viewport};

// ─── character cell ────────────────────────────────────────────────────────

#[derive(Clone, Copy)]
struct Cell {
    ch: char,
    fg: u32,
    bg: u32,
}

impl Cell {
    const fn blank() -> Self {
        Self {
            ch: ' ',
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
        }
    }
}

// ─── ANSI parser state ─────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq)]
enum Ansi {
    Normal,
    Esc,
    Csi,
}

// ─── Console ───────────────────────────────────────────────────────────────

pub struct Console {
    // Framebuffer
    buffer: *mut u32,
    width: usize,  // pixels
    height: usize, // pixels
    pitch: usize,  // u32s per scanline

    // Grid dimensions
    cols: usize,
    rows: usize,

    // Cursor position
    cx: usize,
    cy: usize,
    cursor_on: bool, // whether the cursor is currently drawn inverted

    // Character grid: `rows * cols` cells, row-major.
    cells: Vec<Cell>,

    // Scrollback ring: `SCROLLBACK_ROWS * cols` cells, row-major.
    // `scroll_head` is the index (in rows) of the oldest stored row;
    // `scroll_filled` is the count of valid rows (≤ SCROLLBACK_ROWS).
    scrollback: Vec<Cell>,
    scroll_head: usize,
    scroll_filled: usize,

    // Viewport offset, in rows, from the live bottom. 0 = pinned to live
    // output; positive values show that many rows of scrollback above the
    // live top. Clamped to `scroll_filled`. Any new character output calls
    // `pin_to_bottom()` first so live output always snaps the view back.
    scroll_offset: usize,

    // SGR colour state.  We track base colour indices so that toggling
    // `bold` retroactively re-selects the bright palette entry.
    fg_base: Option<u8>, // 0-7 if an ANSI colour; None = default
    bg_base: Option<u8>,
    bold: bool,

    // ANSI escape-sequence parser
    ansi: Ansi,
    params: [u32; 8], // accumulated CSI parameter values
    nparams: usize,   // params filled so far
    cur_param: u32,   // digit accumulator for the current parameter
}

// SAFETY: the framebuffer pointer is stable for the kernel lifetime;
// concurrent access is serialized through `CONSOLE`'s Mutex.
unsafe impl Send for Console {}

impl Console {
    /// Construct a console over a 32-bpp linear framebuffer.
    ///
    /// # Safety
    /// `base` must point to a valid 32-bpp framebuffer of `height` rows,
    /// each `pitch_bytes` bytes wide, writable for the program's lifetime.
    ///
    /// **Must be called after `mem::init()`** — this allocates on the heap.
    pub unsafe fn new(base: *mut u8, width: u64, height: u64, pitch_bytes: u64) -> Self {
        let pitch = (pitch_bytes / 4) as usize;
        let width = width as usize;
        let height = height as usize;
        let cols = width / GLYPH_W;
        let rows = height / GLYPH_H;

        let mut cells = Vec::with_capacity(rows * cols);
        cells.resize(rows * cols, Cell::blank());

        let mut scrollback = Vec::with_capacity(SCROLLBACK_ROWS * cols);
        scrollback.resize(SCROLLBACK_ROWS * cols, Cell::blank());

        Self {
            buffer: base as *mut u32,
            width,
            height,
            pitch,
            cols,
            rows,
            cx: 0,
            cy: 0,
            cursor_on: false,
            cells,
            scrollback,
            scroll_head: 0,
            scroll_filled: 0,
            scroll_offset: 0,
            fg_base: None,
            bg_base: None,
            bold: false,
            ansi: Ansi::Normal,
            params: [0; 8],
            nparams: 0,
            cur_param: 0,
        }
    }

    // ── colour helpers ────────────────────────────────────────────────────

    fn cur_fg(&self) -> u32 {
        match self.fg_base {
            None => DEFAULT_FG,
            Some(i) => {
                if self.bold {
                    ANSI_BRIGHT[i as usize]
                } else {
                    ANSI_NORMAL[i as usize]
                }
            }
        }
    }

    fn cur_bg(&self) -> u32 {
        match self.bg_base {
            None => DEFAULT_BG,
            Some(i) => ANSI_NORMAL[i as usize],
        }
    }

    // ── screen clear ──────────────────────────────────────────────────────

    pub fn clear(&mut self) {
        self.scroll_offset = 0;
        for cell in self.cells.iter_mut() {
            *cell = Cell::blank();
        }
        for y in 0..self.height {
            for x in 0..self.width {
                unsafe {
                    self.buffer
                        .add(y * self.pitch + x)
                        .write_volatile(DEFAULT_BG);
                }
            }
        }
        self.cx = 0;
        self.cy = 0;
        self.cursor_on = true;
        self.draw_cursor(self.cx, self.cy, true);
    }

    // ── low-level rendering ───────────────────────────────────────────────

    /// Render a single `Cell` to the framebuffer at grid position (col, row).
    fn render_cell_at(&mut self, col: usize, row: usize, cell: Cell) {
        let glyph = font8x8::BASIC_FONTS
            .get(cell.ch)
            .unwrap_or_else(|| font8x8::BASIC_FONTS.get(' ').unwrap());
        let px = col * GLYPH_W;
        let py = row * GLYPH_H;
        for (dy, bits) in glyph.iter().enumerate() {
            for dx in 0..GLYPH_W {
                let lit = (bits >> dx) & 1 != 0;
                let color = if lit { cell.fg } else { cell.bg };
                let x = px + dx;
                let y = py + dy;
                if x < self.width && y < self.height {
                    unsafe {
                        self.buffer.add(y * self.pitch + x).write_volatile(color);
                    }
                }
            }
        }
    }

    // ── cursor ────────────────────────────────────────────────────────────

    /// Draw or erase the cursor at (col, row) by inverting fg/bg.
    fn draw_cursor(&mut self, col: usize, row: usize, visible: bool) {
        if col >= self.cols || row >= self.rows {
            return;
        }
        let cell = self.cells[row * self.cols + col];
        if visible {
            let inv = Cell {
                ch: cell.ch,
                fg: cell.bg,
                bg: cell.fg,
            };
            self.render_cell_at(col, row, inv);
        } else {
            self.render_cell_at(col, row, cell);
        }
    }

    /// Toggle cursor visibility and repaint the cell at the write position.
    /// Called by the blink task.
    pub fn toggle_cursor(&mut self) {
        self.cursor_on = !self.cursor_on;
        // When scrolled back, the live cursor isn't on screen. Flip the
        // state so re-pinning restores the correct phase, but don't paint.
        if self.scroll_offset != 0 {
            return;
        }
        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
        self.draw_cursor(cx, cy, on);
    }

    // ── scrolling ─────────────────────────────────────────────────────────

    /// Scroll the screen up by one row.
    ///
    /// - The departing top row is pushed into the scrollback ring.
    /// - Cell data is shifted up with `Vec::copy_within`.
    /// - Pixel rows are blitted up on the framebuffer with a memmove-style
    ///   `ptr::copy` (handles overlap).
    /// - The vacated last pixel row is cleared to `DEFAULT_BG`.
    fn scroll_up(&mut self) {
        let cols = self.cols;

        // Save row 0 into the scrollback ring.
        let ring_row = (self.scroll_head + self.scroll_filled) % SCROLLBACK_ROWS;
        let dst = ring_row * cols;
        for i in 0..cols {
            self.scrollback[dst + i] = self.cells[i];
        }
        if self.scroll_filled < SCROLLBACK_ROWS {
            self.scroll_filled += 1;
        } else {
            self.scroll_head = (self.scroll_head + 1) % SCROLLBACK_ROWS;
        }

        // Shift cell grid up one row.
        self.cells.copy_within(cols.., 0);
        let last = (self.rows - 1) * cols;
        for i in 0..cols {
            self.cells[last + i] = Cell::blank();
        }

        // Blit pixel rows up (rows 1..rows → rows 0..rows-1).
        let row_pixels = self.pitch * GLYPH_H;
        unsafe {
            // ptr::copy is memmove-compatible and handles overlap.
            core::ptr::copy(
                self.buffer.add(row_pixels),
                self.buffer,
                row_pixels * (self.rows - 1),
            );
        }

        // Clear the last pixel row.
        let last_py = (self.rows - 1) * GLYPH_H;
        for y in last_py..last_py + GLYPH_H {
            for x in 0..self.width {
                unsafe {
                    self.buffer
                        .add(y * self.pitch + x)
                        .write_volatile(DEFAULT_BG);
                }
            }
        }
    }

    // ── scrollback viewport ───────────────────────────────────────────────

    /// Maximum scroll-back offset the current viewport can reach.
    fn max_scroll_offset(&self) -> usize {
        self.scroll_filled
    }

    /// Step size for a page of scrollback — one screen minus one row of
    /// overlap so readers don't lose their place.
    fn page_step(&self) -> usize {
        self.rows.saturating_sub(1).max(1)
    }

    /// Repaint the entire pixel grid from the scroll-back ring + live
    /// `cells`, honoring `scroll_offset`. Used whenever the viewport
    /// shifts or returns to live.
    fn repaint_viewport(&mut self) {
        let cols = self.cols;
        let rows = self.rows;
        let offset = self.scroll_offset.min(self.scroll_filled);
        let (k, _live_rows) = split_viewport(offset, self.scroll_filled, rows);
        // Rows [0..k): scrollback. The oldest visible row is age `offset-1`,
        // and each successive row in the viewport is one step newer.
        for r in 0..k {
            let age = offset - 1 - r;
            // Copy cells from the scrollback ring directly without an
            // intermediate buffer so rows wider than 256 columns render
            // correctly. Index arithmetic is duplicated here rather than
            // calling scrollback_row() to avoid holding an immutable borrow
            // across render_cell_at, which needs &mut self.
            let ring_row =
                (self.scroll_head + self.scroll_filled - 1 - age) % SCROLLBACK_ROWS;
            let base = ring_row * cols;
            for c in 0..cols {
                let cell = self.scrollback[base + c];
                self.render_cell_at(c, r, cell);
            }
        }
        // Rows [k..rows): top `rows - k` rows of live cells.
        for r in k..rows {
            let live_row = r - k;
            for c in 0..cols {
                let cell = self.cells[live_row * cols + c];
                self.render_cell_at(c, r, cell);
            }
        }
    }

    /// If the viewport is scrolled back, snap it to live and repaint.
    /// Called at the top of every output-producing path so new writes
    /// always show up.
    fn pin_to_bottom(&mut self) {
        if self.scroll_offset != 0 {
            self.scroll_offset = 0;
            self.repaint_viewport();
        }
    }

    /// Scroll the viewport up by `lines` (toward older output). Saturates
    /// at `scroll_filled` rows.
    pub fn scroll_view_up(&mut self, lines: usize) {
        let new = clamp_offset_up(self.scroll_offset, lines, self.max_scroll_offset());
        if new != self.scroll_offset {
            self.scroll_offset = new;
            self.repaint_viewport();
            self.draw_indicator();
        }
    }

    /// Scroll the viewport down by `lines` (toward live output). Saturates
    /// at 0; reaching 0 erases the indicator.
    pub fn scroll_view_down(&mut self, lines: usize) {
        let new = clamp_offset_down(self.scroll_offset, lines);
        if new != self.scroll_offset {
            self.scroll_offset = new;
            self.repaint_viewport();
            if self.scroll_offset == 0 {
                // Restore cursor cell — indicator lived there only in pixels.
                let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                self.draw_cursor(cx, cy, on);
            } else {
                self.draw_indicator();
            }
        }
    }

    /// Page one screen up.
    pub fn scroll_view_up_page(&mut self) {
        let step = self.page_step();
        self.scroll_view_up(step);
    }

    /// Page one screen down.
    pub fn scroll_view_down_page(&mut self) {
        let step = self.page_step();
        self.scroll_view_down(step);
    }

    /// Paint a small `[-offset/filled]` marker in the top row's right edge.
    /// Written only to the pixel buffer (not the grid), so a pin-to-bottom
    /// repaint from `cells` naturally erases it.
    fn draw_indicator(&mut self) {
        if self.scroll_offset == 0 || self.cols < 16 {
            return;
        }
        // Build the ASCII marker, e.g. "[-12/200]".
        let mut buf = [0u8; 24];
        let mut w = 0;
        let write_byte = |buf: &mut [u8; 24], w: &mut usize, b: u8| {
            if *w < buf.len() {
                buf[*w] = b;
                *w += 1;
            }
        };
        let write_num = |buf: &mut [u8; 24], w: &mut usize, mut n: usize| {
            if n == 0 {
                write_byte(buf, w, b'0');
                return;
            }
            let mut digits = [0u8; 6];
            let mut d = 0;
            while n > 0 && d < digits.len() {
                digits[d] = b'0' + (n % 10) as u8;
                n /= 10;
                d += 1;
            }
            while d > 0 {
                d -= 1;
                write_byte(buf, w, digits[d]);
            }
        };
        write_byte(&mut buf, &mut w, b'[');
        write_byte(&mut buf, &mut w, b'-');
        write_num(&mut buf, &mut w, self.scroll_offset);
        write_byte(&mut buf, &mut w, b'/');
        write_num(&mut buf, &mut w, self.scroll_filled);
        write_byte(&mut buf, &mut w, b']');
        let len = w;
        if len >= self.cols {
            return;
        }
        let start_col = self.cols - len;
        for (i, b) in buf.iter().enumerate().take(len) {
            let cell = Cell {
                ch: *b as char,
                fg: ANSI_BRIGHT[3], // bright yellow — catches the eye
                bg: DEFAULT_BG,
            };
            self.render_cell_at(start_col + i, 0, cell);
        }
    }

    // ── cursor-aware movement ─────────────────────────────────────────────

    fn move_to_newline(&mut self) {
        self.pin_to_bottom();
        let (cx, cy) = (self.cx, self.cy);
        self.draw_cursor(cx, cy, false);
        self.cx = 0;
        self.cy += 1;
        if self.cy >= self.rows {
            self.scroll_up();
            self.cy = self.rows - 1;
        }
        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
        self.draw_cursor(cx, cy, on);
    }

    // ── character output ──────────────────────────────────────────────────

    fn put_char(&mut self, c: char) {
        // New output must snap the viewport back to live so the user sees
        // what just got written.
        self.pin_to_bottom();

        let fg = self.cur_fg();
        let bg = self.cur_bg();

        // Erase cursor before touching this cell.
        let (cx, cy) = (self.cx, self.cy);
        self.draw_cursor(cx, cy, false);

        // Write to grid and framebuffer.
        let cell = Cell { ch: c, fg, bg };
        self.cells[cy * self.cols + cx] = cell;
        self.render_cell_at(cx, cy, cell);

        // Advance, wrapping to the next line if necessary.
        self.cx += 1;
        if self.cx >= self.cols {
            self.cx = 0;
            self.cy += 1;
            if self.cy >= self.rows {
                self.scroll_up();
                self.cy = self.rows - 1;
            }
        }

        // Draw cursor at new position.
        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
        self.draw_cursor(cx, cy, on);
    }

    // ── SGR (Select Graphic Rendition) ────────────────────────────────────

    fn apply_sgr(&mut self) {
        // An empty parameter list (`\x1b[m`) is treated as a single 0.
        let n = if self.nparams == 0 { 1 } else { self.nparams };
        for i in 0..n {
            match self.params[i] {
                0 => {
                    self.fg_base = None;
                    self.bg_base = None;
                    self.bold = false;
                }
                1 => {
                    self.bold = true;
                }
                22 => {
                    self.bold = false;
                }
                p @ 30..=37 => {
                    self.fg_base = Some((p - 30) as u8);
                }
                39 => {
                    self.fg_base = None;
                }
                p @ 40..=47 => {
                    self.bg_base = Some((p - 40) as u8);
                }
                49 => {
                    self.bg_base = None;
                }
                _ => {}
            }
        }
    }

    // ── public character writer ───────────────────────────────────────────

    pub fn write_char(&mut self, c: char) {
        match self.ansi {
            Ansi::Normal => match c {
                '\x1b' => {
                    self.ansi = Ansi::Esc;
                }
                '\n' => {
                    self.move_to_newline();
                }
                '\r' => {
                    self.pin_to_bottom();
                    let (cx, cy) = (self.cx, self.cy);
                    self.draw_cursor(cx, cy, false);
                    self.cx = 0;
                    let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                    self.draw_cursor(cx, cy, on);
                }
                '\t' => {
                    self.pin_to_bottom();
                    let next_tab = ((self.cx / 8) + 1) * 8;
                    let (cx, cy) = (self.cx, self.cy);
                    self.draw_cursor(cx, cy, false);
                    if next_tab >= self.cols {
                        self.move_to_newline();
                    } else {
                        self.cx = next_tab;
                        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                        self.draw_cursor(cx, cy, on);
                    }
                }
                c => {
                    self.put_char(c);
                }
            },

            Ansi::Esc => {
                if c == '[' {
                    self.ansi = Ansi::Csi;
                    self.params = [0; 8];
                    self.nparams = 0;
                    self.cur_param = 0;
                } else {
                    // Unrecognised escape — discard and resume normal parsing.
                    self.ansi = Ansi::Normal;
                }
            }

            Ansi::Csi => match c {
                '0'..='9' => {
                    self.cur_param = self
                        .cur_param
                        .saturating_mul(10)
                        .saturating_add(c as u32 - '0' as u32);
                }
                ';' => {
                    if self.nparams < self.params.len() {
                        self.params[self.nparams] = self.cur_param;
                        self.nparams += 1;
                    }
                    self.cur_param = 0;
                }
                'm' => {
                    // Commit the last (or only) parameter.
                    if self.nparams < self.params.len() {
                        self.params[self.nparams] = self.cur_param;
                        self.nparams += 1;
                    }
                    self.apply_sgr();
                    self.ansi = Ansi::Normal;
                }
                _ => {
                    // Unrecognised final byte — discard the sequence.
                    self.ansi = Ansi::Normal;
                }
            },
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

// ─── global state ──────────────────────────────────────────────────────────

pub static CONSOLE: Mutex<Option<Console>> = Mutex::new(None);

/// Install `console` as the active console and clear the screen.
/// Must be called after `mem::init()`.
pub fn init(console: Console) {
    let mut guard = CONSOLE.lock();
    *guard = Some(console);
    if let Some(c) = guard.as_mut() {
        c.clear();
    }
}

/// Toggle the cursor blink state.  Called by the cursor-blink kernel task.
pub fn toggle_cursor() {
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.toggle_cursor();
    }
}

/// Scroll the viewport one page up toward older output. No-op when the
/// scrollback ring is empty. Call from the input layer when the user
/// presses Shift+PgUp.
pub fn scroll_view_up_page() {
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.scroll_view_up_page();
    }
}

/// Scroll the viewport one page down toward live output. Reaching 0
/// erases the scroll indicator. Call from the input layer when the user
/// presses Shift+PgDn.
pub fn scroll_view_down_page() {
    if let Some(c) = CONSOLE.lock().as_mut() {
        c.scroll_view_down_page();
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
