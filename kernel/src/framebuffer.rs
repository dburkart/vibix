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
//! DEC private and extended VT100 sequences handled:
//! - `ESC 7` / `ESC 8` (DECSC / DECRC): save / restore cursor + SGR state.
//! - `ESC D` (Index, IND): move cursor down one row, scrolling the active
//!   region if at the bottom margin.
//! - `ESC M` (Reverse Index, RI): move cursor up one row, scrolling the
//!   active region down if at the top margin.
//! - `ESC E` (Next Line, NEL): CR + LF, region-aware.
//! - `ESC c` (RIS, full reset): clear screen, reset SGR, reset scroll
//!   region to full screen, restore default state.
//! - `CSI Pt;Pb r` (DECSTBM): set scroll-region top/bottom margins (clamped
//!   to screen rows) and home the cursor to (1,1). An empty parameter list
//!   resets the region to the full screen.
//! - `CSI ? Pm h` / `CSI ? Pm l` (DECSET / DECRST): set / reset DEC private
//!   modes. Known modes `?1` (cursor-keys app), `?7` (auto-wrap), `?12`
//!   (cursor blink), `?25` (cursor visible) are accepted as no-ops so real
//!   terminal applications (vim, less, htop) do not see sequences rejected.
//!   `?1049` (alt-screen with cursor save) and `?1047` (alt-screen, clear
//!   on exit) swap to a secondary cell grid and back; `?47` (legacy
//!   alt-screen) is treated as `?1047`; `?1048` is cursor save/restore
//!   only. Unrecognized modes are silently ignored.
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

// ─── unicode glyph fallback ────────────────────────────────────────────────

/// Final fallback used when neither the requested code point nor U+FFFD is
/// covered by any linked font8x8 table. A 2×2 dotted check pattern is
/// distinct enough from any letterform that the user can tell rendering
/// failed without it dominating the screen.
const REPLACEMENT_GLYPH: [u8; 8] = [0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA];

/// Resolve `c` to an 8×8 glyph by trying every linked font8x8 table in turn,
/// then U+FFFD, then [`REPLACEMENT_GLYPH`]. Tables are searched in roughly
/// "most likely" order so the common ASCII path resolves on the first
/// lookup.
fn lookup_glyph(c: char) -> [u8; 8] {
    if let Some(g) = font8x8::BASIC_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::LATIN_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::BOX_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::BLOCK_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::GREEK_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::HIRAGANA_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::MISC_FONTS.get(c) {
        return g;
    }
    if let Some(g) = font8x8::SGA_FONTS.get(c) {
        return g;
    }
    if c != '\u{FFFD}' {
        if let Some(g) = font8x8::MISC_FONTS.get('\u{FFFD}') {
            return g;
        }
    }
    REPLACEMENT_GLYPH
}

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
    /// CSI with DEC private-mode introducer `?` already consumed; digits
    /// and `;` accumulate into `params` until a final `h` or `l` dispatches
    /// DECSET / DECRST.
    CsiPrivate,
}

/// Classification of a DEC private-mode code for DECSET (`h`) / DECRST (`l`).
///
/// Modes that vibix doesn't implement but wants to accept silently (so
/// applications that toggle them don't see sequences ping-ponging back as
/// literal text) return [`DecMode::NoOp`].  Unknown modes fall through to
/// [`DecMode::Unknown`] — the caller discards them.
#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
pub(crate) enum DecMode {
    /// Application cursor keys (mode 1). Accepted, not yet honored.
    CursorKeys,
    /// Auto-wrap at right margin (mode 7). Accepted; wrap is the only
    /// behavior vibix currently implements, so this is a no-op.
    AutoWrap,
    /// Cursor blinking (mode 12). The console already blinks; no-op.
    CursorBlink,
    /// Cursor visibility (mode 25). Accepted; gating the actual draw is a
    /// follow-up.
    CursorVisible,
    /// Alt-screen buffer + cursor save/restore (mode 1049, xterm).
    /// Switches to a secondary cell grid on `h`, restores the primary on
    /// `l`. Saves/restores the primary cursor + SGR around the swap.
    AltScreen1049,
    /// Legacy alt-screen (mode 47). xterm-compat: treated like `?1047` —
    /// swap buffers without cursor save/restore.
    AltScreen47,
    /// Alt-screen, clear on exit (mode 1047). Like `?1049` but does not
    /// touch the saved-cursor slot.
    AltScreen1047,
    /// Cursor save/restore (mode 1048). `h` saves cursor + SGR, `l`
    /// restores; no buffer swap.
    SaveCursor1048,
    /// Recognized as safe-to-ignore so apps don't break.
    NoOp,
    /// Not in the recognized set; caller discards silently.
    Unknown,
}

/// Look up a DEC private-mode numeric code.  Pure: no side effects, so it
/// is easy to unit-test without standing up a [`Console`] instance.
pub(crate) fn classify_dec_mode(code: u32) -> DecMode {
    match code {
        1 => DecMode::CursorKeys,
        7 => DecMode::AutoWrap,
        12 => DecMode::CursorBlink,
        25 => DecMode::CursorVisible,
        47 => DecMode::AltScreen47,
        1047 => DecMode::AltScreen1047,
        1048 => DecMode::SaveCursor1048,
        1049 => DecMode::AltScreen1049,
        // Commonly-seen modes whose absence is harmless: keypad
        // application mode (?66), bracketed-paste (?2004), mouse tracking
        // (?1000/?1002/?1003/?1006). Accept without logging — xterm apps
        // spray these during init.
        66 | 1000 | 1002 | 1003 | 1006 | 2004 => DecMode::NoOp,
        _ => DecMode::Unknown,
    }
}

// ─── DECSTBM scroll region ─────────────────────────────────────────────────

/// VT100 scroll region (DECSTBM). Stores 0-indexed inclusive row bounds.
///
/// The active region is `top..=bottom`. Index/Reverse-Index/CR-LF
/// scrolling is confined to that band; rows outside it are unaffected.
/// When the region spans the full screen (`top == 0 && bottom == rows-1`),
/// scroll-up evicts the top row into the scrollback ring; partial regions
/// do *not* push to scrollback because the evicted row isn't truly
/// off-screen.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(test, derive(Debug))]
pub(crate) struct ScrollRegion {
    pub top: usize,
    pub bottom: usize,
}

impl ScrollRegion {
    /// Region covering every row of an `rows`-tall screen.
    pub fn full(rows: usize) -> Self {
        Self {
            top: 0,
            bottom: rows.saturating_sub(1),
        }
    }

    /// True when this region equals `ScrollRegion::full(rows)`.
    pub fn is_full(&self, rows: usize) -> bool {
        self.top == 0 && self.bottom + 1 == rows
    }

    /// Clamp DECSTBM 1-indexed parameters `(pt, pb)` against an `rows`-tall
    /// screen, returning the resulting 0-indexed inclusive region. Per
    /// VT100, an empty / zero parameter list selects the full screen, and
    /// invalid combinations (where the requested top is not strictly
    /// above the requested bottom after clamping) are rejected — the
    /// caller should leave the existing region untouched in that case.
    ///
    /// Returns `None` if the request is invalid.
    pub fn from_decstbm(pt: u32, pb: u32, rows: usize) -> Option<Self> {
        if rows == 0 {
            return None;
        }
        // VT100: empty / zero pt or pb selects full screen for that edge.
        let top = if pt == 0 { 1 } else { pt } as usize;
        let bottom = if pb == 0 { rows } else { pb as usize };
        // Clamp to screen.
        let top = top.min(rows);
        let bottom = bottom.min(rows);
        // Per VT100, a valid region requires top < bottom (1-indexed).
        if top >= bottom {
            return None;
        }
        Some(Self {
            top: top - 1,
            bottom: bottom - 1,
        })
    }
}

/// Scroll the rows of `cells` (a `rows`-by-`cols` row-major grid) up by
/// one within `region`. Rows outside `[region.top, region.bottom]` are
/// untouched; the bottom row of the region is filled with `blank`.
///
/// This is the pure data-model side of `Console::scroll_up`; the pixel
/// blit lives in the impl. Factored out so it can be exercised under
/// host `cargo test` without standing up a framebuffer.
fn scroll_region_up(cells: &mut [Cell], cols: usize, region: ScrollRegion, blank: Cell) {
    if region.top >= region.bottom {
        return;
    }
    for r in region.top..region.bottom {
        let dst = r * cols;
        let src = (r + 1) * cols;
        for c in 0..cols {
            cells[dst + c] = cells[src + c];
        }
    }
    let last = region.bottom * cols;
    for c in 0..cols {
        cells[last + c] = blank;
    }
}

/// Scroll the rows of `cells` down by one within `region` (Reverse Index).
/// Rows outside the region are untouched; the top row of the region is
/// filled with `blank`.
fn scroll_region_down(cells: &mut [Cell], cols: usize, region: ScrollRegion, blank: Cell) {
    if region.top >= region.bottom {
        return;
    }
    let mut r = region.bottom;
    while r > region.top {
        let dst = r * cols;
        let src = (r - 1) * cols;
        for c in 0..cols {
            cells[dst + c] = cells[src + c];
        }
        r -= 1;
    }
    let top = region.top * cols;
    for c in 0..cols {
        cells[top + c] = blank;
    }
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

    // DECSC / DECRC saved state.  `saved_valid == false` means DECRC is a
    // no-op (xterm behavior for a never-saved slot).
    saved_cx: usize,
    saved_cy: usize,
    saved_fg: Option<u8>,
    saved_bg: Option<u8>,
    saved_bold: bool,
    saved_valid: bool,

    // DECSTBM scroll region. Initialized to full screen; reset to full
    // screen on RIS (ESC c). Index/Reverse-Index/scroll-on-newline all
    // confine their work to `[region.top, region.bottom]`.
    region: ScrollRegion,

    // Alt-screen buffer (CSI ?1049/?1047/?47). When `alt_active` is true,
    // `cells` holds the alt grid and `primary_cells` holds the saved
    // primary grid. On exit, the buffers are swapped back. Scrollback
    // (#45) only accumulates in primary mode — `scroll_up` consults
    // `alt_active` and skips the eviction-to-ring step while alt is
    // showing. The alt buffer is wiped to blanks on every `?1049h` /
    // `?1047h` entry, so its contents do not survive a round-trip.
    alt_active: bool,
    primary_cells: Vec<Cell>,
    // Saved primary cursor + SGR for `?1049h` (and `?1048h`). Separate
    // from the DECSC slot so apps that DECSC inside an alt screen
    // session don't disturb the primary's restoration.
    alt_saved_cx: usize,
    alt_saved_cy: usize,
    alt_saved_fg: Option<u8>,
    alt_saved_bg: Option<u8>,
    alt_saved_bold: bool,
    alt_saved_valid: bool,
    // Primary's DECSTBM region, parked on alt-screen entry so the alt
    // session starts with a fresh full-screen region but the primary
    // gets its old margins back on exit.
    primary_region: ScrollRegion,
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

        // Allocate the alt-screen shadow buffer up-front. Same dims as
        // primary; left as all-blanks until first `?1049h` / `?1047h`.
        // Pre-allocating means alt-screen entry can never OOM mid-swap.
        let mut primary_cells = Vec::with_capacity(rows * cols);
        primary_cells.resize(rows * cols, Cell::blank());

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
            saved_cx: 0,
            saved_cy: 0,
            saved_fg: None,
            saved_bg: None,
            saved_bold: false,
            saved_valid: false,
            region: ScrollRegion::full(rows),
            alt_active: false,
            primary_cells,
            alt_saved_cx: 0,
            alt_saved_cy: 0,
            alt_saved_fg: None,
            alt_saved_bg: None,
            alt_saved_bold: false,
            alt_saved_valid: false,
            primary_region: ScrollRegion::full(rows),
        }
    }

    /// Construct a `Console` backed by a caller-owned framebuffer slab,
    /// for host unit tests. The slab must outlive the returned console.
    /// Tests get real `write_char` / SGR / alt-screen behaviour without
    /// having to stand up Limine's framebuffer.
    ///
    /// `cols * GLYPH_W` must equal `width`, `rows * GLYPH_H` must equal
    /// `height`, and `slab.len()` must be `>= height * pitch`.
    #[cfg(test)]
    pub(crate) fn for_test(slab: &mut [u32], width: usize, height: usize, pitch: usize) -> Self {
        assert!(slab.len() >= height * pitch, "test slab too small");
        let cols = width / GLYPH_W;
        let rows = height / GLYPH_H;

        let mut cells = Vec::with_capacity(rows * cols);
        cells.resize(rows * cols, Cell::blank());
        let mut primary_cells = Vec::with_capacity(rows * cols);
        primary_cells.resize(rows * cols, Cell::blank());
        let mut scrollback = Vec::with_capacity(SCROLLBACK_ROWS * cols);
        scrollback.resize(SCROLLBACK_ROWS * cols, Cell::blank());

        Self {
            buffer: slab.as_mut_ptr(),
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
            saved_cx: 0,
            saved_cy: 0,
            saved_fg: None,
            saved_bg: None,
            saved_bold: false,
            saved_valid: false,
            region: ScrollRegion::full(rows),
            alt_active: false,
            primary_cells,
            alt_saved_cx: 0,
            alt_saved_cy: 0,
            alt_saved_fg: None,
            alt_saved_bg: None,
            alt_saved_bold: false,
            alt_saved_valid: false,
            primary_region: ScrollRegion::full(rows),
        }
    }

    /// Test accessor: snapshot of the active grid as a `Vec<(char, fg, bg)>`.
    #[cfg(test)]
    pub(crate) fn snapshot_cells(&self) -> Vec<(char, u32, u32)> {
        self.cells.iter().map(|c| (c.ch, c.fg, c.bg)).collect()
    }

    /// Test accessor: whether the alt screen is currently active.
    #[cfg(test)]
    pub(crate) fn is_alt_active(&self) -> bool {
        self.alt_active
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
        let glyph = lookup_glyph(cell.ch);
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

    /// Scroll the active region up by one row.
    ///
    /// When the region spans the whole screen:
    /// - The departing top row is pushed into the scrollback ring.
    /// - The pixel blit covers the full framebuffer with a memmove-style
    ///   `ptr::copy` (handles overlap).
    ///
    /// When the region is partial (DECSTBM has narrowed it):
    /// - Only rows in `[region.top, region.bottom]` move; rows outside
    ///   are untouched.
    /// - No scrollback push — the evicted top-of-region row isn't truly
    ///   leaving the screen, so preserving it in the back-scroll would
    ///   corrupt history with split-region snippets.
    /// - The pixel blit covers only the region.
    ///
    /// In both cases the vacated bottom-of-region pixel row is cleared
    /// to `DEFAULT_BG`.
    fn scroll_up(&mut self) {
        let cols = self.cols;
        let region = self.region;

        // Full-screen region: feed the evicted row into scrollback —
        // but only when the *primary* buffer is active. Alt-screen
        // applications (vim, less, htop) repaint their own UI; pushing
        // their per-frame scroll into the user's scrollback would
        // corrupt the history they expect to see again on `?1049l`.
        if region.is_full(self.rows) && !self.alt_active {
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
        }

        // Shift cell grid up within the region.
        scroll_region_up(&mut self.cells, cols, region, Cell::blank());

        // Pixel blit: rows [top+1..=bottom] → [top..=bottom-1].
        let row_pixels = self.pitch * GLYPH_H;
        let copy_rows = region.bottom - region.top;
        if copy_rows > 0 {
            let src = region.top + 1;
            let dst = region.top;
            unsafe {
                // ptr::copy is memmove-compatible and handles overlap.
                core::ptr::copy(
                    self.buffer.add(src * row_pixels),
                    self.buffer.add(dst * row_pixels),
                    row_pixels * copy_rows,
                );
            }
        }

        // Clear the bottom-of-region pixel row.
        let last_py = region.bottom * GLYPH_H;
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

    /// Scroll the active region down by one row (Reverse Index).
    /// Rows outside `[region.top, region.bottom]` are untouched. The
    /// top-of-region row is cleared. No scrollback interaction —
    /// reverse-index never evicts to history.
    fn scroll_down(&mut self) {
        let cols = self.cols;
        let region = self.region;

        // Shift cell grid down within the region.
        scroll_region_down(&mut self.cells, cols, region, Cell::blank());

        // Pixel blit: rows [top..=bottom-1] → [top+1..=bottom].
        let row_pixels = self.pitch * GLYPH_H;
        let copy_rows = region.bottom - region.top;
        if copy_rows > 0 {
            let src = region.top;
            let dst = region.top + 1;
            unsafe {
                core::ptr::copy(
                    self.buffer.add(src * row_pixels),
                    self.buffer.add(dst * row_pixels),
                    row_pixels * copy_rows,
                );
            }
        }

        // Clear the top-of-region pixel row.
        let top_py = region.top * GLYPH_H;
        for y in top_py..top_py + GLYPH_H {
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
            let ring_row = (self.scroll_head + self.scroll_filled - 1 - age) % SCROLLBACK_ROWS;
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
        self.line_feed_at_cursor();
        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
        self.draw_cursor(cx, cy, on);
    }

    /// Index (LF / ESC D) semantics: if the cursor is on the bottom
    /// margin of the active scroll region, scroll the region up by one;
    /// otherwise, advance the cursor down by one and clamp to the last
    /// physical row. Does not touch the cursor visual — caller handles
    /// erase/redraw around this.
    fn line_feed_at_cursor(&mut self) {
        if self.cy == self.region.bottom {
            self.scroll_up();
            // Cursor stays at region.bottom; no advance.
        } else if self.cy + 1 < self.rows {
            self.cy += 1;
        }
        // If cy is already at rows-1 and below the region, just clamp.
    }

    /// Reverse Index (ESC M) semantics: if the cursor is on the top
    /// margin of the active region, scroll the region down by one;
    /// otherwise, move the cursor up by one (clamped at row 0).
    fn reverse_index_at_cursor(&mut self) {
        if self.cy == self.region.top {
            self.scroll_down();
        } else if self.cy > 0 {
            self.cy -= 1;
        }
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
            self.line_feed_at_cursor();
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

    // ── DECSC / DECRC cursor + SGR save / restore ─────────────────────────

    fn save_cursor(&mut self) {
        self.saved_cx = self.cx;
        self.saved_cy = self.cy;
        self.saved_fg = self.fg_base;
        self.saved_bg = self.bg_base;
        self.saved_bold = self.bold;
        self.saved_valid = true;
    }

    fn restore_cursor(&mut self) {
        if !self.saved_valid {
            // Per xterm semantics, DECRC without a prior DECSC is a no-op.
            return;
        }
        // Mirror `toggle_cursor`: when the user is scrolled back, the live
        // cursor isn't on screen. Update the logical state but don't paint —
        // otherwise an `ESC 8` punches cursor glyphs into the scrolled-back
        // viewport and corrupts the scrollback read-out.
        let live = self.scroll_offset == 0;

        // Erase the cursor at its current position before moving.
        if live {
            let (cx, cy) = (self.cx, self.cy);
            self.draw_cursor(cx, cy, false);
        }

        self.cx = self.saved_cx.min(self.cols.saturating_sub(1));
        self.cy = self.saved_cy.min(self.rows.saturating_sub(1));
        self.fg_base = self.saved_fg;
        self.bg_base = self.saved_bg;
        self.bold = self.saved_bold;

        // Draw at the new position — only when live; otherwise the next
        // snap-to-bottom (e.g. on next write) repaints with correct state.
        if live {
            let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
            self.draw_cursor(cx, cy, on);
        }
    }

    // ── DEC private mode (DECSET / DECRST) ────────────────────────────────

    fn apply_dec_private(&mut self, set: bool) {
        // Empty param list (`\x1b[?h`) is treated as no mode — do nothing.
        let n = self.nparams;
        for i in 0..n {
            match classify_dec_mode(self.params[i]) {
                DecMode::AltScreen1049 => {
                    if set {
                        self.save_primary_cursor();
                        self.enter_alt_screen();
                    } else {
                        self.exit_alt_screen();
                        self.restore_primary_cursor();
                    }
                }
                DecMode::AltScreen1047 | DecMode::AltScreen47 => {
                    // Pure buffer swap; no cursor save/restore.
                    if set {
                        self.enter_alt_screen();
                    } else {
                        self.exit_alt_screen();
                    }
                }
                DecMode::SaveCursor1048 => {
                    if set {
                        self.save_primary_cursor();
                    } else {
                        self.restore_primary_cursor();
                    }
                }
                // Other recognized modes: still no-ops at this layer.
                DecMode::CursorKeys
                | DecMode::AutoWrap
                | DecMode::CursorBlink
                | DecMode::CursorVisible
                | DecMode::NoOp
                | DecMode::Unknown => {}
            }
        }
    }

    // ── alt-screen buffer (CSI ?1049 / ?1047 / ?47) ───────────────────────

    /// Save the primary cursor + SGR into the alt-screen save slot.
    /// Used by `?1049h` (and `?1048h` directly). Separate from DECSC's
    /// `saved_*` fields so apps that DECSC inside an alt session don't
    /// disturb the primary's restoration.
    fn save_primary_cursor(&mut self) {
        self.alt_saved_cx = self.cx;
        self.alt_saved_cy = self.cy;
        self.alt_saved_fg = self.fg_base;
        self.alt_saved_bg = self.bg_base;
        self.alt_saved_bold = self.bold;
        self.alt_saved_valid = true;
    }

    /// Restore the primary cursor + SGR from the alt-screen save slot.
    /// No-op if no prior save (xterm-compat).
    fn restore_primary_cursor(&mut self) {
        if !self.alt_saved_valid {
            return;
        }
        self.cx = self.alt_saved_cx.min(self.cols.saturating_sub(1));
        self.cy = self.alt_saved_cy.min(self.rows.saturating_sub(1));
        self.fg_base = self.alt_saved_fg;
        self.bg_base = self.alt_saved_bg;
        self.bold = self.alt_saved_bold;
        // The saved slot stays valid — xterm allows ?1049l/h to round-trip
        // multiple times without forcing a fresh save.
    }

    /// Switch the active grid to the alt buffer, clearing it. The
    /// primary grid is parked in `primary_cells` until `exit_alt_screen`
    /// swaps it back.  Cursor stays in place per xterm — apps repaint
    /// before the user notices.  Idempotent: re-entering while already
    /// in alt mode just blanks the alt buffer (matches xterm's
    /// "?1047h while in alt" — clears the alt screen).
    fn enter_alt_screen(&mut self) {
        if !self.alt_active {
            // First entry: park the primary grid + region, swap in a
            // blank alt with a full-screen region.
            core::mem::swap(&mut self.cells, &mut self.primary_cells);
            self.primary_region = self.region;
            self.alt_active = true;
        }
        // Wipe the (now-active) alt buffer.
        for cell in self.cells.iter_mut() {
            *cell = Cell::blank();
        }
        // TUI apps assume they own the full screen.
        self.region = ScrollRegion::full(self.rows);
        self.repaint_viewport();
    }

    /// Switch the active grid back to the primary buffer, discarding
    /// alt contents. Per xterm, alt-screen contents do not survive
    /// `?1049l` — they are wiped on the next entry. We blank
    /// `primary_cells` (now holding alt) before swapping, so the next
    /// `enter_alt_screen` starts from a known-blank state without
    /// having to allocate. Idempotent: a stray `?1049l` while already
    /// on the primary is a no-op.
    fn exit_alt_screen(&mut self) {
        if !self.alt_active {
            return;
        }
        // Wipe the alt grid so a future entry doesn't see stale state,
        // then swap back to primary.
        for cell in self.cells.iter_mut() {
            *cell = Cell::blank();
        }
        core::mem::swap(&mut self.cells, &mut self.primary_cells);
        self.alt_active = false;
        // Restore the primary's DECSTBM region.
        self.region = self.primary_region;
        self.repaint_viewport();
    }

    // ── DECSTBM (CSI Pt;Pb r) ─────────────────────────────────────────────

    /// Apply a parsed `CSI Pt;Pb r` (DECSTBM).
    ///
    /// - With no parameters (or both 0), resets the region to the full
    ///   screen.
    /// - Otherwise sets the region to `[pt..=pb]` (1-indexed, clamped to
    ///   screen rows). Invalid params (top >= bottom after clamp) leave
    ///   the existing region untouched.
    /// - In all valid cases, homes the cursor to the top-left (1,1) per
    ///   the VT100 spec.
    fn apply_decstbm(&mut self) {
        let (pt, pb) = match self.nparams {
            0 => (0, 0),
            1 => (self.params[0], 0),
            _ => (self.params[0], self.params[1]),
        };
        // `from_decstbm` interprets a 0 in either slot as "the default
        // edge" (top→1, bottom→rows). When *both* slots are 0 — bare
        // `CSI r` or `CSI ;r` — that resolves to the full screen anyway,
        // so we don't special-case it.
        if let Some(region) = ScrollRegion::from_decstbm(pt, pb, self.rows) {
            self.region = region;
        } else {
            // Invalid request — drop without homing the cursor or
            // touching state, matching xterm behavior.
            return;
        }

        // Home cursor to (1,1).
        self.pin_to_bottom();
        let (cx, cy) = (self.cx, self.cy);
        self.draw_cursor(cx, cy, false);
        self.cx = 0;
        self.cy = 0;
        let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
        self.draw_cursor(cx, cy, on);
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

            Ansi::Esc => match c {
                '[' => {
                    self.ansi = Ansi::Csi;
                    self.params = [0; 8];
                    self.nparams = 0;
                    self.cur_param = 0;
                }
                '7' => {
                    // DECSC — save cursor position and SGR state.
                    self.save_cursor();
                    self.ansi = Ansi::Normal;
                }
                '8' => {
                    // DECRC — restore.
                    self.restore_cursor();
                    self.ansi = Ansi::Normal;
                }
                'D' => {
                    // IND (Index): line-feed-style downward scroll
                    // honoring the active region.
                    self.pin_to_bottom();
                    let (cx, cy) = (self.cx, self.cy);
                    self.draw_cursor(cx, cy, false);
                    self.line_feed_at_cursor();
                    let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                    self.draw_cursor(cx, cy, on);
                    self.ansi = Ansi::Normal;
                }
                'M' => {
                    // RI (Reverse Index): upward scroll honoring the region.
                    self.pin_to_bottom();
                    let (cx, cy) = (self.cx, self.cy);
                    self.draw_cursor(cx, cy, false);
                    self.reverse_index_at_cursor();
                    let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                    self.draw_cursor(cx, cy, on);
                    self.ansi = Ansi::Normal;
                }
                'E' => {
                    // NEL (Next Line): equivalent to CR + LF.
                    self.pin_to_bottom();
                    let (cx, cy) = (self.cx, self.cy);
                    self.draw_cursor(cx, cy, false);
                    self.cx = 0;
                    self.line_feed_at_cursor();
                    let (cx, cy, on) = (self.cx, self.cy, self.cursor_on);
                    self.draw_cursor(cx, cy, on);
                    self.ansi = Ansi::Normal;
                }
                'c' => {
                    // RIS (Reset to Initial State): reset SGR, drop saved
                    // cursor, reset DECSTBM region, then clear the screen.
                    // `clear()` homes the cursor to (0,0).
                    self.fg_base = None;
                    self.bg_base = None;
                    self.bold = false;
                    self.saved_valid = false;
                    self.region = ScrollRegion::full(self.rows);
                    self.clear();
                    self.ansi = Ansi::Normal;
                }
                _ => {
                    // Unrecognised escape — discard and resume normal parsing.
                    self.ansi = Ansi::Normal;
                }
            },

            Ansi::Csi => match c {
                '?' => {
                    // DEC private-mode introducer must appear before any
                    // digits; already-accumulated params (none at this
                    // point for a well-formed sequence) are cleared.
                    self.params = [0; 8];
                    self.nparams = 0;
                    self.cur_param = 0;
                    self.ansi = Ansi::CsiPrivate;
                }
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
                'r' => {
                    // DECSTBM — set scroll region. Commit the in-flight
                    // parameter (mirrors `m` and the DEC-private branch).
                    // `apply_decstbm` treats `(0, 0)` as "reset to full
                    // screen", so a bare `CSI r` lands there cleanly.
                    if self.nparams < self.params.len() {
                        self.params[self.nparams] = self.cur_param;
                        self.nparams += 1;
                    }
                    self.apply_decstbm();
                    self.ansi = Ansi::Normal;
                }
                _ => {
                    // Unrecognised final byte — discard the sequence.
                    self.ansi = Ansi::Normal;
                }
            },

            Ansi::CsiPrivate => match c {
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
                'h' | 'l' => {
                    if self.nparams < self.params.len() {
                        self.params[self.nparams] = self.cur_param;
                        self.nparams += 1;
                    }
                    self.apply_dec_private(c == 'h');
                    self.ansi = Ansi::Normal;
                }
                _ => {
                    // Unknown final byte for a private sequence; drop.
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

#[cfg(test)]
mod tests {
    use super::{
        classify_dec_mode, scroll_region_down, scroll_region_up, Cell, Console, DecMode,
        ScrollRegion, GLYPH_H, GLYPH_W,
    };

    #[test]
    fn named_modes_classify() {
        assert_eq!(classify_dec_mode(1), DecMode::CursorKeys);
        assert_eq!(classify_dec_mode(7), DecMode::AutoWrap);
        assert_eq!(classify_dec_mode(12), DecMode::CursorBlink);
        assert_eq!(classify_dec_mode(25), DecMode::CursorVisible);
        assert_eq!(classify_dec_mode(47), DecMode::AltScreen47);
        assert_eq!(classify_dec_mode(1047), DecMode::AltScreen1047);
        assert_eq!(classify_dec_mode(1048), DecMode::SaveCursor1048);
        assert_eq!(classify_dec_mode(1049), DecMode::AltScreen1049);
    }

    #[test]
    fn common_ignored_modes_are_noop() {
        for code in [66u32, 1000, 1002, 1003, 1006, 2004] {
            assert_eq!(
                classify_dec_mode(code),
                DecMode::NoOp,
                "mode {code} should be NoOp",
            );
        }
    }

    #[test]
    fn unrecognized_modes_are_unknown() {
        assert_eq!(classify_dec_mode(0), DecMode::Unknown);
        assert_eq!(classify_dec_mode(999), DecMode::Unknown);
        assert_eq!(classify_dec_mode(u32::MAX), DecMode::Unknown);
    }

    // ── DECSTBM scroll region ─────────────────────────────────────────────

    #[test]
    fn scroll_region_full_covers_whole_screen() {
        let r = ScrollRegion::full(24);
        assert_eq!(r.top, 0);
        assert_eq!(r.bottom, 23);
        assert!(r.is_full(24));
    }

    #[test]
    fn from_decstbm_basic() {
        // CSI 3;6 r on a 24-row screen → 0-indexed [2, 5].
        let r = ScrollRegion::from_decstbm(3, 6, 24).unwrap();
        assert_eq!(r, ScrollRegion { top: 2, bottom: 5 });
    }

    #[test]
    fn from_decstbm_clamps_to_screen() {
        // CSI 3;999 r on a 24-row screen → bottom clamped to 24 (1-idx),
        // i.e. 23 (0-idx).
        let r = ScrollRegion::from_decstbm(3, 999, 24).unwrap();
        assert_eq!(r, ScrollRegion { top: 2, bottom: 23 });
    }

    #[test]
    fn from_decstbm_zero_means_default_edge() {
        // CSI ;6 r → top defaults to 1, bottom = 6 → [0, 5].
        let r = ScrollRegion::from_decstbm(0, 6, 24).unwrap();
        assert_eq!(r, ScrollRegion { top: 0, bottom: 5 });
        // CSI 3; r → top = 3, bottom defaults to rows → [2, 23].
        let r = ScrollRegion::from_decstbm(3, 0, 24).unwrap();
        assert_eq!(r, ScrollRegion { top: 2, bottom: 23 });
        // Both zero → full screen.
        let r = ScrollRegion::from_decstbm(0, 0, 24).unwrap();
        assert!(r.is_full(24));
    }

    #[test]
    fn from_decstbm_rejects_inverted_or_degenerate() {
        // top >= bottom is invalid per VT100.
        assert!(ScrollRegion::from_decstbm(5, 5, 24).is_none());
        assert!(ScrollRegion::from_decstbm(10, 3, 24).is_none());
        // Zero rows: nothing to do.
        assert!(ScrollRegion::from_decstbm(0, 0, 0).is_none());
    }

    /// Build a `rows × cols` grid where each cell's `ch` is its row index
    /// as a digit ('0'..'9'). Lets us read the post-scroll grid back as a
    /// per-row identity check.
    fn marked_grid(rows: usize, cols: usize) -> Vec<Cell> {
        let mut g = Vec::with_capacity(rows * cols);
        for r in 0..rows {
            let ch = char::from_u32('0' as u32 + r as u32).unwrap_or('?');
            for _ in 0..cols {
                g.push(Cell { ch, fg: 0, bg: 0 });
            }
        }
        g
    }

    fn row_chars(grid: &[Cell], cols: usize, row: usize) -> Vec<char> {
        (0..cols).map(|c| grid[row * cols + c].ch).collect()
    }

    #[test]
    fn scroll_region_up_only_touches_region() {
        let cols = 4;
        let rows = 8;
        let mut grid = marked_grid(rows, cols);
        let region = ScrollRegion { top: 2, bottom: 5 };
        scroll_region_up(&mut grid, cols, region, Cell::blank());
        // Rows outside region untouched.
        assert_eq!(row_chars(&grid, cols, 0), vec!['0'; cols]);
        assert_eq!(row_chars(&grid, cols, 1), vec!['1'; cols]);
        assert_eq!(row_chars(&grid, cols, 6), vec!['6'; cols]);
        assert_eq!(row_chars(&grid, cols, 7), vec!['7'; cols]);
        // Inside region: rows shifted up by one, bottom blanked.
        assert_eq!(row_chars(&grid, cols, 2), vec!['3'; cols]);
        assert_eq!(row_chars(&grid, cols, 3), vec!['4'; cols]);
        assert_eq!(row_chars(&grid, cols, 4), vec!['5'; cols]);
        assert_eq!(row_chars(&grid, cols, 5), vec![' '; cols]);
    }

    #[test]
    fn scroll_region_down_only_touches_region() {
        let cols = 4;
        let rows = 8;
        let mut grid = marked_grid(rows, cols);
        let region = ScrollRegion { top: 2, bottom: 5 };
        scroll_region_down(&mut grid, cols, region, Cell::blank());
        // Rows outside region untouched.
        assert_eq!(row_chars(&grid, cols, 0), vec!['0'; cols]);
        assert_eq!(row_chars(&grid, cols, 1), vec!['1'; cols]);
        assert_eq!(row_chars(&grid, cols, 6), vec!['6'; cols]);
        assert_eq!(row_chars(&grid, cols, 7), vec!['7'; cols]);
        // Inside region: rows shifted down by one, top blanked.
        assert_eq!(row_chars(&grid, cols, 2), vec![' '; cols]);
        assert_eq!(row_chars(&grid, cols, 3), vec!['2'; cols]);
        assert_eq!(row_chars(&grid, cols, 4), vec!['3'; cols]);
        assert_eq!(row_chars(&grid, cols, 5), vec!['4'; cols]);
    }

    #[test]
    fn region_3_through_6_survives_ten_newlines() {
        // The required regression test from #457: with region [3..6]
        // (1-indexed inclusive) and 10 newlines emitted at the bottom of
        // the region, rows 1-2 and 7+ must remain untouched.
        let cols = 4;
        let rows = 10;
        let mut grid = marked_grid(rows, cols);
        // 1-indexed [3..6] → 0-indexed [2, 5].
        let region = ScrollRegion::from_decstbm(3, 6, rows).unwrap();
        for _ in 0..10 {
            scroll_region_up(&mut grid, cols, region, Cell::blank());
        }
        // Rows 1-2 (1-indexed) i.e. 0-1 (0-indexed) are above the region.
        assert_eq!(row_chars(&grid, cols, 0), vec!['0'; cols]);
        assert_eq!(row_chars(&grid, cols, 1), vec!['1'; cols]);
        // Rows 7+ (1-indexed) i.e. 6+ (0-indexed) are below.
        for r in 6..rows {
            let ch = char::from_u32('0' as u32 + r as u32).unwrap();
            assert_eq!(row_chars(&grid, cols, r), vec![ch; cols]);
        }
        // Region itself should be entirely blank — 10 scrolls evicted
        // every original character in [2, 5].
        for r in 2..=5 {
            assert_eq!(row_chars(&grid, cols, r), vec![' '; cols]);
        }
    }

    // ── alt-screen buffer (CSI ?1049 / ?1047 / ?47) ───────────────────────

    /// Build a small headless console for write_char-driven tests.
    /// 80×25 chars at 8×8 glyphs → 640×200 pixels, pitch == width.
    fn make_test_console() -> (Console, Vec<u32>) {
        let cols = 80;
        let rows = 25;
        let width = cols * GLYPH_W;
        let height = rows * GLYPH_H;
        let pitch = width;
        let mut slab: Vec<u32> = vec![0; height * pitch];
        // SAFETY: slab outlives the console for the test's scope; we
        // return both so the borrow checker enforces that lifetime.
        let console = Console::for_test(&mut slab, width, height, pitch);
        (console, slab)
    }

    fn write_str(c: &mut Console, s: &str) {
        for ch in s.chars() {
            c.write_char(ch);
        }
    }

    #[test]
    fn alt_screen_starts_inactive() {
        let (c, _slab) = make_test_console();
        assert!(!c.is_alt_active());
    }

    #[test]
    fn csi_1049h_then_l_restores_primary_byte_for_byte() {
        // Required regression test from #458: switch to alt, write
        // content there, switch back, primary buffer must equal its
        // pre-switch state byte-for-byte.
        let (mut c, _slab) = make_test_console();

        write_str(&mut c, "primary content here\nsecond line\n");
        let pre_switch = c.snapshot_cells();
        let pre_cx = c.cx;
        let pre_cy = c.cy;

        // CSI ?1049h — enter alt screen.
        write_str(&mut c, "\x1b[?1049h");
        assert!(c.is_alt_active());

        // Alt screen should be blank.
        for cell in c.snapshot_cells() {
            assert_eq!(cell.0, ' ', "alt screen must start blank");
        }

        // Write a bunch on the alt screen.
        write_str(&mut c, "ALT SCREEN GARBAGE\nlots of stuff\n");

        // CSI ?1049l — exit.
        write_str(&mut c, "\x1b[?1049l");
        assert!(!c.is_alt_active());

        let post_switch = c.snapshot_cells();
        assert_eq!(
            pre_switch, post_switch,
            "primary buffer must be byte-identical after alt-screen round trip",
        );
        assert_eq!(c.cx, pre_cx, "cursor x must be restored");
        assert_eq!(c.cy, pre_cy, "cursor y must be restored");
    }

    #[test]
    fn csi_1049_cycle_does_not_grow_scrollback() {
        // Scrollback (#45) must not accumulate alt-screen frames. Run a
        // full enter/scroll/exit cycle and verify scroll_filled is
        // unchanged.
        let (mut c, _slab) = make_test_console();
        // Force some scrollback first so we have a non-trivial baseline.
        for _ in 0..3 {
            for _ in 0..c.rows {
                c.write_char('x');
                c.write_char('\n');
            }
        }
        let before = c.scroll_filled;
        assert!(before > 0, "primary scrollback should accumulate");

        write_str(&mut c, "\x1b[?1049h");
        // Force many scrolls inside alt mode.
        for _ in 0..5 {
            for _ in 0..c.rows {
                c.write_char('a');
                c.write_char('\n');
            }
        }
        write_str(&mut c, "\x1b[?1049l");

        assert_eq!(
            c.scroll_filled, before,
            "alt-screen scrolls must not feed scrollback",
        );
    }

    #[test]
    fn csi_1047_swaps_buffers_without_cursor_save() {
        let (mut c, _slab) = make_test_console();
        write_str(&mut c, "primary text");
        let pre = c.snapshot_cells();

        write_str(&mut c, "\x1b[?1047h");
        assert!(c.is_alt_active());
        write_str(&mut c, "alt text");

        write_str(&mut c, "\x1b[?1047l");
        assert!(!c.is_alt_active());
        assert_eq!(c.snapshot_cells(), pre, "primary grid must round-trip");
    }

    #[test]
    fn csi_47_treated_as_legacy_alt_screen() {
        let (mut c, _slab) = make_test_console();
        write_str(&mut c, "before");
        let pre = c.snapshot_cells();

        write_str(&mut c, "\x1b[?47h");
        assert!(c.is_alt_active());
        write_str(&mut c, "alt");

        write_str(&mut c, "\x1b[?47l");
        assert!(!c.is_alt_active());
        assert_eq!(c.snapshot_cells(), pre);
    }

    #[test]
    fn csi_1048_saves_and_restores_cursor_only() {
        let (mut c, _slab) = make_test_console();
        write_str(&mut c, "abcdef");
        let saved_cx = c.cx;
        let saved_cy = c.cy;

        write_str(&mut c, "\x1b[?1048h"); // save
        write_str(&mut c, "more text after save");
        assert_ne!(c.cx, saved_cx, "cursor moved after writing more text");

        // ?1048l does NOT swap buffers — only restores cursor.
        write_str(&mut c, "\x1b[?1048l");
        assert!(!c.is_alt_active(), "?1048 must not toggle alt buffer");
        assert_eq!(c.cx, saved_cx);
        assert_eq!(c.cy, saved_cy);
    }

    #[test]
    fn alt_screen_dec_region_does_not_leak_to_primary() {
        // If app sets a DECSTBM region inside alt mode, primary's
        // region must be intact on exit.
        let (mut c, _slab) = make_test_console();
        write_str(&mut c, "\x1b[5;10r"); // set primary region rows 5..=10
        let primary_region = c.region;
        assert_eq!(primary_region.top, 4);
        assert_eq!(primary_region.bottom, 9);

        write_str(&mut c, "\x1b[?1049h");
        // In alt mode, the region must be full screen.
        assert!(c.region.is_full(c.rows));
        write_str(&mut c, "\x1b[2;3r"); // set tiny alt region
        write_str(&mut c, "\x1b[?1049l");

        assert_eq!(c.region, primary_region, "primary region must be restored");
    }

    #[test]
    fn stray_csi_1049l_on_primary_is_noop() {
        let (mut c, _slab) = make_test_console();
        write_str(&mut c, "primary");
        let pre = c.snapshot_cells();
        // Already on primary — `?1049l` should be harmless.
        write_str(&mut c, "\x1b[?1049l");
        assert!(!c.is_alt_active());
        assert_eq!(c.snapshot_cells(), pre);
    }

    #[test]
    fn scroll_region_is_noop_when_top_equals_bottom() {
        // Defensive: a degenerate region must not panic or write OOB.
        let cols = 4;
        let rows = 4;
        let mut grid = marked_grid(rows, cols);
        let region = ScrollRegion { top: 1, bottom: 1 };
        scroll_region_up(&mut grid, cols, region, Cell::blank());
        scroll_region_down(&mut grid, cols, region, Cell::blank());
        // Grid should be unchanged.
        for r in 0..rows {
            let ch = char::from_u32('0' as u32 + r as u32).unwrap();
            assert_eq!(row_chars(&grid, cols, r), vec![ch; cols]);
        }
    }
}
