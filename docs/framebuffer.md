# Framebuffer Subsystem

**Source:** `kernel/src/framebuffer.rs`

## Overview

The framebuffer subsystem provides a minimal text console rendered directly into
the linear framebuffer that Limine sets up. It uses 8×8 bitmap glyphs from the
`font8x8` crate and draws characters in a fixed light-gray-on-black color
scheme.

## Design

### `Console`

The `Console` struct holds a raw `*mut u32` pointer to the framebuffer, the
display dimensions (width, height in pixels; pitch in `u32`s per row), the
computed grid size (cols, rows), and the current cursor position (cx, cy).

Rendering is pixel-perfect: each glyph is an 8×8 bit matrix from
`font8x8::BASIC_FONTS`. A set bit is drawn in foreground color (`0x00E0_E0E0`,
near-white), a clear bit in background (`0x0000_0000`, black).

### Scrolling

The console does not implement true scrolling. When the cursor reaches the last
row, the entire screen is cleared and writing wraps back to row 0. This is
intentional for a hobby kernel where simplicity beats polish.

### Concurrency

`Console` holds a raw pointer. A `Mutex<Option<Console>>` (`CONSOLE`) provides
mutual exclusion. The `unsafe impl Send for Console` assertion is sound because
the framebuffer pointer is stable for the lifetime of the kernel and all
concurrent writes go through the mutex.

## Initialization

```rust
// In main.rs, after obtaining the Limine framebuffer response:
let console = unsafe { Console::new(fb.addr(), fb.width(), fb.height(), fb.pitch()) };
framebuffer::init(console);
```

`init` places the console into `CONSOLE` and clears the screen. If no
framebuffer is available the global stays `None` and all `print!` calls silently
no-op.

## API

### Macros

```rust
print!("hello");
println!("value = {}", x);
```

These mirror the standard library macros but route through the framebuffer
console. They are the primary display output path; `serial_println!` is the
debug path.

### `_print(args: fmt::Arguments)`

Internal; called by the macros. Acquires `CONSOLE`, short-circuits if `None`.

## PAT / Write-Combining

The framebuffer physical pages are mapped Write-Combining via the PAT subsystem
(see [memory.md](memory.md)) during the kernel PML4 build. This reduces the
penalty of word-at-a-time pixel writes by coalescing them in the CPU write
buffers before flushing to the display adapter.
