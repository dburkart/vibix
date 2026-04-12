# Serial Subsystem

**Source:** `kernel/src/serial.rs`

## Overview

The serial subsystem drives the COM1 16550 UART (I/O port `0x3F8`). It is the
primary log sink and is the first subsystem initialized in `_start`. All
`serial_print!` / `serial_println!` macro output arrives here.

## Design

A single global `Mutex<SerialPort>` wraps the `uart_16550` crate's driver. The
mutex ensures mutual exclusion between concurrent users (main thread and ISRs),
though in practice all ISRs in vibix halt on fault so a deadlock from within an
ISR is not a current concern.

The output path is intentionally simple — `_print` just calls
`SerialPort::write_fmt`. There is no buffering, no formatting layer, and no
log-level filtering at this layer. For structured, leveled logging see the
[klog subsystem](diagnostics.md).

## API

### `serial::init()`

Programs the 16550 UART (baud rate, FIFO, interrupts disabled on the UART
side). Must be the first call in `_start` so that early panics and assertions
are visible.

### Macros

```rust
serial_print!("hello");
serial_println!("value = {}", x);
```

These are thin wrappers around `serial::_print`. They work identically to
`print!` / `println!` from the standard library.

## Implementation Notes

- The UART is initialized at the standard 115200 baud (set by `uart_16550`).
- The lock is a spin mutex — writes busy-wait if the port is temporarily held.
- Output is not buffered; each macro call flushes immediately to the UART FIFO.
- `serial_println!()` with no arguments emits a bare newline.
