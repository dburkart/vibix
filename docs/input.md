# Input Subsystem

**Source:** `kernel/src/input.rs`

## Overview

The input subsystem provides a PS/2 keyboard driver built on a generic
interrupt-safe ring buffer. Scancodes are pushed by the keyboard ISR and
decoded on the consumer side using the `pc-keyboard` crate's state machine.

## Design

### `RingBuffer<T, N>`

A fixed-capacity, single-reader / single-writer ring buffer implemented with a
`[MaybeUninit<T>; N]` array. Operations:

| Method | Description |
|---|---|
| `push(v) -> bool` | Appends `v`; returns `false` (dropping `v`) if full |
| `pop() -> Option<T>` | Removes and returns the oldest element |
| `is_empty() -> bool` | — |
| `len() -> usize` | Current occupancy |

`RingBuffer` is generic over `T: Copy` and const `N`, and has no kernel-only
dependencies, making it host-unit-testable.

### Scancode Ring (`SCANCODES`)

A `Mutex<RingBuffer<u8, 128>>` holds raw PS/2 scancodes. Capacity 128 is
ample for normal typing; firmware key-repeat bursts stay well below that
between consumer polls. If the ring is full when the ISR tries to push, the
scancode is dropped and `OVERFLOWS` is incremented.

### Keyboard Decoder (`KEYBOARD`)

A `Lazy<Mutex<Keyboard<Us104Key, ScancodeSet1>>>` (from `pc-keyboard`) holds
the keyboard state machine. It maps raw scancodes to `DecodedKey` values
(either Unicode characters or raw keycodes for modifier/function keys).

## ISR Path

```
keyboard ISR
  → input::push_scancode_from_isr(code)
      → SCANCODES.lock().push(code)
```

The ISR is intentionally minimal: read the scancode from port `0x60`, push it,
send EOI. No decoding, no logging, no sleeping.

## Consumer Path

```
input::read_key() -> DecodedKey
```

`read_key()` busy-polls `try_read_scancode()` and feeds each scancode through
the `pc-keyboard` state machine. When `process_keyevent` produces a key, it
returns. If the ring is empty the function disables IRQs, checks again, and
issues `enable_and_hlt()` — this atomically enables interrupts and halts the
CPU, ensuring no scancode can be missed between the empty-check and the `hlt`.

## API (kernel side)

```rust
// From ISR (interrupts already masked):
input::push_scancode_from_isr(code: u8);

// From task / main loop:
let key: DecodedKey = input::read_key(); // blocks until a key arrives
let scancode: Option<u8> = input::try_read_scancode(); // non-blocking
let overflows: u64 = input::scancode_overflows();
```

## Overflow Tracking

`scancode_overflows()` returns the number of scancodes dropped because the ring
was full. A non-zero value means the consumer is not polling fast enough and
modifier-key state in the `pc-keyboard` decoder may be desynchronized (e.g.,
a key-release scancode was dropped, leaving a key stuck in the "pressed" state).
