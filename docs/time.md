# Time Subsystem

**Source:** `kernel/src/time.rs`

## Overview

The time subsystem provides a monotonic millisecond-resolution clock driven by
the Programmable Interval Timer (PIT). It is the simplest possible hardware
timer: channel 0 fires IRQ0 at a fixed rate, and the ISR increments a global
tick counter.

## Design

### PIT Programming

`time::init()` programs PIT channel 0 in **rate-generator mode** (mode 2):

- Command byte `0x34` written to port `0x43`:
  - Channel 0, lobyte/hibyte access, mode 2 (rate generator), binary counting.
- Divisor `PIT_FREQ_HZ / TICK_HZ = 1_193_182 / 100 ≈ 11932` written as
  low byte then high byte to port `0x40`.

This produces ~100 IRQ0 interrupts per second, each 10 ms apart.

### Tick Counter

A single `AtomicU64` (`TICKS`) is incremented by `on_tick()` on every timer
interrupt. Relaxed ordering is used because all callers only need eventual
visibility, not strict synchronization.

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `PIT_FREQ_HZ` | 1_193_182 | PIT oscillator frequency in Hz |
| `TICK_HZ` | 100 | Desired interrupt rate in Hz |
| `TICK_MS` | 10 | Milliseconds per tick (`1000 / TICK_HZ`) |

## API

```rust
time::init();          // Call once after arch::init_apic(); before sti.

time::on_tick();       // Called from the timer ISR. Increments TICKS.
time::ticks() -> u64;  // Raw tick count since init.
time::uptime_ms() -> u64; // Milliseconds since init (= ticks * TICK_MS).
```

## Relationship to the Scheduler

The task scheduler uses `TICK_MS` directly to decrement each task's
`slice_remaining_ms` on every `preempt_tick()` call. A task gets a
`DEFAULT_SLICE_MS = 10` ms time slice, which corresponds to exactly one PIT
tick at 100 Hz.

## Limitations

- Resolution is 10 ms — not suitable for high-resolution timing.
- `uptime_ms()` overflows after ~585 million years. Not a concern.
- The PIT is replaced by the LAPIC timer in future SMP milestones, at which
  point the LAPIC timer will drive per-CPU scheduling and the PIT may be
  repurposed or disabled.
