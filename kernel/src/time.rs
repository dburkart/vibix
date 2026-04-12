//! Monotonic time, driven by the PIT.
//!
//! The PIT (channel 0) is programmed to fire IRQ0 at ~100 Hz; the timer
//! ISR calls `on_tick` which bumps a global counter. `uptime_ms` is a
//! cheap read of that counter.

use core::sync::atomic::{AtomicU64, Ordering};

/// PIT oscillator frequency, in Hz. Divisor = this / desired Hz.
const PIT_FREQ_HZ: u32 = 1_193_182;
/// Desired tick rate. 100 Hz → 10 ms per tick — coarse, but cheap and
/// plenty for a toy kernel.
pub const TICK_HZ: u32 = 100;
pub const TICK_MS: u64 = 1000 / TICK_HZ as u64;

static TICKS: AtomicU64 = AtomicU64::new(0);

/// Program PIT channel 0 in rate-generator mode at `TICK_HZ` and log a
/// marker.
#[cfg(target_os = "none")]
pub fn init() {
    use x86_64::instructions::port::Port;

    let divisor: u16 = (PIT_FREQ_HZ / TICK_HZ) as u16;
    unsafe {
        // Command: channel 0, access lobyte/hibyte, mode 2 (rate gen),
        // binary counting = 0b00_11_010_0 = 0x34.
        Port::<u8>::new(0x43).write(0x34);
        let mut data: Port<u8> = Port::new(0x40);
        data.write((divisor & 0xff) as u8);
        data.write((divisor >> 8) as u8);
    }
    crate::serial_println!("timer: {} Hz", TICK_HZ);
}

/// Called from the timer ISR.
pub fn on_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

pub fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    ticks() * TICK_MS
}
