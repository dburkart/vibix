//! Timekeeping support.
//!
//! The PIT (channel 0) provides monotonic uptime via IRQ0 at ~100 Hz.
//! Separately, the CMOS RTC provides a best-effort wall-clock snapshot
//! during boot for human-readable timestamps.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Once;

#[cfg(target_os = "none")]
use crate::sync::IrqLock;

// Host builds: `sync` is cfg-gated to `target_os = "none"`, so substitute
// a plain `spin::Mutex` with the same interface for the WAKEUPS static
// below. No ISR concurrency exists on host, so IF masking is moot.
#[cfg(not(target_os = "none"))]
use spin::Mutex as IrqLock;

/// PIT oscillator frequency, in Hz. Divisor = this / desired Hz.
#[cfg(target_os = "none")]
const PIT_FREQ_HZ: u32 = 1_193_182;
/// Desired tick rate. 100 Hz → 10 ms per tick — coarse, but cheap and
/// plenty for a toy kernel.
pub const TICK_HZ: u32 = 100;
pub const TICK_MS: u64 = 1000 / TICK_HZ as u64;

static TICKS: AtomicU64 = AtomicU64::new(0);

/// Pending task wakeups keyed by deadline (in ticks). A single deadline
/// may accumulate multiple task ids (unlikely at 100 Hz but cheap to
/// support). Drained by `preempt_tick` each PIT IRQ; see
/// `drain_expired`.
///
/// Reachable from both task context (`enqueue_wakeup`) and ISR
/// context (`drain_expired` from the PIT handler), so it uses
/// [`IrqLock`] to mask IRQs while held — a plain `spin::Mutex` would
/// deadlock if the timer IRQ landed on the same CPU while a task
/// held the lock.
static WAKEUPS: IrqLock<BTreeMap<u64, Vec<usize>>> = IrqLock::new(BTreeMap::new());

/// Calibrated TSC frequency in Hz. Set once by [`calibrate_tsc`]; left
/// unset when `RDTSCP` is unavailable, in which case [`uptime_ns`]
/// falls back to the PIT tick counter.
static TSC_HZ: Once<u64> = Once::new();

/// TSC value captured at the start of calibration. [`uptime_ns`]
/// measures from this point rather than CPU reset so the nanosecond
/// clock aligns with the PIT monotonic counter at calibration time.
static TSC_START: Once<u64> = Once::new();

/// Number of PIT ticks spanned by the calibration window.
///
/// At 100 Hz this is 100 ms — long enough to average over several
/// boundary ticks so scheduling jitter in the spin loop doesn't
/// dominate, short enough that boot latency is still small.
const TSC_CALIBRATION_TICKS: u64 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl fmt::Display for DateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RawRtc {
    second: u8,
    minute: u8,
    hour: u8,
    day: u8,
    month: u8,
    year: u8,
    status_b: u8,
}

#[cfg(target_os = "none")]
const CMOS_SECONDS: u8 = 0x00;
#[cfg(target_os = "none")]
const CMOS_MINUTES: u8 = 0x02;
#[cfg(target_os = "none")]
const CMOS_HOURS: u8 = 0x04;
#[cfg(target_os = "none")]
const CMOS_DAY: u8 = 0x07;
#[cfg(target_os = "none")]
const CMOS_MONTH: u8 = 0x08;
#[cfg(target_os = "none")]
const CMOS_YEAR: u8 = 0x09;
#[cfg(target_os = "none")]
const CMOS_STATUS_A: u8 = 0x0A;
#[cfg(target_os = "none")]
const CMOS_STATUS_B: u8 = 0x0B;
#[cfg(target_os = "none")]
const CMOS_NMI_MASK: u8 = 0x80;
#[cfg(target_os = "none")]
const RTC_UPDATE_IN_PROGRESS: u8 = 0x80;
const RTC_BINARY_MODE: u8 = 0x04;
const RTC_24_HOUR_MODE: u8 = 0x02;
const RTC_HOUR_PM_BIT: u8 = 0x80;
#[cfg(target_os = "none")]
const RTC_MAX_READY_POLLS: usize = 1_000_000;
#[cfg(target_os = "none")]
const RTC_SNAPSHOT_RETRIES: usize = 4;

/// Program PIT channel 0 in rate-generator mode at `TICK_HZ` and log a
/// marker.
#[cfg(target_os = "none")]
pub fn init() {
    use x86_64::instructions::port::Port;

    if !crate::hpet::active() {
        let divisor: u16 = (PIT_FREQ_HZ / TICK_HZ) as u16;
        unsafe {
            // Command: channel 0, access lobyte/hibyte, mode 2 (rate
            // gen), binary counting = 0b00_11_010_0 = 0x34.
            Port::<u8>::new(0x43).write(0x34);
            let mut data: Port<u8> = Port::new(0x40);
            data.write((divisor & 0xff) as u8);
            data.write((divisor >> 8) as u8);
        }
    }
    crate::serial_println!("timer: {} Hz", TICK_HZ);
    match wall_clock() {
        Some(now) => crate::serial_println!("rtc: {}", now),
        None => crate::serial_println!("rtc: unavailable"),
    }
}

/// Called from the timer ISR.
pub fn on_tick() {
    TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Monotonic PIT tick count since boot.
///
/// `pub(crate)` per RFC 0005 — the only intended caller is
/// [`crate::task::env::HwClock::now`]; every other in-tree reader
/// goes through `task::env::env()` so the simulator/mock builds can
/// substitute a deterministic clock. A future PR that reintroduces
/// a direct caller fails at compile time, which is the intended
/// regression gate.
pub(crate) fn ticks() -> u64 {
    TICKS.load(Ordering::Relaxed)
}

pub fn uptime_ms() -> u64 {
    uptime_ns() / 1_000_000
}

/// Monotonic uptime in nanoseconds. Uses the calibrated TSC when
/// available, otherwise falls back to the 10 ms PIT tick counter.
///
/// The TSC path measures from [`calibrate_tsc`]'s start sample, not
/// CPU reset — the two domains are aligned at calibration time so the
/// TSC and PIT clocks agree (within calibration error) from that
/// point on.
pub fn uptime_ns() -> u64 {
    if let (Some(&hz), Some(&start)) = (TSC_HZ.get(), TSC_START.get()) {
        let now = read_tsc();
        return tsc_to_ns(now.wrapping_sub(start), hz);
    }
    ticks() * TICK_MS * 1_000_000
}

/// Convert a TSC delta to nanoseconds given the calibrated frequency.
/// Pulled out of [`uptime_ns`] so the formula is unit-testable on the
/// host.
fn tsc_to_ns(tsc_delta: u64, tsc_hz: u64) -> u64 {
    ((tsc_delta as u128 * 1_000_000_000u128) / tsc_hz as u128) as u64
}

/// Derive the TSC frequency in Hz from a measured cycle delta over
/// `ticks_elapsed` PIT ticks. Pulled out for host testability.
fn compute_tsc_hz(tsc_delta: u64, ticks_elapsed: u64) -> u64 {
    (tsc_delta as u128 * TICK_HZ as u128 / ticks_elapsed as u128) as u64
}

/// Read the current TSC value. Host builds return `0` — only the
/// kernel target has the intrinsic and care what the value is.
#[cfg(target_os = "none")]
fn read_tsc() -> u64 {
    // SAFETY: RDTSC is an unprivileged instruction available on every
    // x86_64 CPU the kernel supports. No side effects beyond reading
    // the timestamp counter.
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(target_os = "none"))]
fn read_tsc() -> u64 {
    0
}

/// Calibrate the TSC against the PIT. Must be called after interrupts
/// are enabled (otherwise [`ticks`] never advances and the spin loop
/// below would deadlock) and after [`init`] has programmed the PIT.
///
/// No-op when `RDTSCP` is unavailable — [`uptime_ns`] silently falls
/// back to the PIT clock in that case.
#[cfg(target_os = "none")]
pub fn calibrate_tsc() {
    use crate::cpu::{self, Feature};

    if !cpu::has(Feature::Rdtscp) {
        crate::serial_println!("timer: TSC calibration skipped (no RDTSCP)");
        return;
    }

    // Wait for the next tick boundary so the window is aligned.
    let start_ticks = ticks();
    while ticks() == start_ticks {
        core::hint::spin_loop();
    }
    let window_start_ticks = ticks();
    let window_start_tsc = read_tsc();

    while ticks() - window_start_ticks < TSC_CALIBRATION_TICKS {
        core::hint::spin_loop();
    }
    let window_end_tsc = read_tsc();
    let elapsed_ticks = ticks() - window_start_ticks;

    let tsc_delta = window_end_tsc.wrapping_sub(window_start_tsc);
    let hz = compute_tsc_hz(tsc_delta, elapsed_ticks);
    if hz == 0 {
        crate::serial_println!("timer: TSC calibration produced 0 Hz — falling back to PIT");
        return;
    }

    TSC_HZ.call_once(|| hz);
    TSC_START.call_once(|| window_start_tsc);
    crate::serial_println!("timer: TSC {} MHz", hz / 1_000_000);
}

/// Host build stub. Present so non-kernel callers can reference the
/// symbol without guarding every call site.
#[cfg(not(target_os = "none"))]
pub fn calibrate_tsc() {}

/// Register `id` to be woken once the tick counter reaches
/// `deadline_ticks`. Callers are task context only — uses a blocking
/// lock. A deadline of `0` or one already in the past will be drained
/// on the very next `preempt_tick`.
/// `pub(crate)` per RFC 0005 — only intended caller is
/// [`crate::task::env::HwClock::enqueue_wakeup`]. See `ticks()`.
pub(crate) fn enqueue_wakeup(deadline_ticks: u64, id: usize) {
    WAKEUPS.lock().entry(deadline_ticks).or_default().push(id);
}

/// Pop every task id whose deadline is ≤ `now` from the wakeup list,
/// in deadline order. Returns an empty `Vec` if the list is empty, if
/// the lock is contended (ISR caller), or if no entry has expired.
///
/// Safe to call from an interrupt context: uses `try_lock` and bails
/// cleanly on contention. A missed drain is self-healing — the next
/// tick's call picks the same entries up.
/// `pub(crate)` per RFC 0005 — only intended caller is
/// [`crate::task::env::HwClock::drain_expired`]. See `ticks()`.
pub(crate) fn drain_expired(now: u64) -> Vec<usize> {
    let Some(mut wakeups) = WAKEUPS.try_lock() else {
        return Vec::new();
    };
    let mut ids: Vec<usize> = Vec::new();
    while let Some((&deadline, _)) = wakeups.iter().next() {
        if deadline > now {
            break;
        }
        if let Some(mut bucket) = wakeups.remove(&deadline) {
            ids.append(&mut bucket);
        }
    }
    ids
}

pub fn wall_clock() -> Option<DateTime> {
    #[cfg(target_os = "none")]
    {
        read_wall_clock()
    }

    #[cfg(not(target_os = "none"))]
    {
        None
    }
}

fn decode_wall_clock(raw: RawRtc) -> Option<DateTime> {
    let binary_mode = (raw.status_b & RTC_BINARY_MODE) != 0;
    let mode_24h = (raw.status_b & RTC_24_HOUR_MODE) != 0;

    let second = decode_component(raw.second, binary_mode)?;
    let minute = decode_component(raw.minute, binary_mode)?;
    let month = decode_component(raw.month, binary_mode)?;
    let day = decode_component(raw.day, binary_mode)?;
    let year = decode_component(raw.year, binary_mode)?;
    let hour = decode_hour(raw.hour, binary_mode, mode_24h)?;

    if binary_mode && year > 99 {
        return None;
    }
    if second > 59 || minute > 59 || hour > 23 {
        return None;
    }
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    Some(DateTime {
        year: 2000 + year as u16,
        month,
        day,
        hour,
        minute,
        second,
    })
}

fn decode_component(raw: u8, binary_mode: bool) -> Option<u8> {
    if binary_mode {
        Some(raw)
    } else {
        let ones = raw & 0x0F;
        let tens = (raw >> 4) & 0x0F;
        if ones > 9 || tens > 9 {
            return None;
        }
        Some(tens * 10 + ones)
    }
}

fn decode_hour(raw: u8, binary_mode: bool, mode_24h: bool) -> Option<u8> {
    let pm = !mode_24h && (raw & RTC_HOUR_PM_BIT) != 0;
    let hour = decode_component(raw & !RTC_HOUR_PM_BIT, binary_mode)?;
    if mode_24h {
        if hour > 23 {
            return None;
        }
        return Some(hour);
    }
    if !(1..=12).contains(&hour) {
        return None;
    }
    Some(match (hour, pm) {
        (12, false) => 0,
        (12, true) => 12,
        (h, true) => h + 12,
        (h, false) => h,
    })
}

#[cfg(target_os = "none")]
fn read_wall_clock() -> Option<DateTime> {
    for _ in 0..RTC_SNAPSHOT_RETRIES {
        if !wait_for_rtc_ready() {
            return None;
        }
        let first = read_raw_rtc();
        if !wait_for_rtc_ready() {
            return None;
        }
        let second = read_raw_rtc();
        if first == second {
            return decode_wall_clock(first);
        }
    }
    None
}

#[cfg(target_os = "none")]
fn wait_for_rtc_ready() -> bool {
    for _ in 0..RTC_MAX_READY_POLLS {
        if read_cmos(CMOS_STATUS_A) & RTC_UPDATE_IN_PROGRESS == 0 {
            return true;
        }
    }
    false
}

#[cfg(target_os = "none")]
fn read_raw_rtc() -> RawRtc {
    RawRtc {
        second: read_cmos(CMOS_SECONDS),
        minute: read_cmos(CMOS_MINUTES),
        hour: read_cmos(CMOS_HOURS),
        day: read_cmos(CMOS_DAY),
        month: read_cmos(CMOS_MONTH),
        year: read_cmos(CMOS_YEAR),
        status_b: read_cmos(CMOS_STATUS_B),
    }
}

#[cfg(target_os = "none")]
fn read_cmos(register: u8) -> u8 {
    use x86_64::instructions::port::Port;

    unsafe {
        let mut index = Port::<u8>::new(0x70);
        let mut data = Port::<u8>::new(0x71);
        index.write(CMOS_NMI_MASK | register);
        let value = data.read();
        index.write(register);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        compute_tsc_hz, decode_wall_clock, tsc_to_ns, DateTime, RawRtc, RTC_24_HOUR_MODE,
        RTC_BINARY_MODE, RTC_HOUR_PM_BIT,
    };

    #[test]
    fn tsc_to_ns_ghz_clock() {
        // A 3 GHz clock: one second = 3_000_000_000 cycles → 10^9 ns.
        assert_eq!(tsc_to_ns(3_000_000_000, 3_000_000_000), 1_000_000_000);
        // Half a second's worth of cycles = 5 * 10^8 ns.
        assert_eq!(tsc_to_ns(1_500_000_000, 3_000_000_000), 500_000_000);
    }

    #[test]
    fn tsc_to_ns_handles_large_deltas_without_overflow() {
        // A sustained read a full hour after calibration on a 4 GHz
        // clock: 4e9 * 3600 = 1.44e13 cycles. Naive (u64 * 1e9) would
        // overflow; the u128 intermediate must not.
        let tsc_delta: u64 = 4_000_000_000u64 * 3600;
        let ns = tsc_to_ns(tsc_delta, 4_000_000_000);
        assert_eq!(ns, 3_600_000_000_000u64);
    }

    #[test]
    fn compute_tsc_hz_matches_expected_frequency() {
        // 30_000_000 cycles across 10 PIT ticks at 100 Hz (100 ms)
        // implies a 300 MHz clock.
        assert_eq!(compute_tsc_hz(30_000_000, 10), 300_000_000);
    }

    #[test]
    fn compute_tsc_hz_single_tick_window() {
        // One PIT tick at 100 Hz = 10 ms. A 2_000_000-cycle delta
        // implies 200 MHz.
        assert_eq!(compute_tsc_hz(2_000_000, 1), 200_000_000);
    }

    #[test]
    fn decodes_bcd_rtc_snapshot() {
        let decoded = decode_wall_clock(RawRtc {
            second: 0x56,
            minute: 0x34,
            hour: 0x12,
            day: 0x13,
            month: 0x04,
            year: 0x26,
            status_b: RTC_24_HOUR_MODE,
        });

        assert_eq!(
            decoded,
            Some(DateTime {
                year: 2026,
                month: 4,
                day: 13,
                hour: 12,
                minute: 34,
                second: 56,
            })
        );
    }

    #[test]
    fn decodes_binary_12_hour_pm_snapshot() {
        let decoded = decode_wall_clock(RawRtc {
            second: 59,
            minute: 58,
            hour: RTC_HOUR_PM_BIT | 9,
            day: 1,
            month: 12,
            year: 30,
            status_b: RTC_BINARY_MODE,
        });

        assert_eq!(
            decoded,
            Some(DateTime {
                year: 2030,
                month: 12,
                day: 1,
                hour: 21,
                minute: 58,
                second: 59,
            })
        );
    }

    #[test]
    fn rejects_invalid_bcd_digit() {
        assert_eq!(
            decode_wall_clock(RawRtc {
                second: 0x7a,
                minute: 0x34,
                hour: 0x12,
                day: 0x13,
                month: 0x04,
                year: 0x26,
                status_b: RTC_24_HOUR_MODE,
            }),
            None
        );
    }

    #[test]
    fn rejects_invalid_binary_year() {
        assert_eq!(
            decode_wall_clock(RawRtc {
                second: 59,
                minute: 58,
                hour: 21,
                day: 1,
                month: 12,
                year: 0xff,
                status_b: RTC_BINARY_MODE | RTC_24_HOUR_MODE,
            }),
            None
        );
    }
}
