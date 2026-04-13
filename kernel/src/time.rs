//! Timekeeping support.
//!
//! The PIT (channel 0) provides monotonic uptime via IRQ0 at ~100 Hz.
//! Separately, the CMOS RTC provides a best-effort wall-clock snapshot
//! during boot for human-readable timestamps.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

/// PIT oscillator frequency, in Hz. Divisor = this / desired Hz.
#[cfg(target_os = "none")]
const PIT_FREQ_HZ: u32 = 1_193_182;
/// Desired tick rate. 100 Hz → 10 ms per tick — coarse, but cheap and
/// plenty for a toy kernel.
pub const TICK_HZ: u32 = 100;
pub const TICK_MS: u64 = 1000 / TICK_HZ as u64;

static TICKS: AtomicU64 = AtomicU64::new(0);

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
    match wall_clock() {
        Some(now) => crate::serial_println!("rtc: {}", now),
        None => crate::serial_println!("rtc: unavailable"),
    }
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
        let previous = index.read();
        let nmi_mask = previous & CMOS_NMI_MASK;
        index.write(nmi_mask | register);
        let value = data.read();
        index.write(previous);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::{
        decode_wall_clock, DateTime, RawRtc, RTC_24_HOUR_MODE, RTC_BINARY_MODE, RTC_HOUR_PM_BIT,
    };

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
