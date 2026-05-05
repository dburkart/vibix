//! Time implementation for vibix.
//!
//! Provides SystemTime backed by seconds+nanoseconds from epoch (Unix time),
//! and Instant backed on clock_gettime(CLOCK_MONOTONIC) when available.

use crate::time::Duration;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Instant(Duration);

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct SystemTime {
    tv_sec: i64,
    tv_nsec: i64,
}

pub const UNIX_EPOCH: SystemTime = SystemTime { tv_sec: 0, tv_nsec: 0 };

impl Instant {
    pub fn now() -> Instant {
        // vibix doesn't have clock_gettime wired yet; panic for now.
        // Phase 3 will add CLOCK_MONOTONIC support.
        panic!("Instant::now() not yet supported on vibix")
    }

    pub fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        self.0.checked_sub(other.0)
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_add(*other)?))
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<Instant> {
        Some(Instant(self.0.checked_sub(*other)?))
    }
}

impl SystemTime {
    pub const MAX: SystemTime = SystemTime { tv_sec: i64::MAX, tv_nsec: 999_999_999 };

    pub const MIN: SystemTime = SystemTime { tv_sec: i64::MIN, tv_nsec: 0 };

    /// Create a SystemTime from seconds and nanoseconds since the Unix epoch.
    pub fn new(tv_sec: i64, tv_nsec: i64) -> Result<SystemTime, crate::io::Error> {
        if tv_nsec >= 0 && tv_nsec < 1_000_000_000 {
            Ok(SystemTime { tv_sec, tv_nsec })
        } else {
            Err(crate::io::const_error!(
                crate::io::ErrorKind::InvalidData,
                "invalid timestamp"
            ))
        }
    }

    pub fn now() -> SystemTime {
        // vibix doesn't have clock_gettime wired for userspace yet.
        panic!("SystemTime::now() not yet supported on vibix")
    }

    pub fn sub_time(&self, other: &SystemTime) -> Result<Duration, Duration> {
        if self >= other {
            let sec_diff = (self.tv_sec - other.tv_sec) as u64;
            let nsec_diff = self.tv_nsec - other.tv_nsec;
            if nsec_diff >= 0 {
                Ok(Duration::new(sec_diff, nsec_diff as u32))
            } else {
                Ok(Duration::new(sec_diff - 1, (nsec_diff + 1_000_000_000) as u32))
            }
        } else {
            match other.sub_time(self) {
                Ok(d) => Err(d),
                Err(d) => Ok(d),
            }
        }
    }

    pub fn checked_add_duration(&self, other: &Duration) -> Option<SystemTime> {
        let mut secs = self.tv_sec.checked_add(other.as_secs() as i64)?;
        let mut nsec = self.tv_nsec + other.subsec_nanos() as i64;
        if nsec >= 1_000_000_000 {
            nsec -= 1_000_000_000;
            secs = secs.checked_add(1)?;
        }
        Some(SystemTime { tv_sec: secs, tv_nsec: nsec })
    }

    pub fn checked_sub_duration(&self, other: &Duration) -> Option<SystemTime> {
        let mut secs = self.tv_sec.checked_sub(other.as_secs() as i64)?;
        let mut nsec = self.tv_nsec - other.subsec_nanos() as i64;
        if nsec < 0 {
            nsec += 1_000_000_000;
            secs = secs.checked_sub(1)?;
        }
        Some(SystemTime { tv_sec: secs, tv_nsec: nsec })
    }

    /// Convert to (seconds, nanoseconds) for use with utimensat.
    pub fn to_timespec(&self) -> (i64, i64) {
        (self.tv_sec, self.tv_nsec)
    }
}
