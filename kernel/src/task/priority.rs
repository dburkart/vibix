//! Task scheduling priorities, nice values, and CPU affinity.
//!
//! Priorities run 0..=[`MAX_PRIORITY`] with higher values running first.
//! Nice values follow the UNIX convention (`-20..=19`, lower = hotter)
//! and map onto priority via [`priority_from_nice`]. Default-spawned
//! tasks land at [`DEFAULT_PRIORITY`] (nice 0).
//!
//! CPU affinity is a bitmask over logical CPUs (bit `n` set means the
//! task may run on CPU `n`). The kernel is single-CPU today, so the
//! mask is stored but not enforced — it exists so userspace-visible
//! affinity APIs can be wired up without another Task-shape change
//! once SMP lands.

/// Highest legal priority value. Priorities are `u8` in `0..=MAX_PRIORITY`.
pub const MAX_PRIORITY: u8 = 39;

/// Priority assigned to tasks spawned without an explicit priority.
/// Corresponds to nice 0.
pub const DEFAULT_PRIORITY: u8 = 20;

/// Number of distinct priority levels (0..=MAX_PRIORITY).
pub const NUM_PRIORITIES: usize = MAX_PRIORITY as usize + 1;

/// Lowest legal nice value — equivalent to the hottest priority.
pub const NICE_MIN: i8 = -20;
/// Highest legal nice value — equivalent to the coldest priority.
pub const NICE_MAX: i8 = 19;

/// All CPUs mask; default affinity for every spawned task.
pub const AFFINITY_ALL: u64 = u64::MAX;

/// Map a UNIX nice value (`-20..=19`) onto the scheduler's priority
/// space (`0..=39`). Lower nice = higher priority. Values outside the
/// legal range are clamped.
pub const fn priority_from_nice(nice: i8) -> u8 {
    let clamped = if nice < NICE_MIN {
        NICE_MIN
    } else if nice > NICE_MAX {
        NICE_MAX
    } else {
        nice
    };
    // nice -20 → 39, nice 0 → 20 (DEFAULT_PRIORITY), nice 19 → 1.
    (DEFAULT_PRIORITY as i16 - clamped as i16) as u8
}

/// Inverse of [`priority_from_nice`]: recover the nice value that would
/// produce this priority. Priorities above [`MAX_PRIORITY`] clamp to
/// `NICE_MIN`.
pub const fn nice_from_priority(prio: u8) -> i8 {
    let p = if prio > MAX_PRIORITY { MAX_PRIORITY } else { prio };
    (DEFAULT_PRIORITY as i16 - p as i16) as i8
}

/// Clamp an arbitrary integer priority into the legal range.
pub const fn clamp_priority(p: u8) -> u8 {
    if p > MAX_PRIORITY {
        MAX_PRIORITY
    } else {
        p
    }
}

