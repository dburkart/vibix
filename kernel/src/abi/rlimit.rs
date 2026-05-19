//! Resource-limit types pinned to the Linux x86_64 syscall ABI.
//!
//! `struct rlimit` is the payload for `getrlimit(2)` / `setrlimit(2)`.
//! `struct rlimit64` is the payload for `prlimit64(2)`.
//! On x86_64 both layouts are identical (rlim_t == unsigned long == u64).
//!
//! Resource constants (`RLIMIT_*`) and their default soft/hard limits
//! match `include/uapi/asm-generic/resource.h` in the Linux source.

/// `rlim_t` — Linux x86_64: `unsigned long` — 64 bits.
pub type rlim_t = u64;

/// Sentinel for "no limit".
pub const RLIM_INFINITY: rlim_t = u64::MAX;

// ── Resource IDs (match Linux x86_64) ─────────────────────────────────

pub const RLIMIT_CPU: u32 = 0;
pub const RLIMIT_FSIZE: u32 = 1;
pub const RLIMIT_DATA: u32 = 2;
pub const RLIMIT_STACK: u32 = 3;
pub const RLIMIT_CORE: u32 = 4;
pub const RLIMIT_RSS: u32 = 5;
pub const RLIMIT_NPROC: u32 = 6;
pub const RLIMIT_NOFILE: u32 = 7;
pub const RLIMIT_MEMLOCK: u32 = 8;
pub const RLIMIT_AS: u32 = 9;
pub const RLIMIT_LOCKS: u32 = 10;
pub const RLIMIT_SIGPENDING: u32 = 11;
pub const RLIMIT_MSGQUEUE: u32 = 12;
pub const RLIMIT_NICE: u32 = 13;
pub const RLIMIT_RTPRIO: u32 = 14;
pub const RLIMIT_RTTIME: u32 = 15;

/// Number of distinct resource-limit IDs.
pub const RLIM_NLIMITS: usize = 16;

/// A single soft/hard limit pair, matching `struct rlimit` on Linux
/// x86_64 (two `unsigned long` fields, naturally aligned).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rlimit {
    pub rlim_cur: rlim_t, // soft limit
    pub rlim_max: rlim_t, // hard limit
}

/// Per-process table of resource limits, indexed by `RLIMIT_*`.
/// Cloned into the child on `fork`.
#[derive(Clone, Debug)]
pub struct RlimitTable {
    pub limits: [Rlimit; RLIM_NLIMITS],
}

impl RlimitTable {
    /// Safe defaults matching a freshly-booted Linux system.
    pub fn defaults() -> Self {
        let inf = Rlimit {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        };
        let mut limits = [inf; RLIM_NLIMITS];

        // RLIMIT_STACK: 8 MiB soft, unlimited hard.
        limits[RLIMIT_STACK as usize] = Rlimit {
            rlim_cur: 8 * 1024 * 1024,
            rlim_max: RLIM_INFINITY,
        };
        // RLIMIT_NOFILE: 1024 soft, 1024*1024 hard (Linux default).
        limits[RLIMIT_NOFILE as usize] = Rlimit {
            rlim_cur: 1024,
            rlim_max: 1024 * 1024,
        };
        // RLIMIT_CORE: 0 (no core dumps).
        limits[RLIMIT_CORE as usize] = Rlimit {
            rlim_cur: 0,
            rlim_max: RLIM_INFINITY,
        };
        // RLIMIT_NPROC: generous default.
        limits[RLIMIT_NPROC as usize] = Rlimit {
            rlim_cur: 4096,
            rlim_max: 4096,
        };

        Self { limits }
    }

    /// Get the limit pair for `resource`, or `None` if out of range.
    pub fn get(&self, resource: u32) -> Option<&Rlimit> {
        self.limits.get(resource as usize)
    }

    /// Set the limit pair for `resource`. Returns `false` if out of
    /// range.
    pub fn set(&mut self, resource: u32, val: Rlimit) -> bool {
        if (resource as usize) < RLIM_NLIMITS {
            self.limits[resource as usize] = val;
            true
        } else {
            false
        }
    }
}

// Compile-time layout pins so ABI drift is caught at build time.
const _: () = assert!(core::mem::size_of::<Rlimit>() == 16);
const _: () = assert!(core::mem::align_of::<Rlimit>() == 8);

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{align_of, size_of};

    #[test]
    fn rlimit_layout_matches_linux() {
        assert_eq!(size_of::<Rlimit>(), 16);
        assert_eq!(align_of::<Rlimit>(), 8);
    }

    #[test]
    fn defaults_are_sane() {
        let tbl = RlimitTable::defaults();
        assert_eq!(tbl.limits[RLIMIT_NOFILE as usize].rlim_cur, 1024);
        assert_eq!(
            tbl.limits[RLIMIT_STACK as usize].rlim_cur,
            8 * 1024 * 1024
        );
        assert_eq!(tbl.limits[RLIMIT_AS as usize].rlim_cur, RLIM_INFINITY);
        assert_eq!(tbl.limits[RLIMIT_CORE as usize].rlim_cur, 0);
    }

    #[test]
    fn get_set_roundtrip() {
        let mut tbl = RlimitTable::defaults();
        let new_val = Rlimit {
            rlim_cur: 42,
            rlim_max: 100,
        };
        assert!(tbl.set(RLIMIT_NOFILE, new_val));
        assert_eq!(*tbl.get(RLIMIT_NOFILE).unwrap(), new_val);
    }

    #[test]
    fn out_of_range_returns_none() {
        let tbl = RlimitTable::defaults();
        assert!(tbl.get(99).is_none());
    }

    #[test]
    fn clone_is_independent() {
        let mut parent = RlimitTable::defaults();
        let child = parent.clone();
        parent.set(
            RLIMIT_NOFILE,
            Rlimit {
                rlim_cur: 9999,
                rlim_max: 9999,
            },
        );
        // child should still have the original default
        assert_eq!(child.limits[RLIMIT_NOFILE as usize].rlim_cur, 1024);
    }
}
