//! CPU hardware random-number helpers.
//!
//! Wraps the `RDRAND` and `RDSEED` instructions behind CPUID-gated
//! accessors. Callers that need a 16-byte block for AT_RANDOM use
//! [`rdrand16`]; it tries RDRAND first, falls back to RDSEED, and
//! returns `None` when neither is available (QEMU without `-cpu max`,
//! or ancient hardware). In that case the caller is expected to fall
//! back to a documented-insecure deterministic derivation with a
//! warning — see `init_process::launch` and `syscall::exec_atomic`.
//!
//! Host unit tests exercise only the feature-gated fallback: `cpu::has`
//! returns `false` when `FEATURES` is uninitialised, so the public
//! wrappers take the `None` path and callers get to test their fallback
//! logic without executing RDRAND on the test host.

use crate::cpu::{self, Feature};

/// Intel SDM recommends 10 retries for RDRAND (one per 64-bit pull).
const RDRAND_RETRIES: u32 = 10;
/// Intel SDM recommends longer retry bounds for RDSEED; 100 is the
/// commonly-cited figure.
const RDSEED_RETRIES: u32 = 100;

/// Attempt one RDRAND read. Returns `None` if RDRAND is not supported
/// or every retry returned CF=0.
pub fn rdrand64() -> Option<u64> {
    if !cpu::has(Feature::Rdrand) {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { rdrand64_inner() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Attempt one RDSEED read. Returns `None` if RDSEED is not supported
/// or every retry returned CF=0.
pub fn rdseed64() -> Option<u64> {
    if !cpu::has(Feature::Rdseed) {
        return None;
    }
    #[cfg(target_arch = "x86_64")]
    {
        unsafe { rdseed64_inner() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        None
    }
}

/// Fill a 16-byte buffer from the CPU RNG. Tries RDRAND for both
/// 64-bit halves first; if either half fails, falls back to RDSEED for
/// that half. Returns `None` only when neither RDRAND nor RDSEED can
/// produce a value — callers must then use their documented fallback.
pub fn rdrand16() -> Option<[u8; 16]> {
    let lo = rdrand64().or_else(rdseed64)?;
    let hi = rdrand64().or_else(rdseed64)?;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&lo.to_le_bytes());
    out[8..].copy_from_slice(&hi.to_le_bytes());
    Some(out)
}

/// Produce 16 bytes for AT_RANDOM. Prefers [`rdrand16`]; if the CPU
/// supports neither RDRAND nor RDSEED (or every retry failed), falls
/// back to splatting `seed` across the buffer — **insecure**, documented
/// as such, and intended only to keep old QEMU configs bootable.
pub fn at_random_or_fallback(seed: u64) -> [u8; 16] {
    if let Some(bytes) = rdrand16() {
        return bytes;
    }
    let mut out = [0u8; 16];
    for (i, b) in out.iter_mut().enumerate() {
        *b = ((seed >> ((i % 8) * 8)) & 0xFF) as u8;
    }
    out
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdrand")]
unsafe fn rdrand64_inner() -> Option<u64> {
    use core::arch::x86_64::_rdrand64_step;
    let mut val: u64 = 0;
    for _ in 0..RDRAND_RETRIES {
        if _rdrand64_step(&mut val) == 1 {
            return Some(val);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "rdseed")]
unsafe fn rdseed64_inner() -> Option<u64> {
    use core::arch::x86_64::_rdseed64_step;
    let mut val: u64 = 0;
    for _ in 0..RDSEED_RETRIES {
        if _rdseed64_step(&mut val) == 1 {
            return Some(val);
        }
    }
    None
}

#[cfg(all(test, not(target_os = "none")))]
mod tests {
    use super::*;

    #[test]
    fn wrappers_return_none_without_cpu_init() {
        // FEATURES is uninitialised in host tests — cpu::has always
        // returns false, so the public gates short-circuit before any
        // intrinsic call. Proves the fallback path is reachable from
        // host tests without executing RDRAND on the developer box.
        assert_eq!(rdrand64(), None);
        assert_eq!(rdseed64(), None);
        assert_eq!(rdrand16(), None);
    }

    #[test]
    fn fallback_derives_bytes_from_seed() {
        let bytes = at_random_or_fallback(0xdead_beef_cafe_babe);
        // Seed splatted across 16 bytes: first 8 = seed LE, next 8 = same pattern.
        assert_eq!(&bytes[..8], &0xdead_beef_cafe_babe_u64.to_le_bytes());
        assert_eq!(&bytes[8..], &0xdead_beef_cafe_babe_u64.to_le_bytes());
    }

    #[test]
    fn fallback_zero_seed_is_all_zero() {
        // Documents the known-insecure fallback: seed=0 yields an
        // all-zero array. The kernel must never rely on the fallback
        // for anything security-sensitive — the `serial_println!`
        // warning in the call sites is the user-visible signal.
        assert_eq!(at_random_or_fallback(0), [0u8; 16]);
    }
}
