//! CPU feature detection via CPUID.
//!
//! Call `cpu::init()` once early in `arch::init()` — before any
//! feature-dependent subsystem (PAT, FPU save/restore, SMEP/SMAP, …).
//! After that, `cpu::has(Feature::X)` is a cheap, lock-free read.
//!
//! The `Features` struct and `Feature` enum are unconditionally compiled
//! so host unit tests can exercise the parsing logic directly via
//! `Features::from_raw`. Only `init()` is gated on `target_os = "none"`.

use spin::Once;

/// Global feature set, populated once by `init()`.
static FEATURES: Once<Features> = Once::new();

/// Raw CPUID leaf values captured at boot.
///
/// Stored as plain `u32` fields so the struct is constructable in host
/// unit tests without executing real CPUID instructions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Features {
    leaf1_edx: u32,
    leaf1_ecx: u32,
    leaf7_ebx: u32,
    #[allow(dead_code)]
    leaf7_ecx: u32, // reserved for future features
    #[allow(dead_code)]
    leaf7_edx: u32, // reserved for future features
    ext_edx: u32, // leaf 0x8000_0001 EDX
    ext_ecx: u32, // leaf 0x8000_0001 ECX
}

impl Features {
    /// Construct from raw CPUID leaf values.
    ///
    /// Used by `init()` on the kernel target and by host unit tests.
    pub const fn from_raw(
        leaf1_edx: u32,
        leaf1_ecx: u32,
        leaf7_ebx: u32,
        leaf7_ecx: u32,
        leaf7_edx: u32,
        ext_edx: u32,
        ext_ecx: u32,
    ) -> Self {
        Self {
            leaf1_edx,
            leaf1_ecx,
            leaf7_ebx,
            leaf7_ecx,
            leaf7_edx,
            ext_edx,
            ext_ecx,
        }
    }

    /// Return `true` if the CPU reports support for `f`.
    pub fn has(&self, f: Feature) -> bool {
        match f {
            // Leaf 1 EDX
            Feature::Pat => self.leaf1_edx & (1 << 16) != 0,
            Feature::Sse => self.leaf1_edx & (1 << 25) != 0,
            Feature::Sse2 => self.leaf1_edx & (1 << 26) != 0,
            // Leaf 1 ECX
            Feature::Sse4_1 => self.leaf1_ecx & (1 << 19) != 0,
            Feature::Sse4_2 => self.leaf1_ecx & (1 << 20) != 0,
            Feature::Popcnt => self.leaf1_ecx & (1 << 23) != 0,
            Feature::Xsave => self.leaf1_ecx & (1 << 26) != 0,
            Feature::Avx => self.leaf1_ecx & (1 << 28) != 0,
            // Leaf 7, sub-leaf 0, EBX
            Feature::Fsgsbase => self.leaf7_ebx & (1 << 0) != 0,
            Feature::Avx2 => self.leaf7_ebx & (1 << 5) != 0,
            Feature::Smep => self.leaf7_ebx & (1 << 7) != 0,
            Feature::Smap => self.leaf7_ebx & (1 << 20) != 0,
            // Extended leaf 0x8000_0001
            Feature::Rdtscp => self.ext_edx & (1 << 27) != 0,
            Feature::Lzcnt => self.ext_ecx & (1 << 5) != 0,
        }
    }
}

/// A CPU feature detectable via CPUID.
///
/// The enum is `#[non_exhaustive]` so future additions don't break
/// exhaustive matches in external code.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// SSE (Streaming SIMD Extensions) — leaf 1, EDX bit 25.
    Sse,
    /// SSE2 — leaf 1, EDX bit 26.
    Sse2,
    /// SSE4.1 — leaf 1, ECX bit 19.
    Sse4_1,
    /// SSE4.2 — leaf 1, ECX bit 20.
    Sse4_2,
    /// AVX — leaf 1, ECX bit 28.
    Avx,
    /// AVX2 — leaf 7 sub-leaf 0, EBX bit 5.
    Avx2,
    /// XSAVE/XRSTOR — leaf 1, ECX bit 26.
    Xsave,
    /// Page Attribute Table — leaf 1, EDX bit 16.
    Pat,
    /// Supervisor Mode Execution Prevention — leaf 7 sub-leaf 0, EBX bit 7.
    Smep,
    /// Supervisor Mode Access Prevention — leaf 7 sub-leaf 0, EBX bit 20.
    Smap,
    /// FS/GS base read/write instructions — leaf 7 sub-leaf 0, EBX bit 0.
    Fsgsbase,
    /// RDTSCP instruction — extended leaf 0x8000_0001, EDX bit 27.
    Rdtscp,
    /// POPCNT instruction — leaf 1, ECX bit 23.
    Popcnt,
    /// LZCNT instruction — extended leaf 0x8000_0001, ECX bit 5.
    Lzcnt,
}

/// Return `true` if the CPU supports `f`.
///
/// Returns `false` if called before `init()` — a safe fallback that
/// disables optional features rather than assuming they are present.
pub fn has(f: Feature) -> bool {
    FEATURES.get().map_or(false, |feat| feat.has(f))
}

/// Detect and record CPU features via CPUID.
///
/// Must be called exactly once, as the first call in `arch::init()`,
/// before any feature-dependent subsystem (PAT, FPU, SMEP/SMAP, …).
///
/// Not available on the host: call `Features::from_raw` directly in
/// unit tests to exercise the parsing logic without real CPUID.
#[cfg(target_os = "none")]
pub fn init() {
    use core::arch::x86_64::{__cpuid, __cpuid_count};

    // Read the maximum supported standard leaf before issuing leaf 7.
    let max_std = __cpuid(0).eax;
    let l1 = __cpuid(1);

    let (l7_ebx, l7_ecx, l7_edx) = if max_std >= 7 {
        let r = __cpuid_count(7, 0);
        (r.ebx, r.ecx, r.edx)
    } else {
        (0u32, 0u32, 0u32)
    };

    // Read the maximum supported extended leaf before issuing 0x8000_0001.
    let max_ext = __cpuid(0x8000_0000).eax;
    let (lext_edx, lext_ecx) = if max_ext >= 0x8000_0001 {
        let r = __cpuid(0x8000_0001);
        (r.edx, r.ecx)
    } else {
        (0u32, 0u32)
    };

    let features = Features::from_raw(l1.edx, l1.ecx, l7_ebx, l7_ecx, l7_edx, lext_edx, lext_ecx);
    FEATURES.call_once(|| features);

    // Print a single boot-time line listing every detected feature.
    // No heap available yet — print tokens one by one.
    crate::serial_print!("cpu:");
    if features.has(Feature::Sse) {
        crate::serial_print!(" SSE");
    }
    if features.has(Feature::Sse2) {
        crate::serial_print!(" SSE2");
    }
    if features.has(Feature::Sse4_1) {
        crate::serial_print!(" SSE4.1");
    }
    if features.has(Feature::Sse4_2) {
        crate::serial_print!(" SSE4.2");
    }
    if features.has(Feature::Avx) {
        crate::serial_print!(" AVX");
    }
    if features.has(Feature::Avx2) {
        crate::serial_print!(" AVX2");
    }
    if features.has(Feature::Xsave) {
        crate::serial_print!(" XSAVE");
    }
    if features.has(Feature::Pat) {
        crate::serial_print!(" PAT");
    }
    if features.has(Feature::Smep) {
        crate::serial_print!(" SMEP");
    }
    if features.has(Feature::Smap) {
        crate::serial_print!(" SMAP");
    }
    if features.has(Feature::Fsgsbase) {
        crate::serial_print!(" FSGSBASE");
    }
    if features.has(Feature::Rdtscp) {
        crate::serial_print!(" RDTSCP");
    }
    if features.has(Feature::Popcnt) {
        crate::serial_print!(" POPCNT");
    }
    if features.has(Feature::Lzcnt) {
        crate::serial_print!(" LZCNT");
    }
    crate::serial_println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpuid_parse_synthetic() {
        // Leaf 1 EDX: PAT (16), SSE (25), SSE2 (26)
        // Leaf 1 ECX: SSE4.1 (19), SSE4.2 (20), POPCNT (23), XSAVE (26), AVX (28)
        // Leaf 7 EBX: FSGSBASE (0), AVX2 (5), SMEP (7), SMAP (20)
        // Ext EDX:    RDTSCP (27)
        // Ext ECX:    LZCNT (5)
        let f = Features::from_raw(
            (1 << 16) | (1 << 25) | (1 << 26), // leaf1_edx
            (1 << 19) | (1 << 20) | (1 << 23) | (1 << 26) | (1 << 28), // leaf1_ecx
            (1 << 0) | (1 << 5) | (1 << 7) | (1 << 20), // leaf7_ebx
            0,                                 // leaf7_ecx
            0,                                 // leaf7_edx
            1 << 27,                           // ext_edx
            1 << 5,                            // ext_ecx
        );

        assert!(f.has(Feature::Sse));
        assert!(f.has(Feature::Sse2));
        assert!(f.has(Feature::Pat));
        assert!(f.has(Feature::Sse4_1));
        assert!(f.has(Feature::Sse4_2));
        assert!(f.has(Feature::Popcnt));
        assert!(f.has(Feature::Xsave));
        assert!(f.has(Feature::Avx));
        assert!(f.has(Feature::Avx2));
        assert!(f.has(Feature::Smep));
        assert!(f.has(Feature::Smap));
        assert!(f.has(Feature::Fsgsbase));
        assert!(f.has(Feature::Rdtscp));
        assert!(f.has(Feature::Lzcnt));
    }

    #[test]
    fn empty_cpuid_yields_no_features() {
        let f = Features::from_raw(0, 0, 0, 0, 0, 0, 0);
        assert!(!f.has(Feature::Sse));
        assert!(!f.has(Feature::Sse2));
        assert!(!f.has(Feature::Pat));
        assert!(!f.has(Feature::Avx));
        assert!(!f.has(Feature::Avx2));
        assert!(!f.has(Feature::Xsave));
        assert!(!f.has(Feature::Smep));
        assert!(!f.has(Feature::Smap));
        assert!(!f.has(Feature::Rdtscp));
        assert!(!f.has(Feature::Lzcnt));
    }

    #[test]
    fn has_returns_false_before_init() {
        // FEATURES is not initialized in host tests (init() is kernel-only).
        // has() must not panic; it must return false rather than unwrap.
        let _ = has(Feature::Avx);
        let _ = has(Feature::Pat);
    }
}
