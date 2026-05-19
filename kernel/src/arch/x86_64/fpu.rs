//! FPU/SSE/AVX register state save and restore across context switches.
//!
//! The kernel target (`x86_64-unknown-none`) is soft-float, so kernel
//! Rust code never emits FPU/SSE instructions itself. The reason this
//! module exists anyway is userspace: once a ring-3 task touches XMM
//! registers, preempting into another task would silently corrupt its
//! FPU state without a save/restore on switch.
//!
//! ## XSAVE / XRSTOR
//!
//! When the CPU advertises XSAVE (CPUID leaf 1 ECX bit 26), the kernel
//! programs `XCR0` with the supported component mask (x87 + SSE + AVX
//! when available) and uses `xsave64`/`xrstor64` instead of
//! `fxsave64`/`fxrstor64`. XSAVEOPT is used for saves when available
//! (CPUID leaf 0xD sub-leaf 1 EAX bit 0) to skip writing unchanged
//! state components. The save area is widened to the CPUID-enumerated
//! XSAVE size so AVX (YMM) state is preserved across context switches.
//!
//! ## Lazy FPU save (CR0.TS + `#NM`)
//!
//! After a context switch, CR0.TS is set and the incoming task's FPU
//! state is not restored immediately. The first FPU/SSE/AVX instruction
//! the task executes triggers a `#NM` (Device Not Available) exception,
//! whose handler clears TS, performs the `fxrstor64`/`xrstor64`, and
//! records the task as the FPU owner. If the same task is scheduled
//! again without any other task touching the FPU in between, neither
//! save nor restore is needed. The `fpu_used` flag on the task tracks
//! whether the FPU was actually used since the last switch.

use alloc::boxed::Box;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Once;

/// Size of an FXSAVE area, in bytes. Fixed by the ISA.
pub const FXSAVE_SIZE: usize = 512;
/// Required alignment for `fxsave64` / `fxrstor64`. Fixed by the ISA.
pub const FXSAVE_ALIGN: usize = 16;
/// Alignment used for [`FpuArea`]. XSAVE requires 64-byte alignment.
pub const FPU_AREA_ALIGN: usize = 64;

/// Maximum XSAVE area size we support. CPUID leaf 0xD sub-leaf 0 ECX
/// returns the actual size; we cap it to avoid unbounded allocation.
/// 4096 bytes covers x87 + SSE + AVX + AVX-512 comfortably.
pub const MAX_XSAVE_SIZE: usize = 4096;

/// Runtime XSAVE area size in bytes. Set by [`init`] based on CPUID.
/// Falls back to [`FXSAVE_SIZE`] (512) when XSAVE is unavailable.
static XSAVE_AREA_SIZE: Once<usize> = Once::new();

/// XCR0 mask programmed at boot. 0 means XSAVE is not in use.
static XCR0_MASK: Once<u64> = Once::new();

/// `true` when `init()` detected XSAVE and configured XCR0.
static XSAVE_ENABLED: AtomicBool = AtomicBool::new(false);

/// `true` when `init()` detected XSAVEOPT support.
static XSAVEOPT_ENABLED: AtomicBool = AtomicBool::new(false);

/// Return the runtime FPU save area size in bytes.
pub fn area_size() -> usize {
    XSAVE_AREA_SIZE.get().copied().unwrap_or(FXSAVE_SIZE)
}

/// Return `true` if XSAVE/XRSTOR are in use (vs FXSAVE/FXRSTOR).
pub fn xsave_enabled() -> bool {
    XSAVE_ENABLED.load(Ordering::Relaxed)
}

// ── Lazy FPU state ──────────────────────────────────────────────────

/// Task ID of the current FPU owner, or `usize::MAX` if no task owns
/// the FPU state. Used by the lazy-save mechanism: if the incoming
/// task is already the FPU owner, no restore is needed.
static FPU_OWNER: AtomicUsize = AtomicUsize::new(usize::MAX);

/// Return the task ID currently owning the FPU registers, or
/// `usize::MAX` if nobody does.
pub fn fpu_owner() -> usize {
    FPU_OWNER.load(Ordering::Relaxed)
}

/// Set the FPU owner to `task_id`.
pub fn set_fpu_owner(task_id: usize) {
    FPU_OWNER.store(task_id, Ordering::Relaxed);
}

/// Invalidate the FPU owner (nobody owns the live FPU state).
pub fn clear_fpu_owner() {
    FPU_OWNER.store(usize::MAX, Ordering::Relaxed);
}

/// Set CR0.TS so the next FPU instruction triggers `#NM`.
///
/// # Safety
/// Must be called with interrupts disabled.
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn set_ts() {
    use x86_64::registers::control::{Cr0, Cr0Flags};
    unsafe {
        Cr0::update(|f| {
            f.insert(Cr0Flags::TASK_SWITCHED);
        });
    }
}

/// Clear CR0.TS so FPU instructions execute without `#NM`.
///
/// # Safety
/// Must be called with interrupts disabled.
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn clear_ts() {
    // `clts` is the canonical single-instruction way to clear CR0.TS.
    unsafe {
        core::arch::asm!("clts", options(nomem, nostack, preserves_flags));
    }
}

/// Per-task FPU save area. 64-byte aligned, dynamically sized up to
/// [`MAX_XSAVE_SIZE`] bytes. When XSAVE is unavailable, only the first
/// 512 bytes (FXSAVE region) are used.
#[repr(C, align(64))]
pub struct FpuArea {
    bytes: [u8; MAX_XSAVE_SIZE],
}

/// Canonical FPU image captured once in [`init`], cloned by
/// [`FpuArea::new_initialized`] into every new task.
static CANONICAL_FPU_IMAGE: Once<FpuArea> = Once::new();

impl FpuArea {
    /// Allocate a fresh save area pre-populated with the canonical FPU
    /// image (x87 reset: `FCW=0x037F`, all data registers empty;
    /// `MXCSR=0x1F80`).
    ///
    /// Must not be called before [`init`] — that's where the template
    /// is captured.
    pub fn new_initialized() -> Box<Self> {
        let template = CANONICAL_FPU_IMAGE
            .get()
            .expect("fpu::init must run before FpuArea::new_initialized");
        Box::new(Self {
            bytes: template.bytes,
        })
    }

    /// Return a read-only slice of the FPU state bytes, sized to the
    /// runtime area size. Used for copying into signal frames.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..area_size()]
    }

    /// Return a mutable slice of the FPU state bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..area_size()]
    }

    /// Return a raw pointer to the save area for inline assembly.
    pub fn as_ptr(&self) -> *const u8 {
        self.bytes.as_ptr()
    }

    /// Return a mutable raw pointer to the save area.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.bytes.as_mut_ptr()
    }
}

/// Enable FPU save/restore on this CPU.
///
/// Detects XSAVE support via CPUID and configures either the
/// XSAVE or legacy FXSAVE path. Programs XCR0 when XSAVE is
/// available.
///
/// Call after [`crate::cpu::init`] and before any task is spawned.
#[cfg(target_os = "none")]
pub fn init() {
    use crate::cpu::{self, Feature};
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

    // SAFETY: adjusting CR0/CR4 with paging already live is safe as
    // long as we don't toggle paging-critical bits (PG, PE, PAE).
    unsafe {
        Cr0::update(|f| {
            f.remove(Cr0Flags::EMULATE_COPROCESSOR);
            f.remove(Cr0Flags::TASK_SWITCHED);
            f.insert(Cr0Flags::MONITOR_COPROCESSOR);
            f.insert(Cr0Flags::NUMERIC_ERROR);
        });
        Cr4::update(|f| {
            f.insert(Cr4Flags::OSFXSR);
            f.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }

    // Detect XSAVE support and configure.
    let use_xsave = cpu::has(Feature::Xsave);
    let (save_size, xcr0_mask) = if use_xsave {
        // Enable CR4.OSXSAVE so XSAVE/XRSTOR and XCR0 access are legal.
        unsafe {
            Cr4::update(|f| {
                f.insert(Cr4Flags::OSXSAVE);
            });
        }

        // Query CPUID leaf 0xD sub-leaf 0 for supported XCR0 bits and
        // the area size.
        let cpuid_d0 = core::arch::x86_64::__cpuid_count(0xD, 0);
        let supported_xcr0 = (cpuid_d0.edx as u64) << 32 | cpuid_d0.eax as u64;

        // Build XCR0 mask: always include x87 (bit 0) and SSE (bit 1);
        // add AVX (bit 2) if supported.
        let mut xcr0: u64 = 0x3; // x87 + SSE (mandatory)
        if supported_xcr0 & (1 << 2) != 0 && cpu::has(Feature::Avx) {
            xcr0 |= 1 << 2; // AVX (YMM upper halves)
        }

        // Program XCR0.
        unsafe {
            core::arch::asm!(
                "xsetbv",
                in("ecx") 0u32,
                in("edx") (xcr0 >> 32) as u32,
                in("eax") xcr0 as u32,
                options(nomem, nostack, preserves_flags),
            );
        }

        // Query the actual XSAVE area size for the configured XCR0.
        // Re-query after programming XCR0 for accuracy.
        let cpuid_d0_post = core::arch::x86_64::__cpuid_count(0xD, 0);
        let xsave_size = (cpuid_d0_post.ebx as usize).max(FXSAVE_SIZE).min(MAX_XSAVE_SIZE);

        XSAVE_ENABLED.store(true, Ordering::Relaxed);

        // Check for XSAVEOPT.
        if cpu::has(Feature::Xsaveopt) {
            XSAVEOPT_ENABLED.store(true, Ordering::Relaxed);
        }

        (xsave_size, xcr0)
    } else {
        (FXSAVE_SIZE, 0u64)
    };

    XSAVE_AREA_SIZE.call_once(|| save_size);
    XCR0_MASK.call_once(|| xcr0_mask);

    // Capture the canonical image.
    CANONICAL_FPU_IMAGE.call_once(|| {
        let mut image = FpuArea {
            bytes: [0u8; MAX_XSAVE_SIZE],
        };
        let default_mxcsr: u32 = 0x1F80;
        if use_xsave {
            let rfbm = xcr0_mask;
            // SAFETY: CR4.OSXSAVE is set and XCR0 is programmed.
            unsafe {
                core::arch::asm!(
                    "fninit",
                    "ldmxcsr [{m}]",
                    "xsave64 [{p}]",
                    m = in(reg) &default_mxcsr,
                    p = in(reg) image.bytes.as_mut_ptr(),
                    in("edx") (rfbm >> 32) as u32,
                    in("eax") rfbm as u32,
                    options(nostack, preserves_flags),
                );
            }
        } else {
            // SAFETY: CR0.EM is clear and CR4.OSFXSR is set.
            unsafe {
                core::arch::asm!(
                    "fninit",
                    "ldmxcsr [{m}]",
                    "fxsave64 [{p}]",
                    m = in(reg) &default_mxcsr,
                    p = in(reg) image.bytes.as_mut_ptr(),
                    options(nostack, preserves_flags),
                );
            }
        }
        image
    });

    if use_xsave {
        let opt = if XSAVEOPT_ENABLED.load(Ordering::Relaxed) {
            "+XSAVEOPT"
        } else {
            ""
        };
        crate::serial_println!(
            "fpu: XSAVE{} context switch online (area={}B, xcr0={:#x})",
            opt,
            save_size,
            xcr0_mask,
        );
    } else {
        crate::serial_println!("fpu: FXSAVE context switch online");
    }
}

/// Save the current CPU FPU state into `area`.
///
/// Uses XSAVEOPT > XSAVE > FXSAVE depending on CPU support.
///
/// # Safety
/// - [`init`] must have run on this CPU.
/// - `area` must not alias any other FPU save currently in flight.
/// - CR0.TS must be clear (the caller must have ensured the FPU is
///   accessible, e.g. via the `#NM` handler or explicit `clts`).
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn save(area: &mut FpuArea) {
    if XSAVE_ENABLED.load(Ordering::Relaxed) {
        let mask = XCR0_MASK.get().copied().unwrap_or(0x3);
        if XSAVEOPT_ENABLED.load(Ordering::Relaxed) {
            unsafe {
                core::arch::asm!(
                    "xsaveopt64 [{p}]",
                    p = in(reg) area.bytes.as_mut_ptr(),
                    in("edx") (mask >> 32) as u32,
                    in("eax") mask as u32,
                    options(nostack, preserves_flags),
                );
            }
        } else {
            unsafe {
                core::arch::asm!(
                    "xsave64 [{p}]",
                    p = in(reg) area.bytes.as_mut_ptr(),
                    in("edx") (mask >> 32) as u32,
                    in("eax") mask as u32,
                    options(nostack, preserves_flags),
                );
            }
        }
    } else {
        unsafe {
            core::arch::asm!(
                "fxsave64 [{p}]",
                p = in(reg) area.bytes.as_mut_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Load the FPU state stored in `area` into the current CPU.
///
/// Uses XRSTOR or FXRSTOR depending on CPU support.
///
/// # Safety
/// - [`init`] must have run on this CPU.
/// - `area` must hold a valid save image.
/// - CR0.TS must be clear.
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn restore(area: &FpuArea) {
    if XSAVE_ENABLED.load(Ordering::Relaxed) {
        let mask = XCR0_MASK.get().copied().unwrap_or(0x3);
        unsafe {
            core::arch::asm!(
                "xrstor64 [{p}]",
                p = in(reg) area.bytes.as_ptr(),
                in("edx") (mask >> 32) as u32,
                in("eax") mask as u32,
                options(nostack, preserves_flags),
            );
        }
    } else {
        unsafe {
            core::arch::asm!(
                "fxrstor64 [{p}]",
                p = in(reg) area.bytes.as_ptr(),
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Handle `#NM` (Device Not Available) exception for lazy FPU restore.
///
/// Called from the IDT `#NM` handler. Delegates to the scheduler's
/// [`crate::task::do_lazy_fpu_restore`] which clears CR0.TS, restores
/// the pending task's FPU state, and records it as the FPU owner.
///
/// Returns `true` if the handler resolved the `#NM` (the task can
/// continue), `false` if this was an unexpected `#NM` (should panic).
///
/// # Safety
/// Must be called from the `#NM` exception handler.
#[cfg(target_os = "none")]
pub unsafe fn handle_device_not_available() -> bool {
    crate::task::do_lazy_fpu_restore()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpu_area_layout() {
        assert_eq!(core::mem::size_of::<FpuArea>(), MAX_XSAVE_SIZE);
        assert_eq!(core::mem::align_of::<FpuArea>(), FPU_AREA_ALIGN);
        assert!(FPU_AREA_ALIGN >= FXSAVE_ALIGN);
        assert_eq!(FXSAVE_ALIGN, 16);
    }

    #[test]
    fn area_size_defaults_to_fxsave() {
        // Before init() runs, area_size() falls back to FXSAVE_SIZE.
        // In host tests init() doesn't run, so this exercises the
        // fallback path.
        assert_eq!(area_size(), FXSAVE_SIZE);
    }
}
