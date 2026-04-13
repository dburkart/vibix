//! x87/SSE register state save and restore across context switches.
//!
//! The kernel target (`x86_64-unknown-none`) is soft-float, so kernel
//! Rust code never emits FPU/SSE instructions itself. The reason this
//! module exists anyway is userspace: once a ring-3 task touches XMM
//! registers, preempting into another task would silently corrupt its
//! FPU state without a save/restore on switch.
//!
//! Scope for this first cut — eager, non-lazy:
//!
//!  - `init()` clears `CR0.EM`, sets `CR0.MP` / `CR0.NE`, and sets
//!    `CR4.OSFXSR` / `CR4.OSXMMEXCPT`. With those, `fxsave64` /
//!    `fxrstor64` are legal and SSE instructions don't raise `#NM`.
//!  - Each [`Task`](crate::task::task::Task) owns a 64-byte-aligned,
//!    512-byte [`FpuArea`]. [`FpuArea::new_initialized`] clones a
//!    canonical FXSAVE image (x87 reset + `MXCSR=0x1F80`) captured
//!    once during [`init`], so spawning never touches the live FPU.
//!  - [`save`] / [`restore`] wrap `fxsave64` / `fxrstor64` against a
//!    Task's `FpuArea`; the scheduler (`task::mod`) calls them around
//!    every `context_switch`.
//!
//! Deliberately **not in this module yet**:
//!
//!  - XSAVE / XRSTOR for YMM / ZMM state — tracked as a follow-up; the
//!    kernel is soft-float and no userspace code uses AVX yet.
//!  - Lazy save via `CR0.TS` + `#NM` — same follow-up. Correctness is
//!    unaffected; the optimisation can land separately with its own
//!    `#NM` handler and per-CPU FPU-owner tracking.
//!  - `kernel_fpu_begin` / `kernel_fpu_end` guards — unused on a
//!    soft-float kernel. Will be added when a kernel fast-path (e.g.
//!    an AVX `memcpy`) actually wants SIMD.

use alloc::boxed::Box;
use spin::Once;

/// Size of an FXSAVE area, in bytes. Fixed by the ISA.
pub const FXSAVE_SIZE: usize = 512;
/// Required alignment for `fxsave64` / `fxrstor64`. Fixed by the ISA.
pub const FXSAVE_ALIGN: usize = 16;
/// Alignment used for [`FpuArea`]. Oversized relative to `FXSAVE_ALIGN`
/// so the same storage is compatible with future XSAVE widening (which
/// requires 64-byte alignment).
pub const FPU_AREA_ALIGN: usize = 64;

/// Per-task FPU save area. 64-byte aligned, 512 bytes — compatible with
/// `fxsave64` / `fxrstor64`.
#[repr(C, align(64))]
pub struct FpuArea {
    bytes: [u8; FXSAVE_SIZE],
}

/// Canonical FXSAVE image captured once in [`init`], cloned by
/// [`FpuArea::new_initialized`] into every new task. Holding this as a
/// template (rather than regenerating via `fninit` + `fxsave64` on each
/// spawn) means spawning never mutates the live CPU FPU — which would
/// otherwise clobber whatever state the spawning task was using.
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
}

/// Enable FXSAVE/FXRSTOR on this CPU.
///
/// Clears `CR0.EM` (so SSE instructions don't raise `#NM`), sets
/// `CR0.MP` and `CR0.NE`, then sets `CR4.OSFXSR` and
/// `CR4.OSXMMEXCPT`. Leaves `CR0.TS` unchanged (we eager-save for now).
///
/// Safe to call more than once — each bit is an idempotent set/clear.
/// Call after [`crate::cpu::init`] and before any task is spawned.
#[cfg(target_os = "none")]
pub fn init() {
    use x86_64::registers::control::{Cr0, Cr0Flags, Cr4, Cr4Flags};

    // SAFETY: adjusting CR0/CR4 with paging already live is safe as
    // long as we don't toggle paging-critical bits (PG, PE, PAE). We
    // only touch EM/MP/NE and OSFXSR/OSXMMEXCPT.
    unsafe {
        Cr0::update(|f| {
            f.remove(Cr0Flags::EMULATE_COPROCESSOR);
            // Clear TS so `fxsave64` / `fxrstor64` / `ldmxcsr` below
            // (and every subsequent context-switch save/restore) don't
            // take `#NM` if the bootloader or firmware left TS set.
            // We eager-save; there's no lazy-FPU state machine that
            // wants TS asserted.
            f.remove(Cr0Flags::TASK_SWITCHED);
            f.insert(Cr0Flags::MONITOR_COPROCESSOR);
            f.insert(Cr0Flags::NUMERIC_ERROR);
        });
        Cr4::update(|f| {
            f.insert(Cr4Flags::OSFXSR);
            f.insert(Cr4Flags::OSXMMEXCPT_ENABLE);
        });
    }

    // Capture the canonical FXSAVE image once — immediately after the
    // FPU is enabled and before any task has had a chance to touch it.
    // Running `fninit` + `ldmxcsr(0x1F80)` here only mutates the live
    // FPU state that nothing has used yet, so there's no caller state
    // to clobber. Every subsequent `FpuArea::new_initialized` clones
    // this template without touching the CPU.
    CANONICAL_FPU_IMAGE.call_once(|| {
        let mut image = FpuArea {
            bytes: [0u8; FXSAVE_SIZE],
        };
        let default_mxcsr: u32 = 0x1F80;
        // SAFETY: CR0.EM is clear and CR4.OSFXSR is set by the updates
        // above, so `fninit`, `ldmxcsr`, and `fxsave64` are all legal.
        // `image.bytes` is 64-byte aligned and 512 bytes, satisfying
        // `fxsave64`'s operand requirements.
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
        image
    });

    crate::serial_println!("fpu: FXSAVE context switch online");
}

/// Save the current CPU FPU state into `area`.
///
/// # Safety
/// - [`init`] must have run on this CPU.
/// - `area` must not alias any other FPU save currently in flight.
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn save(area: &mut FpuArea) {
    // SAFETY: caller upheld the preconditions above. The inline asm
    // writes 512 bytes into `area.bytes`; the reference guarantees
    // write-exclusive access and 64-byte alignment.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{p}]",
            p = in(reg) area.bytes.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
    }
}

/// Load the FPU state stored in `area` into the current CPU.
///
/// # Safety
/// - [`init`] must have run on this CPU.
/// - `area` must hold a valid FXSAVE image (produced by [`save`] or
///   [`FpuArea::new_initialized`]).
#[cfg(target_os = "none")]
#[inline]
pub unsafe fn restore(area: &FpuArea) {
    // SAFETY: caller upheld the preconditions above. `fxrstor64`
    // reads 512 bytes from `area.bytes`; the reference guarantees the
    // storage is live and 64-byte aligned.
    unsafe {
        core::arch::asm!(
            "fxrstor64 [{p}]",
            p = in(reg) area.bytes.as_ptr(),
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fpu_area_layout_matches_fxsave() {
        assert_eq!(core::mem::size_of::<FpuArea>(), FXSAVE_SIZE);
        assert_eq!(core::mem::align_of::<FpuArea>(), FPU_AREA_ALIGN);
        assert!(FPU_AREA_ALIGN >= FXSAVE_ALIGN);
        assert_eq!(FXSAVE_ALIGN, 16);
    }
}
