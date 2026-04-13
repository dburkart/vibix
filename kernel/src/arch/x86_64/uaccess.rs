//! Ring-0 user-memory access primitives with SMEP/SMAP enforcement.
//!
//! ## SMEP (CR4.20)
//! Blocks ring-0 fetch of instructions from user (U=1) pages. No software
//! bracket — once enabled it's always on. Mitigates ret2user exploits.
//!
//! ## SMAP (CR4.21)
//! Blocks ring-0 read/write of user pages unless RFLAGS.AC is set. The
//! `STAC`/`CLAC` instructions toggle AC without touching other flag bits.
//! Accesses outside a `stac()`/`clac()` bracket take a `#PF` with the
//! user bit set — exactly what we want if the kernel accidentally chases
//! a user pointer.
//!
//! `copy_from_user` / `copy_to_user` are the only sanctioned way to cross
//! the ring-0/ring-3 boundary from kernel code. They bounds-check the
//! user VA against the lower canonical half, bracket the byte-copy with
//! STAC/CLAC, and return `Efault` on range failure.

use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::registers::control::{Cr4, Cr4Flags};

use crate::cpu::{self, Feature};
// Single source of truth for the lower/upper canonical-half boundary.
// Re-exported so callers in this module can use the short name.
pub use crate::mem::addrspace::USER_VA_END;

/// Cached so `stac`/`clac` can skip the SMAP ops on CPUs that don't
/// implement them (e.g. `qemu64` without `-cpu max`).
static SMAP_ON: AtomicBool = AtomicBool::new(false);

/// `-EFAULT`.
pub const EFAULT: i64 = -14;

/// Zero-sized error type for `copy_from_user` / `copy_to_user`.
#[derive(Debug, Clone, Copy)]
pub struct Efault;

impl Efault {
    pub const fn as_errno(self) -> i64 {
        EFAULT
    }
}

/// Read CR4 and set SMEP / SMAP bits iff the CPU supports them.
///
/// Call after `cpu::init()` so feature detection has populated the
/// global `FEATURES`. Safe to call once; subsequent calls are a no-op
/// because setting the bit again is idempotent.
pub fn enable_smep_smap() {
    let have_smep = cpu::has(Feature::Smep);
    let have_smap = cpu::has(Feature::Smap);

    let mut flags = Cr4::read();
    if have_smep {
        flags |= Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION;
    }
    if have_smap {
        flags |= Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION;
    }
    // SAFETY: We're only asserting bits we've proven the CPU implements.
    // SMEP/SMAP enforcement is exactly the protection we want; no other
    // CR4 bits are being touched.
    unsafe { Cr4::write(flags) };

    SMAP_ON.store(have_smap, Ordering::Relaxed);

    crate::serial_println!(
        "uaccess: smep={} smap={}",
        if have_smep { "on" } else { "unavailable" },
        if have_smap { "on" } else { "unavailable" },
    );
}

/// Set RFLAGS.AC so ring-0 loads/stores of user pages are permitted.
/// No-op if the CPU lacks SMAP.
///
/// # Safety
/// Must be paired with a `clac()` before returning to arbitrary kernel
/// code. Leaving AC=1 defeats SMAP for the rest of the thread.
#[inline(always)]
unsafe fn stac() {
    if SMAP_ON.load(Ordering::Relaxed) {
        core::arch::asm!("stac", options(nomem, nostack));
    }
}

/// Clear RFLAGS.AC. Pair with a prior `stac()`.
#[inline(always)]
unsafe fn clac() {
    if SMAP_ON.load(Ordering::Relaxed) {
        core::arch::asm!("clac", options(nomem, nostack));
    }
}

/// Validate `[uva, uva + len)` lies entirely within the lower canonical
/// half. Returns `Efault` on overflow or kernel-half overlap.
///
/// Exposed so syscall handlers can reject a bad range up front before
/// any observable side effect (e.g. emitting bytes to the UART).
#[inline]
pub fn check_user_range(uva: usize, len: usize) -> Result<(), Efault> {
    if len == 0 {
        return Ok(());
    }
    let end = (uva as u64).checked_add(len as u64).ok_or(Efault)?;
    if uva as u64 >= USER_VA_END || end > USER_VA_END {
        return Err(Efault);
    }
    Ok(())
}

/// Copy `dst.len()` bytes from user VA `src_uva` into `dst`.
///
/// Bounds-checks the user range against `USER_VA_END`, then brackets the
/// byte-wise copy with `stac`/`clac`. On SMEP/SMAP-capable CPUs a stray
/// kernel pointer or an unmapped user page surfaces as a `#PF` rather
/// than silent data corruption.
///
/// # Safety
/// The active PML4 must map `[src_uva, src_uva + dst.len())` as user
/// pages. Interrupts must be disabled for the duration (SMAP is a
/// per-CPU AC bit; a context switch clobbers it). Syscalls already
/// run with IF=0 via the SFMASK we install.
pub unsafe fn copy_from_user(dst: &mut [u8], src_uva: usize) -> Result<(), Efault> {
    check_user_range(src_uva, dst.len())?;
    let src = src_uva as *const u8;
    stac();
    for i in 0..dst.len() {
        dst[i] = core::ptr::read_volatile(src.add(i));
    }
    clac();
    Ok(())
}

/// Copy `src.len()` bytes from `src` into user VA `dst_uva`.
///
/// # Safety
/// Same constraints as `copy_from_user` but the user range must be
/// mapped writable.
pub unsafe fn copy_to_user(dst_uva: usize, src: &[u8]) -> Result<(), Efault> {
    check_user_range(dst_uva, src.len())?;
    let dst = dst_uva as *mut u8;
    stac();
    for i in 0..src.len() {
        core::ptr::write_volatile(dst.add(i), src[i]);
    }
    clac();
    Ok(())
}
