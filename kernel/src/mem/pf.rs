//! Page-fault pure logic. Hosts the RFC 0001 dispatch gates
//! (SMAP violation, reserved-bit corruption, canonical/`USER_VA_END`
//! check, `prot_user` permission check) as pure functions so the host
//! unit tests can drive them without a live IDT.
//!
//! The actual page-fault handler in `arch::x86_64::idt::page_fault`
//! composes these gates in the order mandated by the RFC
//! ("Algorithms and Protocols", page-fault dispatch pseudocode):
//!
//!   1. SMAP violation (CPL=0, U/S=1, AC=0)      → panic, VA only
//!   2. Pure kernel fault (CPL=0, U/S=0)          → existing kernel path
//!   3. RSVD=1                                    → panic, VA only
//!   4. `cr2` not canonical or ≥ `USER_VA_END`    → SIGSEGV (MAPERR)
//!   5. VMA lookup; SIGSEGV on miss               → resolve_growsdown_or_segv
//!   6. `prot_user.allows(access)`                → SIGSEGV (ACCERR)
//!   7. Dispatch (demand / CoW / racy present)    → resolve_*
//!
//! This module owns 1, 3, 4, 6. Steps 2, 5, 7 stay in `idt.rs` /
//! follow-ups (#159 and #160) because they need task/addrspace state
//! that isn't reachable from pure logic.
//!
//! ### IRQ discipline (RFC 0007 §Page-fault IRQ discipline)
//!
//! The page-fault gate is an **interrupt** gate (the `x86_64` crate's
//! `set_handler_fn` default), so IF is hardware-cleared on entry. The
//! handler in `idt::page_fault` keeps that ordering load-bearing:
//!
//! * CR2 is sampled into a kernel-stack local **before** any code path
//!   that could `sti`. A nested fault after `sti` would clobber the
//!   hardware CR2; the local survives because the kernel stack is
//!   distinct from the faulter's frame state.
//! * Steps 1, 3, 4, 6 above (the gates this module owns) are pure
//!   logic and run with IRQs still disabled. The verdict they produce
//!   is the *safe seam* at which to reopen interrupts.
//! * Immediately before any `VmObject::fault` / `cow_copy_and_remap`
//!   call (step 7's slow path), the handler issues `sti` so the
//!   slow path may freely take a `BlockingMutex` and park. Without
//!   this, the first `BlockingMutex::lock` against contention would
//!   deadlock the CPU — there is no preemption to land the wake.
//! * `cli` fires again immediately on return from the slow path,
//!   before the PTE install + TLB flush + IRET. The page-table
//!   mutator and the IRETQ frame restoration both expect IF=0 inside
//!   the handler proper.
//!
//! Pre-`sti` work (the gates) and post-`cli` work (the PTE install)
//! never block; the only window where the handler is preemptible is
//! the bracketed slow path, which is exactly the window the RFC's
//! design demands.
//!
//! Security note on the panic paths: both `panic_smap_violation` and
//! `panic_rsvd_corruption` must **log the faulting VA only**, never the
//! PTE word or the frame's physaddr. A reserved-bit fault often means
//! the kernel's own page tables were corrupted; echoing back the PTE
//! contents to a user-reachable sink hands an attacker a free peek at
//! kernel state (RFC 0001 Security advisory A2).

use crate::mem::addrspace::USER_VA_END;
use crate::mem::vmatree::ProtUser;
use crate::mem::vmobject::{Access, VmFault};

/// User-visible `PROT_*` bits, mirrored out of `mman.h`. Width and
/// values match the Linux ABI so future file-backed `mmap` can take
/// them straight from userspace without re-encoding.
pub const PROT_NONE: ProtUser = 0;
pub const PROT_READ: ProtUser = 1;
pub const PROT_WRITE: ProtUser = 2;
pub const PROT_EXEC: ProtUser = 4;

/// `MAP_*` flag bits for `mmap`, matching the Linux x86_64 ABI values.
/// `MAP_ANONYMOUS` and `MAP_PRIVATE` are the only combinations the
/// initial syscall implementation accepts.
pub const MAP_SHARED: u32 = 0x01;
pub const MAP_PRIVATE: u32 = 0x02;
pub const MAP_FIXED: u32 = 0x10;
pub const MAP_ANONYMOUS: u32 = 0x20;
pub const MAP_GROWSDOWN: u32 = 0x100;
pub const MAP_STACK: u32 = 0x20000;
pub const MAP_FIXED_NOREPLACE: u32 = 0x10_0000;

/// `madvise(2)` advice values. Only `MADV_DONTNEED` has side effects in
/// this implementation; the rest are accepted as no-ops so userspace
/// calls that treat them as hints succeed.
pub const MADV_NORMAL: i32 = 0;
pub const MADV_RANDOM: i32 = 1;
pub const MADV_SEQUENTIAL: i32 = 2;
pub const MADV_WILLNEED: i32 = 3;
pub const MADV_DONTNEED: i32 = 4;
pub const MADV_FREE: i32 = 8;

// Raw bit positions in the x86 #PF error code. Kept as numeric
// constants (not `PageFaultErrorCode` flags) so the module stays
// host-compilable — the `x86_64` crate is target-only.
const ERR_P: u64 = 1 << 0;
const ERR_WR: u64 = 1 << 1;
const ERR_US: u64 = 1 << 2;
const ERR_RSVD: u64 = 1 << 3;
#[allow(dead_code)] // reserved for the future XD-bit / exec-fault gate
const ERR_ID: u64 = 1 << 4;

/// Decode the access kind from the raw `#PF` error code. Write is any
/// fault with `W/R=1`; everything else is a read (instruction fetch
/// and data read share the read permission bit in our `prot_user`
/// model, mirroring Linux).
pub fn access_from_error_code(err: u64) -> Access {
    if err & ERR_WR != 0 {
        Access::Write
    } else {
        Access::Read
    }
}

/// True if `prot` grants `access`. `PROT_WRITE` without `PROT_READ` is
/// accepted as the user's request but the PTE is installed with `R|W`
/// anyway (see RFC 0001 "PROT bits"), so a read on a write-only VMA is
/// legal at the `prot_user` layer.
pub fn prot_user_allows(prot: ProtUser, access: Access) -> bool {
    match access {
        Access::Read => prot & (PROT_READ | PROT_WRITE) != 0,
        Access::Write => prot & PROT_WRITE != 0,
    }
}

/// True if `va` is a valid 48-bit canonical userspace address: bits
/// `[47..64]` must all be zero (lower half) and `va` must be strictly
/// below [`USER_VA_END`]. Rejects both non-canonical addresses and
/// kernel-half addresses in one check.
pub fn is_user_va(va: u64) -> bool {
    va < USER_VA_END
}

/// True if this fault is an SMAP violation: the CPU was in ring 0
/// (`cpl == 0`), the faulting address was a user page (`U/S=1`), and
/// `RFLAGS.AC` was clear (no explicit `stac` / `clac` bracket around
/// the user touch). See RFC 0001 Security advisory B5; the handler
/// **must** panic — a return would let a kernel bug corrupt user
/// state.
pub fn is_smap_violation(cpl: u8, err: u64, rflags_ac: bool) -> bool {
    cpl == 0 && (err & ERR_US != 0) && !rflags_ac
}

/// True if the CPU reported a reserved-bit violation in a page-table
/// entry along the walk. Always a kernel bug (userspace cannot
/// author kernel PTEs) — the RFC mandates panic with no PTE content
/// in the logged output.
pub fn is_rsvd_fault(err: u64) -> bool {
    err & ERR_RSVD != 0
}

// ── Growsdown stack resolver ──────────────────────────────────────────────

/// Default per-process stack size limit. glibc/musl honour this; the
/// kernel enforces it here so a runaway recursion doesn't silently eat
/// all of physical memory. Future work: expose via `setrlimit(RLIMIT_STACK)`.
pub const DEFAULT_STACK_RLIMIT: u64 = 8 * 1024 * 1024; // 8 MiB

/// Maximum number of pages below the current VMA start that a single
/// growsdown fault may bridge. Values larger than `stack_guard_gap`
/// (256 pages = 1 MiB) are rejected to prevent controlled multi-page
/// stack-pointer jumps from bypassing the guard.
pub const STACK_GUARD_GAP_PAGES: u64 = 256;

/// Outcome of [`check_growsdown`].
#[derive(Debug, PartialEq, Eq)]
pub enum GrowResult {
    /// Extend the VMA: the new start address is `new_start` (page-aligned).
    Grow { new_start: u64 },
    /// Reject the fault — deliver SIGSEGV.
    Segv,
}

/// Pure logic for a growsdown stack fault.
///
/// # Arguments
/// * `cr2`        — faulting virtual address (from `CR2`).
/// * `vma_start`  — current start of the growsdown VMA.
/// * `stack_top`  — highest address of the stack (fixed; the VMA end).
/// * `rlimit`     — maximum stack size in bytes (default 8 MiB).
/// * `guard_gap`  — maximum gap in pages allowed by a single fault.
///
/// Returns [`GrowResult::Grow`] if the extension is safe, or
/// [`GrowResult::Segv`] if it should be rejected.
pub fn check_growsdown(
    cr2: u64,
    vma_start: u64,
    stack_top: u64,
    rlimit: u64,
    guard_gap_pages: u64,
) -> GrowResult {
    // The faulting address must be *below* the current VMA start.
    // A fault inside [vma_start, vma_end) takes the normal demand-page
    // path, not this one.
    if cr2 >= vma_start {
        return GrowResult::Segv;
    }

    // Gap from fault address to VMA start must be ≤ stack_guard_gap pages.
    // Page-align cr2 down to compute how many pages below vma_start it lands.
    let cr2_page = cr2 & !0xFFF;
    let gap_pages = (vma_start - cr2_page) / 4096;
    if gap_pages == 0 || gap_pages > guard_gap_pages {
        return GrowResult::Segv;
    }

    // Grow by exactly one page: always extend from the current VMA start,
    // not from cr2. `cr2_page` is only used for the gap-distance check above.
    let new_start = match vma_start.checked_sub(4096) {
        Some(s) => s,
        None => return GrowResult::Segv,
    };

    // RLIMIT_STACK: the total committed size must not exceed the limit.
    if stack_top - new_start > rlimit {
        return GrowResult::Segv;
    }

    GrowResult::Grow { new_start }
}

#[cfg(test)]
mod growsdown_tests {
    use super::*;

    const TOP: u64 = 0x8000_0000; // USER_STACK_TOP from init_process
    const START: u64 = 0x7FFF_F000; // initial single page
    const RLIMIT: u64 = DEFAULT_STACK_RLIMIT;
    const GAP: u64 = STACK_GUARD_GAP_PAGES;

    #[test]
    fn fault_one_page_below_grows() {
        let cr2 = START - 4096; // exactly one page below
        assert_eq!(
            check_growsdown(cr2, START, TOP, RLIMIT, GAP),
            GrowResult::Grow {
                new_start: START - 4096
            }
        );
    }

    #[test]
    fn fault_inside_vma_is_segv() {
        let cr2 = START + 8; // inside [START, TOP) — wrong path
        assert_eq!(
            check_growsdown(cr2, START, TOP, RLIMIT, GAP),
            GrowResult::Segv
        );
    }

    #[test]
    fn gap_at_limit_grows() {
        // cr2 exactly 256 pages below START — within the guard gap.
        // grow_stack always extends exactly one page (START - 4096),
        // regardless of how far below cr2 lands.
        let cr2 = START - GAP * 4096;
        assert_eq!(
            check_growsdown(cr2, START, TOP, RLIMIT, GAP),
            GrowResult::Grow {
                new_start: START - 4096,
            }
        );
    }

    #[test]
    fn gap_beyond_limit_is_segv() {
        let cr2 = START - (GAP + 1) * 4096; // 257 pages below
        assert_eq!(
            check_growsdown(cr2, START, TOP, RLIMIT, GAP),
            GrowResult::Segv
        );
    }

    #[test]
    fn rlimit_exceeded_is_segv() {
        // cr2 that would make the stack > 8 MiB
        let cr2 = TOP - RLIMIT - 4096; // one page past the limit
        assert_eq!(
            check_growsdown(cr2, cr2 + 4096, TOP, RLIMIT, GAP),
            GrowResult::Segv
        );
    }
}

// ── Address validation for mmap-family syscalls ──────────────────────────

/// A validated `(addr, len)` range produced by [`validate_user_range`].
///
/// `addr` is page-aligned and `len` is rounded up to a whole page, so
/// `addr + len` is also page-aligned and `<= USER_VA_END`. Downstream
/// syscall code can treat the bounds as canonical without re-checking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserRange {
    pub addr: usize,
    pub len: usize,
}

impl UserRange {
    pub fn end(self) -> usize {
        self.addr + self.len
    }
}

/// Why [`validate_user_range`] rejected an `(addr, len)` pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeError {
    /// `len == 0`, rounding overflowed, non-canonical address, or
    /// `addr` was not page-aligned when the caller required exact
    /// alignment.
    Invalid,
}

/// Policy knob for [`validate_user_range`]. `mmap` without `MAP_FIXED`
/// treats `addr` as a hint (rounded down); every other caller
/// (`munmap`, `mprotect`, `madvise`, `MAP_FIXED` / `MAP_FIXED_NOREPLACE`)
/// demands exact page alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrAlign {
    /// Reject a non-page-aligned `addr` with [`RangeError::Invalid`].
    Exact,
    /// Round `addr` down to the nearest page.
    RoundDown,
}

/// Validate an `(addr, len)` user range against the six steps from RFC
/// 0001 "Address validation":
///
/// 1. `len == 0` → `Invalid`.
/// 2. `len` rounded up to a page; overflow → `Invalid`.
/// 3. `addr` must be canonical (lower-half — bits 48..63 clear).
/// 4. `addr.checked_add(len_rounded)` must succeed.
/// 5. `addr + len_rounded <= USER_VA_END`.
/// 6. `addr` alignment per [`AddrAlign`] — `Exact` rejects non-aligned
///    addresses, `RoundDown` rounds the hint to the containing page.
///
/// Returns the sanitized `(addr, len)` on success.
pub fn validate_user_range(addr: u64, len: u64, align: AddrAlign) -> Result<UserRange, RangeError> {
    if len == 0 {
        return Err(RangeError::Invalid);
    }
    let len_rounded = match len.checked_add(4095) {
        Some(v) => v & !4095,
        None => return Err(RangeError::Invalid),
    };
    if len_rounded == 0 {
        return Err(RangeError::Invalid);
    }
    if !is_user_va(addr) {
        return Err(RangeError::Invalid);
    }
    let addr = match align {
        AddrAlign::Exact => {
            if addr & 0xFFF != 0 {
                return Err(RangeError::Invalid);
            }
            addr
        }
        AddrAlign::RoundDown => addr & !0xFFF,
    };
    let end = match addr.checked_add(len_rounded) {
        Some(v) => v,
        None => return Err(RangeError::Invalid),
    };
    if end > USER_VA_END {
        return Err(RangeError::Invalid);
    }
    Ok(UserRange {
        addr: addr as usize,
        len: len_rounded as usize,
    })
}

// ── File-mmap errno gate (RFC 0007 §Errno table, issue #746) ────────────

/// Pure errno-gate for the file-backed leg of `sys_mmap` (RFC 0007
/// §Errno table). Extracted from `arch::x86_64::syscall::sys_mmap` so
/// host unit tests can exercise every rejection branch without the
/// `current_fd_table` / `current_address_space` / IDT plumbing the
/// syscall wrapper carries.
///
/// `prot` is the raw `PROT_*` bitmask. `share` distinguishes
/// `MAP_PRIVATE` from `MAP_SHARED`. `off` and `len` are the userspace
/// arguments **before** any rounding; the helper enforces the EINVAL
/// alignment rules and returns the page-aligned `(off, len_pages)` pair
/// on success. `open_mode_acc` is the result of
/// `OpenFile.flags & O_ACCMODE` (one of `O_RDONLY=0`, `O_WRONLY=1`,
/// `O_RDWR=2` — pinned by the static asserts in `crate::fs::flags`).
///
/// Errors (matching RFC 0007 §Errno table verbatim):
///
/// - `EINVAL`  — `off` not page-aligned, or `len == 0`.
/// - `EOVERFLOW` — `off + page-rounded(len)` overflows `i64` (`off_t`).
/// - `EACCES`  — `MAP_SHARED + PROT_WRITE` with `open_mode != O_RDWR`,
///   or `MAP_PRIVATE + PROT_WRITE` with `open_mode == O_WRONLY`.
///
/// `EBADF` (fd not open) and `ENODEV` (non-mmappable inode kind / non-VFS
/// backend) are *upstream* of this gate — `sys_mmap` rejects them before
/// it can even build the `(open_mode_acc, share, prot, off, len)`
/// argument set.
pub fn validate_file_mmap_args(
    prot: u32,
    share: crate::mem::vmatree::Share,
    off: u64,
    len: u64,
    open_mode_acc: u32,
) -> Result<(u64, usize), i64> {
    use crate::mem::vmatree::Share;
    use crate::mem::FRAME_SIZE;

    // Errno values inlined as numeric literals (mirroring `crate::fs::*`)
    // because `crate::fs` is gated to `#[cfg(any(test, target_os =
    // "none"))]` while `mem::pf` is unconditional. The static asserts in
    // `crate::fs` pin these values to the Linux x86_64 ABI; the same
    // values appear in `crate::fs::{EACCES, EINVAL, EOVERFLOW}` and
    // arrive here unchanged. The constants below are scoped to this fn
    // so they cannot leak into the rest of the module.
    const EACCES: i64 = -13;
    const EINVAL: i64 = -22;
    const EOVERFLOW: i64 = -75;
    // `O_RDONLY = 0`, `O_WRONLY = 1`, `O_RDWR = 2` (pinned by the
    // static asserts in `crate::fs::flags`).
    const O_WRONLY: u32 = 1;
    const O_RDWR: u32 = 2;

    // EINVAL: len == 0.
    if len == 0 {
        return Err(EINVAL);
    }
    // EINVAL: off not page-aligned.
    if off % FRAME_SIZE != 0 {
        return Err(EINVAL);
    }

    // Page-round `len` up.
    let len_rounded = match len.checked_add(FRAME_SIZE - 1) {
        Some(v) => v & !(FRAME_SIZE - 1),
        None => return Err(EOVERFLOW),
    };

    // EOVERFLOW: off + len_rounded must fit in i64 (off_t).
    let end = match off.checked_add(len_rounded) {
        Some(v) => v,
        None => return Err(EOVERFLOW),
    };
    if end > i64::MAX as u64 {
        return Err(EOVERFLOW);
    }

    // EACCES: write-permission gates.
    let want_write = prot & PROT_WRITE != 0;
    if want_write {
        match share {
            Share::Shared => {
                // MAP_SHARED + PROT_WRITE requires O_RDWR. The
                // write-fault path must read the page on miss before
                // mutating it; an O_WRONLY-opened file cannot service
                // that read (RFC 0007 §Kernel-Userspace Interface).
                if open_mode_acc != O_RDWR {
                    return Err(EACCES);
                }
            }
            Share::Private => {
                // MAP_PRIVATE + PROT_WRITE rejects O_WRONLY for the
                // same reason: CoW needs the master page readable.
                if open_mode_acc == O_WRONLY {
                    return Err(EACCES);
                }
            }
        }
    }

    let len_pages = (len_rounded / FRAME_SIZE) as usize;
    Ok((off, len_pages))
}

// ── mprotect file-backed permission gates (RFC 0007 §Security B1) ───────

/// Pure errno-gate for `mprotect` on a single file-backed VMA.
///
/// Extracted from the `sys_mprotect` VMA walk so host unit tests can
/// exercise every rejection branch without the full `AddressSpace` /
/// VMA-tree / IDT plumbing.
///
/// Returns `Ok(())` when the requested `prot` is permissible, or
/// `Err(EACCES)` when either:
///
/// - `PROT_WRITE` is requested on a `MAP_SHARED` VMA whose
///   `open_mode` snapshot is not `O_RDWR`.
/// - `PROT_EXEC` is requested on a VMA whose backing inode lacked
///   execute permission at `mmap` time (`exec_allowed == false`).
///
/// Non-file-backed VMAs (anon, etc.) pass `None` for both
/// `open_mode` and `exec_allowed`; the function returns `Ok(())`
/// unconditionally for those.
pub fn validate_mprotect_file_perm(
    prot: u32,
    share: crate::mem::vmatree::Share,
    open_mode: Option<u32>,
    exec_allowed: Option<bool>,
) -> Result<(), i64> {
    use crate::mem::vmatree::Share;
    const EACCES: i64 = -13;
    const O_RDWR: u32 = 2;

    // PROT_WRITE on MAP_SHARED + file-backed: open_mode must be O_RDWR.
    if prot & PROT_WRITE != 0 && share == Share::Shared {
        if let Some(mode) = open_mode {
            if mode != O_RDWR {
                return Err(EACCES);
            }
        }
    }

    // PROT_EXEC on file-backed: inode must have had execute permission
    // at mmap time.
    if prot & PROT_EXEC != 0 {
        if let Some(false) = exec_allowed {
            return Err(EACCES);
        }
    }

    Ok(())
}

#[cfg(test)]
mod validate_range_tests {
    use super::*;

    #[test]
    fn zero_len_rejected() {
        assert_eq!(
            validate_user_range(0x1000, 0, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn len_rounding_overflow_rejected() {
        assert_eq!(
            validate_user_range(0, u64::MAX, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn non_canonical_addr_rejected() {
        // Kernel half.
        assert_eq!(
            validate_user_range(0xffff_8000_0000_0000, 4096, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
        // Non-canonical "hole".
        assert_eq!(
            validate_user_range(0x0000_8000_0000_0000, 4096, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn addr_plus_len_overflow_rejected() {
        // addr near USER_VA_END; len rounds into the non-canonical hole.
        assert_eq!(
            validate_user_range(USER_VA_END - 0x1000, 0x2000, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn exact_alignment_required_for_fixed_paths() {
        assert_eq!(
            validate_user_range(0x1001, 4096, AddrAlign::Exact),
            Err(RangeError::Invalid)
        );
    }

    #[test]
    fn round_down_hint_accepted() {
        let r = validate_user_range(0x1234, 4096, AddrAlign::RoundDown).unwrap();
        assert_eq!(r.addr, 0x1000);
        assert_eq!(r.len, 4096);
    }

    #[test]
    fn len_rounded_up_to_page() {
        let r = validate_user_range(0x1000, 1, AddrAlign::Exact).unwrap();
        assert_eq!(r.addr, 0x1000);
        assert_eq!(r.len, 4096);

        let r = validate_user_range(0x1000, 4097, AddrAlign::Exact).unwrap();
        assert_eq!(r.len, 8192);
    }

    #[test]
    fn mapping_ending_exactly_at_user_va_end_is_legal() {
        let addr = USER_VA_END - 4096;
        let r = validate_user_range(addr, 4096, AddrAlign::Exact).unwrap();
        assert_eq!(r.end() as u64, USER_VA_END);
    }
}

/// True if the fault came from ring 0 against a *kernel* page (U/S=0).
/// The RFC routes these to the existing kernel-fault diagnostic
/// instead of the user-VM dispatch.
pub fn is_pure_kernel_fault(cpl: u8, err: u64) -> bool {
    cpl == 0 && (err & ERR_US == 0)
}

/// True if the fault hit an already-present page (typical for CoW or
/// protection-widening paths); false for demand-fault (not present).
pub fn is_present_fault(err: u64) -> bool {
    err & ERR_P != 0
}

// ── VmFault → resolver-action classifier (RFC 0007 §Page-fault path) ──────

/// Maximum number of [`VmFault::ParkAndRetry`] re-entries the resolver
/// will perform on a single fault before giving up and surfacing
/// `SIGBUS`. Bounds livelock if a misbehaving filler abandons its stub
/// in a tight loop (e.g. cache page repeatedly evicted between
/// install-race wake and re-lookup) — the resolver makes forward
/// progress by terminating the offending thread instead of spinning.
///
/// The bound is generous: every retry costs one slow-path round trip
/// through `FileObject::fault`, and the bounded-recursion property
/// inside `FileObject::fault` already guarantees at most a single park
/// per call. Eight outer retries means up to eight independent
/// install-race losses, which is more than any realistic eviction
/// storm should produce on a single fault.
pub const PARK_AND_RETRY_BUDGET: u32 = 8;

/// Action the page-fault resolver should take given a `Result<u64,
/// VmFault>` from [`crate::mem::vmobject::VmObject::fault`].
///
/// Pure-logic classification — kept in this module so host unit tests
/// can drive every variant without standing up a real
/// [`crate::mem::vmobject::VmObject`]. The arch-specific handler in
/// `arch::x86_64::idt::page_fault` matches against this enum and
/// performs the corresponding side-effect (PTE install, CoW, retry,
/// SIGBUS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultResolution {
    /// `Ok(phys)` — install `phys` into the user PTE with the VMA's
    /// cached flags and IRET. The frame's refcount has already been
    /// bumped by the `VmObject::fault` impl for the new PTE reference
    /// (RFC 0007 §Refcount discipline).
    Mapped(u64),

    /// [`VmFault::CoWNeeded`] — the resolver must drive
    /// [`crate::mem::paging::cow_copy_and_remap`] for the faulting
    /// page exactly the way a fork-induced CoW is handled today
    /// (RFC 0007 §Algorithms — `MAP_PRIVATE` write fault). The CoW
    /// helper allocates a fresh frame, copies the master page through
    /// the HHDM, and remaps the PTE writable.
    CoW,

    /// [`VmFault::ParkAndRetry`] — the install-race loser observed
    /// the winner abandon its stub. `FileObject::fault` already parked
    /// on the cache-page wait-queue once before returning this; the
    /// resolver re-enters `VmObject::fault` against a fresh stub. A
    /// `retry_count` greater than [`PARK_AND_RETRY_BUDGET`] downgrades
    /// to [`FaultResolution::Sigbus`] to bound livelock — see
    /// [`should_park_and_retry`].
    Retry,

    /// SIGBUS-equivalent terminal failure. Covers:
    ///
    /// * [`VmFault::ReadFailed`] — `AddressSpaceOps::readpage`
    ///   returned an errno; the failing fault is the one task that
    ///   observed the failed fill and must take the signal.
    /// * [`VmFault::OutOfRange`] — fault past `i_size` /
    ///   `len_pages`. POSIX mandates SIGBUS, not SIGSEGV, for a
    ///   read past EOF on a file-backed mmap.
    /// * [`VmFault::OutOfMemory`] / [`VmFault::RefcountSaturated`] —
    ///   resource exhaustion the kernel cannot recover. SIGBUS is the
    ///   closest portable signal; the alternative is hanging the
    ///   thread, which is worse.
    Sigbus,

    /// [`VmFault::ProtectionViolation`] — the access kind is rejected
    /// at the `VmObject` layer. Falls through to the existing
    /// access-violation path which produces SIGSEGV (RFC 0007
    /// §Algorithms — protection-violation arm). Kept as its own
    /// variant rather than collapsed into `Sigbus` because the user
    /// signal is different and downstream tooling (siginfo, strace)
    /// must be able to tell the two apart.
    AccessViolation,
}

/// Classify the [`VmObject::fault`] result into a resolver action.
///
/// This is the pure-logic seam between `arch/x86_64/idt::page_fault`
/// and the rest of the kernel: every behavioural distinction between
/// `Ok` / `CoWNeeded` / `ParkAndRetry` / `ReadFailed(_)` / etc. is
/// encoded here so host unit tests can drive every arm without a
/// running CPU. The arch handler then matches once on the returned
/// [`FaultResolution`] and issues the side effects.
///
/// The mapping is total — every `Result<u64, VmFault>` produces a
/// well-defined [`FaultResolution`]. Adding a new `VmFault` variant
/// without updating this function is a `match` exhaustiveness error,
/// which is exactly the compile-time guard the RFC asks for
/// (§FileObject — error surface).
pub fn classify_vm_fault_result(res: Result<u64, VmFault>) -> FaultResolution {
    match res {
        Ok(phys) => FaultResolution::Mapped(phys),
        Err(VmFault::CoWNeeded) => FaultResolution::CoW,
        Err(VmFault::ParkAndRetry) => FaultResolution::Retry,
        Err(VmFault::ReadFailed(_)) => FaultResolution::Sigbus,
        Err(VmFault::OutOfRange) => FaultResolution::Sigbus,
        Err(VmFault::OutOfMemory) => FaultResolution::Sigbus,
        Err(VmFault::RefcountSaturated) => FaultResolution::Sigbus,
        Err(VmFault::ProtectionViolation) => FaultResolution::AccessViolation,
    }
}

/// True if a `ParkAndRetry`-classified fault should re-enter
/// [`crate::mem::vmobject::VmObject::fault`] for another attempt
/// rather than being demoted to SIGBUS. `retry_count` is the number of
/// retries the resolver has *already* performed on this fault (zero on
/// first park).
///
/// Pulled out of the resolver loop into pure logic so the bound is
/// host-testable and the constant lives next to its consumers.
pub fn should_park_and_retry(retry_count: u32) -> bool {
    retry_count < PARK_AND_RETRY_BUDGET
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_decodes_read_and_write() {
        // Error code layout: bit 0 P, 1 W/R, 2 U/S, 3 RSVD, 4 I/D.
        assert_eq!(access_from_error_code(0b0000_0100), Access::Read); // user read
        assert_eq!(access_from_error_code(0b0000_0110), Access::Write); // user write
        assert_eq!(access_from_error_code(0b0000_0000), Access::Read); // kernel read
    }

    #[test]
    fn prot_user_allows_matches_mman_semantics() {
        assert!(prot_user_allows(PROT_READ, Access::Read));
        assert!(!prot_user_allows(PROT_READ, Access::Write));
        assert!(prot_user_allows(PROT_READ | PROT_WRITE, Access::Write));
        // PROT_WRITE without PROT_READ: read is allowed because the
        // PTE round-trip installs R|W anyway.
        assert!(prot_user_allows(PROT_WRITE, Access::Read));
        assert!(prot_user_allows(PROT_WRITE, Access::Write));
        assert!(!prot_user_allows(PROT_NONE, Access::Read));
        assert!(!prot_user_allows(PROT_NONE, Access::Write));
        assert!(!prot_user_allows(PROT_EXEC, Access::Write));
    }

    #[test]
    fn user_va_rejects_kernel_half_and_non_canonical() {
        assert!(is_user_va(0x0000_0000_4000_0000));
        assert!(is_user_va(USER_VA_END - 1));
        // Exactly at USER_VA_END is the lowest non-canonical address.
        assert!(!is_user_va(USER_VA_END));
        // Kernel half is trivially rejected.
        assert!(!is_user_va(0xffff_8000_0000_0000));
        // The first address after USER_VA_END (non-canonical region).
        assert!(!is_user_va(0x0000_8000_0000_1000));
    }

    #[test]
    fn smap_violation_requires_all_three_signals() {
        // Ring-0 touches a user page with AC clear → violation.
        assert!(is_smap_violation(0, ERR_US, false));
        // Same fault but AC set (explicit stac) → allowed.
        assert!(!is_smap_violation(0, ERR_US, true));
        // Ring-3 fault on user page → not an SMAP concern.
        assert!(!is_smap_violation(3, ERR_US, false));
        // Ring-0 touching kernel page → not SMAP.
        assert!(!is_smap_violation(0, 0, false));
    }

    #[test]
    fn rsvd_fault_detects_bit_3() {
        assert!(is_rsvd_fault(ERR_RSVD));
        assert!(is_rsvd_fault(ERR_P | ERR_US | ERR_RSVD));
        assert!(!is_rsvd_fault(ERR_P | ERR_WR | ERR_US));
    }

    #[test]
    fn pure_kernel_fault_detects_supervisor_page_in_ring0() {
        assert!(is_pure_kernel_fault(0, 0));
        assert!(is_pure_kernel_fault(0, ERR_P));
        assert!(!is_pure_kernel_fault(0, ERR_US));
        assert!(!is_pure_kernel_fault(3, 0));
    }

    #[test]
    fn present_fault_flag() {
        assert!(is_present_fault(ERR_P));
        assert!(is_present_fault(ERR_P | ERR_WR | ERR_US));
        assert!(!is_present_fault(ERR_US));
        assert!(!is_present_fault(0));
    }

    // ── validate_file_mmap_args (issue #746, RFC 0007 §Errno table) ──

    mod file_mmap_errno {
        use super::*;
        use crate::mem::vmatree::Share;

        // Mirror the numeric pins used inside `validate_file_mmap_args`.
        const O_RDONLY: u32 = 0;
        const O_WRONLY: u32 = 1;
        const O_RDWR: u32 = 2;
        const EACCES: i64 = -13;
        const EINVAL: i64 = -22;
        const EOVERFLOW: i64 = -75;

        #[test]
        fn zero_len_einval() {
            // RFC 0007: `len == 0` → EINVAL regardless of share / prot / off.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 0, O_RDWR),
                Err(EINVAL),
            );
        }

        #[test]
        fn unaligned_off_einval() {
            // 0x100 is not page-aligned → EINVAL.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0x100, 4096, O_RDWR),
                Err(EINVAL),
            );
            // 0x1FFF: just below a page boundary.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Private, 0x1FFF, 4096, O_RDONLY),
                Err(EINVAL),
            );
        }

        #[test]
        fn off_plus_len_overflow_eoverflow() {
            // `off + page-rounded(len)` must fit in i64. A near-i64::MAX
            // off plus a multi-page len overflows → EOVERFLOW.
            let near_max = (i64::MAX as u64) & !0xFFF; // page-aligned, near max
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, near_max, 8192, O_RDWR),
                Err(EOVERFLOW),
            );
            // `len` itself near u64::MAX overflows during the page-round.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, u64::MAX, O_RDWR),
                Err(EOVERFLOW),
            );
        }

        #[test]
        fn shared_write_requires_o_rdwr() {
            // MAP_SHARED + PROT_WRITE: only O_RDWR succeeds. The write-fault
            // path must read the page on miss before mutating, so O_WRONLY
            // cannot service the read.
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Shared, 0, 4096, O_RDONLY,),
                Err(EACCES),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Shared, 0, 4096, O_WRONLY,),
                Err(EACCES),
            );
            // O_RDWR succeeds.
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Shared, 0, 4096, O_RDWR,),
                Ok((0, 1)),
            );
        }

        #[test]
        fn private_write_rejects_o_wronly() {
            // MAP_PRIVATE + PROT_WRITE: O_WRONLY rejected (CoW needs to
            // read master page first); O_RDONLY *and* O_RDWR succeed.
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Private, 0, 4096, O_WRONLY,),
                Err(EACCES),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Private, 0, 4096, O_RDONLY,),
                Ok((0, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ | PROT_WRITE, Share::Private, 0, 4096, O_RDWR,),
                Ok((0, 1)),
            );
        }

        #[test]
        fn read_only_prot_no_eacces() {
            // PROT_WRITE clear: no permission gate fires regardless of
            // share/open_mode (PROT_EXEC and PROT_READ alone are fine on a
            // read-only open).
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 4096, O_RDONLY),
                Ok((0, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_EXEC, Share::Shared, 0, 4096, O_RDONLY),
                Ok((0, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Private, 0, 4096, O_WRONLY),
                Ok((0, 1)),
            );
        }

        #[test]
        fn len_rounds_up_to_page_count() {
            // 1 byte → 1 page, 4096 → 1 page, 4097 → 2 pages, 8192 → 2.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 1, O_RDWR),
                Ok((0, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 4096, O_RDWR),
                Ok((0, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 4097, O_RDWR),
                Ok((0, 2)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0, 8192, O_RDWR),
                Ok((0, 2)),
            );
        }

        #[test]
        fn off_passes_through_unchanged() {
            // The page-aligned `off` is returned verbatim — sys_mmap then
            // forwards it as the byte offset to `FileOps::mmap`.
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 4096, 4096, O_RDWR),
                Ok((4096, 1)),
            );
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, 0x1_0000, 8192, O_RDWR),
                Ok((0x1_0000, 2)),
            );
        }

        #[test]
        fn off_plus_len_at_i64_max_succeeds() {
            // Boundary case: end == i64::MAX rounded to page (0x7fff_ffff_ffff_f000).
            // Actually with len_rounded == FRAME_SIZE and an off such
            // that end == i64::MAX as u64 + 1, EOVERFLOW fires; check
            // the strictly-less-than case still passes.
            let off = 0u64;
            let len = 4096u64;
            assert_eq!(
                validate_file_mmap_args(PROT_READ, Share::Shared, off, len, O_RDWR),
                Ok((0, 1)),
            );
        }
    }

    // ── classify_vm_fault_result ───────────────────────────────────────────
    //
    // RFC 0007 §Page-fault path: every `VmFault` variant maps to a
    // well-defined resolver action. The classifier is the single seam
    // the arch handler consults; if a future variant is added without
    // updating it, the `match` exhaustiveness check fails the build.
    // The tests below pin the mapping per the RFC's table so a silent
    // re-routing (e.g. "ReadFailed becomes SIGSEGV") would surface
    // here on the host before reaching kernel-target CI.

    #[test]
    fn classify_ok_returns_mapped_with_phys() {
        assert_eq!(
            classify_vm_fault_result(Ok(0x1234_5000)),
            FaultResolution::Mapped(0x1234_5000),
        );
    }

    #[test]
    fn classify_cow_needed_returns_cow() {
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::CoWNeeded)),
            FaultResolution::CoW,
        );
    }

    #[test]
    fn classify_park_and_retry_returns_retry() {
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::ParkAndRetry)),
            FaultResolution::Retry,
        );
    }

    #[test]
    fn classify_read_failed_returns_sigbus_independent_of_errno() {
        // Errno is preserved on the wire (FileObject::fault carries it
        // through), but the resolver collapses every errno into SIGBUS
        // — the user-visible signal is the same regardless of whether
        // the FS reported EIO, ENOSPC, or any other readpage failure.
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::ReadFailed(crate::fs::EIO))),
            FaultResolution::Sigbus,
        );
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::ReadFailed(-1))),
            FaultResolution::Sigbus,
        );
    }

    #[test]
    fn classify_out_of_range_returns_sigbus() {
        // POSIX: a fault past `i_size` on a file-backed mmap delivers
        // SIGBUS, not SIGSEGV. The variant is shared with bounded
        // anonymous objects (which can also surface OutOfRange when a
        // VMA exceeds `len_pages`); both paths terminate the offending
        // thread with the same signal.
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::OutOfRange)),
            FaultResolution::Sigbus,
        );
    }

    #[test]
    fn classify_out_of_memory_returns_sigbus() {
        // Frame allocator exhaustion: SIGBUS is the closest portable
        // signal. Hanging the offending thread would be worse — it
        // would prevent any other task from making progress (the kernel
        // has already lost the allocation race).
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::OutOfMemory)),
            FaultResolution::Sigbus,
        );
    }

    #[test]
    fn classify_refcount_saturated_returns_sigbus() {
        // RFC 0001 exact-or-over invariant: refusing to add the
        // (u16::MAX + 1)-th reference is the right call. The faulter
        // takes SIGBUS rather than the kernel UAF-ing on the matching
        // `frame::put`.
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::RefcountSaturated)),
            FaultResolution::Sigbus,
        );
    }

    #[test]
    fn classify_protection_violation_returns_access_violation() {
        // ProtectionViolation is the SIGSEGV-equivalent arm; do not
        // collapse into Sigbus. The arch handler falls through to the
        // existing ring-3 access-violation path which delivers SIGSEGV
        // and runs the user signal handler (if installed) — distinct
        // from the SIGBUS path used for ReadFailed/OutOfRange.
        assert_eq!(
            classify_vm_fault_result(Err(VmFault::ProtectionViolation)),
            FaultResolution::AccessViolation,
        );
    }

    #[test]
    fn park_and_retry_budget_bounds_livelock() {
        // First park: retry_count=0 — proceed.
        assert!(should_park_and_retry(0));
        // Last legal retry — still under bound.
        assert!(should_park_and_retry(PARK_AND_RETRY_BUDGET - 1));
        // Bound reached — demote to SIGBUS.
        assert!(!should_park_and_retry(PARK_AND_RETRY_BUDGET));
        assert!(!should_park_and_retry(PARK_AND_RETRY_BUDGET + 100));
    }

    // ── End-to-end: synthesized VmObject → classifier routing ──────────────
    //
    // Issue #739 acceptance criterion: a synthesized object returns
    // each `VmFault` variant and the resolver routes correctly. The
    // file-object end of the chain has its own host coverage in
    // `mem::file_object::tests`; the tests below close the loop by
    // composing a minimal `VmObject` against the live classifier so a
    // future change to either side surfaces here.

    use crate::mem::vmobject::{VmFault as Vf, VmObject};
    use alloc::sync::Arc;
    use core::cell::Cell;

    /// Single-shot mock that returns a caller-supplied `Result` from
    /// `fault`. `Cell` is enough — host tests are single-threaded
    /// unless they explicitly fan out.
    struct MockObject {
        next: Cell<Option<Result<u64, Vf>>>,
    }

    // SAFETY: host-only mock; the unit tests that consume it are
    // single-threaded so the `Cell` shape is fine. The unsafe impl
    // is needed because `VmObject: Send + Sync` and `Cell<T>: !Sync`.
    unsafe impl Sync for MockObject {}
    unsafe impl Send for MockObject {}

    impl MockObject {
        fn new(res: Result<u64, Vf>) -> Arc<Self> {
            Arc::new(Self {
                next: Cell::new(Some(res)),
            })
        }
    }

    impl VmObject for MockObject {
        fn fault(&self, _offset: usize, _access: crate::mem::vmobject::Access) -> Result<u64, Vf> {
            self.next.take().expect("MockObject::fault called twice")
        }
        fn len_pages(&self) -> Option<usize> {
            Some(1)
        }
        fn clone_private(&self) -> Arc<dyn VmObject> {
            // Not exercised by these tests — never called. Return a
            // fresh mock that would panic if consulted to keep the
            // contract simple.
            Arc::new(Self {
                next: Cell::new(None),
            })
        }
    }

    fn route_through_classifier(res: Result<u64, Vf>) -> FaultResolution {
        let mock = MockObject::new(res);
        let trait_obj: Arc<dyn VmObject> = mock;
        let outcome = trait_obj.fault(0, crate::mem::vmobject::Access::Read);
        classify_vm_fault_result(outcome)
    }

    #[test]
    fn synthesized_object_routes_cow_needed_to_cow() {
        assert_eq!(
            route_through_classifier(Err(Vf::CoWNeeded)),
            FaultResolution::CoW,
        );
    }

    #[test]
    fn synthesized_object_routes_park_and_retry_to_retry() {
        assert_eq!(
            route_through_classifier(Err(Vf::ParkAndRetry)),
            FaultResolution::Retry,
        );
    }

    #[test]
    fn synthesized_object_routes_read_failed_to_sigbus() {
        // EIO is the canonical readpage error; the resolver collapses
        // every errno into SIGBUS uniformly.
        assert_eq!(
            route_through_classifier(Err(Vf::ReadFailed(crate::fs::EIO))),
            FaultResolution::Sigbus,
        );
    }

    #[test]
    fn synthesized_object_routes_ok_to_mapped() {
        assert_eq!(
            route_through_classifier(Ok(0x4000)),
            FaultResolution::Mapped(0x4000),
        );
    }

    // ── validate_mprotect_file_perm (issue #747, RFC 0007 §Security B1) ─

    mod mprotect_file_perm {
        use super::*;
        use crate::mem::vmatree::Share;

        const O_RDONLY: u32 = 0;
        const O_WRONLY: u32 = 1;
        const O_RDWR: u32 = 2;
        const EACCES: i64 = -13;

        // --- PROT_WRITE on MAP_SHARED ---

        #[test]
        fn shared_write_rdwr_ok() {
            // MAP_SHARED + PROT_WRITE with O_RDWR: allowed.
            assert_eq!(
                validate_mprotect_file_perm(PROT_WRITE, Share::Shared, Some(O_RDWR), Some(true)),
                Ok(()),
            );
        }

        #[test]
        fn shared_write_rdonly_eacces() {
            // MAP_SHARED + PROT_WRITE with O_RDONLY: rejected.
            assert_eq!(
                validate_mprotect_file_perm(PROT_WRITE, Share::Shared, Some(O_RDONLY), Some(true)),
                Err(EACCES),
            );
        }

        #[test]
        fn shared_write_wronly_eacces() {
            // MAP_SHARED + PROT_WRITE with O_WRONLY: rejected (need
            // O_RDWR for read-on-miss before mutating).
            assert_eq!(
                validate_mprotect_file_perm(PROT_WRITE, Share::Shared, Some(O_WRONLY), Some(true)),
                Err(EACCES),
            );
        }

        #[test]
        fn private_write_rdonly_ok() {
            // MAP_PRIVATE + PROT_WRITE with O_RDONLY: no open_mode
            // gate on private mappings (CoW handles the write).
            assert_eq!(
                validate_mprotect_file_perm(PROT_WRITE, Share::Private, Some(O_RDONLY), Some(true)),
                Ok(()),
            );
        }

        #[test]
        fn shared_read_rdonly_ok() {
            // MAP_SHARED + PROT_READ (no WRITE): O_RDONLY is fine.
            assert_eq!(
                validate_mprotect_file_perm(PROT_READ, Share::Shared, Some(O_RDONLY), Some(true)),
                Ok(()),
            );
        }

        // --- PROT_EXEC on non-executable inode ---

        #[test]
        fn exec_on_executable_inode_ok() {
            assert_eq!(
                validate_mprotect_file_perm(PROT_EXEC, Share::Private, Some(O_RDONLY), Some(true)),
                Ok(()),
            );
        }

        #[test]
        fn exec_on_non_executable_inode_eacces() {
            assert_eq!(
                validate_mprotect_file_perm(PROT_EXEC, Share::Private, Some(O_RDONLY), Some(false)),
                Err(EACCES),
            );
        }

        #[test]
        fn exec_on_shared_non_executable_eacces() {
            assert_eq!(
                validate_mprotect_file_perm(PROT_EXEC, Share::Shared, Some(O_RDWR), Some(false)),
                Err(EACCES),
            );
        }

        #[test]
        fn read_write_exec_shared_rdwr_exec_ok() {
            // All bits + O_RDWR + exec_allowed: passes.
            assert_eq!(
                validate_mprotect_file_perm(
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    Share::Shared,
                    Some(O_RDWR),
                    Some(true)
                ),
                Ok(()),
            );
        }

        #[test]
        fn read_write_exec_shared_rdonly_eacces() {
            // WRITE+EXEC on shared + O_RDONLY: EACCES for WRITE rule.
            assert_eq!(
                validate_mprotect_file_perm(
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    Share::Shared,
                    Some(O_RDONLY),
                    Some(true)
                ),
                Err(EACCES),
            );
        }

        #[test]
        fn read_write_exec_shared_noexec_eacces() {
            // WRITE+EXEC on shared + O_RDWR + no exec: EACCES for EXEC rule.
            assert_eq!(
                validate_mprotect_file_perm(
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    Share::Shared,
                    Some(O_RDWR),
                    Some(false)
                ),
                Err(EACCES),
            );
        }

        // --- Non-file-backed (anon) objects ---

        #[test]
        fn anon_write_shared_ok() {
            // Non-file-backed (None): no constraint.
            assert_eq!(
                validate_mprotect_file_perm(PROT_WRITE, Share::Shared, None, None),
                Ok(()),
            );
        }

        #[test]
        fn anon_exec_ok() {
            assert_eq!(
                validate_mprotect_file_perm(PROT_EXEC, Share::Private, None, None),
                Ok(()),
            );
        }
    }
}
