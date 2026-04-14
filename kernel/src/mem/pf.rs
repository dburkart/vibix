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
//! Security note on the panic paths: both `panic_smap_violation` and
//! `panic_rsvd_corruption` must **log the faulting VA only**, never the
//! PTE word or the frame's physaddr. A reserved-bit fault often means
//! the kernel's own page tables were corrupted; echoing back the PTE
//! contents to a user-reachable sink hands an attacker a free peek at
//! kernel state (RFC 0001 Security advisory A2).

use crate::mem::addrspace::USER_VA_END;
use crate::mem::vmatree::ProtUser;
use crate::mem::vmobject::Access;

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
}
