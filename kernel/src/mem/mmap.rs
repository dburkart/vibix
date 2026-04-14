//! Userspace memory-mapping syscall implementations.
//!
//! Implements `mmap(2)`, `munmap(2)`, `mprotect(2)`, and `madvise(2)` per
//! RFC 0001 — Userspace Virtual Memory Subsystem.  All four syscalls share
//! a common address-range validation helper and route through the
//! `AddressSpace` / `VmaTree` layer for structural bookkeeping, with direct
//! PTE manipulation via `paging::*_in_pml4` helpers for the cases that
//! need to tear down or reprotect live mappings.
//!
//! None of these functions are `unsafe extern "C"` — they are called from
//! the safe Rust dispatcher in `arch::x86_64::syscall`, which is itself
//! declared `unsafe extern "C"`.

#![cfg(target_os = "none")]

use alloc::vec::Vec;
use x86_64::{
    structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB},
    VirtAddr,
};

use crate::{
    mem::{
        addrspace::USER_VA_END,
        frame,
        paging,
        vmatree::{Share, Vma},
        vmobject::AnonObject,
        FRAME_SIZE,
    },
    task,
};

// ---------------------------------------------------------------------------
// PROT_* bits (Linux ABI, mman.h)
// ---------------------------------------------------------------------------
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;

// ---------------------------------------------------------------------------
// MAP_* flags (Linux x86_64 ABI)
// ---------------------------------------------------------------------------
const MAP_SHARED: u32 = 0x01;
const MAP_PRIVATE: u32 = 0x02;
const MAP_FIXED: u32 = 0x10;
const MAP_ANONYMOUS: u32 = 0x20;
const MAP_FIXED_NOREPLACE: u32 = 0x0010_0000;

// ---------------------------------------------------------------------------
// MADV_* advice (Linux ABI)
// ---------------------------------------------------------------------------
const MADV_DONTNEED: i32 = 4;

// ---------------------------------------------------------------------------
// errno values (Linux ABI, negated)
// ---------------------------------------------------------------------------
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const EEXIST: i64 = -17;
const ENODEV: i64 = -19;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Convert user `PROT_*` flags to `x86_64::PageTableFlags` for PTE entries.
///
/// Rules (RFC 0001):
/// - Any readable mapping → `PRESENT | USER_ACCESSIBLE | NO_EXECUTE` (default NX).
/// - `PROT_WRITE` adds `WRITABLE`.
/// - `PROT_EXEC` clears `NO_EXECUTE`.
/// - `PROT_NONE` → empty flags (no `PRESENT`; VMA exists but fault → SIGSEGV).
pub fn prot_user_to_pte(prot: u32) -> PageTableFlags {
    if prot == 0 {
        return PageTableFlags::empty();
    }
    let mut f = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    if prot & PROT_WRITE != 0 {
        f |= PageTableFlags::WRITABLE;
    }
    if prot & PROT_EXEC != 0 {
        f -= PageTableFlags::NO_EXECUTE;
    }
    f
}

/// Validate `[addr, addr + len)` as a userspace virtual range.
///
/// Steps (RFC 0001 §Address validation):
/// 1. `len == 0` → `EINVAL`
/// 2. `len` overflows when rounded up to page boundary → `EINVAL`
/// 3. `addr` is non-canonical (≥ `USER_VA_END`) for non-zero addr → `EINVAL`
/// 4. `addr + rounded_len` overflows → `EINVAL`
/// 5. `addr + rounded_len > USER_VA_END` → `EINVAL`
/// 6. If `require_aligned`: `addr` is not page-aligned → `EINVAL`
///
/// Returns `(addr, rounded_len)` on success.
fn validate_range(addr: u64, len: u64, require_aligned: bool) -> Result<(u64, u64), i64> {
    const PAGE: u64 = FRAME_SIZE;

    if len == 0 {
        return Err(EINVAL);
    }

    // Round len up to next page boundary; check for overflow.
    let rounded_len = len
        .checked_add(PAGE - 1)
        .map(|v| v & !(PAGE - 1))
        .ok_or(EINVAL)?;
    if rounded_len == 0 {
        return Err(EINVAL);
    }

    // Non-canonical addr: anything ≥ USER_VA_END is in kernel half.
    if addr >= USER_VA_END {
        return Err(EINVAL);
    }

    // addr + rounded_len must not overflow and must stay in user half.
    let end = addr.checked_add(rounded_len).ok_or(EINVAL)?;
    if end > USER_VA_END {
        return Err(EINVAL);
    }

    if require_aligned && addr % PAGE != 0 {
        return Err(EINVAL);
    }

    Ok((addr, rounded_len))
}

/// Return `true` if any VMA in `aspace` overlaps `[start, end)`.
fn range_has_vma(
    aspace: &crate::mem::addrspace::AddressSpace,
    start: usize,
    end: usize,
) -> bool {
    for v in aspace.iter() {
        if v.start < end && v.end > start {
            return true;
        }
    }
    false
}

/// Tear down all PTEs in `[start, end)` within `pml4_frame`, decrement the
/// per-frame refcount for each, and structurally remove the VMA records from
/// `aspace`.  Returns the number of *virtual pages* removed from `vm_pages`.
///
/// This is the shared munmap kernel — called by both `sys_munmap` and the
/// MAP_FIXED overlap-clear path in `sys_mmap`.
fn unmap_range(
    aspace: &mut crate::mem::addrspace::AddressSpace,
    pml4_frame: PhysFrame<Size4KiB>,
    start: usize,
    end: usize,
) -> usize {
    // Walk present PTEs and release each frame's PTE reference.
    let mut va = start;
    while va < end {
        if let Ok(page) = Page::<Size4KiB>::from_start_address(VirtAddr::new(va as u64)) {
            if let Ok(phys_frame) = paging::unmap_in_pml4(pml4_frame, page) {
                // `unmap_in_pml4` does NOT decrement the refcount.  We do it
                // here — mirroring AddressSpace::drop's per-PTE decrement.
                frame::put(phys_frame.start_address().as_u64());
            }
        }
        va += FRAME_SIZE as usize;
    }

    // Count how many vm_pages we will remove before the structural change.
    let pages_before: usize = aspace
        .iter()
        .filter(|v| v.start < end && v.end > start)
        .map(|v| {
            let s = v.start.max(start);
            let e = v.end.min(end);
            (e - s) / FRAME_SIZE as usize
        })
        .sum();

    // Structural VMA removal (splits as needed, drops Arc<VmObject> refs).
    aspace.vmas.unmap_range(start, end);
    aspace.vm_pages = aspace.vm_pages.saturating_sub(pages_before);

    pages_before
}

/// Find the first free virtual address range of exactly `len` bytes (already
/// page-rounded) starting at or above `hint`.
///
/// Scans the ordered VMA tree for a sufficiently large gap.  O(n VMAs).
fn find_free_range(
    aspace: &crate::mem::addrspace::AddressSpace,
    hint: u64,
    len: u64,
) -> Option<u64> {
    // Round hint up to page boundary.
    let mut candidate = (hint.wrapping_add(FRAME_SIZE - 1)) & !(FRAME_SIZE - 1);

    // Collect (start, end) pairs; we need to scan for gaps.
    let vmas: Vec<(usize, usize)> = aspace.iter().map(|v| (v.start, v.end)).collect();

    'outer: loop {
        let cand_end = candidate.checked_add(len)?;
        if cand_end > USER_VA_END {
            return None;
        }

        for &(v_start, v_end) in &vmas {
            // Overlap: the candidate window intersects this VMA.
            if (v_start as u64) < cand_end && (v_end as u64) > candidate {
                // Skip past this VMA and retry.
                candidate = v_end as u64;
                continue 'outer;
            }
        }

        return Some(candidate);
    }
}

// ---------------------------------------------------------------------------
// Syscall implementations
// ---------------------------------------------------------------------------

/// `mmap(addr, len, prot, flags, fd, offset)` — syscall 9.
///
/// Supported flags: `MAP_PRIVATE | MAP_ANONYMOUS` and `MAP_SHARED | MAP_ANONYMOUS`.
/// `MAP_FIXED` and `MAP_FIXED_NOREPLACE` are honoured.
/// File-backed mappings (`fd != -1`) return `ENODEV`.
pub fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, _offset: u64) -> i64 {
    let prot = prot as u32;
    let flags = flags as u32;
    let fd_signed = fd as i64;

    // Anonymous-only: MAP_ANONYMOUS must be set and fd must be -1.
    if flags & MAP_ANONYMOUS == 0 || fd_signed != -1 {
        return ENODEV;
    }

    // Must specify exactly one of MAP_PRIVATE or MAP_SHARED.
    let is_private = flags & MAP_PRIVATE != 0;
    let is_shared = flags & MAP_SHARED != 0;
    if is_private == is_shared {
        // Neither set, or both set (Linux rejects MAP_PRIVATE|MAP_SHARED).
        return EINVAL;
    }
    let share = if is_shared { Share::Shared } else { Share::Private };

    let map_fixed = flags & MAP_FIXED != 0;
    let map_fixed_noreplace = flags & MAP_FIXED_NOREPLACE != 0;

    // Validate length (addr validated below per flag).
    if len == 0 {
        return EINVAL;
    }
    let rounded_len = match len.checked_add(FRAME_SIZE - 1).map(|v| v & !(FRAME_SIZE - 1)) {
        Some(l) if l > 0 => l,
        _ => return EINVAL,
    };

    let pte_flags = prot_user_to_pte(prot);

    let aspace_arc = task::current_address_space();
    let mut aspace = aspace_arc.write();
    let pml4 = aspace.page_table_frame();

    let map_addr: u64 = if map_fixed || map_fixed_noreplace {
        // MAP_FIXED / MAP_FIXED_NOREPLACE require a page-aligned non-zero addr.
        match validate_range(addr, len, true) {
            Ok((a, _)) if a == 0 => return EINVAL,
            Ok((a, _)) => {
                if map_fixed {
                    // MAP_FIXED takes precedence over MAP_FIXED_NOREPLACE when
                    // both are set (Linux-documented behaviour): replace any
                    // existing mapping in the range unconditionally.
                    unmap_range(&mut aspace, pml4, a as usize, (a + rounded_len) as usize);
                } else {
                    // MAP_FIXED_NOREPLACE only: fail if any VMA overlaps.
                    if range_has_vma(&aspace, a as usize, (a + rounded_len) as usize) {
                        return EEXIST;
                    }
                }
                a
            }
            Err(e) => return e,
        }
    } else {
        // Hint-based: start from the provided addr (if in range) or mmap_base.
        let hint = if addr > 0 && addr < USER_VA_END {
            addr
        } else {
            aspace.mmap_base.as_u64()
        };
        match find_free_range(&aspace, hint, rounded_len) {
            Some(a) => a,
            None => return ENOMEM,
        }
    };

    // Final range check after address is resolved.
    let map_end = match map_addr.checked_add(rounded_len) {
        Some(e) if e <= USER_VA_END => e,
        _ => return EINVAL,
    };

    let object = AnonObject::new(None);
    let vma = Vma::new(
        map_addr as usize,
        map_end as usize,
        prot,
        pte_flags.bits(),
        share,
        object,
        0,
    );
    aspace.insert(vma);

    map_addr as i64
}

/// `munmap(addr, len)` — syscall 11.
///
/// `addr` must be page-aligned.  Unmapping a hole (or a region with no VMA)
/// is not an error — POSIX-conformant.  Returns `0` on success, `-EINVAL` on
/// bad arguments.
pub fn sys_munmap(addr: u64, len: u64) -> i64 {
    let (addr, rounded_len) = match validate_range(addr, len, true) {
        Ok(r) => r,
        Err(e) => return e,
    };

    let aspace_arc = task::current_address_space();
    let mut aspace = aspace_arc.write();
    let pml4 = aspace.page_table_frame();

    unmap_range(&mut aspace, pml4, addr as usize, (addr + rounded_len) as usize);
    0
}

/// `mprotect(addr, len, prot)` — syscall 10.
///
/// Applies `prot` to every VMA byte in `[addr, addr+len)`.  Returns
/// `-ENOMEM` if any sub-page within the range is not covered by a VMA
/// (Linux mprotect_fixup semantics).
pub fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    let prot = prot as u32;
    let (addr, rounded_len) = match validate_range(addr, len, true) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let end = addr + rounded_len;

    let aspace_arc = task::current_address_space();
    let mut aspace = aspace_arc.write();
    let pml4 = aspace.page_table_frame();

    // ENOMEM check: every page in [addr, end) must be covered by a VMA.
    let mut va = addr as usize;
    while va < end as usize {
        if aspace.find(va).is_none() {
            return ENOMEM;
        }
        va += FRAME_SIZE as usize;
    }

    let new_pte = prot_user_to_pte(prot);

    // Update VMA records structurally (splits at boundaries as needed).
    aspace.vmas.change_protection(addr as usize, end as usize, prot, new_pte.bits());

    // Walk present PTEs: unmap old PTE, remap same frame with new flags.
    // `unmap_in_pml4` does not change the refcount; re-mapping the same frame
    // does not change it either — so the net refcount effect is zero.
    let mut va = addr;
    while va < end {
        if let Ok(page) = Page::<Size4KiB>::from_start_address(VirtAddr::new(va)) {
            if let Some((old_frame, _)) =
                paging::translate_in_pml4(pml4, VirtAddr::new(va))
            {
                // Remove the old PTE (TLB flushed inside unmap_in_pml4).
                let _ = paging::unmap_in_pml4(pml4, page);

                // Only remap if the new protection is not PROT_NONE.
                if new_pte.contains(PageTableFlags::PRESENT) {
                    if paging::map_existing_in_pml4(pml4, page, old_frame, new_pte).is_err() {
                        // Remap failed: PTE is gone but refcount was not
                        // decremented by unmap_in_pml4; release it now.
                        frame::put(old_frame.start_address().as_u64());
                    }
                } else {
                    // PROT_NONE: the PTE stays absent but the frame is still
                    // owned by the VMA.  `unmap_in_pml4` does not decrement
                    // the PTE refcount, so we must do it here to avoid a leak.
                    frame::put(old_frame.start_address().as_u64());
                }
            }
        }
        va += FRAME_SIZE;
    }

    0
}

/// `madvise(addr, len, advice)` — syscall 28.
///
/// Only `MADV_DONTNEED` on `MAP_PRIVATE | MAP_ANONYMOUS` regions is
/// implemented.  All other advice values are silently accepted (no-op).
///
/// `MADV_DONTNEED` drops the PTE for each faulted page in the range and
/// evicts the backing-object cache entry, releasing both references to the
/// physical frame so it is reclaimed.  On next access the fault handler
/// allocates a fresh zero-filled frame — giving Linux-compatible
/// zero-on-next-touch semantics.  VMA records are preserved so subsequent
/// accesses do not SIGSEGV.
pub fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    let advice = advice as i32;

    // All advice other than MADV_DONTNEED is a no-op.
    if advice != MADV_DONTNEED {
        return 0;
    }

    let (addr, rounded_len) = match validate_range(addr, len, true) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let end = addr + rounded_len;

    let aspace_arc = task::current_address_space();
    let aspace = aspace_arc.write();
    let pml4 = aspace.page_table_frame();

    // For each present PTE in the range: unmap and release the PTE's frame
    // reference, then evict the backing-object cache entry so the frame's
    // refcount reaches zero and it is reclaimed.  A subsequent fault calls
    // AnonObject::fault, sees no cached frame, and allocates a fresh
    // zero-filled page — giving Linux-compatible zero-on-next-touch semantics.
    let mut va = addr;
    while va < end {
        if let Ok(page) = Page::<Size4KiB>::from_start_address(VirtAddr::new(va)) {
            if let Ok(phys_frame) = paging::unmap_in_pml4(pml4, page) {
                // Release the PTE's reference.
                frame::put(phys_frame.start_address().as_u64());
            }
        }
        // Evict the cache entry so the backing object releases its reference
        // and a future fault sees a fresh zero-filled page.
        if let Some(vma) = aspace.vmas.find(va as usize) {
            let obj_offset = vma.object_offset + (va as usize - vma.start);
            vma.object.evict_page(obj_offset);
        }
        va += FRAME_SIZE;
    }

    0
}
