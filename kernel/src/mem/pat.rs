//! Program the IA32_PAT MSR so one slot maps to Write-Combining.
//!
//! Default PAT (slots 0..7): WB, WT, UC-, UC, WB, WT, UC-, UC. The low
//! four slots are the ones selected by PTEs with PAT=0, and we leave
//! them alone so every existing mapping keeps its default memory type.
//! We repurpose slot 4 (selected by PAT=1, PCD=0, PWT=0) from WB to WC
//! so the kernel can mark MMIO pages — currently just the linear
//! framebuffer — as write-combining for burst-friendly writes.
//!
//! Reprogramming PAT *before* any PTE sets the PAT bit means we don't
//! have to do the SDM "disable caching, flush, switch, re-enable" dance
//! — no live mapping changes memory type as a side effect of the MSR
//! write. Stale WB cache lines for the framebuffer (populated by writes
//! through the old Limine WB mapping) are flushed later, around the CR3
//! swap, via WBINVD.

use x86_64::registers::model_specific::Msr;

const IA32_PAT: u32 = 0x277;

// Memory type encodings, Intel SDM Vol 3, Table 11-10.
const WB: u64 = 0x06;
const WT: u64 = 0x04;
const UC_MINUS: u64 = 0x07;
const UC: u64 = 0x00;
const WC: u64 = 0x01;

/// Raw bit position of the PAT flag in a 4 KiB PTE (bit 7). At L2/L3
/// this same bit is PS (page-size); the `x86_64` crate's `map_to`
/// asserts it's clear at L1, so callers install a normal mapping first
/// and then OR this bit onto the raw PTE by hand.
pub const PAT_BIT_4K: u64 = 1 << 7;

/// Reprogram IA32_PAT so slot 4 = WC. Must run on every CPU that will
/// use WC mappings; today that's just the BSP.
///
/// Skipped if the CPU does not report PAT support via CPUID. On such
/// hardware the default PAT layout remains in effect and the framebuffer
/// falls back to its Limine-assigned memory type.
pub fn init() {
    if !crate::cpu::has(crate::cpu::Feature::Pat) {
        crate::serial_println!("pat: PAT not supported, skipping WC slot setup");
        return;
    }
    let pat = WB
        | (WT << 8)
        | (UC_MINUS << 16)
        | (UC << 24)
        | (WC << 32)
        | (WT << 40)
        | (UC_MINUS << 48)
        | (UC << 56);

    // SAFETY: writing architecturally defined memory-type encodings to
    // IA32_PAT. No existing PTE sets the PAT bit, so slot 4's change
    // from WB to WC doesn't retroactively alter any live mapping.
    unsafe {
        Msr::new(IA32_PAT).write(pat);
    }
}
