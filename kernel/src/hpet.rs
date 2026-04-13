//! Minimal HPET driver.
//!
//! Discovers the HPET via its ACPI description table, maps the MMIO
//! block, and programs comparator 0 in periodic mode at [`TICK_HZ`].
//! LegacyReplacement routing is enabled so comparator 0 appears on
//! IRQ0 (GSI 2 after the standard MADT override), reusing the IOAPIC
//! redirection the APIC bring-up already installed for the PIT.
//!
//! The PIT stays physically present but is left unprogrammed when
//! HPET is active — vector 0x20 is shared between the two sources and
//! only one ever drives it per boot.
//!
//! Reference: IA-PC HPET Specification Rev 1.0a, sections 2.3 / 2.4.
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use x86_64::structures::paging::PageTableFlags;

use crate::acpi::{self, SdtHeader};
use crate::mem::paging;
use crate::serial_println;
use crate::time::TICK_HZ;

/// MMIO register offsets (bytes) within the HPET block.
const REG_CAPS: usize = 0x00;
const REG_CONFIG: usize = 0x10;
const REG_MAIN_COUNTER: usize = 0xF0;
const REG_TIMER0_CONFIG: usize = 0x100;
const REG_TIMER0_COMPARATOR: usize = 0x108;

/// General Configuration bits.
const CFG_ENABLE: u64 = 1 << 0;
const CFG_LEG_RT: u64 = 1 << 1;

/// Timer N Configuration bits.
const TN_INT_ENB: u64 = 1 << 2;
const TN_TYPE_PERIODIC: u64 = 1 << 3;
const TN_PER_INT_CAP: u64 = 1 << 4;
const TN_VAL_SET: u64 = 1 << 6;

/// HPET description table. The ACPI-provided address structure is
/// inlined rather than carved out as a GAS since we only use the
/// address + address_space_id fields.
#[repr(C, packed)]
struct HpetTable {
    header: SdtHeader,
    event_timer_block_id: u32,
    address_space_id: u8,
    reg_bit_width: u8,
    reg_bit_offset: u8,
    _reserved: u8,
    base_address: u64,
    hpet_number: u8,
    min_tick: u16,
    page_protection: u8,
}

#[derive(Debug)]
pub enum HpetError {
    TableMissing,
    HhdmMissing,
    UnsupportedAddressSpace(u8),
    ZeroPeriod,
    PeriodTooLarge(u64),
    PeriodicUnsupported,
    LegacyReplacementUnsupported,
}

/// Bit 15 of the General Capabilities register: set when the HPET
/// supports LegacyReplacement routing (timer 0 → IRQ0, timer 1 → IRQ8).
/// Without it, writing `CFG_LEG_RT` is silently ignored, so we must
/// refuse to initialize rather than end up with a live ACTIVE flag and
/// no timer IRQ.
const CAPS_LEG_RT_SUPPORTED: u64 = 1 << 15;

static ACTIVE: AtomicBool = AtomicBool::new(false);

/// True once `init` has successfully armed comparator 0. The PIT path
/// keys off this to avoid double-driving vector 0x20.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Discover, map, and start the HPET. On `Err`, callers should fall
/// back to the PIT path; [`active`] will remain `false`.
pub fn init() -> Result<(), HpetError> {
    let table_ptr = acpi::find_sdt(b"HPET").ok_or(HpetError::TableMissing)?;
    let hhdm = acpi::hhdm_offset().ok_or(HpetError::HhdmMissing)?;

    // The find_sdt helper already checked the header + checksum, so we
    // can safely project through HpetTable here.
    let table = unsafe { &*(table_ptr as *const HpetTable) };
    let address_space_id = table.address_space_id;
    if address_space_id != 0 {
        return Err(HpetError::UnsupportedAddressSpace(address_space_id));
    }
    let base_phys = table.base_address;

    // The register block is 1024 bytes per spec; one page covers it.
    paging::map_phys_into_hhdm(
        base_phys,
        0x1000,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::NO_CACHE,
    )
    .expect("failed to map HPET MMIO");

    let base = (base_phys + hhdm) as *mut u8;
    let caps = unsafe { read64(base, REG_CAPS) };
    let period_fs = caps >> 32;
    let num_timers = ((caps >> 8) & 0x1f) as u8 + 1;
    if period_fs == 0 {
        return Err(HpetError::ZeroPeriod);
    }
    // Spec caps the tick period at 100 ns = 10^8 fs.
    if period_fs > 100_000_000 {
        return Err(HpetError::PeriodTooLarge(period_fs));
    }
    // LegacyReplacement is how we land on IRQ0; refuse to proceed if
    // the HPET can't support it. Otherwise the CFG_LEG_RT write below
    // is a no-op, ACTIVE still flips true, time::init skips the PIT,
    // and calibrate_tsc spins forever waiting on a timer IRQ that
    // never fires.
    if caps & CAPS_LEG_RT_SUPPORTED == 0 {
        return Err(HpetError::LegacyReplacementUnsupported);
    }

    let timer0_caps = unsafe { read64(base, REG_TIMER0_CONFIG) };
    if timer0_caps & TN_PER_INT_CAP == 0 {
        return Err(HpetError::PeriodicUnsupported);
    }

    // Disable before programming so the counter can't race our writes
    // to the comparator accumulator.
    let mut cfg = unsafe { read64(base, REG_CONFIG) };
    cfg &= !CFG_ENABLE;
    unsafe { write64(base, REG_CONFIG, cfg) };

    // Zero the main counter so ticks-since-boot is meaningful from the
    // first fire.
    unsafe { write64(base, REG_MAIN_COUNTER, 0) };

    let delta = ticks_for_hz(period_fs, TICK_HZ);

    // Program comparator 0: periodic, IRQ enabled, accumulator-set.
    // Preserve reserved bits by reading-modify-writing.
    let mut t0_cfg = timer0_caps;
    t0_cfg &= !(0xffff << 9); // clear int-route bits (ignored in LegacyReplacement anyway)
    t0_cfg |= TN_INT_ENB | TN_TYPE_PERIODIC | TN_VAL_SET;
    unsafe { write64(base, REG_TIMER0_CONFIG, t0_cfg) };
    // With VAL_SET latched, the first write sets the comparator
    // (first-fire deadline) and the second write sets the periodic
    // reload interval.
    unsafe { write64(base, REG_TIMER0_COMPARATOR, delta) };
    unsafe { write64(base, REG_TIMER0_COMPARATOR, delta) };

    // Enable LegacyReplacement so Timer 0 lands on IRQ0 (→ GSI 2 after
    // the standard MADT override), then enable the main counter.
    let mut cfg = unsafe { read64(base, REG_CONFIG) };
    cfg |= CFG_LEG_RT | CFG_ENABLE;
    unsafe { write64(base, REG_CONFIG, cfg) };

    ACTIVE.store(true, Ordering::Release);
    serial_println!(
        "hpet: initialized (period={}fs, timers={}, base={:#x})",
        period_fs,
        num_timers,
        base_phys
    );
    serial_println!(
        "hpet: periodic timer armed ({} Hz, {} ticks/period)",
        TICK_HZ,
        delta
    );
    Ok(())
}

unsafe fn read64(base: *mut u8, offset: usize) -> u64 {
    ptr::read_volatile(base.add(offset) as *const u64)
}

unsafe fn write64(base: *mut u8, offset: usize, value: u64) {
    ptr::write_volatile(base.add(offset) as *mut u64, value);
}

/// Ticks between fires to land on `hz` Hz given `period_fs` per tick.
/// Pulled out for host unit testing.
fn ticks_for_hz(period_fs: u64, hz: u32) -> u64 {
    // 10^15 fs per second; integer division rounds toward zero, which
    // slightly over-shoots the target Hz by at most one period — fine
    // for a coarse 100 Hz tick.
    1_000_000_000_000_000u64 / period_fs / hz as u64
}

#[cfg(test)]
mod tests {
    use super::ticks_for_hz;

    #[test]
    fn hundred_hz_at_typical_period() {
        // QEMU HPET reports a 10 ns period (10_000_000 fs). 100 Hz →
        // 10 ms → 1_000_000 ticks.
        assert_eq!(ticks_for_hz(10_000_000, 100), 1_000_000);
    }

    #[test]
    fn thousand_hz_at_typical_period() {
        assert_eq!(ticks_for_hz(10_000_000, 1000), 100_000);
    }

    #[test]
    fn handles_smaller_period() {
        // Real hardware sometimes reports ~14.3 MHz (≈69841 fs).
        // 100 Hz → 10 ms = 10^13 fs → ~143_218_250 ticks.
        let t = ticks_for_hz(69_841, 100);
        assert!((143_200_000..=143_300_000).contains(&t), "got {t}");
    }
}
