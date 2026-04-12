//! xAPIC Local APIC and IOAPIC drivers for the BSP.
//!
//! The LAPIC is the per-CPU interrupt controller; here we only bring up
//! the bootstrap processor's LAPIC (APs are a future milestone). The
//! IOAPIC(s) take device IRQs (legacy ISA plus anything else a bus
//! hands us) and route them to a LAPIC as a redirection entry.
//!
//! We stay in xAPIC (MMIO) mode — x2APIC's MSR interface is simpler in
//! some ways but not worth the conditional until SMP needs it.

use core::ptr::{read_volatile, write_volatile};

use spin::Once;
use x86_64::structures::paging::PageTableFlags;

use crate::acpi;
use crate::mem::paging;
use crate::serial_println;

fn map_mmio(phys: u64, size: u64) {
    paging::map_phys_into_hhdm(
        phys,
        size,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::NO_CACHE
            | PageTableFlags::WRITE_THROUGH,
    )
    .expect("failed to map APIC MMIO");
}

// LAPIC register offsets (all MMIO 32-bit, aligned on 16 bytes).
const LAPIC_ID: usize = 0x20;
const LAPIC_EOI: usize = 0xB0;
const LAPIC_SPURIOUS: usize = 0xF0;
const LAPIC_TPR: usize = 0x80;

// IOAPIC indirect registers.
const IOAPIC_VER_REG: u32 = 0x01;
const IOAPIC_REDTBL_BASE: u32 = 0x10;

struct LocalApic {
    base: *mut u32,
}

unsafe impl Send for LocalApic {}
unsafe impl Sync for LocalApic {}

impl LocalApic {
    unsafe fn read(&self, reg: usize) -> u32 {
        read_volatile(self.base.byte_add(reg))
    }

    unsafe fn write(&self, reg: usize, val: u32) {
        write_volatile(self.base.byte_add(reg), val);
    }
}

struct IoApic {
    base: *mut u32,
    gsi_base: u32,
    id: u8,
}

unsafe impl Send for IoApic {}
unsafe impl Sync for IoApic {}

impl IoApic {
    unsafe fn read(&self, reg: u32) -> u32 {
        write_volatile(self.base, reg);
        read_volatile(self.base.byte_add(0x10))
    }

    unsafe fn write(&self, reg: u32, val: u32) {
        write_volatile(self.base, reg);
        write_volatile(self.base.byte_add(0x10), val);
    }

    /// Max redirection entries for this IOAPIC (reads from the version
    /// register; the high byte is `max_redirection_entry`, 0-indexed).
    unsafe fn max_redirection_entries(&self) -> u32 {
        ((self.read(IOAPIC_VER_REG) >> 16) & 0xFF) + 1
    }

    /// Program a redirection entry.
    ///
    /// * `gsi_offset` — entry index within this IOAPIC (GSI minus its
    ///   gsi_base).
    /// * `vector` — CPU IDT vector the LAPIC should raise.
    /// * `lapic_id` — physical destination LAPIC id.
    /// * `trigger_level` / `active_low` — come from the MADT override
    ///   flags for the source IRQ.
    /// * `masked` — leave the entry masked?
    unsafe fn set_redirection(
        &self,
        gsi_offset: u32,
        vector: u8,
        lapic_id: u8,
        trigger_level: bool,
        active_low: bool,
        masked: bool,
    ) {
        let mut low: u32 = vector as u32;
        // Delivery mode = 0 (fixed), dest mode = 0 (physical).
        if active_low {
            low |= 1 << 13;
        }
        if trigger_level {
            low |= 1 << 15;
        }
        if masked {
            low |= 1 << 16;
        }
        let high: u32 = (lapic_id as u32) << 24;

        let idx = IOAPIC_REDTBL_BASE + gsi_offset * 2;
        // High half first, then low — writing low unmasks the entry,
        // so it must be last.
        self.write(idx + 1, high);
        self.write(idx, low);
    }
}

static LAPIC: Once<LocalApic> = Once::new();
static IOAPICS: Once<[Option<IoApic>; 4]> = Once::new();

/// Initialize the BSP's LAPIC. Must run after `acpi::init`.
pub fn init_bsp(hhdm_offset: u64) {
    let info = acpi::info().expect("acpi::init must run before apic::init_bsp");
    // LAPIC MMIO is 4 KiB starting at `lapic_phys`.
    map_mmio(info.lapic_phys, 0x1000);
    let base = (info.lapic_phys + hhdm_offset) as *mut u32;
    let lapic = LocalApic { base };
    unsafe {
        // TPR = 0: accept every priority.
        lapic.write(LAPIC_TPR, 0);
        // Spurious vector register: vector 0xFF + software enable bit.
        lapic.write(LAPIC_SPURIOUS, 0x100 | 0xFF);
    }
    let id = unsafe { lapic.read(LAPIC_ID) } >> 24;
    LAPIC.call_once(|| lapic);
    serial_println!("apic: BSP online (lapic_id={})", id);
}

/// Set up every IOAPIC: mask all redirection entries. Legacy IRQs are
/// programmed later via `route_legacy_irq`.
pub fn ioapic_init(hhdm_offset: u64) {
    let info = acpi::info().expect("acpi::init must run before ioapic_init");
    let mut slots: [Option<IoApic>; 4] = [None, None, None, None];
    let mut count = 0usize;
    for (i, io) in info.ioapics().enumerate().take(4) {
        map_mmio(io.phys_addr as u64, 0x1000);
        let base = (io.phys_addr as u64 + hhdm_offset) as *mut u32;
        let ioa = IoApic {
            base,
            gsi_base: io.gsi_base,
            id: io.id,
        };
        let entries = unsafe { ioa.max_redirection_entries() };
        // Mask every entry. Vector/dest don't matter while masked.
        for e in 0..entries {
            unsafe {
                ioa.set_redirection(e, 0xFE, 0, false, false, true);
            }
        }
        slots[i] = Some(ioa);
        count += 1;
    }
    IOAPICS.call_once(|| slots);
    serial_println!("ioapic: initialized ({} controller(s))", count);
}

/// Route a legacy ISA IRQ to an IDT vector on the BSP.
pub fn route_legacy_irq(isa_irq: u8, vector: u8) {
    let info = acpi::info().expect("acpi not initialized");
    let ioapics = IOAPICS.get().expect("ioapic not initialized");
    let lapic_id = bsp_lapic_id();

    let (gsi, flags) = info.resolve_isa_irq(isa_irq);
    // MPS INTI flags: polarity bits [1:0], trigger bits [3:2].
    //   polarity: 00=bus default, 01=active high, 11=active low
    //   trigger:  00=bus default, 01=edge,        11=level
    // ISA bus default is edge / active-high.
    let polarity = flags & 0b11;
    let trigger = (flags >> 2) & 0b11;
    let active_low = polarity == 0b11;
    let level = trigger == 0b11;

    let (io, offset) = ioapics
        .iter()
        .filter_map(|e| e.as_ref())
        .find_map(|io| {
            let entries =
                unsafe { io.max_redirection_entries() };
            if gsi >= io.gsi_base && gsi < io.gsi_base + entries {
                Some((io, gsi - io.gsi_base))
            } else {
                None
            }
        })
        .expect("no IOAPIC owns this GSI");

    unsafe {
        io.set_redirection(offset, vector, lapic_id, level, active_low, false);
    }
    serial_println!(
        "ioapic: IRQ{} -> gsi {} -> vec {:#x} on lapic {} (ioapic {})",
        isa_irq,
        gsi,
        vector,
        lapic_id,
        io.id
    );
}

pub fn bsp_lapic_id() -> u8 {
    let lapic = LAPIC.get().expect("lapic not initialized");
    (unsafe { lapic.read(LAPIC_ID) } >> 24) as u8
}

/// End-of-interrupt, called from ISRs instead of the old 8259 EOI.
pub fn lapic_eoi() {
    if let Some(lapic) = LAPIC.get() {
        unsafe { lapic.write(LAPIC_EOI, 0) };
    }
}
