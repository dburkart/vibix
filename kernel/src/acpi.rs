//! Minimal ACPI table parser — just enough to discover LAPIC / IOAPIC
//! topology from the MADT. We do NOT walk the DSDT or execute AML; that
//! is a future milestone. We read:
//!
//!   RSDP → XSDT (or RSDT, on rev 0 firmware) → MADT → entries
//!
//! Limine hands us a pre-mapped virtual pointer to the RSDP in its HHDM
//! window (base revision ≥ 2), so we treat all physical addresses we
//! encounter while walking tables as HHDM offsets too.
//!
//! Reference: ACPI Specification, section 5 (RSDP/XSDT) and section
//! 5.2.12 (MADT).
use core::mem;
use core::slice;

use spin::Once;
use x86_64::structures::paging::PageTableFlags;

use crate::mem::paging;
use crate::serial_println;

/// Maximum IOAPICs we record. One is the common case; two is exotic.
const MAX_IOAPICS: usize = 4;
/// Maximum interrupt source overrides. Spec allows up to 16 (one per
/// ISA IRQ); in practice firmware reports ≤ 4.
const MAX_OVERRIDES: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct IoApic {
    pub id: u8,
    pub phys_addr: u32,
    pub gsi_base: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct InterruptOverride {
    pub bus: u8,
    pub source: u8,
    pub gsi: u32,
    pub flags: u16,
}

#[derive(Debug)]
pub struct AcpiInfo {
    pub lapic_phys: u64,
    pub cpu_count: u32,
    ioapics: [Option<IoApic>; MAX_IOAPICS],
    overrides: [Option<InterruptOverride>; MAX_OVERRIDES],
}

impl AcpiInfo {
    pub fn ioapics(&self) -> impl Iterator<Item = &IoApic> {
        self.ioapics.iter().filter_map(|e| e.as_ref())
    }

    pub fn overrides(&self) -> impl Iterator<Item = &InterruptOverride> {
        self.overrides.iter().filter_map(|e| e.as_ref())
    }

    /// Map ISA IRQ → (GSI, flags), applying any interrupt source
    /// override from the MADT. With no override, ISA IRQs are identity
    /// mapped (IRQ N → GSI N, edge-triggered active-high — flags 0).
    pub fn resolve_isa_irq(&self, irq: u8) -> (u32, u16) {
        for ov in self.overrides() {
            if ov.bus == 0 && ov.source == irq {
                return (ov.gsi, ov.flags);
            }
        }
        (irq as u32, 0)
    }
}

static INFO: Once<AcpiInfo> = Once::new();

pub fn info() -> Option<&'static AcpiInfo> {
    INFO.get()
}

#[repr(C, packed)]
struct Rsdp {
    signature: [u8; 8],
    checksum: u8,
    oem_id: [u8; 6],
    revision: u8,
    rsdt_address: u32,
    // v2+ fields below.
    length: u32,
    xsdt_address: u64,
    ext_checksum: u8,
    _reserved: [u8; 3],
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
    pub checksum: u8,
    pub oem_id: [u8; 6],
    pub oem_table_id: [u8; 8],
    pub oem_revision: u32,
    pub creator_id: u32,
    pub creator_revision: u32,
}

/// Cached pointer to the root table (XSDT or RSDT) plus the HHDM base.
/// Populated by [`init`] so follow-on callers (e.g. the HPET driver)
/// can re-walk the root looking for additional SDTs without having to
/// re-parse the RSDP.
struct RootTable {
    root_phys: u64,
    hhdm_offset: u64,
    is_xsdt: bool,
}

static ROOT: Once<RootTable> = Once::new();

const MADT_PROCESSOR_LAPIC: u8 = 0;
const MADT_IOAPIC: u8 = 1;
const MADT_INTERRUPT_OVERRIDE: u8 = 2;
const MADT_LAPIC_ADDRESS_OVERRIDE: u8 = 5;

/// Initialize ACPI from Limine's RSDP response.
///
/// `rsdp_phys` is the physical address Limine provided. Under base
/// revision 3 this is always a physical address; we add the HHDM
/// offset ourselves to reach it. All physical pointers inside the
/// ACPI tables (XSDT entries, child SDTs) are translated the same
/// way.
pub fn init(rsdp_phys: usize, hhdm_offset: u64) {
    // Firmware tables may live in reserved/ROM ranges that Limine's
    // HHDM doesn't cover. Map the RSDP page (with some slack for the
    // extended part) into HHDM before we touch it.
    map_phys(rsdp_phys as u64, mem::size_of::<Rsdp>() as u64);
    let rsdp_virt = rsdp_phys as u64 + hhdm_offset;
    let rsdp = unsafe { &*(rsdp_virt as *const Rsdp) };
    assert_eq!(&rsdp.signature, b"RSD PTR ", "bad RSDP signature");
    // RSDP checksum: the first 20 bytes (fields through rsdt_address)
    // must sum to 0 mod 256. For revision ≥ 2 the full `length` bytes
    // must also checksum to zero, covering the extended fields.
    assert!(
        checksum(rsdp_virt as *const u8, 20) == 0,
        "bad RSDP v1 checksum"
    );
    if rsdp.revision >= 2 {
        let len = rsdp.length as usize;
        assert!(len >= mem::size_of::<Rsdp>(), "RSDP length too small");
        assert!(
            checksum(rsdp_virt as *const u8, len) == 0,
            "bad RSDP v2 checksum"
        );
    }

    let xsdt_phys = rsdp.xsdt_address;
    let rsdt_phys = rsdp.rsdt_address;

    let (root_phys, is_xsdt) = if rsdp.revision >= 2 && xsdt_phys != 0 {
        (xsdt_phys, true)
    } else {
        (rsdt_phys as u64, false)
    };
    ROOT.call_once(|| RootTable {
        root_phys,
        hhdm_offset,
        is_xsdt,
    });

    let madt_ptr = find_sdt_in_root(root_phys, hhdm_offset, is_xsdt, b"APIC")
        .expect("MADT not found in ACPI tables");

    let info = parse_madt(madt_ptr);
    serial_println!(
        "acpi: MADT parsed (cpus={}, ioapics={}, overrides={}, lapic={:#x})",
        info.cpu_count,
        info.ioapics().count(),
        info.overrides().count(),
        info.lapic_phys
    );
    INFO.call_once(|| info);
}

/// Look up a non-MADT SDT by its 4-byte signature in the previously
/// walked root table. Returns a pointer to the full SDT (including its
/// header); callers cast to their own `#[repr(C, packed)]` layout.
/// Returns `None` if [`init`] hasn't run yet or the signature is
/// absent.
pub fn find_sdt(signature: &[u8; 4]) -> Option<*const SdtHeader> {
    let root = ROOT.get()?;
    find_sdt_in_root(root.root_phys, root.hhdm_offset, root.is_xsdt, signature)
}

/// HHDM offset recorded during [`init`]. Used by drivers that map
/// additional MMIO regions once ACPI discovery has completed.
pub fn hhdm_offset() -> Option<u64> {
    ROOT.get().map(|r| r.hhdm_offset)
}

fn find_sdt_in_root(
    root_phys: u64,
    hhdm: u64,
    is_xsdt: bool,
    signature: &[u8; 4],
) -> Option<*const SdtHeader> {
    if is_xsdt {
        find_by_sig_xsdt(root_phys, hhdm, signature)
    } else {
        find_by_sig_rsdt(root_phys, hhdm, signature)
    }
}

fn find_by_sig_xsdt(xsdt_phys: u64, hhdm: u64, signature: &[u8; 4]) -> Option<*const SdtHeader> {
    let header = read_sdt(xsdt_phys, hhdm);
    let entries_bytes = header.length as usize - mem::size_of::<SdtHeader>();
    let count = entries_bytes / 8;
    let entries_ptr = (xsdt_phys + hhdm + mem::size_of::<SdtHeader>() as u64) as *const u64;
    for i in 0..count {
        let phys = unsafe { entries_ptr.add(i).read_unaligned() };
        let sdt = read_sdt(phys, hhdm);
        if &sdt.signature == signature {
            return Some(sdt as *const _);
        }
    }
    None
}

fn find_by_sig_rsdt(rsdt_phys: u64, hhdm: u64, signature: &[u8; 4]) -> Option<*const SdtHeader> {
    let header = read_sdt(rsdt_phys, hhdm);
    let entries_bytes = header.length as usize - mem::size_of::<SdtHeader>();
    let count = entries_bytes / 4;
    let entries_ptr = (rsdt_phys + hhdm + mem::size_of::<SdtHeader>() as u64) as *const u32;
    for i in 0..count {
        let phys = unsafe { entries_ptr.add(i).read_unaligned() } as u64;
        let sdt = read_sdt(phys, hhdm);
        if &sdt.signature == signature {
            return Some(sdt as *const _);
        }
    }
    None
}

fn read_sdt(phys: u64, hhdm: u64) -> &'static SdtHeader {
    // First map enough for the header; then re-map the full table
    // once we know its length. Both calls are no-ops if the range is
    // already mapped.
    map_phys(phys, mem::size_of::<SdtHeader>() as u64);
    let virt = phys + hhdm;
    let header = unsafe { &*(virt as *const SdtHeader) };
    let len = header.length as usize;
    assert!(
        len >= mem::size_of::<SdtHeader>(),
        "SDT length {len} smaller than header"
    );
    map_phys(phys, len as u64);
    assert!(
        checksum(virt as *const u8, len) == 0,
        "bad SDT checksum (sig {:?})",
        header.signature
    );
    header
}

/// Sum `len` bytes starting at `ptr`, returning the low 8 bits. ACPI
/// tables are valid when this sum is 0.
fn checksum(ptr: *const u8, len: usize) -> u8 {
    let mut sum: u8 = 0;
    for i in 0..len {
        sum = sum.wrapping_add(unsafe { *ptr.add(i) });
    }
    sum
}

fn map_phys(phys: u64, size: u64) {
    paging::map_phys_into_hhdm(
        phys,
        size,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    )
    .expect("failed to map ACPI physical range");
}

fn parse_madt(madt: *const SdtHeader) -> AcpiInfo {
    let header = unsafe { &*madt };
    let total_len = header.length as usize;
    // MADT layout after the SDT header: u32 local_apic_address, u32
    // flags, then variable-length entries. Anything shorter than
    // header + the two u32s is malformed.
    const MADT_FIXED_FIELDS: usize = 8;
    assert!(
        total_len >= mem::size_of::<SdtHeader>() + MADT_FIXED_FIELDS,
        "MADT length {total_len} too small"
    );
    let body_len = total_len - mem::size_of::<SdtHeader>();

    let body = unsafe {
        slice::from_raw_parts(
            (madt as *const u8).add(mem::size_of::<SdtHeader>()),
            body_len,
        )
    };

    let lapic_addr = u32::from_le_bytes(body[0..4].try_into().unwrap()) as u64;

    let mut info = AcpiInfo {
        lapic_phys: lapic_addr,
        cpu_count: 0,
        ioapics: [None; MAX_IOAPICS],
        overrides: [None; MAX_OVERRIDES],
    };

    let mut off = 8; // skip lapic_addr + flags
    let mut ioapic_idx = 0usize;
    let mut override_idx = 0usize;
    while off + 2 <= body.len() {
        let entry_type = body[off];
        let entry_len = body[off + 1] as usize;
        if entry_len < 2 || off + entry_len > body.len() {
            break;
        }
        let payload = &body[off + 2..off + entry_len];
        match entry_type {
            MADT_PROCESSOR_LAPIC if payload.len() >= 6 => {
                // u8 acpi_processor_id, u8 apic_id, u32 flags
                let flags = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                // bit0 = Enabled, bit1 = Online-Capable (ACPI 6.3+).
                if flags & 0b11 != 0 {
                    info.cpu_count += 1;
                }
            }
            MADT_IOAPIC if payload.len() >= 10 && ioapic_idx < MAX_IOAPICS => {
                // u8 ioapic_id, u8 reserved, u32 addr, u32 gsi_base
                let id = payload[0];
                let addr = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                let gsi_base = u32::from_le_bytes(payload[6..10].try_into().unwrap());
                info.ioapics[ioapic_idx] = Some(IoApic {
                    id,
                    phys_addr: addr,
                    gsi_base,
                });
                ioapic_idx += 1;
            }
            MADT_INTERRUPT_OVERRIDE if payload.len() >= 8 && override_idx < MAX_OVERRIDES => {
                // u8 bus, u8 source, u32 gsi, u16 flags
                let bus = payload[0];
                let source = payload[1];
                let gsi = u32::from_le_bytes(payload[2..6].try_into().unwrap());
                let flags = u16::from_le_bytes(payload[6..8].try_into().unwrap());
                info.overrides[override_idx] = Some(InterruptOverride {
                    bus,
                    source,
                    gsi,
                    flags,
                });
                override_idx += 1;
            }
            MADT_LAPIC_ADDRESS_OVERRIDE if payload.len() >= 10 => {
                // u16 reserved, u64 addr
                info.lapic_phys = u64::from_le_bytes(payload[2..10].try_into().unwrap());
            }
            _ => {}
        }
        off += entry_len;
    }

    info
}
