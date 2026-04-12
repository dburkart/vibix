# ACPI Subsystem

**Source:** `kernel/src/acpi.rs`

## Overview

The ACPI subsystem parses just enough of the ACPI table hierarchy to discover
the interrupt topology needed to bring up the APIC: the LAPIC physical address
and the set of IOAPICs and interrupt source overrides recorded in the MADT.

AML execution, the DSDT, SSDT, and any other ACPI functionality are out of
scope.

## Design

Limine hands the kernel a physical pointer to the RSDP (Root System Description
Pointer). The parser follows the chain:

```
RSDP → XSDT (64-bit pointer table, preferred)
     → RSDT (32-bit pointer table, fallback for revision 0 firmware)
     → MADT (signature "APIC")
     → entries
```

All physical addresses encountered in the tables are translated to virtual by
adding the HHDM offset. Because ACPI tables may live in ROM or reserved regions
not covered by Limine's HHDM, `map_phys_into_hhdm` is called before each
table is accessed.

Checksums (byte-sum over the entire table = 0) are verified for the RSDP and
every SDT that is read.

## Data Structures

### `AcpiInfo`

Returned from `parse_madt` and stored in a global `Once<AcpiInfo>`:

| Field | Type | Meaning |
|---|---|---|
| `lapic_phys` | `u64` | Physical address of the Local APIC registers (may be overridden by entry type 5) |
| `cpu_count` | `u32` | Number of enabled (or online-capable) processors |
| `ioapics` | `[Option<IoApic>; 4]` | Up to 4 IOAPIC descriptors |
| `overrides` | `[Option<InterruptOverride>; 16]` | ISA IRQ → GSI remappings |

### `IoApic`

| Field | Type | Meaning |
|---|---|---|
| `id` | `u8` | IOAPIC APIC ID |
| `phys_addr` | `u32` | MMIO base address |
| `gsi_base` | `u32` | First Global System Interrupt handled by this IOAPIC |

### `InterruptOverride`

| Field | Type | Meaning |
|---|---|---|
| `bus` | `u8` | Source bus (0 = ISA) |
| `source` | `u8` | ISA IRQ number |
| `gsi` | `u32` | Target Global System Interrupt |
| `flags` | `u16` | Polarity and trigger mode bits (from the MADT entry) |

## MADT Entry Types Parsed

| Type | Name | Action |
|---|---|---|
| 0 | Processor Local APIC | Increment `cpu_count` if enabled or online-capable |
| 1 | IOAPIC | Record `IoApic` descriptor |
| 2 | Interrupt Source Override | Record `InterruptOverride` |
| 5 | LAPIC Address Override | Replace `lapic_phys` with the 64-bit address |

## Initialization

```rust
acpi::init(rsdp_phys, hhdm_offset);
```

Must be called after `mem::init()` (the HHDM mapper must be live to map ACPI
table pages). Stores the result in `INFO` via `Once::call_once`. After init,
call `acpi::info()` to get a `&'static AcpiInfo`.

## API

```rust
// After acpi::init():
if let Some(info) = acpi::info() {
    for ioapic in info.ioapics() { /* ... */ }
    let (gsi, flags) = info.resolve_isa_irq(1); // keyboard
}
```

`resolve_isa_irq(irq)` maps an ISA IRQ number to a GSI and polarity/trigger
flags, applying any override from the MADT. With no override, ISA IRQs are
identity-mapped (IRQ N → GSI N, edge-triggered active-high).
