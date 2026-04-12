# Interrupts Subsystem

**Sources:** `kernel/src/arch/x86_64/`
- `gdt.rs` — Global Descriptor Table and Task State Segment
- `idt.rs` — Interrupt Descriptor Table and exception handlers
- `pic.rs` — 8259 PIC remap and mask
- `apic.rs` — Local APIC and IOAPIC initialization and IRQ routing
- `interrupts.rs` — hardware IRQ vectors and ISR implementations
- `ist_guard.rs` — unmapped guard page below the `#DF` IST stack

All components are initialized by `arch::init()` followed by
`arch::init_apic()`. Interrupts remain disabled until `_start` calls `sti`
after both return.

---

## GDT and TSS (`gdt.rs`)

### Design

vibix uses a minimal GDT with three entries:

1. **Kernel code segment** — `DPL=0`, 64-bit code.
2. **Kernel data segment** — `DPL=0`.
3. **TSS descriptor** — points to the kernel TSS.

The TSS is required solely to register an Interrupt Stack Table (IST) entry for
the `#DF` (double-fault) handler. When the CPU takes a double fault it switches
RSP to the IST stack, bypassing whatever (potentially corrupt or overflowed)
stack the faulting code was on.

### IST Stack

A 20 KiB static buffer (`DOUBLE_FAULT_STACK`) is allocated page-aligned. The
TSS points its IST[0] entry to the top of this buffer. The lowest 4 KiB page
of the buffer becomes the guard page (unmapped by `ist_guard::init()`) after
paging is up, leaving 16 KiB of usable stack for the `#DF` handler.

`df_stack_guard_addr()` returns the virtual address of the guard page so
`ist_guard` can unmap it.

### Initialization

```rust
gdt::init();
// Loads the GDT, sets CS/DS/ES/FS/GS/SS, loads the TSS selector.
```

---

## IDT and Exception Handlers (`idt.rs`)

### Design

The IDT registers handlers for the following vectors:

| Vector | Name | Handler behavior |
|---|---|---|
| `#DE` (0) | Divide Error | Log to serial + halt |
| `#UD` (6) | Invalid Opcode | Log to serial + halt |
| `#GP` (13) | General Protection | Log error code + frame + halt |
| `#PF` (14) | Page Fault | Check test hook / stack overflow; log + halt |
| `#DF` (8) | Double Fault | Uses IST[0]; check stack overflow; log + halt |
| 0x20 | Timer IRQ | See `interrupts.rs` |
| 0x21 | Keyboard IRQ | See `interrupts.rs` |

The `#DF` vector has an IST index (`DOUBLE_FAULT_IST_INDEX = 0`) so the CPU
always switches to the dedicated IST stack regardless of the current RSP.

### Page Fault Hook

The `#PF` handler checks `test_hook::take_page_fault_expectation()` before
the normal diagnostic path. Integration tests that deliberately trigger a page
fault (e.g., the `page_fault` test) pre-arm this hook with the expected fault
address. A matching fault exits QEMU with success; a mismatch exits with
failure.

The `#PF` handler also checks whether the fault address falls inside a kernel
task's guard page (via `task::find_stack_overflow`). If it does, the output
identifies the overflowing task by ID before halting.

### Initialization

```rust
idt::init();
// Calls IDT.load() — installs the static IDT into IDTR.
```

---

## 8259 PIC (`pic.rs`)

### Design

The legacy 8259 Programmable Interrupt Controller ships remapped to vector
offsets `0x20` (master) and `0x28` (slave) at `pic::init_and_disable()`. This
puts legacy IRQs above the CPU exception range (0–31) so that e.g. IRQ0 fires
at vector 0x20 instead of colliding with the `#DE` exception.

Immediately after remapping, all IRQ lines on both PICs are masked. Once the
IOAPIC is configured the PIC remains permanently disabled and the APIC handles
all interrupts.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `PIC_1_OFFSET` | `0x20` | Vector base for master PIC (and for LAPIC vectors too) |
| `PIC_2_OFFSET` | `0x28` | Vector base for slave PIC |

---

## LAPIC and IOAPIC (`apic.rs`)

### Design

vibix uses the xAPIC (MMIO) interface. The LAPIC and IOAPIC physical addresses
come from the ACPI MADT (see [acpi.md](acpi.md)).

**LAPIC initialization (`init_bsp`):**
1. Maps the LAPIC MMIO region (`0x1000` bytes) into the HHDM window with
   `NO_CACHE | WRITE_THROUGH` flags so MMIO accesses are not cached.
2. Reads and logs the BSP LAPIC ID.
3. Sets the Task Priority Register (TPR) to 0 — all interrupt priorities
   allowed.
4. Sets the Spurious Interrupt Vector (SVR) to vector `0xFF` with the APIC
   software-enable bit, bringing the LAPIC online.

**IOAPIC initialization (`ioapic_init`):**
1. Maps each IOAPIC MMIO region (also `NO_CACHE | WRITE_THROUGH`).
2. Reads the IOAPIC version register to find the max redirection-entry count.
3. Masks all redirection entries on startup.

**IRQ routing (`route_legacy_irq`):**

After init, `arch::init_apic` routes two legacy ISA IRQs:
- IRQ0 (PIT timer) → vector `0x20` (Timer)
- IRQ1 (PS/2 keyboard) → vector `0x21` (Keyboard)

The MADT `InterruptSourceOverride` records are consulted for each ISA IRQ to
determine the correct GSI, trigger mode (edge/level), and polarity (active-high/
low) before writing the IOAPIC redirection entry.

### EOI Protocol

Both the LAPIC and the legacy PIC need an EOI (End-Of-Interrupt) signal at the
end of each ISR. `pic::notify_eoi(vector)` handles both: it always writes to
the LAPIC EOI register, and if the vector is in the slave PIC range it also
sends an EOI to the slave PIC's command port. This keeps the hybrid path working
during the brief window between PIC remap and APIC takeover.

---

## Hardware ISRs (`interrupts.rs`)

### Timer ISR (`timer_interrupt`, vector 0x20)

1. `time::on_tick()` — increment the monotonic tick counter.
2. `notify_eoi(Timer)` — send EOI before any preemption (avoids a second
   tick interrupt landing on the incoming task before it sends its own EOI).
3. `task::preempt_tick()` — check the current task's time slice; rotate if
   expired.

### Keyboard ISR (`keyboard_interrupt`, vector 0x21)

1. Read one scancode byte from I/O port `0x60`.
2. `input::push_scancode_from_isr(code)` — push into the lock-free ring buffer.
3. `notify_eoi(Keyboard)` — acknowledge.

ISRs are deliberately thin: no decoding, no logging, no blocking I/O.

---

## IST Guard Page (`ist_guard.rs`)

After paging is initialized, `ist_guard::init()` unmaps the 4 KiB page at
`gdt::df_stack_guard_addr()`. This is the lowest page of the `DOUBLE_FAULT_STACK`
buffer. An overflow of the `#DF` IST stack walks RSP downward into this unmapped
page, triggering a `#PF` with a fault address that identifies the overflow,
rather than silently corrupting adjacent kernel data.
