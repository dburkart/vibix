# vibix Kernel — Subsystem Documentation

This directory contains documentation for each major subsystem of the vibix
kernel. Each file describes the design, key data structures, initialization
sequence, and public API for its subsystem.

## Subsystems

| Document | Subsystem | Source |
|---|---|---|
| [boot.md](boot.md) | Limine boot protocol interface | `kernel/src/boot.rs` |
| [serial.md](serial.md) | COM1 serial console | `kernel/src/serial.rs` |
| [framebuffer.md](framebuffer.md) | Framebuffer text console | `kernel/src/framebuffer.rs` |
| [memory.md](memory.md) | Physical frame allocator, heap, paging, PAT | `kernel/src/mem/` |
| [interrupts.md](interrupts.md) | GDT, IDT, PIC, APIC, ISRs | `kernel/src/arch/x86_64/` |
| [acpi.md](acpi.md) | ACPI RSDP/MADT parser | `kernel/src/acpi.rs` |
| [time.md](time.md) | PIT-driven monotonic clock | `kernel/src/time.rs` |
| [input.md](input.md) | PS/2 keyboard and ring buffer | `kernel/src/input.rs` |
| [tasks.md](tasks.md) | Cooperative/preemptive scheduler | `kernel/src/task/` |
| [diagnostics.md](diagnostics.md) | klog ring, ksymtab, backtrace unwinder | `kernel/src/klog.rs`, `kernel/src/ksymtab.rs`, `kernel/src/arch/x86_64/backtrace.rs` |

## Initialization Order

The kernel brings subsystems up in a fixed sequence. The `vibix::init()`
function (in `kernel/src/lib.rs`) encodes the mandatory ordering for code
shared between the main binary and integration tests:

```
serial::init()          — COM1 online; all subsequent output is visible
arch::init()            — GDT + TSS, IDT, 8259 PIC remapped + masked
mem::init()             — frame allocator, paging mapper, heap
arch::init_apic()       — ACPI parse, LAPIC + IOAPIC init, IRQ routing
time::init()            — PIT at 100 Hz
sti                     — interrupts enabled (done by the caller)
task::init()            — bootstrap task, scheduler online
```

The framebuffer console is optional and initialized separately in `main.rs`
immediately after `serial::init()`, before the shared `vibix::init()` call.
