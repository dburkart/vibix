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
| [tasks.md](tasks.md) | Preemptive scheduler + blocking primitives | `kernel/src/task/`, `kernel/src/sync/` |
| [diagnostics.md](diagnostics.md) | klog ring, ksymtab, backtrace unwinder | `kernel/src/klog.rs`, `kernel/src/ksymtab.rs`, `kernel/src/arch/x86_64/backtrace.rs` |
| *(see below)* | Virtual filesystem + per-process fd table | `kernel/src/fs/vfs/`, `kernel/src/fs/mod.rs` |

## Initialization Order

The kernel initializes subsystems in a fixed sequence. The `vibix::init()`
function (in `kernel/src/lib.rs`) encodes the mandatory ordering for code
shared between the main binary and integration tests:

```
serial::init()          — COM1 online; all subsequent output is visible
arch::init()            — GDT + TSS, IDT, 8259 PIC remapped + masked
mem::init()             — frame allocator, paging mapper, heap
arch::init_apic(rsdp_phys, hhdm_offset)
                        — ACPI parse, LAPIC + IOAPIC init, IRQ routing
time::init()            — PIT at 100 Hz
                          (vibix::init() returns; interrupts still disabled)
```

After `vibix::init()` returns, the caller (`main.rs`) completes initialization:

```
sti                     — interrupts enabled
task::init()            — bootstrap task, scheduler online
```

The framebuffer console is optional and initialized separately in `main.rs`
immediately after `serial::init()`, before the shared `vibix::init()` call.

## Filesystem

The filesystem layer follows the classic vnode model (Kleiman, USENIX 1986),
split across two directories:

- `kernel/src/fs/vfs/` — the virtual filesystem core. Three refcounted
  in-kernel objects (`SuperBlock`, `Inode`, `Dentry`) driven by four
  dyn-dispatch traits (`FileSystem`, `SuperOps`, `InodeOps`, `FileOps`). A
  mount table attaches superblocks at dentries; path resolution walks the
  dentry tree across mount points and terminates at an `Arc<Inode>`.
  Concrete filesystems (`ramfs`, `tarfs`, `devfs`) live beside `mod.rs` in
  that directory and plug in by implementing the operation traits.
- `kernel/src/fs/mod.rs` — the per-process fd table (`FileDescTable`) and
  the `FileBackend` trait. This is a thin adapter: path-opened files flow
  through `vfs::VfsBackend`; `SerialBackend` provides stdio on fds 0/1/2
  without going through the VFS so console I/O works before any mount.

See [RFC 0002](RFC/0002-virtual-filesystem.md) for the design rationale,
object lifetimes, locking order, and roadmap.
