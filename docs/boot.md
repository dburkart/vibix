# Boot Subsystem

**Source:** `kernel/src/boot.rs`

## Overview

vibix boots under the [Limine boot protocol](https://github.com/limine-bootloader/limine/blob/trunk/PROTOCOL.md).
The boot subsystem is a thin collection of Limine request statics that the
bootloader locates via dedicated link sections and fills in before transferring
control to `_start`.

No initialization function is required — the statics are populated by the
bootloader before the kernel runs. All other subsystems that need boot
information (memory map, HHDM offset, RSDP) call the relevant `.get_response()`
method directly.

## Design

Limine's protocol works by embedding well-known magic-number structs (requests)
in the kernel binary inside a specific linker section. The bootloader scans the
image, fills each request in place, then jumps to the kernel entry point. The
start and end markers (`_START_MARKER`, `_END_MARKER`) delimit this section so
the bootloader can efficiently scan it.

## Requests

| Static | Type | Purpose |
|---|---|---|
| `BASE_REVISION` | `BaseRevision` | Asserts protocol compatibility (checked in `_start`) |
| `FRAMEBUFFER_REQUEST` | `FramebufferRequest` | Linear framebuffer address, dimensions, pixel format |
| `MEMMAP_REQUEST` | `MemoryMapRequest` | Physical memory map (USABLE, reserved, reclaimable regions) |
| `HHDM_REQUEST` | `HhdmRequest` | Higher-Half Direct Map base offset |
| `STACK_REQUEST` | `StackSizeRequest` | Requests a 64 KiB bootstrap stack |
| `KERNEL_ADDRESS_REQUEST` | `ExecutableAddressRequest` | Physical + virtual base of the loaded kernel image (used by ksymtab) |
| `KERNEL_FILE_REQUEST` | `ExecutableFileRequest` | The kernel ELF file itself (used by ksymtab to embed the symbol table) |
| `RSDP_REQUEST` | `RsdpRequest` | Physical address of the ACPI RSDP (passed to `acpi::init`) |

## Usage

All requests are `pub` and can be accessed from anywhere in the kernel:

```rust
use vibix::boot::HHDM_REQUEST;

let hhdm_offset = HHDM_REQUEST
    .get_response()
    .expect("Limine HHDM response missing")
    .offset();
```

`get_response()` returns `None` if the bootloader did not fill in the request
(e.g., the bootloader does not support that feature). Most callers `expect` or
`unwrap` these responses because the kernel cannot make progress without them.

## Higher-Half Direct Map

The HHDM offset is a key constant for the rest of the kernel. Limine maps all
of physical memory at `HHDM_OFFSET + physical_address`. Subsystems that need to
dereference physical addresses (ACPI table walking, APIC MMIO, paging) add the
HHDM offset to convert physical → virtual.

## Linker Integration

`kernel/linker.ld` reserves the `.limine_requests` section so the bootloader
can find all requests. The start and end marker objects delimit the extent of
this section.
