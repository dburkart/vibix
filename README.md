# vibix

A hobby x86_64 kernel, vibe-coded in Rust. Boots under the Limine boot
protocol, prints to serial + a framebuffer console, installs a minimal
GDT/TSS + IDT with CPU exception handlers, owns a 1 MiB kernel heap,
and drives a PIT-backed timer + PS/2 keyboard through the legacy 8259
PIC.

## Status

Milestones complete:

- **M1 — hello-kernel:** Limine boot (BIOS + UEFI), COM1 serial,
  framebuffer text console (font8x8), GDT/TSS + `#DF` IST, IDT for
  `#DE`/`#UD`/`#GP`/`#PF`/`#DF`.
- **M2 — memory + testing:** bump frame allocator over Limine's
  USABLE map, `linked_list_allocator`-backed `#[global_allocator]`
  (1 MiB via HHDM — no custom paging yet), three-layer automated
  testing story (see below).
- **M3 — interrupts:** 8259 PIC remapped to 0x20/0x28, PIT at 100 Hz
  driving `time::uptime_ms()`, PS/2 keyboard ISR feeding a ring
  buffer decoded by `pc-keyboard` on the consumer side. Keystrokes
  in QEMU echo over serial.

Out of scope for now: paging beyond Limine's defaults, a reclaiming
frame allocator, APIC, preemptive scheduling, userspace.

## Requirements

- Rust nightly (auto-selected via `rust-toolchain.toml`)
- `qemu-system-x86_64`
- `xorriso` (for ISO assembly)
- `git`, `make`, a C compiler (first run builds the Limine host tool)

## Build & run

```sh
cargo xtask run              # build + iso + boot under QEMU (serial on stdio)
cargo xtask run --release    # optimized build
cargo xtask run --fault-test # trigger a ud2 to verify the #UD handler
cargo xtask iso              # produce target/vibix.iso without booting
cargo xtask test             # host unit tests + QEMU integration tests
cargo xtask smoke            # boot the kernel, assert on expected serial markers
cargo xtask clean            # wipe target/ and build/
```

On first `iso`/`run`, xtask clones Limine (`v8.x-binary`) into
`build/limine/` and builds the host `limine` tool.

Exit QEMU with `Ctrl-a x`.

## Testing

Three layers, all driven by xtask:

1. **Host unit tests** (`cargo xtask test`, first phase) — `cargo test
   --lib` over pure-logic modules (e.g. `mem::frame`). The kernel crate
   is `#![cfg_attr(not(test), no_std)]` so these modules compile against
   host `std` under `cargo test`.
2. **In-kernel integration tests** (`cargo xtask test`, second phase) —
   each file under `kernel/tests/` is its own `no_std` + `no_main`
   kernel binary. `cargo test --target x86_64-unknown-none` builds each,
   and a custom runner (`xtask test-runner`) wraps each compiled ELF in
   an ISO and boots it under QEMU. Pass/fail comes from the
   `isa-debug-exit` protocol (Success = 0x20 → process 65, Failure =
   0x10 → process 33). `should_panic` inverts its panic handler to
   verify the panic path itself.
3. **End-to-end smoke** (`cargo xtask smoke`) — boots the normal kernel,
   captures serial output, and asserts on a fixed list of markers
   (`vibix booting`, `memory map:`, `hhdm offset:`, `GDT + IDT loaded`,
   `heap: 1024 KiB`, `vibix online.`). Cheap regression lane: rename a
   log line and this goes red.

## Layout

```
kernel/              # the kernel crate (lib + thin bin)
  linker.ld          # higher-half layout, Limine request sections
  limine.conf        # boot-loader config
  src/
    lib.rs           # module tree; #![cfg_attr(not(test), no_std)]
    main.rs          # _start, init sequence, panic handler
    boot.rs          # Limine request statics
    serial.rs        # COM1 writer + serial_print!/serial_println!
    framebuffer.rs   # font8x8 console + print!/println!
    test_harness.rs  # QemuExitCode, Testable, test panic handler
    mem/
      frame.rs       # BumpFrameAllocator (host-unit-tested)
      heap.rs        # heap init + #[global_allocator]
    arch/x86_64/     # gdt + idt
  tests/             # one no_std kernel binary per file
    basic_boot.rs
    heap_alloc.rs
    should_panic.rs
xtask/               # build/iso/run/test/smoke orchestrator
```

## License

Dual-licensed under MIT or Apache-2.0.
