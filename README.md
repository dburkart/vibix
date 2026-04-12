# vibix

A hobby x86_64 kernel, vibe-coded in Rust. Boots under the Limine boot
protocol, prints to serial + a framebuffer console, and installs a
minimal GDT/TSS + IDT with CPU exception handlers.

## Status

Hello-kernel milestone complete:

- Limine boot (BIOS + UEFI via a hybrid ISO)
- COM1 16550 serial logging
- Linear-framebuffer text console (font8x8 glyphs)
- GDT + TSS with a dedicated IST stack for `#DF`
- IDT handlers for `#DE`, `#UD`, `#GP`, `#PF`, `#DF`
- Panic handler that logs + exits QEMU via `isa-debug-exit`

Out of scope for now: paging beyond Limine's defaults, physical frame
allocator, heap, PIC/APIC + timer IRQs, keyboard, scheduling, userspace.

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
cargo xtask clean            # wipe target/ and build/
```

On first `iso`/`run`, xtask clones Limine (`v8.x-binary`) into
`build/limine/` and builds the host `limine` tool.

Exit QEMU with `Ctrl-a x`.

## Layout

```
kernel/              # the kernel crate
  linker.ld          # higher-half layout, Limine request sections
  limine.conf        # boot-loader config
  src/
    main.rs          # _start, init sequence, panic handler
    boot.rs          # Limine request statics
    serial.rs        # COM1 writer + serial_print!/serial_println!
    framebuffer.rs   # font8x8 console + print!/println!
    arch/x86_64/     # gdt + idt
xtask/               # build/iso/run orchestrator
```

## License

Dual-licensed under MIT or Apache-2.0.
