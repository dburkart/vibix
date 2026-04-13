# vibix
*Pronounced VIBE-IX*

A hobby x86_64 kernel, vibe-coded in Rust. Boots under the Limine boot
protocol, prints to serial + a framebuffer console, installs a full GDT/TSS +
IDT with CPU exception handlers, manages physical memory with a bitmap frame
allocator, owns a growing kernel heap backed by custom paging, drives APIC
interrupts discovered via ACPI, runs preemptively-scheduled kernel tasks
with blocking synchronisation primitives, and emits symbolicated panic
backtraces via an embedded kernel symbol table.

## Instructions for Humans

vibix is built by autonomous agents. The original loop lives in
`.claude/skills/auto-engineer/SKILL.md` as `/auto-engineer`, a Claude Code
skill that picks an unblocked GitHub issue, plans the change, implements
it, opens a PR, chases CI + review-bot feedback, and loops. Cursor Cloud now
has a companion skill at `.cursor/skills/cursor-cloud-auto-engineer/SKILL.md`
invoked as `/cursor-cloud-auto-engineer`, which mirrors the branch-to-PR flow
but stops at the PR handoff instead of self-merging or self-rescheduling.

To run the loop yourself, you need Docker, a Claude Code login on the host
(`claude` logged in at least once, so `~/.claude.json` + `~/.claude/`
exist), and a GitHub token with repo write access.

```sh
# one-time: add yourself to the docker group so the wrapper doesn't need sudo
sudo usermod -aG docker "$USER" && newgrp docker

# each run
export GITHUB_TOKEN=ghp_...
./scripts/auto-engineer.sh
```

The wrapper builds a container image (first run ~5–10 min) that bundles
every build/test dep — Rust nightly, `qemu-system-x86_64`, `xorriso`,
`gh`, and Claude Code itself — then runs `claude --dangerously-skip-permissions`
against a fresh clone inside the container. Your host `~/.claude` auth is
bind-mounted in, so the container talks to Anthropic as you.

Under the hood:

- **`Dockerfile`** — Ubuntu 24.04 base, dep install, rustup pre-warm.
- **`scripts/docker-entrypoint.sh`** — clones the repo, wires up `gh` auth,
  execs `claude`.
- **`scripts/auto-engineer.sh`** — host wrapper: sources `.env`, builds the
  image, and runs the container with the right mounts + SELinux handling.

Ctrl-C at any time to stop the loop.

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
cargo xtask run --panic-test # trigger a deliberate panic to test backtraces
cargo xtask iso              # produce target/vibix.iso without booting
cargo xtask test             # host unit tests + QEMU integration tests
cargo xtask smoke            # boot the kernel, assert on expected serial markers
cargo xtask lint             # clippy --all-targets with -D warnings
cargo xtask clean            # wipe target/ and build/
```

On first `iso`/`run`, xtask clones Limine (`v8.x-binary`) into
`build/limine/` and builds the host `limine` tool. After linking, xtask
strips debug sections and patches the embedded kernel symbol table in-place
before assembling the ISO.

Exit QEMU with `Ctrl-a x`.

## Testing

Three layers, all driven by xtask:

1. **Host unit tests** (`cargo xtask test`, first phase) — `cargo test
   --lib` over pure-logic modules (e.g. `mem::frame`, `input::RingBuffer`).
   The kernel crate is `#![cfg_attr(not(test), no_std)]` so these modules
   compile against host `std` under `cargo test`.
2. **In-kernel integration tests** (`cargo xtask test`, second phase) —
   each file under `kernel/tests/` is its own `no_std` + `no_main`
   kernel binary. `cargo test --target x86_64-unknown-none` builds each,
   and a custom runner (`xtask test-runner`) wraps each compiled ELF in
   an ISO and boots it under QEMU. Pass/fail comes from the
   `isa-debug-exit` protocol (Success = 0x20 → process 65, Failure =
   0x10 → process 33). `should_panic` inverts its panic handler to
   verify the panic path itself.

   Current integration tests: `basic_boot`, `heap_alloc`, `heap_grow`,
   `should_panic`, `timer_tick`, `paging`, `pml4_switch`, `page_fault`,
   `tasks`, `preempt`, `blocking_sync`, `apic_online`, `backtrace`.
3. **End-to-end smoke** (`cargo xtask smoke`) — boots the normal kernel,
   captures serial output, and asserts on a fixed list of markers:
   `vibix booting`, `memory map:`, `hhdm offset:`, `GDT + IDT loaded`,
   `heap: 1024 KiB`, `paging: mapper online`, `paging: IST guard installed`,
   `paging: switched to kernel PML4`, `PIC remapped`, `acpi: MADT parsed`,
   `apic: BSP online`, `ioapic: initialized`, `timer: 100 Hz`,
   `vibix online.`, `interrupts enabled`, `tasks: scheduler online`.
   Cheap regression lane: rename a log line and this goes red.

## Layout

```
kernel/              # the kernel crate (lib + thin bin)
  linker.ld          # higher-half layout, Limine request sections
  limine.conf        # boot-loader config
  src/
    lib.rs           # module tree; #![cfg_attr(not(test), no_std)]
    main.rs          # _start, init sequence, panic handler (backtrace + klog dump)
    boot.rs          # Limine request statics (framebuffer, HHDM, memmap, RSDP)
    serial.rs        # COM1 writer + serial_print!/serial_println!
    framebuffer.rs   # font8x8 console + print!/println!
    test_harness.rs  # QemuExitCode, Testable, test panic handler
    test_hook.rs     # one-shot #PF expectation hooks for fault-injection tests
    klog.rs          # 64 KiB leveled ring-buffer log (Error/Warn/Info/Debug/Trace)
    ksymtab.rs       # embedded kernel symbol table (addr→name, patched post-link)
    acpi.rs          # RSDP→XSDT/RSDT→MADT parser; extracts LAPIC/IOAPIC topology
    time.rs          # PIT channel 0 at 100 Hz; uptime_ms() monotonic clock
    input.rs         # RingBuffer<T,N> + PS/2 keyboard ISR + pc_keyboard decoding
    mem/
      frame.rs       # BitmapFrameAllocator (host-unit-tested; supports deallocation)
      heap.rs        # heap init + #[global_allocator]; auto-grows via paging
      paging.rs      # kernel PML4 builder; map_range; WC framebuffer via PAT
      pat.rs         # Page Attribute Table reprogramming (WC slot)
    arch/x86_64/
      gdt.rs         # GDT + TSS with IST for #DF
      idt.rs         # IDT installation; exception handlers
      interrupts.rs  # PIT timer + keyboard ISR vectors
      pic.rs         # 8259 PIC remap + mask (disabled once APIC takes over)
      apic.rs        # LAPIC + IOAPIC init; IRQ routing; BSP bringup
      ist_guard.rs   # unmapped guard page below #DF IST stack
      backtrace.rs   # RBP-chain unwinder; resolves frames via ksymtab
    task/
      mod.rs         # scheduler entry points; preemption tick hook
      task.rs        # per-task kernel stack + saved register context
      scheduler.rs   # round-robin ready queue
      switch.rs      # hand-written context-switch assembly
  tests/             # one no_std kernel binary per file (13 total)
    basic_boot.rs
    heap_alloc.rs
    heap_grow.rs
    should_panic.rs
    timer_tick.rs
    paging.rs
    pml4_switch.rs
    page_fault.rs
    tasks.rs
    preempt.rs
    blocking_sync.rs
    apic_online.rs
    backtrace.rs
xtask/               # build/iso/run/test/smoke/lint orchestrator
```

## License

Dual-licensed under MIT or Apache-2.0.
