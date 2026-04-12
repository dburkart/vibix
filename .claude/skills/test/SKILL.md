---
name: test
description: Run vibix tests — host unit tests, in-kernel QEMU integration tests, or the end-to-end serial-marker smoke check. Use when the user asks to test, verify, check, or regression-test the kernel.
---

# Testing vibix

Three layers, all driven by xtask:

```sh
cargo xtask test     # host unit tests (cargo test --lib) + QEMU integration tests
cargo xtask smoke    # boot the normal kernel, assert expected serial markers
```

## Layer 1 — host unit tests

Pure-logic modules (e.g. `mem::frame::BumpFrameAllocator`) compile under host `std` because `kernel/src/lib.rs` is `#![cfg_attr(not(test), no_std)]`. Kernel-only modules gate on `#[cfg(target_os = "none")]` so they don't drag MMIO or x86 intrinsics into the host build.

To add host-testable logic: put it in a module that does **not** touch `x86_64`, `uart_16550`, MMIO, or Limine statics. Add `#[cfg(test)] mod tests { ... }` inline. It will run under `cargo xtask test`'s first phase.

## Layer 2 — QEMU integration tests

Each file under `kernel/tests/*.rs` is its own `#![no_std] #![no_main]` kernel binary with its own `_start`, panic handler, and explicit test list. `cargo test --target x86_64-unknown-none` builds each, and `.cargo/config.toml` points its `runner` at `xtask test-runner`, which wraps the ELF in an ISO and boots it under QEMU.

Pass/fail comes from the `isa-debug-exit` protocol:
- Success = write `0x20` to port `0xf4` → QEMU process exits `65`
- Failure = write `0x10` → QEMU process exits `33`

`should_panic.rs` inverts its panic handler (panic → Success, no-panic → Failure) to verify the panic path itself.

To add an integration test, create `kernel/tests/my_test.rs` modeled on `basic_boot.rs`, then add a `[[test]] name = "my_test" harness = false` entry to `kernel/Cargo.toml` **and** add `"my_test"` to the test name list in `xtask/src/main.rs::test_all`.

## Layer 3 — smoke / regression

`cargo xtask smoke` boots the normal kernel, captures serial for 4 seconds, kills QEMU, then greps the output for a fixed list of markers (see `SMOKE_MARKERS` in `xtask/src/main.rs`). Cheap lane for catching serial-pipeline regressions — rename a log line and this goes red.

When adding a new boot-phase milestone log line worth regression-guarding, add it to `SMOKE_MARKERS`.

## Gotchas

- **Do not** add `-no-shutdown` to the `test_runner` QEMU args — it suppresses `isa-debug-exit` and causes tests to hang until the 30 s timeout. `-no-shutdown` is fine in `run` and `smoke` because neither relies on the exit device for termination.
- `cargo test --target x86_64-unknown-none` **without** explicit `--test <name>` flags will try to build the lib's unittest harness, which fails (no std). `test_all` in xtask iterates test names explicitly for this reason.
- `-Z panic-abort-tests = true` in `.cargo/config.toml` is required; without it, cargo builds a second `core` with `panic=unwind` that clashes with the kernel's abort core.
- Host unit tests and kernel-target tests must not share `build-std` config — see the build skill.
