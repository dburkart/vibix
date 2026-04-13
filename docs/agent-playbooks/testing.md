# Testing playbook

This playbook captures repo-level test behavior that applies across agent runtimes.

## Core commands

```sh
cargo xtask test     # host unit tests + QEMU integration tests
cargo xtask smoke    # boot the normal kernel and assert expected serial markers
```

Run `cargo xtask test` for code changes that can affect logic or boot behavior. Run
`cargo xtask smoke` when you need end-to-end confidence that the normal boot path still
prints the expected serial markers.

## Layer 1 - host unit tests

Pure-logic modules can compile under host `std` because `kernel/src/lib.rs` is
`#![cfg_attr(not(test), no_std)]`.

Use inline `#[cfg(test)] mod tests { ... }` blocks for code that does not touch:

- `x86_64`
- `uart_16550`
- MMIO
- Limine statics

Those tests run in the first phase of `cargo xtask test`.

## Layer 2 - QEMU integration tests

Each file under `kernel/tests/*.rs` is its own `#![no_std] #![no_main]` kernel binary
with its own `_start`, panic handler, and explicit test list. The repo builds them for
`x86_64-unknown-none`, wraps them in ISOs, and boots them under QEMU through
`xtask test-runner`.

Pass/fail comes from the `isa-debug-exit` protocol:

- Success: write `0x20` to port `0xf4`, which makes QEMU exit `65`
- Failure: write `0x10` to port `0xf4`, which makes QEMU exit `33`

`should_panic.rs` intentionally inverts its panic handler so the panic path itself is
tested.

To add a new integration test:

1. Create `kernel/tests/my_test.rs` modeled on an existing test such as `basic_boot.rs`.
2. Add a `[[test]] name = "my_test" harness = false` entry to `kernel/Cargo.toml`.
3. Add `"my_test"` to the explicit test-name list in `xtask/src/main.rs::test_all`.

## Layer 3 - smoke regression

`cargo xtask smoke` boots the normal kernel, captures serial output for a short window,
then checks that every marker in `SMOKE_MARKERS` is present.

When a new boot-phase log line becomes part of the expected healthy path, add it to
`SMOKE_MARKERS` so the smoke lane protects it.

## Gotchas

- Do not add `-no-shutdown` to the `test_runner` QEMU args. It breaks the
  `isa-debug-exit` pass/fail protocol and causes tests to hang until timeout.
- Do not run `cargo test --target x86_64-unknown-none` without explicit `--test <name>`
  arguments. Cargo will try to build the library unittest harness and fail because that
  flow expects `std`.
- Keep host tests and kernel-target tests on separate `build-std` paths. `xtask` owns
  the kernel-target flags so host unit tests can use the normal sysroot.
