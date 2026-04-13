# Build and run playbook

This playbook captures repo-level build and boot behavior that applies across agent runtimes.

## Core rule

All build and boot orchestration goes through `cargo xtask`. Do not invoke `cargo build`
directly on the kernel crate; `xtask` owns the target selection, `-Z build-std` flags,
Limine fetch, ISO assembly, and QEMU launch behavior.

## Commands

```sh
cargo xtask build              # compile kernel for x86_64-unknown-none
cargo xtask iso                # build + produce target/vibix.iso
cargo xtask run                # build + iso + boot under QEMU (serial on stdio)
cargo xtask run --release      # optimized build
cargo xtask run --fault-test   # boot with a `ud2` in _start to exercise the #UD handler
cargo xtask run --panic-test   # trigger a deliberate panic to test backtraces
cargo xtask clean              # wipe target/ and build/
```

`--release`, `--fault-test`, and `--panic-test` are accepted by the relevant `xtask`
subcommands.

## First run

The first `iso`, `run`, `test`, or `smoke` invocation clones Limine into `build/limine/`
and compiles the host `limine` tool. That requires:

- `git`
- `make`
- a C compiler on `PATH`
- `xorriso`
- `qemu-system-x86_64`

## QEMU behavior

- `cargo xtask run` launches QEMU with serial attached to stdio.
- The normal kernel end-state is `hlt_loop()`, so QEMU idles until it is exited manually.
- In an interactive terminal, exit QEMU with `Ctrl-a x`.
- In Cursor Cloud, prefer `timeout 6 cargo xtask run` or a tmux-backed session, because
  the kernel does not terminate on its own in the happy path.

## Gotchas

- Do not add `build-std` to `.cargo/config.toml`. Host tests rely on the normal sysroot
  `std`, while kernel-target builds need `xtask` to pass `-Z build-std` only on the CLI.
- The workspace root `Cargo.toml` owns the kernel `panic = "abort"` profile settings.
  The test profile behavior is enforced with `-Z panic-abort-tests` in `.cargo/config.toml`.
- If `build/limine/` is stale or corrupted, remove that directory and rerun an `xtask`
  command to let the repo re-clone it.
