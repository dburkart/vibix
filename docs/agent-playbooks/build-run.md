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

## Base system programs

Programs in `base/` are the shipped userspace — they must be written against the in-repo
`std` fork (`library/std/`), not `#![no_std]`. The only exceptions are the low-level
crates that live *below* `std` in the dependency stack (`vibix_abi`, `vibix_libc`,
`vibix_libc_defs`, `ld_vibix`, `init`).

New base programs are built out-of-workspace via `--manifest-path` with:

- Target spec: `x86_64-unknown-vibix.json` (workspace root).
- `-Z build-std=std,core,alloc,panic_abort -Z build-std-features=compiler-builtins-mem`.
- `__CARGO_TESTS_ONLY_SRC_ROOT` pointing at `library/`.

See `build_userspace_std_hello()` in `xtask/src/main.rs` for the reference pattern. Each
new program needs a matching `build_<name>()` function wired into the ISO/rootfs assembly.

See `base/README.md` for the full convention.

## Gotchas

- Do not add `build-std` to `.cargo/config.toml`. Host tests rely on the normal sysroot
  `std`, while kernel-target builds need `xtask` to pass `-Z build-std` only on the CLI.
- The workspace root `Cargo.toml` owns the kernel `panic = "abort"` profile settings.
  The test profile behavior is enforced with `-Z panic-abort-tests` in `.cargo/config.toml`.
- If `build/limine/` is stale or corrupted, remove that directory and rerun an `xtask`
  command to let the repo re-clone it.
