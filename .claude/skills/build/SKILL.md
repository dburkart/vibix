---
name: build
description: Build the vibix kernel, assemble a bootable ISO, or run it under QEMU. Use when the user asks to build, compile, make an ISO, boot, or run the kernel.
---

# Building and running vibix

All build/boot orchestration goes through the `xtask` workspace crate — **never** call `cargo build` on the kernel directly. xtask handles the `-Z build-std` flags, target selection, Limine fetch, ISO assembly, and QEMU launch.

## Commands

```sh
cargo xtask build              # compile kernel for x86_64-unknown-none
cargo xtask iso                # build + produce target/vibix.iso
cargo xtask run                # build + iso + boot under QEMU (serial on stdio)
cargo xtask run --release      # optimized build
cargo xtask run --fault-test   # boot with a `ud2` in _start to exercise the #UD handler
cargo xtask clean              # wipe target/ and build/
```

`--release` and `--fault-test` are flags that apply to `build`, `iso`, and `run`.

## First run

xtask will clone Limine (`v8.x-binary`) into `build/limine/` and compile the host `limine` tool. This needs `git`, `make`, and a C compiler on PATH; `xorriso` is required for ISO assembly; `qemu-system-x86_64` for `run`.

## Exit QEMU

`Ctrl-a x` in the serial terminal. The kernel's normal end-state is `hlt_loop()` after printing `vibix online.`, so QEMU will idle until you kill it (except when `--fault-test` triggers a panic exit).

## Gotchas

- Don't add `build-std` to `.cargo/config.toml` — it will break host `cargo test --lib` by conflicting with the sysroot's `std`. xtask passes `-Z build-std=core,compiler_builtins,alloc` on the CLI only for kernel-target builds.
- The kernel `panic="abort"` profile is set at the workspace root `Cargo.toml`, not the kernel crate. For the test profile, panic=abort is enforced via `-Z panic-abort-tests` in `.cargo/config.toml` (cargo silently ignores `[profile.test] panic="abort"`).
- If `build/limine/` is stale or corrupted, `rm -rf build/limine` and re-run — xtask will re-clone.
