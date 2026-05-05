# base/

Base system programs shipped with vibix. Everything here is installed into the
root filesystem; test and demo binaries live in `tests/userspace/` instead.

## Convention: use std

All base system programs **must** be written against the in-repo `std` fork
(`library/std/`). They are compiled with `-Z build-std` targeting
`x86_64-unknown-vibix.json`, the same toolchain used by `tests/userspace/std_hello/`.

This means every crate here gets `String`, `Vec`, `HashMap`, `BufRead`,
`std::fs`, `std::process`, formatted I/O, and everything else `std` provides —
backed by the vibix PAL (`vibix_abi` → syscall ABI → kernel).

Do **not** write `#![no_std]` base system programs. The `no_std` + raw-syscall
style is appropriate for the low-level shim crates (`vibix_abi`, `vibix_libc`,
`ld_vibix`, `init`) that exist below `std` in the dependency stack, but
everything above that layer should use `std`.

## Build integration

Each new base program needs:

1. A `Cargo.toml` with a `[[bin]]` target (not a workspace member — built
   out-of-workspace via `--manifest-path`, same as `std_hello`).
2. A `build_<name>()` function in `xtask/src/main.rs` using the
   `VIBIX_USERSPACE_TARGET` spec and the `__CARGO_TESTS_ONLY_SRC_ROOT` env var
   to point `-Z build-std` at `library/`.
3. Integration into the ISO / rootfs assembly so the binary is available at
   boot.

## Current contents

| Crate | Role | Uses std? |
|---|---|---|
| `init` | PID 1 — first userspace process | No (below std) |
| `vibix_abi` | Syscall wrappers, `GlobalAlloc`, TLS errno | No (dep of std) |
| `vibix_libc` | C-ABI shim over `vibix_abi` | No (dep of std) |
| `vibix_libc_defs` | Shared type definitions | No (dep of std) |
| `ld_vibix` | Dynamic linker | No (below std) |
| `lib/` | Prebuilt shared objects (ld-musl stub) | N/A |
| `sh` | POSIX shell (`/bin/sh`) | Yes |
