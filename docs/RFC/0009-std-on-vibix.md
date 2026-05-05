---
rfc: 0009
title: Rust std on vibix
status: In Review
created: 2026-05-05
---

# RFC 0009: Rust std on vibix

## Abstract

Bring up Rust's `std` library on vibix so that standard Rust programs
(`std::fs`, `std::io`, `std::process`, `std::time`, etc.) can be
cross-compiled for the kernel, the vendored pjdfstest suite (186 tests
using `nix`, `tempfile`, `figment`, `inventory`) can run natively, and
real software can be ported over time. The design introduces a
`vibix_abi` runtime crate that bridges Rust's std platform abstraction
layer to vibix syscalls, a thin Rust-native libc shim for C-ABI
compatibility with the `libc`/`nix` crate ecosystem, a custom
`x86_64-unknown-vibix` target spec, and the missing syscalls needed to
close the gap.

## Motivation

vibix userspace today is `no_std`-only. Every binary — `init`,
`pjdfstest_runner`, `hello`, `shell_pipeline` — uses raw inline
`syscall` assembly with hand-rolled argument marshalling and no error
abstraction. This works for smoke tests but blocks three goals:

1. **Standard Rust programs.** Any crate that `use std::fs` or
   `use std::io` cannot compile for vibix. The pjdfstest suite
   (`tests/pjdfstest/`) depends on `nix`, `tempfile`, `figment`,
   `inventory`, `walkdir` — none of which build without std and a
   working `libc` crate.

2. **Developer velocity.** Writing raw syscall stubs for every new test
   binary is slow and error-prone (issue #531 documents the
   clobber-register footgun). A working std eliminates this friction.

3. **Software porting.** No real-world Rust program targets
   `x86_64-unknown-none`. Bringing up std opens the door to coreutils
   replacements, shell implementations, and eventually a self-hosted
   build environment.

The prerequisites are now in place:

- **TLS** (epic #827, closed): PT_TLS parsing, per-task `fs_base`,
  `arch_prctl(ARCH_SET_FS/ARCH_GET_FS)`, MSR_FS_BASE save/restore on
  context switch, fork/exec TLS handling, CR4.FSGSBASE.
- **Page cache + file mmap** (RFC 0007, accepted): demand-paged ELF
  loading, file-backed VMAs, PT_INTERP recursive interpreter loading.
- **VFS + ext2** (RFC 0004, implemented): 65+ syscalls covering file
  I/O, process lifecycle, signals, credentials, I/O multiplexing.
- **auxv** (`kernel/src/mem/auxv.rs`): AT_PHDR, AT_BASE, AT_ENTRY,
  AT_PHNUM, AT_PHENT, AT_RANDOM, AT_PAGESZ — ready for dynamic
  linker consumption.

## Background

### How Rust's std abstracts platforms

Rust's `library/std/src/sys/` contains two abstraction layers:

1. **PAL (Platform Abstraction Layer)** at `sys/pal/<os>/mod.rs` —
   thin: `init()`, `cleanup()`, `abort_internal()`, optional futex
   bindings.
2. **Subsystem modules** at `sys/<subsystem>/mod.rs` — heavyweight:
   `thread`, `fs`, `sync/mutex`, `sync/condvar`, `net`, `stdio`,
   `process`, `alloc`, `random`, `time`, `pipe`, `args`, `env`. Each
   uses `cfg_select!` to dispatch to platform-specific implementations.

Adding a new OS requires either:

- **Fork-and-patch**: add `target_os = "vibix"` branches to every
  subsystem module. Heavy maintenance burden; breaks on toolchain
  updates.
- **ABI-crate model** (Hermit, Motor OS): define a `vibix_abi` crate
  with a stable ABI surface that std calls into. The in-tree PAL is
  thin; the real implementation lives in `vibix_abi`. Hermit's PAL is
  only 2 files (`mod.rs` + `futex.rs`).
- **Unix-family model** (Redox): present as `target_family = "unix"`,
  reuse the `unix` PAL, provide a full libc implementation. Heaviest
  but gives full ecosystem compatibility.

### Prior art

**Redox OS** is the most mature Rust-based OS with std support. Their
`relibc` is a POSIX C library written in Rust with a PAL trait
defining ~84 methods. The `x86_64-unknown-redox` target was upstreamed
in December 2016 and reclassified as `target_family = "unix"` in
August 2019. Errno uses `#[thread_local] static ERRNO: Cell<c_int>`.

**Hermit OS** uses a minimal `hermit_abi` crate (alloc, futex, thread,
I/O) that std calls into — no libc needed. The PAL is 2 files. This
is the fastest path to a working std but doesn't support the `libc`
crate ecosystem.

**SerenityOS** built a custom LibC from scratch plus a custom dynamic
linker. Over 300 third-party ports. Demonstrates the value of a
complete libc for ecosystem compatibility.

**Managarm's mlibc** is a portable C library with a `sysdeps/`
abstraction layer. Used by Managarm, Lyre, and others. 250+ ports.

**Asterinas** (USENIX ATC '25) implements 210+ Linux syscalls with
a framekernel architecture, achieving Linux ABI compatibility with
performance parity. Demonstrates that full Linux ABI compatibility
is viable for Rust kernels.

### vibix's current syscall surface

vibix implements ~65 syscall numbers using the Linux x86_64 ABI
(`rax`=nr, `rdi`/`rsi`/`rdx`/`r10`/`r8`/`r9`=args):

| Category | Implemented |
|---|---|
| File I/O | `read`(0), `write`(1), `open`(2), `close`(3), `stat`(4), `fstat`(5), `lstat`(6), `lseek`(8), `ioctl`(16), `fcntl`(72), `fsync`(74), `fdatasync`(75), `truncate`(76), `ftruncate`(77), `getdents64`(217), `openat`(257), `newfstatat`(262) |
| Directory | `getcwd`(79), `chdir`(80), `mkdir`(83), `rmdir`(84) |
| Links | `link`(86), `unlink`(87), `symlink`(88), `readlink`(89), `linkat`(265), `symlinkat`(266), `readlinkat`(267), `unlinkat`(263) |
| Permissions | `chmod`(90), `fchmod`(91), `chown`(92), `fchown`(93), `lchown`(94), `fchownat`(260), `fchmodat`(268), `access`(21), `faccessat`(269), `faccessat2`(439) |
| Metadata | `utimensat`(280), `mknod`(133), `mknodat`(259), `mkdirat`(258) |
| Process | `fork`(57), `execve`(59), `exit`(60), `wait4`(61) |
| Memory | `mmap`(9), `mprotect`(10), `munmap`(11), `brk`(12), `madvise`(28) |
| Signals | `rt_sigaction`(13), `rt_sigprocmask`(14), `rt_sigreturn`(15), `kill`(62) |
| FD mgmt | `dup`(32), `dup2`(33), `dup3`(292), `pipe`(22), `pipe2`(293) |
| I/O mux | `poll`(7), `select`(23), `pselect6`(270), `ppoll`(271) |
| Creds | `getuid`(102), `getgid`(104), `geteuid`(107), `getegid`(108), `setuid`(105), `setgid`(106), `setreuid`(113), `setregid`(114), `setresuid`(117), `setresgid`(119), `getgroups`(115), `setgroups`(116) |
| Session | `setpgid`(109), `setsid`(112), `getpgid`(121), `getsid`(124) |
| Mount | `mount`(165), `umount2`(166) |
| Sync | `sync`(162) |
| Arch | `arch_prctl`(158) |

**Missing for std** (critical path):

| Syscall | Nr | Needed by |
|---|---|---|
| `getpid` | 39 | `std::process::id()`, libc, nix |
| `getppid` | 110 | `nix::unistd::getppid()` |
| `gettid` | 186 | pthread, `set_tid_address` |
| `exit_group` | 231 | std process exit (kills all threads) |
| `clock_gettime` | 228 | `std::time::Instant`, `SystemTime` |
| `nanosleep` | 35 | `std::thread::sleep()` |
| `getrandom` | 318 | `std::collections::HashMap` seed |
| `writev` | 20 | `std::io::Write` vectored I/O |
| `pread64` | 17 | `std::os::unix::fs::FileExt` |
| `pwrite64` | 18 | `std::os::unix::fs::FileExt` |
| `rename` | 82 | `std::fs::rename()` (impl exists, not wired) |
| `renameat` | 264 | `nix::fcntl::renameat()` |
| `set_tid_address` | 218 | glibc/musl init, `clone` child |
| `uname` | 63 | libc crate platform detection |

**Missing for threads** (Phase 3):

| Syscall | Nr | Needed by |
|---|---|---|
| `clone` | 56 | `std::thread::spawn()` |
| `futex` | 202 | `std::sync::Mutex`, `Condvar`, `Once` |
| `sched_yield` | 24 | `std::thread::yield_now()` |

## Design

### Overview

The design uses a **hybrid staged approach** that combines the Hermit
ABI-crate model (fast path to working std) with a Redox-style libc
shim (ecosystem compatibility for `nix`/`libc` crates):

```
┌─────────────────────────────────────────────────┐
│  User program (std Rust)                        │
│  use std::fs; use nix::unistd;                  │
├─────────────────────────────────────────────────┤
│  Rust std                                       │
│  sys/pal/vibix/ → calls vibix_abi               │
├────────────────────┬────────────────────────────┤
│  vibix_abi crate   │  vibix_libc crate          │
│  (Rust ABI for     │  (C ABI shim for           │
│   std internals)   │   libc/nix crates)         │
├────────────────────┴────────────────────────────┤
│  Inline syscall stubs (shared)                  │
│  syscall!(nr, a0, a1, ...) → i64               │
├─────────────────────────────────────────────────┤
│  vibix kernel                                   │
│  Linux x86_64 syscall ABI                       │
└─────────────────────────────────────────────────┘
```

**`vibix_abi`** is a `#![no_std]` crate that defines the ABI surface
std's PAL calls into: memory allocation, futex, thread lifecycle,
file I/O wrappers, time, random bytes, stdio. It contains inline
`syscall` assembly and marshals arguments/errors.

**`vibix_libc`** is a `cdylib`/`staticlib` crate that exposes C-ABI
symbols (`open`, `read`, `write`, `mmap`, `fork`, `__errno_location`,
etc.) so the upstream `libc` crate's extern declarations resolve. It
is a thin wrapper over the same syscall stubs that `vibix_abi` uses.

### Key Data Structures

#### Custom target specification

`x86_64-unknown-vibix.json`:

```json
{
  "llvm-target": "x86_64-unknown-none-elf",
  "data-layout": "e-m:e-p270:32:32-p271:32:32-p272:64:64-i64:64-i128:128-f80:128-n8:16:32:64-S128",
  "arch": "x86_64",
  "target-endian": "little",
  "target-pointer-width": "64",
  "target-c-int-width": "32",
  "os": "vibix",
  "env": "",
  "vendor": "unknown",
  "linker-flavor": "gnu-lld-cc",
  "linker": "rust-lld",
  "pre-link-args": {
    "gnu-lld-cc": ["-nostdlib", "-static"]
  },
  "panic-strategy": "abort",
  "disable-redzone": true,
  "features": "+sse,+sse2",
  "has-thread-local": true,
  "tls-model": "initial-exec",
  "position-independent-executables": true,
  "static-position-independent-executables": true,
  "relocation-model": "static",
  "executables": true,
  "max-atomic-width": 64,
  "crt-objects-fallback": "false"
}
```

Key choices:
- `"os": "vibix"` — enables `cfg(target_os = "vibix")` in std and
  the `libc` crate.
- `"has-thread-local": true` — vibix has TLS (epic #827).
- `"tls-model": "initial-exec"` — matches vibix's static TLS
  (ELF variant II). No `__tls_get_addr` needed.
- `"panic-strategy": "abort"` — no unwinding infrastructure yet.
- `"features": "+sse,+sse2"` — userspace can use SSE (kernel
  does XSAVE/XRSTOR on context switch).
- `"relocation-model": "static"` — static linking in Phase 1.

#### vibix_abi crate structure

```
userspace/vibix_abi/
├── Cargo.toml          # #![no_std], no deps
└── src/
    ├── lib.rs          # pub mod syscall, alloc, thread, ...
    ├── syscall.rs      # syscall!() macro, raw wrappers
    ├── alloc.rs        # GlobalAlloc via brk/mmap
    ├── errno.rs        # #[thread_local] ERRNO + __errno_location
    ├── thread.rs       # clone wrapper, thread exit
    ├── futex.rs        # futex(WAIT/WAKE) wrapper
    ├── time.rs         # clock_gettime wrapper
    ├── random.rs       # getrandom wrapper
    └── stdio.rs        # write(1, ...) / write(2, ...)
```

#### vibix_libc crate structure

```
userspace/vibix_libc/
├── Cargo.toml          # cdylib + staticlib, depends on vibix_abi
├── cbindgen.toml       # generates libc-compatible C headers
└── src/
    ├── lib.rs
    ├── errno.rs        # __errno_location() → &ERRNO
    ├── string.rs       # memcpy, memset, strlen, ...
    ├── stdio.rs        # write, writev, read, pread, pwrite
    ├── fcntl.rs        # open, openat, fcntl
    ├── unistd.rs       # close, dup2, fork, execve, getpid, ...
    ├── mman.rs         # mmap, munmap, mprotect
    ├── stat.rs         # stat, fstat, lstat, chmod, chown
    ├── dirent.rs       # opendir, readdir, closedir
    ├── signal.rs       # sigaction, sigprocmask, kill
    ├── time.rs         # clock_gettime, nanosleep
    ├── wait.rs         # waitpid, wait4
    ├── stdlib.rs       # malloc, free, realloc, exit
    └── crt.rs          # _start, __libc_start_main
```

#### errno without (and with) TLS

vibix now has TLS support (epic #827). Errno uses Rust's
`#[thread_local]` attribute directly, following Redox's approach:

```rust
// vibix_abi/src/errno.rs
use core::cell::Cell;

#[thread_local]
pub static ERRNO: Cell<i32> = Cell::new(0);

#[no_mangle]
pub extern "C" fn __errno_location() -> *mut i32 {
    ERRNO.as_ptr()
}
```

This is zero-cost on x86_64: the compiler emits `%fs:`-relative
accesses. Each task's TLS block gets its own `ERRNO` cell because
the kernel allocates a fresh TLS block per task (epic #827) and sets
`MSR_FS_BASE` to the TCB pointer.

### Algorithms and Protocols

#### Phase 1: Minimum viable std (`println!("hello")`)

The critical path to a working `println!` on vibix:

1. **Add missing syscalls to kernel** — `getpid`(39), `exit_group`(231),
   `writev`(20), `getrandom`(318), `clock_gettime`(228). These are
   trivial implementations (≤20 lines each).

2. **Create `vibix_abi` crate** — syscall macro, `GlobalAlloc` via
   `brk`/`mmap`, errno, stdio (`write` to fd 1/2).

3. **Create `x86_64-unknown-vibix.json`** target spec.

4. **Fork std, add vibix PAL** — `sys/pal/vibix/mod.rs` (init,
   cleanup, abort), `sys/pal/vibix/alloc.rs` (delegates to
   `vibix_abi`), stub all other subsystems as `unsupported`. Wire
   `stdio` to `vibix_abi::stdio`.

5. **Build with `-Z build-std`** —
   `cargo +nightly build -Z build-std=std --target x86_64-unknown-vibix.json`

6. **Test** — load the resulting ELF into the ext2 image, boot under
   QEMU, capture `hello from std` on serial.

#### Phase 2: File I/O + process (`std::fs`, `std::process`)

1. **Wire remaining VFS syscalls** — `rename`(82), `renameat`(264),
   `pread64`(17), `pwrite64`(18).

2. **Implement `sys/fs/vibix.rs`** in the std fork — `File`, `OpenOptions`,
   `FileAttr`, `ReadDir`, `DirEntry` backed by vibix_abi wrappers around
   `openat`, `read`, `write`, `fstat`, `getdents64`, `lseek`, `close`.

3. **Implement `sys/process/vibix.rs`** — `Command::spawn()` via
   `fork` + `execve`, `Child::wait()` via `wait4`.

4. **Add `nanosleep`(35) and `uname`(63)** to the kernel.

5. **Create `vibix_libc` crate** — expose C-ABI symbols for the `libc`
   crate. Fork the upstream `libc` crate to add `target_os = "vibix"`
   type definitions (struct `stat`, `timespec`, `sigaction`, etc.)
   matching the Linux x86_64 layout vibix already uses.

6. **Test** — a std binary that creates a file, writes, reads back,
   stats, and removes it.

#### Phase 3: Threading + sync (`std::thread`, `std::sync`)

1. **Implement `clone`(56) syscall** — `CLONE_VM | CLONE_FS |
   CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SETTLS |
   CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID`. This is the most
   complex new syscall — requires shared address space, shared fd
   table, per-thread TLS allocation.

2. **Implement `futex`(202) syscall** — `FUTEX_WAIT`, `FUTEX_WAKE`,
   `FUTEX_WAIT_PRIVATE`, `FUTEX_WAKE_PRIVATE`. Backed by a
   per-address wait queue in the kernel.

3. **Add `sched_yield`(24), `set_tid_address`(218), `gettid`(186)**.

4. **Implement `sys/thread/vibix.rs`** in std — `Thread::new()` via
   `clone`, `Thread::join()` via futex wait on `CHILD_CLEARTID`.

5. **Implement `sys/sync/vibix/` in std** — `Mutex`, `Condvar`,
   `RwLock`, `Once` via futex (same approach as Linux's
   `sys/sync/futex.rs`).

6. **Test** — spawn 4 threads, each increments an `Arc<Mutex<u64>>`,
   verify final count.

#### Phase 4: Ecosystem compatibility (`nix`, `tempfile`, `libc`)

1. **Complete `vibix_libc`** — all C-ABI symbols the `libc` crate
   declares for Linux x86_64. Focus on the symbols `nix 0.29` actually
   links against: `open`, `openat`, `read`, `write`, `close`, `stat`,
   `fstat`, `lstat`, `mkdir`, `rmdir`, `unlink`, `link`, `symlink`,
   `readlink`, `chmod`, `chown`, `rename`, `pipe2`, `dup2`, `fork`,
   `execve`, `waitpid`, `kill`, `sigaction`, `mmap`, `munmap`,
   `getuid`, `getgid`, `geteuid`, `getegid`, `setuid`, `setgid`,
   `chdir`, `getcwd`, `access`, `fchmod`, `fchown`, `ftruncate`,
   `utimensat`, `getpid`, `getppid`, `clock_gettime`, `nanosleep`,
   `__errno_location`.

2. **Fork `libc` crate** — add `x86_64-unknown-vibix` definitions.
   The struct layouts are identical to Linux x86_64 (same ABI).

3. **Build pjdfstest** — `cargo build --target x86_64-unknown-vibix.json
   -Z build-std` inside `tests/pjdfstest/`.

4. **Test** — boot pjdfstest under QEMU, compare pass/fail against
   the no_std `pjdfstest_runner` baseline.

#### Phase 5: Dynamic linking

1. **Build `vibix_libc` as a shared object** — `crate-type = ["cdylib"]`,
   link as `libvibix_libc.so` (or `libc.so` symlink).

2. **Write a minimal dynamic linker** in Rust — handles
   `R_X86_64_RELATIVE`, `R_X86_64_GLOB_DAT`, `R_X86_64_JUMP_SLOT`.
   Eager binding only (no lazy PLT resolver). Self-relocates on entry.
   The kernel's PT_INTERP infrastructure already loads it at
   `INTERP_LOAD_BASE` (0x4000_0000).

3. **DT_NEEDED chain walking** — breadth-first load of transitive
   dependencies. Initially only `libc.so`.

4. **PT_GNU_RELRO** — `mprotect` GOT read-only after relocation.

5. **Test** — dynamically-linked hello binary with
   `PT_INTERP = /lib/ld-vibix.so`.

### Kernel–Userspace Interface

All new syscalls use the existing Linux x86_64 ABI. No new ABI
concepts are introduced. The syscall numbers match Linux so that the
`libc` crate's `SYS_*` constants work unmodified.

**New syscall implementations (Phase 1):**

| Nr | Name | Signature | Notes |
|---|---|---|---|
| 39 | `getpid` | `() → pid_t` | Return current task's PID |
| 231 | `exit_group` | `(status: i32) → !` | Exit all threads in process |
| 20 | `writev` | `(fd, iov, iovcnt) → ssize_t` | Vectored write |
| 318 | `getrandom` | `(buf, len, flags) → ssize_t` | Fill buf from CSPRNG |
| 228 | `clock_gettime` | `(clk_id, tp) → 0/-errno` | CLOCK_MONOTONIC, CLOCK_REALTIME |

**New syscall implementations (Phase 2):**

| Nr | Name | Notes |
|---|---|---|
| 82 | `rename` | Wire existing `fs::ext2::rename` to dispatch |
| 264 | `renameat` | *at variant |
| 17 | `pread64` | Positional read |
| 18 | `pwrite64` | Positional write |
| 35 | `nanosleep` | Sleep with timespec |
| 63 | `uname` | Return "vibix" + version |

**New syscall implementations (Phase 3):**

| Nr | Name | Notes |
|---|---|---|
| 56 | `clone` | Thread creation with shared VM/FD/signals |
| 202 | `futex` | WAIT/WAKE operations |
| 24 | `sched_yield` | Yield current timeslice |
| 218 | `set_tid_address` | Set clear_child_tid pointer |
| 186 | `gettid` | Return current thread ID |
| 110 | `getppid` | Return parent PID |

## Security Considerations

**Syscall argument validation.** Every new syscall must validate
userspace pointers via `uaccess::check_user_range` before
dereferencing. The existing pattern in `syscall.rs` (`copy_from_user` /
`copy_to_user`) is well-established; new syscalls must follow it.

**getrandom entropy quality.** `sys_getrandom` must source from the
existing CSPRNG (`kernel/src/arch/x86_64/csprng.rs`) which uses
RDRAND/RDSEED. The kernel already warns when hardware RNG is
unavailable (for AT_RANDOM). `getrandom` should block or return
`-EAGAIN` if entropy is insufficient, per the Linux semantics.

**clone thread isolation.** Threads share an address space and fd
table. The kernel must ensure: (a) the shared fd table uses proper
locking (it already does — `spin::Mutex`), (b) TLS blocks are
allocated per-thread (epic #827 handles this for fork; clone needs
the same path), (c) signal disposition is shared but signal masks
are per-thread.

**vibix_libc as attack surface.** The libc shim runs in userspace
(ring 3). A bug in `vibix_libc` cannot compromise the kernel — it
can only corrupt the calling process. This is strictly better than
a kernel-resident libc. Memory-safety bugs in the Rust
implementation are caught at compile time (no C code).

**Dynamic linker relocation.** The dynamic linker processes
relocations in userspace. A malicious ELF could craft relocations
that point to arbitrary addresses, but the linker runs at ring 3
and can only corrupt its own address space. PT_GNU_RELRO
(`mprotect` GOT read-only) hardens against post-relocation GOT
overwrites.

## Performance Considerations

**Syscall overhead.** vibix's syscall path (SYSCALL/SYSRET) adds
~100–200 cycles per call. This is identical to Linux and unavoidable
for a monolithic kernel. No additional overhead is introduced by
this RFC.

**Static vs. dynamic linking.** Phase 1–4 use static linking. Each
binary includes its own copy of `vibix_libc` and `vibix_abi`, adding
~100–200 KiB per binary. This is acceptable for a hobby OS. Dynamic
linking (Phase 5) amortizes this across processes via shared
file-backed mmap pages.

**TLS access cost.** `__errno_location()` compiles to a single
`%fs:`-relative load — zero overhead vs. a global variable. The
`initial-exec` TLS model avoids the `__tls_get_addr` call overhead
of the `general-dynamic` model.

**Memory allocator.** `vibix_abi`'s `GlobalAlloc` uses `brk` for
small allocations and `mmap` for large ones, matching musl's
approach. No slab allocator or thread-local caching in Phase 1.
Performance-sensitive allocators (mimalloc, jemalloc) can be
substituted later via `#[global_allocator]`.

**futex fast path.** The futex implementation should use atomic
operations for the uncontended fast path (no syscall needed for
uncontended mutex lock/unlock). The kernel only wakes on contention.
This matches Linux's approach and keeps mutex overhead to a single
`lock cmpxchg` in the common case.

## Alternatives Considered

### Port musl libc directly

musl is a production-quality POSIX libc in ~100K lines of C.
Porting it to vibix would give immediate ecosystem compatibility.

**Rejected because:** vibix's goal is a Rust-native stack. Porting
musl introduces 100K lines of C that must be audited, cross-compiled,
and maintained. The Rust-based approach (`vibix_libc`) is smaller,
memory-safe, and can share syscall stubs with `vibix_abi`. The
`ld-musl-x86_64.so.1` already present in `userspace/lib/` was
shipped for PT_INTERP testing (#762), not as a long-term libc
strategy.

### Use the Hermit model exclusively (no libc shim)

Define only `vibix_abi`, add a thin PAL to std, skip the C-ABI
libc entirely.

**Rejected because:** the pjdfstest suite depends on the `nix` and
`libc` crates, which expect C-ABI libc symbols (`open`, `read`,
`__errno_location`, etc.). Without `vibix_libc`, these crates
cannot link. The hybrid approach gives us the fast path (Phase 1
via `vibix_abi`) without sacrificing ecosystem compatibility
(Phase 4 via `vibix_libc`).

### Upstream `x86_64-unknown-vibix` into rustc immediately

Register vibix as a Tier 3 target in the Rust compiler.

**Deferred because:** Tier 3 requires a designated maintainer,
consistent CI, and stability commitments. vibix's syscall surface
and ABI are still evolving rapidly. A custom target JSON with
`-Z build-std` is the right approach until the ABI stabilizes.
Upstreaming can happen after Phase 4 when the target is mature
enough to maintain.

### Use `target_family = "unix"` from the start (Redox model)

Present vibix as a Unix-like OS and reuse std's `unix` PAL.

**Deferred to Phase 4.** The `unix` PAL assumes a complete POSIX
libc is linked. In Phase 1–3, vibix does not have a complete libc.
Starting with a custom `vibix` PAL lets us bring up std
incrementally — modules that aren't ready return `unsupported()`.
Once `vibix_libc` is complete, migrating to `target_family = "unix"`
becomes a one-PR change (remove the custom PAL, add cfg guards in
the unix PAL, update the target JSON).

## Open Questions

1. **Should `vibix_libc` be a static archive or shared object in
   Phase 4?** Static is simpler (no dynamic linker needed) but
   wastes memory when multiple processes run. The RFC recommends
   static-first with a migration to shared in Phase 5, but the
   exact trigger for this transition is TBD.

2. **How should the std fork be maintained?** Options: (a) vendor
   a copy of `library/std/` in the vibix repo, (b) maintain a
   separate fork repo, (c) use cargo's `[patch]` to overlay vibix
   modules. Option (a) is simplest for a hobby OS. The vendored
   copy can track nightly via periodic rebases.

3. **Should `vibix_abi` define its own allocator or reuse an existing
   one?** Phase 1 uses a simple brk/mmap allocator. Phase 3+ could
   benefit from a thread-aware allocator. The choice between a custom
   allocator, dlmalloc, or mimalloc is deferred to implementation.

4. **What is the minimum `nix` crate version that works?** The
   vendored pjdfstest uses `nix 0.29`. The `libc` crate fork must
   provide all types and constants that `nix 0.29` references for
   the `x86_64-unknown-vibix` target. A precise audit is needed
   during Phase 4 implementation.

5. **When should vibix migrate from custom PAL to `target_family =
   "unix"`?** The RFC recommends after Phase 4 when `vibix_libc`
   is feature-complete. The trigger is: all pjdfstest cases pass
   with the custom PAL, and the unix PAL produces identical results
   when swapped in.

## Implementation Roadmap

- [ ] Implement missing Phase 1 syscalls: `getpid`, `exit_group`, `writev`, `getrandom`, `clock_gettime`
- [ ] Create `vibix_abi` crate with syscall macro, GlobalAlloc, errno, and stdio
- [ ] Create `x86_64-unknown-vibix.json` target spec and integrate with xtask build pipeline
- [ ] Fork std and add vibix PAL (`sys/pal/vibix/`) with stdio support; build with `-Z build-std`
- [ ] End-to-end test: `println!("hello from std")` running on vibix under QEMU
- [ ] Implement Phase 2 syscalls: `rename`, `renameat`, `pread64`, `pwrite64`, `nanosleep`, `uname`
- [ ] Implement `sys/fs/vibix.rs` and `sys/process/vibix.rs` in the std fork
- [ ] Create `vibix_libc` crate with C-ABI symbols and fork the `libc` crate for vibix type definitions
- [ ] Implement Phase 3 syscalls: `clone`, `futex`, `sched_yield`, `set_tid_address`, `gettid`, `getppid`
- [ ] Implement `sys/thread/vibix.rs` and `sys/sync/vibix/` (futex-based) in the std fork
- [ ] Complete `vibix_libc` C-ABI surface and build pjdfstest natively on vibix
- [ ] Implement minimal Rust-based dynamic linker (`ld-vibix.so`) with eager binding
