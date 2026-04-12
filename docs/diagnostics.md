# Diagnostics Subsystem

**Sources:**
- `kernel/src/klog.rs` — leveled ring-buffer log
- `kernel/src/ksymtab.rs` — embedded kernel symbol table
- `kernel/src/arch/x86_64/backtrace.rs` — frame-pointer stack unwinder

## Overview

Three components work together to provide structured kernel logging and
symbolicated panic backtraces:

1. **klog** retains the most recent log records in a fixed 64 KiB ring buffer.
   On panic, the last N records are dumped to serial.
2. **ksymtab** embeds a post-link symbol table (address → name mappings) in the
   kernel `.rodata` section. It is patched in place by `xtask` after linking.
3. **backtrace** walks the frame-pointer chain from any point in the kernel and
   resolves each return address through ksymtab.

---

## klog (`klog.rs`)

### Design

The ring buffer stores records in the format:

```
[level: u8][len_lo: u8][len_hi: u8][utf8 payload: len bytes]
```

The buffer is 64 KiB (`RING_BYTES`). When full, the oldest record is evicted to
make room. Records longer than `RECORD_MAX = 512` bytes are truncated.

The write path (`_log`):
1. Checks the level threshold (default: `Info`).
2. Formats `args` into a `FixedBuf` (stack-allocated, avoids heap during logging).
3. Under an interrupt-disabled lock, pushes the record into the ring.
4. Forwards the formatted message to `serial::_print` and `framebuffer::_print`.

The interrupt-disable is necessary on the kernel target so that an ISR that logs
cannot deadlock against code that logged on the main thread while holding the
ring lock.

### Levels

| Level | Value | Macro |
|---|---|---|
| `Error` | 0 | `kerror!(...)` |
| `Warn` | 1 | `kwarn!(...)` |
| `Info` | 2 | `kinfo!(...)` |
| `Debug` | 3 | `kdebug!(...)` |
| `Trace` | 4 | `ktrace!(...)` |

The global threshold (default `Info`) is stored in an `AtomicU8`. Records at
levels above the threshold are silently dropped.

### API

```rust
// Logging macros (most common usage):
kinfo!("heap: {} KiB", size / 1024);
kerror!("frame allocator: OOM");

// Control:
klog::set_threshold(Level::Debug);
klog::threshold() -> Level;
klog::enabled(level: Level) -> bool;

// Output:
klog::drain_to(&mut w) -> fmt::Result;      // all records, oldest first
klog::tail_to(&mut w, n) -> fmt::Result;    // last n records
klog::dump_tail_to_serial(n: usize);        // panic-safe serial dump
```

### Host Testability

`klog` compiles under `cargo test --lib`. A `TEST_LOCK` serializes tests that
access the global ring (because the ring is global, concurrent tests would
interleave records). Tests cover wrap-around eviction, level filtering, and tail
slicing.

---

## ksymtab (`ksymtab.rs`)

### Design

The kernel symbol table maps `u64` return addresses to `&'static str` function
names. It is embedded in a 256 KiB reserved region in `.rodata` and patched in
place by `cargo xtask build` / `cargo xtask iso` after the kernel is linked:

1. The linker produces the kernel ELF.
2. `xtask` reads the ELF's symbol table (`.symtab`), encodes address/name pairs
   into a compact binary format, and writes them into the reserved `.rodata`
   region using the `KERNEL_FILE_REQUEST` Limine response.
3. At runtime, `ksymtab` reads that patched region to resolve addresses.

### API

```rust
// Resolve a return address to a name (if known):
ksymtab::lookup(addr: u64) -> Option<&'static str>;

// Format an address as "name+offset" or "0x<hex>" if unknown:
ksymtab::format_addr(w: &mut impl Write, addr: u64) -> fmt::Result;
```

`format_addr` is used by the backtrace printer to produce output like:

```
backtrace:
  #0  vibix::arch::backtrace::dump_to_serial+0x3c
  #1  vibix::_start::panic+0x18
  ...
```

---

## Backtrace Unwinder (`backtrace.rs`)

### Design

The kernel is compiled with `-Cforce-frame-pointers=yes`. Every non-leaf
function emits the System V AMD64 prologue:

```asm
push rbp
mov  rbp, rsp
```

This creates a linked list of saved-RBP values on the stack. Each frame looks
like:

```
[rbp + 0]  saved RBP of caller
[rbp + 8]  return address into caller
```

`walk(skip, f)` reads the current `RBP` register, then follows the chain:
1. Validates each `rbp` (non-zero, 8-byte aligned, canonical higher-half address).
2. Reads `[rbp]` (saved rbp) and `[rbp+8]` (return address).
3. Calls `f(Frame { return_addr })` after skipping the first `skip` frames.
4. Detects a corrupt chain if `saved_rbp <= rbp` (stack grows downward, so the
   saved value must be strictly greater) and stops.
5. Caps total frames walked at `MAX_FRAMES = 32`.

### API

```rust
// Walk the call stack from the current point:
backtrace::walk(skip: usize, f: impl FnMut(Frame));

// Dump to COM1 (panic-safe):
backtrace::dump_to_serial(skip: usize);

// Macro shorthand:
kbacktrace!();  // equivalent to dump_to_serial(1)
```

### Panic Integration

The panic handler in `main.rs` calls the three diagnostics tools in sequence:

```rust
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    arch::backtrace::dump_to_serial(1);
    serial_println!("--- kernel log tail ---");
    klog::dump_tail_to_serial(32);
    serial_println!("--- end kernel log ---");
    exit_qemu(QemuExitCode::Failure)
}
```

This produces a symbolicated backtrace followed by the last 32 log records,
giving full context for diagnosing a panic from the serial output alone.
