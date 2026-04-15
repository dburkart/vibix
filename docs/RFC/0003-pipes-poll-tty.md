---
rfc: 0003
title: Pipes, Poll, and TTY Line Discipline
status: In Review
created: 2026-04-15
---

# RFC 0003: Pipes, Poll, and TTY Line Discipline

## Abstract

This RFC proposes three tightly-coupled subsystems required for a POSIX-capable
userspace on vibix: anonymous pipes (`pipe(2)` / `pipe2(2)` / FIFOs), the
level-triggered readiness syscall `poll(2)` (with `select(2)` layered on top), and
an N_TTY-compatible line discipline that handles canonical-mode input, echo,
termios flag processing, and job-control signal delivery. Together they are the
minimum surface a shell, `sh`-style job pipeline, and an interactive editor
(`vi`/`readline`) need in order to run on vibix. The RFC also introduces one
novel primitive — **deadline-aware poll readiness with kernel-side
aggregation** (DAPRA) — that extends `poll` with a per-fd soft-deadline hint so
the scheduler can batch wake-ups across a poll group within a latency budget.

## Motivation

vibix today has a serial-backed stdio (`SerialBackend`) and a VFS with `devfs`,
but has no mechanism for:

1. **Inter-process byte streaming.** Shell pipelines (`ls | grep | wc`) require
   an anonymous pipe whose read end and write end can be installed into
   different fd tables after `fork`.
2. **Multiplexed readiness.** Any non-trivial userspace (the shell's prompt
   loop, a network daemon, a supervisor waiting on stdin + timer + child) needs
   `poll`/`select` to wait on multiple descriptors. Without it, either every
   descriptor must be made `O_NONBLOCK` + spun on, or the process blocks
   against one fd and starves the rest.
3. **Line-edited terminal input.** Today every read from `/dev/ttyS0` returns
   raw bytes. A shell cannot implement Ctrl-C (SIGINT), Ctrl-Z (SIGTSTP),
   backspace, or line commit without duplicating a canonical-mode state
   machine in userspace — and even then it cannot correctly generate
   job-control signals to its own process group, because that requires kernel
   cooperation with the process table.

Delivering all three in one RFC reflects their data-flow coupling: the TTY
read buffer is a pipe-shaped producer/consumer queue whose producer is the
line discipline; `poll` is the unified readiness mechanism across pipes, TTYs,
and eventual socket fds. Designing them together prevents the classic trap of
shipping pipes and poll with a waitqueue convention that the TTY can't reuse.

## Background

### Prior art in vibix

- **`FileBackend` trait** (`kernel/src/fs/mod.rs:30-42`) already defines a
  per-fd `read`/`write` dispatch. We extend it with a `poll` method and
  plumb a line-discipline layer between the existing PS/2/serial input path
  and the fd-readable buffer.
- **RFC 0002 VFS** (`docs/RFC/0002-virtual-filesystem.md`) established `devfs`
  as the mount point for character-device fds. Pipe file descriptors are *not*
  VFS-backed (they have no path); they are first-class `FileBackend`
  implementations alongside `SerialBackend`.
- **Signal delivery** (`kernel/src/signal/mod.rs`) gives us per-process
  signal queues. This RFC consumes but does not extend that API.

### Linux reference points

- `fs/pipe.c` — `struct pipe_inode_info` with a power-of-two ring of
  `struct pipe_buffer` slots, `PIPE_DEF_BUFFERS = 16` (`include/linux/pipe_fs_i.h:5`),
  `PIPE_BUF = 4096` (`include/uapi/linux/limits.h`). Atomic writes below
  `PIPE_BUF` are **implemented by buffer merging**, not by locking: if the
  tail buffer has `PIPE_BUF_FLAG_CAN_MERGE` set and offset+chars ≤ PAGE_SIZE,
  the writer appends into the existing slot. Packet mode (`O_DIRECT`) clears
  the merge flag so each write becomes its own slot (`fs/pipe.c:415-418`).
- `fs/select.c` — the `poll_table_struct { _qproc, _key }` (`include/linux/poll.h:37-40`)
  and the two-pass pattern inside each driver's `.poll`: register wait
  callback first, *then* `READ_ONCE` the state, so any concurrent state
  transition either (a) sets the state before the load and is seen, or
  (b) fires the registered callback.
- `fs/eventpoll.c` — epoll's `ep_poll_callback` appends to `rdllist` in O(1);
  level vs edge differs only in whether the epitem is re-queued after delivery
  (`fs/eventpoll.c:1835-1851`). vibix does **not** ship epoll in this RFC —
  only poll. Epoll is a future extension.
- `drivers/tty/n_tty.c` — three 4 KiB ring buffers (`read_buf`, `echo_buf`,
  driver `write_buf`), `N_TTY_BUF_SIZE = 4096` (`drivers/tty/n_tty.c:59`).
  ICANON gates the line-commit path; ISIG dispatches `VINTR/VQUIT/VSUSP` to
  `kill_pgrp(tty->ctrl.pgrp, sig, 1)` (`drivers/tty/n_tty.c:1044-1050`).
- `drivers/tty/tty_jobctrl.c` — `__tty_check_change` returns `-ERESTARTSYS`
  after delivering SIGTTOU to background writers (lines 33-67), and
  `TIOCSPGRP` demands session-matching (lines 493-531).

### POSIX reference points

- XBD §11 — General Terminal Interface (termios: c_iflag / c_oflag / c_cflag /
  c_lflag / c_cc[NCCS]).
- XBD §11.1.7 — non-canonical MIN/TIME four-case semantics.
- XBD §11.1.4 — SIGTTIN/SIGTTOU/SIGTSTP generation rules.
- XSH `pipe()` — O_NONBLOCK/FD_CLOEXEC **shall be clear** on both new fds.
- XSH `write()` — atomicity guaranteed up to `{PIPE_BUF}`, which must be ≥
  `_POSIX_PIPE_BUF = 512` (XBD §13).
- XSH `poll()` — `struct pollfd{int fd; short events; short revents;}`;
  negative `fd` is ignored (revents=0, not POLLNVAL); timeout in ms with
  −1 = infinite, 0 = poll, >0 = minimum ms. POLLERR/POLLHUP/POLLNVAL
  are always returned in `revents` regardless of `events` mask.
- `pipe2(2)` is **not** in POSIX.1-2017 base (it arrives in Issue 8 draft);
  we ship it anyway because it is mandatory on modern Linux and allows
  O_CLOEXEC-atomic creation — a small deviation from strict POSIX for a
  critical race-freedom property.

### SerenityOS / Redox patterns

- **Serenity FIFO** wraps a `DoubleBuffer` (two 64 KiB flip-flop `KBuffer`s)
  and calls `evaluate_block_conditions()` on every state change; EOF-on-no-
  writer and EPIPE-on-no-reader are expressed as "always-ready" so the
  subsequent read/write delivers the right error/short-count. PTYs live
  in-kernel (`MasterPTY`/`SlavePTY`/`PTYMultiplexer`).
- **Redox pipes** use `Mutex<VecDeque<u8>>` with `MAX_QUEUE_SIZE = 65536` and
  encode read-vs-write endpoint in the low bit of the handle ID
  (`WRITE_NOT_READ_BIT = 1`). Poll is expressed via the `event:` scheme +
  per-scheme `fevent`. PTYs are a userspace daemon in Redox drivers, not
  in-kernel.
- **Critical architectural rule from Serenity** (`VirtualConsole::on_key_pressed`
  → `Processor::deferred_call_queue`): the line discipline must **never** run
  in ISR context. Keystrokes from the PS/2 or UART ISR are posted to a
  deferred-call queue, and ldisc work runs in the kernel's soft-IRQ/worker
  thread. We adopt the same rule.

### Academic reference points

- Banga, Mogul, Druschel — "A scalable and explicit event delivery mechanism
  for UNIX" (USENIX ATC 1999). Canonical paper on why `select()` scales poorly;
  motivates the eventual epoll/kqueue, but also motivates the batched-wake
  design we propose in the novel idea below.
- Lamport — "Specifying concurrent program modules" (TOPLAS 1983). SPSC
  lock-free ring correctness proof; justifies our choice of a per-pipe SPSC
  ring over `Mutex<VecDeque>`.
- Ritchie — "A Stream Input-Output System" (Bell Labs TJ 1984). STREAMS
  origin of pluggable line discipline. We adopt the trait-seam in spirit
  (see `LineDiscipline` trait below) without the full STREAMS stack.
- CVE-2022-0847 (Dirty Pipe) — cautionary tale for page-donation semantics
  (splice `SPLICE_F_GIFT`). We deliberately **do not** support page donation
  in this RFC; pipes are byte-copy.

### x86-64 hardware considerations

- TSO guarantees store-store and load-load ordering. An SPSC ring's producer
  (`data[tail] = v; tail = tail + 1;`) and consumer
  (`h = head; v = data[h];`) need *no* fence between the two stores
  (producer) or the two loads (consumer) on x86-64 — only a compiler barrier.
  (Intel SDM Vol. 3A, Memory Ordering chapter.)
- A StoreLoad fence is needed only for wakeup-elision ("publish data, then
  check if consumer is sleeping"). Linux uses `lock addl $0,(%rsp)` rather
  than MFENCE; we follow suit.
- Cache line is 64 B on all x86-64 parts (CPUID leaf 1 EBX[15:8] × 8).
  Head and tail indices live on separate `#[repr(align(64))]` cache lines.
- `rep movsb` with FSRM (CPUID.(EAX=7,ECX=0):EDX[4], Ice Lake+) is
  competitive with SIMD for short copies; pipe small-message traffic
  benefits. We expose a single `copy_to_user` / `copy_from_user` that
  dispatches to `rep movsb` under STAC/CLAC (SMAP bracketing).

## Design

### Overview

Four new kernel modules land together:

```
kernel/src/ipc/pipe.rs     — anonymous pipe + FIFO backend
kernel/src/poll/mod.rs     — poll_table + sys_poll + sys_select
kernel/src/tty/mod.rs      — Tty type, session/pgrp binding
kernel/src/tty/n_tty.rs    — the N_TTY line discipline
```

Plus changes to:

- `kernel/src/fs/mod.rs` — add `fn poll(&self, pt: &mut PollTable) -> PollMask`
  default method on `FileBackend` returning `DEFAULT_POLLMASK` (ready for
  read+write). Pipe, tty, and future socket backends override it.
- `kernel/src/process/mod.rs` — session ID, process-group ID, controlling-tty
  fields on the PCB. (Signal delivery is already there.)
- `kernel/src/arch/x86_64/syscalls/` — six new syscall numbers
  (see §Kernel–Userspace Interface).

### Key Data Structures

#### Pipe (anonymous + FIFO)

```rust
/// Capacity: 16 pages = 65_536 bytes, matching Linux default & Serenity
/// DoubleBuffer. Power of two so head/tail wrap by mask.
pub const PIPE_CAPACITY: usize = 64 * 1024;
pub const PIPE_BUF: usize = 4096;   // POSIX atomic-write bound

/// SPSC-ish byte ring. "-ish" because pipes permit multiple readers
/// and multiple writers (POSIX); the ring itself is protected by a
/// single `IrqSafeMutex`, and the head/tail pair is also exposed as
/// two `AtomicUsize` on separate cache lines for a lock-free poll.
///
/// The cache-line isolation is enforced with a wrapper newtype, since
/// `#[repr(align(N))]` is only valid on type definitions, not struct
/// fields. We reuse a `CachePadded<T>` following crossbeam-utils's pattern.
#[repr(C, align(64))]
pub struct CachePadded<T>(pub T);

#[repr(C)]
pub struct PipeRing {
    // Line 0: written by writer, read by writer + poll fast-path.
    tail: CachePadded<AtomicUsize>,
    // Line 1: written by reader, read by reader + poll fast-path.
    head: CachePadded<AtomicUsize>,
    // Bulk state. `buf` is heap-allocated and zero-initialised at
    // pipe creation (`vec![0u8; PIPE_CAPACITY].into_boxed_slice()`)
    // to prevent kernel-memory information disclosure.
    buf: Box<[UnsafeCell<u8>; PIPE_CAPACITY]>,
    lock: IrqSafeMutex<()>,
}

pub struct Pipe {
    ring: PipeRing,
    rd_wait: WaitQueue,
    wr_wait: WaitQueue,
    // readers/writers counts are mutated ONLY under `pipe.ring.lock` so
    // the "last reader just closed" race described in §Security is
    // impossible: a writer observes `readers` under the same lock it
    // uses to copy bytes, so the EPIPE decision is consistent with
    // the final ring state. The fields remain `AtomicUsize` so
    // `pipe_poll` may read them lock-free via `Acquire`.
    readers: AtomicUsize,
    writers: AtomicUsize,
    // Packet-mode record list — inlined into the ring's lock-protected
    // state to avoid a second mutex on the hot path (see §Lock order).
    packets: Option<VecDeque<PacketHdr>>,  // guarded by `ring.lock`
}

/// Per-fd flag state. Matches Linux: `O_NONBLOCK` is per-file-description,
/// not per-pipe, so `dup2(a, b); fcntl(b, F_SETFL, O_NONBLOCK)` on one fd
/// does not affect the other. `F_GETFL`/`F_SETFL` mutate this field only.
pub struct PipeEnd {
    pipe: Arc<Pipe>,
    /// O_NONBLOCK | O_CLOEXEC | O_DIRECT (packet mode inherited at create).
    flags: AtomicU32,
}

pub struct PipeReadEnd(PipeEnd);
pub struct PipeWriteEnd(PipeEnd);
```

Two fd backends (`PipeReadEnd`, `PipeWriteEnd`) share an `Arc<Pipe>`. On
close, the relevant refcount decrements; when `readers == 0` a pending
writer sees EPIPE + SIGPIPE. When `writers == 0` a reader drains the ring
then sees EOF (`read` returns 0).

The ring holds raw bytes, not `pipe_buffer`-style page references. This
deliberately gives up splice/vmsplice/page-donation in the initial
implementation (see Alternatives). A future RFC can layer `pipe_buffer`-
style scatter/gather on top once we have a splice syscall use case.

**Why bytes, not pages:** Linux's `pipe_buffer` was chosen because splice
moves pages; without splice there is no value to the extra indirection, and
a byte ring is simpler, has half the metadata, and avoids the CVE-2022-0847
family entirely (no `PIPE_BUF_FLAG_CAN_MERGE` + stolen-page interactions).

**Atomic-write guarantee for `n ≤ PIPE_BUF`.** A write of `n` bytes with
`n ≤ PIPE_BUF` holds `lock` for the entire copy *only if* it cannot
complete without blocking. The fast path (enough free bytes) takes `lock`,
copies, updates `tail`, drops `lock` — a single critical section
producing the POSIX non-interleaving guarantee. A blocking write of
`n ≤ PIPE_BUF` waits for **≥ n free bytes** before acquiring the final
copy-lock, so no partial write is ever visible. Writes of `n > PIPE_BUF`
may interleave, matching POSIX XSH `write`.

#### Poll table

```rust
pub type PollMask = u16;   // POLLIN|POLLOUT|POLLHUP|POLLERR|POLLNVAL|...

/// Per-syscall scratch. Either `Scan` (non-blocking probe) or
/// `Wait` (registration pass).
pub struct PollTable {
    mode: PollMode,
    entries: ArrayVec<PollEntry, POLL_STACK_ENTRIES>,
    spill: Option<Vec<PollEntry>>,
    // Deadline-aware extension (§Deadline-aware poll readiness).
    deadlines: Option<DeadlineSet>,
}

enum PollMode {
    /// First pass: non-blocking probe, do not register waits.
    Probe,
    /// Second pass: register waits on each fd's WaitQueue.
    Wait,
}

struct PollEntry {
    /// `Arc` keeps the WaitQueue (and transitively the Pipe/Tty) alive
    /// until `PollTable::drop` runs `cancel_all`. This closes the
    /// close-during-poll UAF: even if another thread `close()`s the fd
    /// and drops the owning Arc, our reference keeps the queue valid
    /// for the duration of the poll syscall.
    waitq: Arc<WaitQueue>,
    token: WaitToken,          // handle for de-registration
}
```

**PollEntry lifetime rule.** A `PollEntry` holds an `Arc<WaitQueue>` for the
lifetime of the `PollTable` that owns it. `close(2)` on a pipe or tty fd
therefore cannot free the `WaitQueue` while any thread has a pending
`sys_poll` registered against it. `PollTable::drop` calls `cancel_all()`
which, under each queue's own IRQ-safe lock, unlinks every `WaitToken`
before the Arc drops. The cancel-vs-fire race is resolved by the queue's
internal lock: both `wake_one`/`wake_all` and `cancel` take it, so an
ISR-side dispatch either completes before `cancel` or is suppressed by
`cancel` removing the entry. `close` that races with an in-flight
`recheck` observes the fd as closed (returns POLLNVAL without
dereferencing any stale pointer) because fd resolution happens by table
lookup on the *current* process fd table, not through any raw pointer in
the `PollEntry`.

Driver `.poll` methods register themselves exactly as in Linux:

```rust
fn poll(&self, pt: &mut PollTable) -> PollMask {
    pt.register(&self.pipe.rd_wait);   // no-op in Probe mode
    pt.register(&self.pipe.wr_wait);
    self.current_mask()                 // READ_ONCE of the atomics
}
```

**Wait-latching invariant on the WaitQueue primitive.** `WaitQueue::register`
returns a `WaitToken` and, critically, the semantics are: *any* `wake_one` or
`wake_all` delivered after `register` returns and before the owning task
parks in `sleep_until` must flip the task's wake-state such that
`sleep_until` returns `Woken` *without sleeping*. This is the same
`prepare_to_wait` + `schedule` discipline Linux uses
(`include/linux/wait.h`). Without this property, the two-pass `recheck`
would still admit a lost wakeup between the recheck and the park. The
invariant is part of the `WaitQueue` contract and exercised by a unit
test that fires a wake between `register` and `sleep_until`.

**Formal invariant of the two-pass pattern (informal):** For every state
transition *t* of a source (pipe bytes arriving, reader closing, termios
change, …):

- either *t* is published **before** the driver's `.poll` returns in the
  Probe pass — in which case `scan` observes the readiness mask and the
  syscall returns without waiting;
- or *t* is published **after** the Wait-pass `register` call — in which
  case *t*'s wake is delivered to a live `WaitToken` and reaches the
  parked task (via the wait-latching rule above).

There is no window in which *t* is neither observed nor delivered. This
is the standard "publication with double-check" invariant; a lightweight
TLA+ model over the two states `{registered, state_observed}` is
deferred to Open Question #8.

The **two-pass pattern** lives in the syscall body, not the driver:

```rust
fn sys_poll(fds: &mut [PollFd], timeout: Timeout) -> Result<usize> {
    loop {
        let mut pt = PollTable::probe();
        let ready = scan(fds, &mut pt)?;        // Probe pass
        if ready > 0 || timeout.is_zero() { return Ok(ready); }

        let mut pt = PollTable::wait();
        scan(fds, &mut pt)?;                    // Wait pass: register
        // All waits are registered; re-check once more to close the race.
        let ready2 = recheck(fds, &mut pt);
        if ready2 > 0 { pt.cancel_all(); return Ok(ready2); }

        match pt.sleep_until(timeout) {
            Slept::Signal => return Err(EINTR),
            Slept::Timeout => return Ok(0),
            Slept::Woken => continue,   // loop and rescan
        }
    }
}
```

#### TTY

```rust
pub struct Tty {
    ldisc: Box<dyn LineDiscipline>,   // default: NTty
    driver: Arc<dyn TtyDriver>,       // SerialTty, VirtualConsoleTty, Pty{Master,Slave}
    termios: IrqSafeMutex<Termios>,
    ctrl: IrqSafeMutex<JobControl>,
    read_wait: WaitQueue,
    write_wait: WaitQueue,
}

pub struct JobControl {
    session: Option<SessionId>,       // set when a session leader acquires
    pgrp: Option<ProcessGroupId>,     // foreground pgrp (TIOCSPGRP target)
}

/// Seam for pluggable line disciplines. N_TTY is the only one shipped here;
/// future raw-mode, SLIP, or N_BPF (speculative) slot in behind this trait.
pub trait LineDiscipline: Send + Sync {
    /// Called from the driver side (ISR-deferred) with one raw byte.
    fn receive_byte(&self, tty: &Tty, byte: u8);
    /// Called from the userspace `read(2)` side; fills user buffer per
    /// termios MIN/TIME and ICANON rules.
    fn read(&self, tty: &Tty, buf: &mut [u8]) -> Result<usize, i64>;
    /// Called from the userspace `write(2)` side; applies OPOST.
    fn write(&self, tty: &Tty, buf: &[u8]) -> Result<usize, i64>;
    /// Readiness predicate for poll.
    fn poll(&self, tty: &Tty, pt: &mut PollTable) -> PollMask;
}
```

```rust
/// Termios layout. This matches Linux's kernel-side `struct termios2` /
/// `ktermios`, NOT the userspace glibc `struct termios` from `<termios.h>`
/// (which omits `c_ispeed`/`c_ospeed` unless `__USE_MISC` is set — they
/// are populated via `TCGETS2`/`TCSETS2`, not the base `TCGETS`, on Linux).
///
/// We deliberately ship the termios2-shaped struct as vibix's canonical
/// termios, and expose it through `TCGETS`/`TCSETS` directly. This is a
/// documented deviation from strict Linux userspace-ABI compatibility:
/// a program built against glibc's `<termios.h>` (the 36-byte shape
/// without ispeed/ospeed) will read/write the first 36 bytes correctly
/// and leave the baud-rate fields at zero. vibix's libc should provide
/// a `struct termios` that *does* carry the ispeed/ospeed fields, and
/// `cfsetispeed`/`cfsetospeed` operate on them directly (no speed-in-cflag
/// back-compat dance). `TCGETS2`/`TCSETS2` are accepted as aliases for
/// `TCGETS`/`TCSETS` to ease porting of Linux userspace.
///
/// c_line is retained as a 1-byte ldisc selector for Linux ABI shape;
/// vibix currently supports only N_TTY (0).
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line:  u8,
    pub c_cc:    [u8; 19],   // NCCS
    pub c_ispeed: u32,       // default: B38400 (0x000f) on pipe creation
    pub c_ospeed: u32,       // default: B38400
}

const _: () = assert!(core::mem::size_of::<Termios>() == 44);
```

#### N_TTY

The canonical-mode state machine lives in `kernel/src/tty/n_tty.rs`. We
deliberately diverge from Serenity's "parallel bitmask" trick and use an
explicit `VecDeque<Line>`:

```rust
pub struct NTty {
    state: IrqSafeMutex<NTtyState>,
}

struct NTtyState {
    /// Incomplete line being accumulated in ICANON mode.
    line_buf: ArrayVec<u8, 4096>,
    /// Completed lines ready to read. A line ends at '\n', VEOF, or VEOL.
    committed: VecDeque<Line>,
    /// Raw-mode ring (ICANON off). Flat byte buffer.
    raw: Ring<u8, 4096>,
    /// Bytes queued to echo back to the driver.
    echo: VecDeque<u8>,
}

struct Line { bytes: Box<[u8]>, contains_eof: bool }
```

**Justification for committed-line-queue over Linux's byte+bitmap:** in
canonical mode, the boundary between "committed bytes readable now" and
"line-in-progress not yet readable" is the dominant piece of state. Linux
uses parallel bits per byte (`read_flags` bitmap) because its buffer is
byte-flat; with a Rust `VecDeque<Line>` the boundary is structural and the
readiness predicate is `!committed.is_empty()`. Memory overhead is one
`Line` struct (24 B) per outstanding uncommitted line — bounded by the
typical 1 or 2 lines in flight during interactive editing.

### Algorithms and Protocols

#### Lock order (global, kernel-wide)

All sleepable/IRQ-safe locks touched by this subsystem have a total
order. **Outer → inner**:

1. `process.fd_table_lock`
2. `pipe.ring.lock` *or* `tty.termios` *or* `tty.ctrl` *or* `ntty.state`
   (these are mutually exclusive — no code path holds two of them at once)
3. WaitQueue-internal lock (always innermost; never held across any
   other lock acquire)

Driver `.poll` methods MUST NOT acquire any lock at levels 1 or 2 — they
may only take the level-3 WaitQueue lock (via `register`) and read
atomic indices. This prevents inversion with `sys_poll`'s wait-queue
registration pass.

`IrqSafeMutex` both disables preemption and (per its name) disables
interrupts on acquire; wake-from-ISR paths therefore never block on an
IrqSafeMutex held at the level-2 bulk-state layer because the ISR
either (a) posts to the deferred-call queue (for ldisc work) or (b) only
takes a level-3 WaitQueue lock (for cross-CPU wakes). The WaitQueue's
internal lock is itself IRQ-safe and short-held (append/remove a
waiter record).

#### Pipe ring concurrency rule

The pipe ring's lock-free poll path rests on a strict invariant about
how the `head` and `tail` indices are mutated:

1. **Only the last action of a completed mutation ever updates the
   index.** The writer does `copy chunk into buf[tail..tail+n];
   tail.store(tail + n, Release);` as the final pair of operations
   inside the `pipe.ring.lock` critical section — no intermediate
   `tail` stores are permitted, no mid-critical-section partial
   advance.
2. **Indices advance monotonically.** `tail` never decreases; `head`
   never decreases; both are `AtomicUsize` (64-bit on x86-64), so
   single-word loads are atomic and never torn.
3. **Readiness is derived from the snapshot pair.** Poll reads
   `h = head.load(Acquire); t = tail.load(Acquire);` — because head and
   tail are never regressed, `fill = t.wrapping_sub(h)` is a valid
   *consistent* snapshot in the sense that `fill ≤ CAPACITY` and any
   observed state was real at some point between the two loads. The
   poll mask is computed from `fill` and `fill == CAPACITY`
   (POLLOUT/POLLIN respectively).
4. **On x86-64 (TSO), `Release` on the index store inside the critical
   section is sufficient for the lock-free reader to observe
   data-then-index ordering.** This RFC's design targets x86-64 only;
   a future port to weakly-ordered ISAs (ARMv8) will add an explicit
   `fence(Release)` before `tail.store`. This caveat is stated so no
   one copies the pattern to a non-TSO arch without re-checking.

With these rules, `pipe_poll` is lock-free and race-free.

#### Pipe read / write fast paths

Both operate under `pipe.ring.lock`. Poll readiness checks do NOT take
the lock: they read `head`/`tail` via `Ordering::Acquire` per the rule
above.

```
Writer (total n bytes):
  acquire pipe.ring.lock
  loop:
    fill = tail - head
    free = CAPACITY - fill
    // EPIPE check is under-lock: `readers` is mutated only under this
    // same lock by the reader-drop path, so the observation is coherent
    // with the ring state.
    if readers == 0:
      release lock
      queue_signal(current, SIGPIPE)   // via pending-signal set
      return EPIPE
    // Atomicity rule: writes of `n ≤ PIPE_BUF` wait for free ≥ n
    // (not merely free > 0), so every sub-PIPE_BUF write is visible
    // as a single non-interleaved chunk in the ring.
    need = if n <= PIPE_BUF { n } else { 1 };
    if free >= need: break
    if end.flags & O_NONBLOCK: release lock; return EAGAIN
    let tok = wr_wait.register();       // under queue's own lock
    release pipe.ring.lock
    sleep_until(tok, no timeout)        // wake-latching (see invariant)
    acquire pipe.ring.lock
  let m = min(n, free);
  copy_from_user(buf[tail..tail+m])     // STAC/CLAC via UserSlice
  tail.store(tail + m, Release)         // the single publishing store
  release lock
  // Wake every epoll/poll-table registrant + one blocking waiter.
  rd_wait.wake_poll_then_one()
```

**`wake_poll_then_one`.** On every state transition, we run the
poll-callback for *every* registered `PollEntry` (so every epoll
watcher / DAPRA group waiter is notified and can make an edge-trigger
decision) **and** wake exactly one blocking `read(2)` waiter. This
mirrors Linux's `wake_up_interruptible_sync_poll(..., EPOLLIN)` — all
pollers get the notification, only one blocking reader is woken to
avoid thundering herd. Plain `wake_one` (as the v0 draft proposed) would
lose edge-triggered wakes under multi-watcher epoll/DAPRA usage; that
bug is fixed here.

**Co-writer fairness.** Two concurrent writers on the same `Pipe`
(via `dup(2)` or fd-passing) share a single `pipe.ring.lock` and a
single `wr_wait` queue. `wr_wait` is FIFO-ordered (first to
`register` is first to `wake`), and `pipe.ring.lock` hands the lock
to the waiter just woken (ticket handoff). Together these guarantee
no writer is starved by a co-writer performing a tight write loop — a
concern raised by the Security review. Strictly speaking this is a
property of the `WaitQueue` and `IrqSafeMutex` implementations; both
are already FIFO in the current vibix codebase, and this RFC commits
to preserving that property.

**Reader drop path (symmetric correctness for EPIPE).** The last
`PipeReadEnd` drop acquires `pipe.ring.lock`, decrements `readers`,
drops the lock, then calls `wr_wait.wake_all()` (all blocked writers
re-check under lock and return EPIPE together — there is no point in
waking just one). The decrement-under-lock closes the "writer sees
`readers > 0`, copies, then reader vanished" race: any writer that
enters its critical section after the decrement observes `readers ==
0` and returns EPIPE; any writer that entered before the decrement
completes its atomic ≤PIPE_BUF write before releasing the lock, and
the reader sees those bytes on its last read before EOF.

#### Deferred-call queue (ISR → ldisc handoff)

The ISR-to-ldisc handoff uses a per-device bounded ring (128 bytes per
UART / PS-2 controller). When the ring is full, the ISR drops the
**newest** byte — matching the behaviour of the downstream 4 KiB raw
ring on ldisc overflow, so both overflow regimes look the same to
userspace and neither can be used to grow kernel memory unboundedly.
A dropped byte bumps a per-device counter surfaced via a future
sysfs/debugfs node (out of scope here). On UART specifically, when
the deferred ring crosses a high-water mark (96/128) we deassert RTS
(if CRTSCTS is negotiated) so the remote side stops transmitting;
this is the Serenity pattern the RFC Background references. PS-2 has
no equivalent flow-control primitive and relies on drop.

The ldisc worker runs in **soft-IRQ context**. vibix does not yet have
a formal soft-IRQ subsystem; for this RFC, "soft-IRQ context" means
*a pinned kernel worker thread per CPU that runs at a higher priority
than normal kernel threads and is allowed to acquire level-2 sleepable
locks*. The equivalent Linux concept is tasklets / workqueue. The
concrete primitive will be introduced in a companion implementation
issue (roadmap item: "Introduce soft-IRQ worker for ldisc + deferred-
call queue"). Until it exists, the ldisc work runs on the task that
triggered the interrupt via a late-IRQ-return hook — acceptable for
the UP development configuration but not a final design.

#### TTY input path (ISR → ldisc → ring)

```
UART/PS-2 ISR:
  byte = read_data_register()
  if !deferred_call_queue.try_push(|| tty.driver.recv_byte(byte)):
    // Bounded queue full: drop newest, increment drop counter,
    // deassert RTS on UART if CRTSCTS is set.
    tty.driver.isr_drop_count += 1
  eoi()

Soft-IRQ worker:
  drain deferred_call_queue
  for each byte:
    tty.ldisc.receive_byte(tty, byte)

NTty::receive_byte(tty, b):
  t = tty.termios.lock()
  // Input flags (c_iflag)
  if ISTRIP: b &= 0x7f
  if INLCR and b == '\n': b = '\r'
  else if IGNCR and b == '\r': return
  else if ICRNL and b == '\r': b = '\n'
  // ISIG (before ICANON processing)
  if ISIG in c_lflag:
    if b == c_cc[VINTR]: send_signal(SIGINT); flush(); echo_control(); return
    if b == c_cc[VQUIT]: send_signal(SIGQUIT); flush(); return
    if b == c_cc[VSUSP]: send_signal(SIGTSTP); flush(); return
  if ICANON in c_lflag:
    handle_canonical_byte(b)   // VERASE, VKILL, VEOF, line commit on '\n'
  else:
    state.raw.push(b)
    tty.read_wait.wake_one()
  if ECHO: queue_echo(b)
```

`send_signal` resolves to `kill_pgrp(tty.ctrl.pgrp, sig)` with the same
orphaned-pgrp check Linux performs (`drivers/tty/tty_jobctrl.c:33-67`).

#### TTY write path (userspace → OPOST → driver)

```
NTty::write(tty, user_buf):
  let t = tty.termios.lock();
  // Background-pgrp check (SIGTTOU if TOSTOP).
  if current.pgrp != tty.ctrl.pgrp
     && t.c_lflag & TOSTOP
     && !current.blocks(SIGTTOU)
     && !current.orphaned_pgrp():
      kill_pgrp(current.pgrp, SIGTTOU)
      // Kernel-internal sentinel; translated at syscall-exit by the
      // syscall trampoline (see below) — never returned to userspace.
      return KERN_ERESTARTSYS
  drop t
  ...  (OPOST pass, same as before)
  return user_buf.len()
```

**`KERN_ERESTARTSYS` translation (kernel-internal, not user-visible).**
The syscall trampoline in `kernel/src/arch/x86_64/syscall.rs` inspects
every negative return code on the way out:

- If the code is `KERN_ERESTARTSYS` **and** the signal that triggered
  the restart was delivered with `SA_RESTART` set, the trampoline
  rewinds `%rip` to the `syscall` instruction so the userspace
  instruction re-issues the syscall after the signal handler returns.
- Otherwise, the trampoline substitutes `-EINTR` as the syscall return
  value to userspace.

Userspace therefore sees either (a) a transparent restart, or (b)
`EINTR` — never `ERESTARTSYS`. The errno table in §Kernel–Userspace
Interface is updated to reflect this: the row for TTY background-write
reads `EINTR (restartable if SA_RESTART)`. The same rule applies to
any blocking pipe read/write or poll that is interrupted by a signal.

#### Job control

- **Controlling-terminal acquisition on `open(2)`**. Matching Linux
  convention: when a session leader (`getsid() == getpid()`) `open`s
  a TTY without `O_NOCTTY`, and the session has no existing
  controlling tty, and the tty has no existing session, the tty
  becomes the session's controlling tty. Any other combination leaves
  the ctty state unchanged. `O_NOCTTY` is a *functional* flag, not a
  no-op: it suppresses acquisition. This closes the POSIX-shell
  portability gap raised by the User Space reviewer.
- `TIOCSCTTY` (ioctl) — if caller is session leader and tty has no
  session, bind `tty.ctrl.session = caller.session`. The Linux
  `force` argument (root-steal) is **not** supported.
- `TIOCNOTTY` — release the controlling tty for the calling process's
  session; also called automatically when the session leader exits.
- `TIOCSPGRP` — tty.ctrl.session must equal caller.session AND target pgrp
  must be in caller.session; else EPERM. If caller is background and not
  ignoring/blocking SIGTTOU, deliver SIGTTOU first (per POSIX `tcsetpgrp`).
- `TIOCGPGRP` / `TIOCGSID` — read-only.

#### FIFO open rendezvous (POSIX `open(2)` on a FIFO)

A FIFO created via `mkfifo(3)` / `mknod(2)` is a VFS inode whose
backing is a shared `Arc<Pipe>` (the same type as the anonymous pipe
above). `open(2)` semantics are the POSIX-required rendezvous:

| Mode | O_NONBLOCK clear | O_NONBLOCK set |
|---|---|---|
| `O_RDONLY` | block until a writer opens | return immediately (success) |
| `O_WRONLY` | block until a reader opens | return `-ENXIO` if no reader |
| `O_RDWR` | return immediately (Linux-compatible extension) | return immediately |

Implementation: the FIFO's `Pipe` carries `open_waiters_r: WaitQueue`
and `open_waiters_w: WaitQueue`. `O_RDONLY` increments `readers`, wakes
any waiter on `open_waiters_w`, then (if O_NONBLOCK clear and
`writers == 0`) blocks on `open_waiters_r` until `writers > 0`.
Symmetric on the write side. The fd is installed in the caller's fd
table only after the rendezvous completes.

A signal during the rendezvous returns `KERN_ERESTARTSYS` and follows
the same translation rule as above (user sees EINTR or a restart).

#### Deadline-aware poll readiness (novel contribution)

The novel idea this RFC introduces. **Problem**: a server waiting on many
fds with mixed latency requirements wakes once per fd readiness event. If
several fds become ready in a short window, the waiter is woken N times
but only needs to be woken once per "batch" — the remaining N-1 wake-ups
are wasted work. io_uring's multishot poll partially addresses this per
ring; epoll's EPOLLEXCLUSIVE addresses thundering herd but not batching.

**Prior art and positioning.** The core trade — "accept a bounded
latency budget in exchange for amortized wake/IRQ cost" — has well-
established analogs at other layers:

- **Adaptive NIC interrupt moderation / coalescing** (Mogul &
  Ramakrishnan, "Eliminating Receive Livelock in an Interrupt-Driven
  Kernel," TOCS 1997; Intel's `InterruptThrottleRate`; DPDK's adaptive
  polling) applies the same idea *at the device IRQ layer*, with a
  single device-wide moderation parameter.
- **Soft timers** (Aron & Druschel, "Soft Timers: efficient microsecond
  software timer support for network processing," SOSP 1999 / TOCS
  2000) provide the exact cheap per-group deadline-firing mechanism
  DAPRA relies on internally.
- **EPOLLEXCLUSIVE** (Linux ~4.5) picks one thread out of many
  watchers to avoid thundering herd, but does not batch events.
- **`io_uring` multishot poll** (Axboe, Kernel Recipes 2020+) amortizes
  submission/completion within one ring, but the wake itself is still
  per-event and per-ring.
- **Pariag et al.**, EuroSys 2007 ("Comparing the Performance of Web
  Server Architectures") — thundering-herd measurements that motivate
  wake-one pipe semantics.

DAPRA is a new point in this known design space, not unclaimed
territory. What it adds is (a) a **per-fd deferral hint**, rather than
a single device-wide knob, (b) composition across a **poll group**
shared by cooperating threads in a process, and (c) integration with
readiness notification (not device IRQs or scheduler deadlines). The
novelty claim is this specific composition — readiness-notification
batching with a per-fd budget, aggregated at the kernel level across a
poll group — not the underlying idea of deferred wake.

**Proposal.** Extend `struct pollfd` with an optional per-fd deadline via
a new variant syscall:

```rust
// Existing POSIX shape:
#[repr(C)] pub struct PollFd { pub fd: i32, pub events: i16, pub revents: i16 }

// New, additive:
#[repr(C)]
pub struct PollFdDeadline {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
    pub _pad: i16,
    /// Max wake-defer window in nanoseconds. 0 = "wake me immediately"
    /// (classic poll). Nonzero = "you may defer my wake by up to N ns
    /// past readiness if you're batching". Hard cap: DAPRA_MAX_DEFER_NS
    /// = 10_000_000 (10 ms); values above are rejected with -EINVAL on
    /// syscall entry.
    pub deferral_ns: u32,
}

const DAPRA_MAX_DEFER_NS: u32 = 10_000_000;  // 10 ms

const _: () = assert!(core::mem::size_of::<PollFdDeadline>() == 16);

sys_poll_deadline(fds: *mut PollFdDeadline, nfds: usize,
                  timeout_ns: i64, group: PollGroupToken) -> isize;
```

**Semantics.**

1. The `group` argument (optional; `0` = anonymous per-call group) names a
   kernel-side aggregation bucket. Threads polling the same group share
   one wake-batch window.
2. On first readiness event, the kernel schedules a deadline timer at
   `now + min(deferral_ns over all pollfds in group)`. Until that timer
   fires (or the waiter is explicitly woken because a POLLERR / POLLHUP
   shows up — those are never deferred), further readiness events are
   **coalesced**: they update `revents` in the pollfd array but do not
   issue a wake-up.
3. The thread is woken exactly once per batch.
4. If all pollfds have `deferral_ns == 0`, `sys_poll_deadline` is
   behaviourally identical to `sys_poll` — strict POSIX fallback.
5. POLLERR, POLLHUP, POLLNVAL are **never deferred**: an error path must
   not be held back for a latency budget.

**Expected benefit (conditional, pending measurement).** We conjecture
DAPRA reduces wake count for workloads with ≥ 2 fds becoming ready
within the deferral window — this is the condition for any batching
scheme to beat single-event delivery. DAPRA is not strictly beneficial:
when bursts never exceed 1 ready fd per window it reduces to classic
poll with an added timer cost. The concrete microbenchmark target
(see §Performance Considerations) is subject to measurement in the
`pipe-broadcast` bench before any claim of superiority is made.

**Invariants and failure modes.**

- **Liveness bound.** For every waiter *w* in group *g*, the wake-time
  obeys `wake_time(w) ≤ min(arrival_time(w) + timeout(w),
  first_ready(g) + min_deferral(g), signal_time(w))`. This is the
  complete set of bounds: there is no way for a waiter to be deferred
  past any of them.
- **Complete list of deferral-exempt wake sources** (nothing may delay
  these): POLLERR, POLLHUP, POLLNVAL, signal delivery to the waiter,
  `timeout` expiry, and *peer-blocked-on-me promotion* (see next).
- **Peer-blocked-on-me promotion (cross-process DoS prevention).** When
  thread A has a deferred wake pending on fd *F* and thread B is
  blocked on *F*'s complementary direction (B is waiting for A to
  read so B can write, or vice versa), A's deferral is promoted to
  immediate on the ISR side: the moment B registers on the
  `WaitQueue`, the kernel checks "does any member of the peer waiter
  set have a pending-deferred readiness that would unblock B?" and, if
  so, cancels the deferral timer and wakes A now. This prevents the
  attack described in the Security review (attacker A defers its own
  read wake, transitively starving victim B's write).
- **Hard cap on `deferral_ns`.** `DAPRA_MAX_DEFER_NS = 10 ms`. Any
  value above is rejected with EINVAL. This bounds worst-case waiter
  latency at 10 ms even in the absence of peer-blocked-on-me
  promotion, keeping DAPRA in the "interactive" latency regime.
- **`PollGroupToken` lifecycle.** Tokens are per-process and opaque.
  Not inheritable across `fork`. Across `execve`, all tokens are
  revoked (the kernel tears down group state alongside the rest of
  the process's ephemeral kernel state). Bounded at 64 groups per
  process; further `poll_group_create` returns EMFILE.

**Scope for this RFC.** We ship `sys_poll_deadline` and the group-token
syscalls as *additive* — classic POSIX `sys_poll` is unchanged and works
without any group infrastructure. Measurement (§Performance Considerations)
determines whether the default libc `poll()` should transparently use
the deadline variant with `deferral_ns = 0`.

### Kernel–Userspace Interface

New syscall numbers (matching Linux x86_64 ABI where a Linux equivalent
exists; new numbers allocated from vibix's reserved range for DAPRA):

| # | Name | Linux # | Notes |
|---|---|---|---|
| 22 | `pipe` | 22 | `int pipe(int fds[2]);` Linux ABI exact. |
| 293 | `pipe2` | 293 | `int pipe2(int fds[2], int flags);` accepts `O_NONBLOCK`, `O_CLOEXEC`, `O_DIRECT`. |

**`pipe(2)` vs `pipe2(2)` flag semantics (POSIX XSH §pipe, explicit).**
`sys_pipe(fds)` with no flag argument MUST return two fds with:
- `O_NONBLOCK` **clear** on both file descriptions (blocking I/O by default);
- `FD_CLOEXEC` **clear** on both file descriptors (inherited across `execve`).

`sys_pipe2(fds, flags)` honours the three flag bits atomically at create
time (no `fcntl` round-trip):
- `O_NONBLOCK` in `flags` → set on both file descriptions.
- `O_CLOEXEC` in `flags` → set `FD_CLOEXEC` on both fds.
- `O_DIRECT` in `flags` → select packet-mode semantics (deferred to a
  future RFC; v1 rejects this bit with `EINVAL` rather than silently
  accepting it).

Any other bit in `flags` → `EINVAL`. Both fds end up in the calling
process's fd table in a single atomic installation step — fork/exec
races that would leak one end to a child are impossible because
`FD_CLOEXEC` is set before the syscall returns to userspace.

| 7 | `poll` | 7 | `int poll(struct pollfd *, nfds_t, int timeout_ms);` |
| 271 | `ppoll` | 271 | adds sigmask + timespec. |
| 23 | `select` | 23 | Classic BSD shape. Layered on poll. |
| 270 | `pselect6` | 270 | Modern select with sigmask. |
| 16 | `ioctl` | 16 | Already exists; add TTY/TIOC* opcodes. |
| — (vibix) 600 | `poll_group_create` | — | `int poll_group_create(void);` |
| — (vibix) 601 | `poll_group_destroy` | — | `int poll_group_destroy(int token);` |
| — (vibix) 602 | `poll_deadline` | — | `int poll_deadline(struct pollfd_deadline *, nfds_t, int64_t timeout_ns, int group);` |

**TTY ioctls (matching Linux `<asm/ioctls.h>`):**

| opcode | Name | Semantics |
|---|---|---|
| 0x5401 | TCGETS | `ioctl(fd, TCGETS, struct termios *)` |
| 0x5402 | TCSETS | TCSANOW equivalent |
| 0x5403 | TCSETSW | TCSADRAIN (drain output first) |
| 0x5404 | TCSETSF | TCSAFLUSH (drain output, flush input) |
| 0x5409 | TCFLSH | `tcflush()` — TCIFLUSH/TCOFLUSH/TCIOFLUSH |
| 0x540B | TCFLOW | `tcflow()` |
| 0x540D | TIOCGPGRP | `tcgetpgrp()` |
| 0x540E | TIOCSPGRP | `tcsetpgrp()` |
| 0x5410 | TIOCGSID | `getsid()` of the controlling tty's session |
| 0x540F | TIOCSCTTY | acquire controlling tty (session leader only) |
| 0x5422 | TIOCNOTTY | release controlling tty |

**Termios constants (Linux `<asm-generic/termbits-common.h>`):**

We expose the standard bit values verbatim:
- `c_iflag`: BRKINT=0x2, ICRNL=0x100, IGNBRK=0x1, IGNCR=0x80, INLCR=0x40, ISTRIP=0x20, IXON=0x400.
- `c_oflag`: OPOST=0x1, ONLCR=0x4, OCRNL=0x8.
- `c_lflag`: ISIG=0x1, ICANON=0x2, ECHO=0x8, ECHOE=0x10, ECHOK=0x20, ECHONL=0x40, NOFLSH=0x80, TOSTOP=0x100, IEXTEN=0x8000.
- `c_cc` indices: VINTR=0, VQUIT=1, VERASE=2, VKILL=3, VEOF=4, VTIME=5, VMIN=6, VSTART=8, VSTOP=9, VSUSP=10, VEOL=11.
- Default `c_cc`: VINTR=^C=0x03, VQUIT=^\=0x1c, VERASE=0x7f, VKILL=^U=0x15, VEOF=^D=0x04, VSUSP=^Z=0x1a, VSTART=^Q, VSTOP=^S.

**Errno table for new paths:**

| Error | Path | Reason |
|---|---|---|
| EAGAIN | pipe read/write | O_NONBLOCK with no data / no space |
| EPIPE + SIGPIPE | pipe write | no readers |
| EINTR | pipe/tty/poll | signal delivered during wait |
| EIO | tty read | background read, pgrp orphaned |
| ERESTARTSYS | tty write | background write, SIGTTOU delivered |
| ENOTTY | tty ioctl | fd is not a TTY |
| EPERM | TIOCSPGRP/TIOCSCTTY | session/leader check failed |
| EINVAL | poll | nfds exceeds limit |

## Security Considerations

- **SMAP bracketing.** All `copy_to_user` / `copy_from_user` in pipe read/write,
  poll fd-array access, and termios marshalling bracket with STAC/CLAC. The
  existing vibix `UserSlice` abstraction is reused; no new direct user-pointer
  dereferences in this RFC.
- **fd validation.** `poll`'s fd array is copied in with a single
  `copy_from_user`, bounded by an explicit `nfds ≤ 4096` cap (configurable;
  matches Linux's `RLIMIT_NOFILE`-derived cap). Negative fds are ignored per
  POSIX; positive-but-closed fds yield `POLLNVAL` in `revents` and **do not
  register** on any wait queue.
- **Signal-injection surface.** The TTY line discipline generates SIGINT /
  SIGQUIT / SIGTSTP / SIGTTIN / SIGTTOU. Attack surface: a process must
  already be in the foreground pgrp of a TTY (for the first three) or
  accessing the TTY at all (for TTIN/TTOU). Acquiring a TTY requires being
  a session leader; becoming a session leader requires `setsid()` (no
  privilege). This is correct POSIX semantics — the risk is not
  privilege-escalation but self-inflicted denial-of-service by scripts
  sending control characters to themselves. No mitigation beyond matching
  POSIX.
- **Pipe ring information disclosure.** Uninitialized ring memory is zeroed
  on pipe creation (Box<[u8; N]> must be explicitly `vec![0u8; N]` rather
  than `MaybeUninit`). Reads below the current fill never observe stale
  bytes because the ring invariant enforces `head ≤ tail` (wrapping).
- **Wake-queue entry lifetime (TOCTOU).** The two-pass poll pattern requires
  `WaitQueue::register` to hold a lifetime that outlives the ISR wake path.
  We implement wait entries as `Pin<&PollEntry>` stored in the `PollTable`
  (stack-allocated where possible), with explicit cancellation in
  `PollTable::drop`. A wait queue that fires after the `PollTable` has
  dropped is a kernel bug — covered by a debug-assert on wake and a
  unit test that exercises drop-before-wake.
- **Race: reader-closed between probe and wait.** If a writer computes
  `readers > 0` during Probe, blocks, and the last reader closes during
  Wait, the reader's drop path must call `wr_wait.wake_all()` so the
  blocked writer resumes and re-checks `readers`, then returns EPIPE.
  Symmetric rule on the read side for `writers`.
- **DAPRA wake starvation.** A malicious or buggy process cannot starve
  others because groups are per-process; its deadlines only defer its own
  wakes. The kernel never defers a POLLERR / POLLHUP / POLLNVAL or a
  signal-delivery wake.
- **TTY line-discipline DoS.** A user filling the raw-mode ring (4 KiB) and
  never reading cannot consume unbounded kernel memory — the ring is
  fixed-size and overflow drops the newest byte (Linux "silent drop",
  matches N_TTY behaviour). We explicitly do **not** grow the tty buffer
  like Linux's flip-buffer (`TTY_BUFFER_PAGE`); the cost of unbounded
  growth outweighs the benefit at our scale.
- **Controlling-tty hijack.** `TIOCSCTTY` requires session-leader + no
  existing session on the tty. `TIOCSCTTY` with the `force` argument
  (Linux extension allowing root to steal a tty) is **not implemented**
  in this RFC — strictly session-leader acquisition only.

## Performance Considerations

- **Pipe single-pair throughput (speculative, pending measurement).**
  Aspirational target: ≥ 2 GB/s on a single core for bulk
  `write(pipe, buf, 64K); read(pipe, buf, 64K)` loops under QEMU-KVM on a
  modern x86-64 host. This is not an SLA — it is an upper-bound
  plausibility estimate based on two cache-resident `memcpy`s per
  round-trip with FSRM-aware `rep movsb`. For calibration, Linux
  `fs/pipe.c` on bare metal reports ~5–10 GB/s on the same workload; a
  factor-of-3 to factor-of-5 gap is expected for a younger Rust
  implementation under a virtualized guest. The commitment is to
  **measure and publish** `pipe-bulk` benchmark results as part of the
  implementation PR; if the first measurement comes in below 500 MB/s we
  investigate before landing, and if it comes in between 500 MB/s and
  2 GB/s we document the gap and land anyway.
- **Pipe small-message latency (revised, with budget).** Target:
  **2–5 µs** RTT on a pipe ping-pong with 8-byte payloads, single core.
  Budget per round-trip: 2× context switch (≈400-800 ns on modern
  x86-64 with PCID), 2× wake (≈100-300 ns each), 2× STAC/CLAC +
  `copy_from/to_user` of 8 bytes (≈100 ns), 2× `IrqSafeMutex`
  lock/unlock pair (≈50-100 ns uncontested), 2× waitqueue register +
  cancel (≈200 ns). Sum: ≈2-4 µs before any I-cache/TLB effects. A
  sub-microsecond target would require avoiding the context switch
  entirely (e.g., busy-wait on a shared user-kernel ring, out of scope
  for this RFC), so we publicly commit to 2-5 µs and treat <2 µs as a
  stretch goal for a later optimization pass.
- **Poll syscall cost.** Classic `poll` is O(nfds) per call — this is
  fundamental to the API. We amortize with (a) stack-allocated
  `ArrayVec<PollEntry, 8>` fast path for ≤ 8 fds (matches Linux
  `FRONTEND_STACK_ALLOC`-ish), (b) single `copy_from_user` for the fd
  array, (c) the two-pass pattern avoiding a wait registration on the
  common "something is already ready" case.
- **DAPRA expected gain.** For an interactive shell waiting on stdin +
  SIGCHLD-fd + child stdout, the typical burst of 2-3 ready fds per event
  reduces 2-3 wake-ups to 1 wake-up — a ~50% reduction in schedule
  invocations on pipe-heavy workloads. Microbenchmark target: `pipe-ring`
  bench (8 pipes, broadcast wake) shows ≥ 30% fewer schedule events with
  `deferral_ns = 100_000`. This is speculative pending measurement.
- **Cache-line discipline.** `head` and `tail` on separate 64-byte lines
  (enforced by `#[repr(align(64))]`). In the single-producer / single-
  consumer case (one reader, one writer) on two cores, only two cache
  lines bounce per round-trip.
- **Lock contention.** Pipe fast path takes one `IrqSafeMutex` for the
  copy; this is uncontested in the SPSC case and contested only if
  multiple readers/writers share an fd. We do **not** ship a lock-free
  multi-producer ring in this RFC — `dup(2)`-sharing a pipe between
  multiple writers is rare and the mutex is fine.
- **TTY input path.** ISR cost: enqueue one byte on a deferred-call queue,
  ~5-10 cycles plus the IRQ entry/exit. Soft-IRQ cost: `receive_byte`
  takes the termios mutex briefly, then appends to a `VecDeque` or
  `ArrayVec`. No per-byte allocation — `Line` is boxed only on line
  commit, once per newline.
- **SMP considerations.** vibix is currently UP but all structures are
  SMP-safe: `AtomicUsize` head/tail, `IrqSafeMutex` for bulk state,
  per-tty (not global) `read_wait`/`write_wait`. No global lock.
- **MFENCE avoidance.** Per the x86-TSO memory model, the pipe ring's
  producer and consumer need only `Ordering::Release` on the index store
  and `Ordering::Acquire` on the index load — no MFENCE. Verified
  against Intel SDM Vol. 3A memory-ordering rules.

## Alternatives Considered

- **`pipe_buffer`-style page ring (Linux).** Rejected for v1 because without
  splice/vmsplice the page indirection is pure overhead, and the
  `PIPE_BUF_FLAG_CAN_MERGE` + stolen-page logic is exactly the surface
  Dirty Pipe (CVE-2022-0847) exploited. A future RFC can add splice on
  top of a byte ring by introducing a second fast path.
- **`Mutex<VecDeque<u8>>` (Redox).** Rejected for performance: VecDeque
  reallocates, and even at fixed capacity its indexing is a pair of
  branches per byte. The raw-byte ring is simpler and faster.
- **DoubleBuffer (Serenity).** Rejected as 2× memory for modest benefit
  without measurable performance win in a Rust-kernel context.
- **Put canonical mode in userspace (Plan 9 style).** Attractively simple
  — libreadline/linenoise already do this in practice. Rejected because
  POSIX requires the canonical-mode state machine at the kernel
  boundary (notably for job-control signal generation tied to the
  controlling TTY), and the userspace alternative still requires a
  kernel TTY with termios and job control — so we do not save much.
- **epoll in this RFC.** Deferred to a later RFC. `poll` + the DAPRA
  extension already cover most of the practical need; epoll belongs in
  a networking-focused RFC once sockets exist.
- **BPF-programmable line discipline (N_BPF).** Considered as the "novel
  idea" but rejected in favour of DAPRA because it requires a BPF
  verifier (very large scope) and is less architecturally deep than
  deadline-aware readiness.
- **Wake-all instead of wake-one on pipe state change.** Matches
  Serenity/Redox but scales poorly past ~2 blocked waiters. We use
  wake_one; correctness depends on waiters re-checking state on wake
  (standard condvar discipline).
- **Unbounded pipe capacity (Linux `F_SETPIPE_SZ`).** Deferred. Fixed 64 KiB
  matches common defaults and simplifies the ring.

## Open Questions

1. **Pipe SPSC vs locked ring, revisited.** If initial benchmarking shows
   lock contention is significant even in the SPSC case, swap the inner
   mutex for true SPSC atomics. Defer until measurement.
2. **PTY scope.** This RFC mentions `Pty{Master,Slave}` as TTY-driver
   implementers but does not design `devpts` or the `/dev/ptmx` path.
   File a follow-on RFC for PTY once the base TTY lands.
3. **`sigaltstack` for SIGPIPE delivery.** vibix's signal delivery does
   not yet support alternate stacks; SIGPIPE is delivered on the default
   stack only. POSIX permits this; flag as an `area:security` follow-up.
4. **Canonical VMIN/VTIME timer source.** MIN=0,TIME>0 needs a per-read
   one-shot timer; we assume `hpet.rs` gives us ≤ 100 µs resolution.
   Verify before implementing non-canonical reads.
5. **DAPRA default deferral via libc.** Whether a future `libc.so` should
   set a conservative default `deferral_ns` on normal `poll(3)` calls is
   deferred to userspace policy. Kernel defaults to 0.
6. **POLLRDBAND / POLLWRBAND.** Accept the flags (POSIX requires the
   symbols) but never set them (no STREAMS priority bands). Documented
   as a known POSIX-conforming no-op.
7. **select exceptfds semantics.** Linux maps `exceptfds` to POLLPRI. We
   do the same — documented here to avoid surprise.

## Implementation Roadmap

- [ ] Add `poll` method to `FileBackend` trait with default `DEFAULT_POLLMASK`; plumb through existing `SerialBackend` and `VfsBackend`.
- [ ] Implement `WaitQueue` with `register(PollEntry)` / `wake_one` / `wake_all` and `PollTable` (Probe/Wait modes) in `kernel/src/poll/mod.rs`.
- [ ] Implement anonymous pipe (`PipeRing`, `Pipe`, `PipeReadEnd`, `PipeWriteEnd`, `sys_pipe`, `sys_pipe2`) in `kernel/src/ipc/pipe.rs`.
- [ ] Implement `sys_poll` + `sys_ppoll` + `sys_select` + `sys_pselect6` with two-pass scan in `kernel/src/poll/syscalls.rs`.
- [ ] Add session/pgrp/controlling-tty fields to the PCB and wire `setsid`/`getpgid`/`setpgid`/`getsid` syscalls.
- [ ] Implement `Termios` (Linux ABI layout) + `TCGETS`/`TCSETS`/`TCSETSW`/`TCSETSF` ioctls.
- [ ] Implement `Tty` wrapper + `LineDiscipline` trait + ISR-deferred input plumbing; wire existing serial UART and PS/2 keyboard paths through it.
- [ ] Implement `NTty`: ISTRIP/ICRNL/INLCR/IGNCR input mapping, ISIG signal generation (VINTR/VQUIT/VSUSP), ICANON line buffering with VERASE/VKILL/VEOF, OPOST/ONLCR output mapping, echo.
- [ ] Implement TTY job control: TIOCSCTTY, TIOCSPGRP, TIOCGPGRP, TIOCGSID, TIOCNOTTY; SIGTTIN on background read; SIGTTOU on background write under TOSTOP.
- [ ] Add FIFO support via `mkfifo` path + VFS inode wiring (uses the same `Pipe` as anonymous pipes).
- [ ] Implement DAPRA: `sys_poll_group_create` / `sys_poll_group_destroy` / `sys_poll_deadline` + kernel-side group bucket + deadline timer. Guard behind a `kconfig`-style feature flag if non-trivial.
- [ ] Integration test: `pipe-broadcast` bench measuring wake events under classic `poll` vs DAPRA with `deferral_ns = 100_000` across a 4-pipe fan-in; target ≥ 30% reduction.
- [ ] Integration test: shell pipeline `echo foo | cat | wc -c` returning `4\n` end-to-end in userspace QEMU run.
- [ ] Integration test: canonical-mode input — ^C from TTY delivers SIGINT to foreground pgrp and flushes the line buffer.
