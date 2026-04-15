---
rfc: 0003
title: Pipes, Poll, and TTY Line Discipline
status: Draft
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
#[repr(C)]
pub struct PipeRing {
    // Line 0: written by writer, read by writer + poll fast-path.
    #[repr(align(64))] tail: AtomicUsize,
    // Line 1: written by reader, read by reader + poll fast-path.
    #[repr(align(64))] head: AtomicUsize,
    // Bulk state.
    buf: Box<[UnsafeCell<u8>; PIPE_CAPACITY]>,
    lock: IrqSafeMutex<()>,
}

pub struct Pipe {
    ring: PipeRing,
    rd_wait: WaitQueue,
    wr_wait: WaitQueue,
    readers: AtomicUsize,
    writers: AtomicUsize,
    flags: AtomicU32,   // O_NONBLOCK, O_DIRECT (packet mode)
    // Each record is (start, len); in packet mode this carries boundaries.
    packets: IrqSafeMutex<Option<VecDeque<PacketHdr>>>,
}

pub struct PipeReadEnd(Arc<Pipe>);
pub struct PipeWriteEnd(Arc<Pipe>);
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
    waitq: *const WaitQueue,   // back-pointer into pipe/tty
    token: WaitToken,          // handle for de-registration
}
```

Driver `.poll` methods register themselves exactly as in Linux:

```rust
fn poll(&self, pt: &mut PollTable) -> PollMask {
    pt.register(&self.pipe.rd_wait);   // no-op in Probe mode
    pt.register(&self.pipe.wr_wait);
    self.current_mask()                 // READ_ONCE of the atomics
}
```

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
/// Termios bit layout matches Linux x86_64 ABI verbatim (see
/// <asm-generic/termbits.h>): 4 × u32 flags + cc_t c_cc[NCCS] with
/// NCCS = 19, c_line = 1 byte, ispeed/ospeed = u32. This is 36 bytes,
/// and we preserve the Linux layout so a userspace built against Linux
/// headers needs no shim.
#[repr(C)]
pub struct Termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line:  u8,
    pub c_cc:    [u8; 19],   // NCCS
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}
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

#### Pipe read / write fast paths

Both operate under `pipe.lock`. Poll readiness checks do NOT take the
lock: they read `head`/`tail` via `Ordering::Acquire` and use the ring's
invariant `fill = tail - head (wrapping)` to compute readiness. This
matches Linux's `READ_ONCE(pipe->head_tail)` trick (see Background).

```
Writer:
  acquire pipe.lock
  loop:
    fill = tail - head
    free = CAPACITY - fill
    if free >= min_needed: break
    if O_NONBLOCK: return EAGAIN
    if readers == 0:
       signal current with SIGPIPE (deferred past lock release)
       return EPIPE
    drop lock; wait on wr_wait; acquire lock
  copy chunk into buf[tail..tail+n]
  tail.store(tail + n, Release)
  release lock
  rd_wait.wake_one()          // directed wake, not wake_all
```

`wake_one` is a deliberate divergence from Serenity and Redox, both of
which wake_all on every transition. Wake-all is a thundering-herd
hazard for pipes with many blocked readers and no correctness benefit;
the Linux pipe wait queues use `wake_up_interruptible_sync_poll(...,
EPOLLIN)` which conceptually wakes one waiter plus any epoll watchers.

#### TTY input path (ISR → ldisc → ring)

```
UART/PS-2 ISR:
  byte = read_data_register()
  deferred_call_queue.push(|| tty.driver.recv_byte(byte))
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
      return ERESTARTSYS
  drop t
  for b in user_buf:
    if OPOST:
      if ONLCR and b == '\n': driver.put(b'\r'); driver.put(b'\n')
      else if OCRNL and b == '\r': driver.put(b'\n')
      else: driver.put(b)
    else: driver.put(b)
  return user_buf.len()
```

#### Job control

- `TIOCSCTTY` (ioctl) — if caller is session leader and tty has no session,
  bind tty.ctrl.session = caller.session.
- `TIOCSPGRP` — tty.ctrl.session must equal caller.session AND target pgrp
  must be in caller.session; else EPERM. If caller is background and not
  ignoring/blocking SIGTTOU, deliver SIGTTOU first (per POSIX `tcsetpgrp`).
- `TIOCGPGRP` / `TIOCGSID` — read-only.

#### Deadline-aware poll readiness (novel contribution)

The novel idea this RFC introduces. **Problem**: a server waiting on many
fds with mixed latency requirements wakes once per fd readiness event. If
several fds become ready in a short window, the waiter is woken N times
but only needs to be woken once per "batch" — the remaining N-1 wake-ups
are wasted work. io_uring's multishot poll partially addresses this per
ring; epoll's EPOLLEXCLUSIVE addresses thundering herd but not batching.

Academic search found no prior art for attaching a **soft-deadline hint**
to individual pollfd entries and letting the scheduler **aggregate the
wake** across a poll group within that latency budget.

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
    /// past readiness if you're batching".
    pub deferral_ns: u32,
}

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

**Why this is novel and better than the state of the art.**

- `epoll` + timerfd: gives you a global wake budget but not per-fd; every
  fd pays the same deferral.
- `io_uring` multishot poll: amortizes submission/completion within one
  ring; the wake itself is still per-event.
- `EPOLLEXCLUSIVE`: picks *one* waiter out of many on the same fd; does
  not batch events.
- DAPRA lets a server say, e.g., "stdin has 0 ns deferral (interactive
  latency), network sockets have 200 µs, internal work-stealing channels
  have 1 ms — wake me coherently". The kernel has the information to do
  the right thing because the scheduler *already* knows who's sleeping.

**Invariants and failure modes.**

- Deferral is soft: the waiter is always eventually woken if ready. A
  stuck deadline timer must not starve a ready waiter; the timer is
  per-group and bounded by `max(deferral_ns in group)`.
- If the process receives a signal during the deferral window, the wake
  is promoted to immediate (signal delivery trumps deferral).
- Deferral never extends `timeout` — if timeout expires during a batch
  window, the waiter is woken at the earlier of (timeout, batch deadline).
- `PollGroupToken` is a per-process opaque token allocated via a small
  `sys_poll_group_create` / `sys_poll_group_destroy` pair. Tokens are
  process-scoped (not inheritable across fork) to keep the group
  membership model simple.

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
| 293 | `pipe2` | 293 | `int pipe2(int fds[2], int flags);` |
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

- **Pipe single-pair throughput.** Target: ≥ 2 GB/s on a single core for
  bulk `write(pipe, buf, 64K); read(pipe, buf, 64K)` loops under QEMU-KVM
  on a modern x86-64 host. Dominated by two `memcpy`s per round-trip; with
  FSRM-aware `rep movsb` and cache-resident `buf`, this is achievable.
- **Pipe small-message latency.** Target: < 1 µs RTT on a pipe ping-pong
  with 8-byte payloads, single core. Two context switches + two 8-byte
  copies + two wakes. Limiting factor is the context-switch cost, not the
  pipe itself.
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
