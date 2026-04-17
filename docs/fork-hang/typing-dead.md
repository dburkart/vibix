# "Typing-dead" symptom during the init fork hang — root cause

**Issue:** [#503](https://github.com/dburkart/vibix/issues/503) (child of epic
[#501](https://github.com/dburkart/vibix/issues/501)).

**Conclusion:** The typing-dead symptom that accompanies the ~50% init fork
hang is *not* a separate bug. It is a direct, unavoidable consequence of the
fork-path spin diagnosed in [#502](https://github.com/dburkart/vibix/issues/502):
while the fork syscall handler is wedged, `RFLAGS.IF=0` on the only CPU, so
**all** maskable IRQs (PS/2 IRQ1, serial-rx IRQ4, HPET timer IRQ0) are blocked.
Nothing reaches `input::SCANCODES` or `serial::try_read_byte`, and the shell's
`hlt` wait is never woken. Resolving #502 (and its dependent structural fixes
[#504](https://github.com/dburkart/vibix/issues/504) /
[#505](https://github.com/dburkart/vibix/issues/505)) resolves this symptom
automatically. **No driver-side or input-side fix is required.**

This doc is the write-up promised in the #503 work list. It captures the
evidence chain so the conclusion is auditable without re-running the probes,
and so the same question doesn't get re-opened the next time a related
symptom appears.

## The symptom

Captured by the reporter against `vibix.iso` at HEAD (epic #501 body):

```
vibix> init: switched to process PML4
init: entering ring-3 entry=0x400000 stack=0x80000000
init: hello from pid 1
<hang — no further output; typing to serial/PS-2 produces nothing>
```

The last userspace instruction before the hang is `syscall(57) = fork()`.
The shell prompt (`vibix> `) is on screen, but keystrokes on both PS/2 and
COM1 produce no echo and no visible kernel reaction.

## Hypothesis going in (from #503 body)

> The most plausible cause is that IRQs are globally masked (IF=0 on the CPU)
> and stuck there — a consequence of sub-issue #1's fork-handler spin.

## Evidence chain

### 1. `MSR_FMASK` clears IF on every SYSCALL entry, by design

`kernel/src/arch/x86_64/syscall.rs`:

```rust
/// RFLAGS bits cleared by SFMASK on SYSCALL entry.
/// TF (bit 8) — trap / single-step
/// IF (bit 9) — interrupts: disabled while handling syscall to prevent
///              IRQ re-use of the shared `INIT_KERNEL_STACK`
/// DF (bit 10) — direction: clear so string instructions run forward
/// NT (bit 14) — nested task: should never be set in 64-bit mode, clear defensively
/// AC (bit 18) — alignment check: clear to avoid spurious faults in handler
const RFLAGS_SYSCALL_MASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18);

// ...in init():
Msr::new(MSR_FMASK).write(RFLAGS_SYSCALL_MASK);
```

So when the `SYSCALL` instruction executes in userspace, the CPU atomically
switches to ring 0 *and* clears IF. Normal syscalls return quickly (SYSRETQ
restores user RFLAGS, which has IF=1 set), so IF=0 only holds for the brief
lifetime of each syscall. Long-running syscalls are the pathological case.

### 2. Fork dispatch is confirmed to run with IF=0

Verified end-to-end by the `fork-trace` instrumentation merged in
[#515](https://github.com/dburkart/vibix/issues/515) (closes #502). The
captured serial log lives at
[`docs/incident-logs/502-fork-trace-boot.log`](../incident-logs/502-fork-trace-boot.log).
The first fork-trace line reads:

```
fork-trace: [syscall:FORK enter] parent_task=4 user_rip=0x400025
  user_rflags=0x212 user_rsp=0x7fffff4c kernel_rflags=0x87 IF=0
```

`kernel_rflags=0x87` = `0b1000_0111` → bit 9 (IF) is **0**. The probe reads
live RFLAGS immediately on entry into the fork dispatch arm; the value is
the authoritative kernel-side flag state at that point. This matches what
`MSR_FMASK` should produce and proves the fork dispatcher (and everything it
calls) runs with IRQs masked.

### 3. While IF=0, the I/O-APIC's signal to the LAPIC never reaches the CPU

Boot-time wiring (from the trace log):

```
PIC remapped to 0x20/0x28 and masked
ioapic: IRQ0 -> gsi 2 -> vec 0x20 on lapic 0 (ioapic 0)
ioapic: IRQ1 -> gsi 1 -> vec 0x21 on lapic 0 (ioapic 0)
ioapic: IRQ4 -> gsi 4 -> vec 0x24 on lapic 0 (ioapic 0)
serial: rx irq enabled
```

The three IRQs that could wake the shell — HPET/timer (0x20, drives
preemption), PS/2 keyboard (0x21), UART rx (0x24) — are all regular *maskable*
external interrupts. They are gated by `RFLAGS.IF`. With IF=0, the LAPIC
still *receives* the message from the I/O-APIC, but the CPU refuses to
vector into the ISR until IF transitions back to 1. That transition happens
on `sti` or on SYSRETQ/IRETQ; neither can run while the fork handler is
spinning in the kernel.

### 4. The shell's input path depends entirely on those IRQs

`kernel/src/input.rs`:

```rust
/// Called from the keyboard ISR. Interrupts are already disabled.
pub fn push_scancode_from_isr(code: u8) {
    if !SCANCODES.lock().push(code) {
        OVERFLOWS.fetch_add(1, Ordering::Relaxed);
    }
}
```

`SCANCODES` is *only* written by the keyboard ISR. There is no polling
fallback. If IRQ 0x21 never fires, the ring never fills, and
`try_read_scancode()` returns `None` forever.

`kernel/src/shell/mod.rs`:

```rust
loop {
    if let Some(ev) = next_input(&mut ansi) {
        // ...process key
    } else {
        // Nothing in either input ring. Halt until the next IRQ
        // (keyboard or UART byte wakes us; PIT rotates us out on
        // slice expiry).
        x86_64::instructions::hlt();
    }
}
```

The shell's empty-input branch is `hlt`. On a CPU with IF=0, `hlt` still
halts execution but an incoming maskable IRQ does *not* wake it; only NMI,
SMI, or INIT can — and none of those fire on a PS/2 or serial keypress. Even
if the shell were woken somehow, `input::read_key` (used elsewhere, e.g.
pre-shell prompts) performs an `enable_and_hlt` that would also be a no-op
for key events because the ring is still empty.

### 5. Scheduler preemption also depends on those IRQs

The HPET periodic timer at 100 Hz drives `preempt_tick` via vector 0x20
(`kernel/src/arch/x86_64/interrupts.rs:27-39`). With IF=0 on a uniprocessor,
timer ticks don't fire, so even task rotation is frozen while fork spins —
the shell task can't even be scheduled in to notice its input rings. This
makes the typing-dead symptom doubly-locked: input doesn't arrive, *and* the
consumer can't run.

### 6. Ring-buffer / lock-ordering audit — nothing suspicious

The #503 body asked for an audit of `input.rs` to rule out ring-fullness or
lock-ordering bugs that could drop bytes *even if* IRQs do fire. Findings:

- **Ring size** is 128 bytes (`kernel/src/input.rs:82`). A typist can't fill
  it faster than the shell drains it (shell drain is per-keypress, ring
  overflow would take ~128 keystrokes in a single scheduler slice).
  `scancode_overflows()` exposes the counter if this ever does happen; it
  is zero in every known trace.
- **Lock type** is `IrqLock<RingBuffer>`, the repo's IF-aware wrapper. It
  disables IRQs in `lock()` and restores on drop. This is the correct choice
  for a structure shared between an ISR producer and a task consumer;
  replacing it with `spin::Mutex` would be the bug, not keeping it.
- **Lock ordering:** the ISR (IRQ 0x21) is the only producer. It calls
  `push_scancode_from_isr → SCANCODES.lock()`. On the consumer side,
  `try_read_scancode` and `read_key` also take only `SCANCODES.lock()`. No
  nested locks, no path from the ISR into any other `spin::Mutex`. Lock
  ordering is trivial and free of hazards.
- **Missed-wakeup window in `read_key`:**
  `kernel/src/input.rs:148-169` uses the `interrupts::disable() →
  check-empty → enable_and_hlt()` idiom. `enable_and_hlt` is atomic: IF=1
  and `hlt` execute on adjacent cycles with no window for a pending IRQ to
  be missed. This is the standard correct pattern; no race.

So the input path itself is sound. The hang is upstream of it.

### 7. PIT heartbeat probe — not needed

The #503 body proposed adding a periodic `serial_println!("heartbeat: pit=N")`
from the timer ISR to confirm (by *absence* during hang) that IRQs are dead.
That probe is now redundant: the fork-trace from #515 already witnessed
`IF=0` in the dispatcher directly, which is strictly stronger evidence than
a heartbeat (IF=0 proves IRQs are masked *regardless* of whether a heartbeat
path would have fired). Skipping the heartbeat probe keeps the timer ISR
hot-path clean.

If a future regression makes IRQ-mask state ambiguous again, the heartbeat
pattern remains the right tool; it is just unnecessary for this issue.

## Why this resolves as "duplicate of #502" rather than a code change

The entire causal chain is:

```
fork syscall enters with IF=0 (by design, MSR_FMASK)
    → fork_current_task() spins somewhere
    → IF never restored (SYSRETQ never reached)
    → maskable IRQs 0x20/0x21/0x24 are gated
    → scheduler can't preempt, PS/2 drops, serial drops
    → shell hlt never wakes
    → symptom: "typing-dead" on a visibly-present prompt
```

The link `fork handler spins → typing-dead` is purely architectural; there
is no input-side patch that could loosen it. Polling the PS/2 / UART
registers from a non-IRQ context would require the kernel to *be running*,
which it isn't — it's inside the fork spin. Moving input processing into
softirqs wouldn't help either; softirqs drain in `preempt_tick`, which is
itself gated by the timer IRQ.

The only durable fix is to stop the fork path from spinning with IF=0:

- **#504** — Replace the `FORK_USER_{RIP,RFLAGS,RSP}` globals with per-task
  saved context. Eliminates the race that (per epic #501's H2 hypothesis) can
  clobber saved state between two concurrent forks.
- **#505** — Consolidate the `syscall_stack_top` / `SYSCALL_KERNEL_RSP` /
  `TSS.rsp[0]` update sites into a single choke point. Eliminates the
  three-way divergence that can leave the child sysret-ing onto a
  stale/garbage kernel stack.

When those land, forks complete quickly, IF-masking windows close, and the
typing-dead window closes with them.

## Files consulted

- `kernel/src/arch/x86_64/syscall.rs` — `MSR_FMASK` setup (lines 67, 79,
  153-154); fork dispatcher with IF probe (lines 520-553).
- `kernel/src/arch/x86_64/interrupts.rs` — keyboard/serial/timer ISRs (lines
  27-64).
- `kernel/src/arch/x86_64/idt.rs` — vector wiring, first-ring3-fault latch.
- `kernel/src/input.rs` — `SCANCODES` ring, `push_scancode_from_isr`,
  `read_key` (lines 82-169).
- `kernel/src/shell/mod.rs` — shell run loop and `hlt` wait (lines 45-89).
- `kernel/src/tty/ps2.rs`, `kernel/src/tty/serial.rs` — tty-side drain
  softirqs (observational, not the shell's read path today — #474).
- `docs/incident-logs/502-fork-trace-boot.log` — live RFLAGS capture.

## Cross-references

- Epic [#501](https://github.com/dburkart/vibix/issues/501)
- Sibling diagnostic [#502](https://github.com/dburkart/vibix/issues/502)
  (closed by #515)
- Structural fixes [#504](https://github.com/dburkart/vibix/issues/504),
  [#505](https://github.com/dburkart/vibix/issues/505)
- Unrelated (do **not** confuse): [#474](https://github.com/dburkart/vibix/issues/474)
  (N_TTY ldisc wiring) — the shell bypasses the ldisc and reads
  `input::SCANCODES` directly, so ldisc state has no bearing on this symptom.
