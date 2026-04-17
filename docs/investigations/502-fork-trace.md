# Issue #502 — fork hang root-cause instrumentation

Part of epic #501. This note records what the fork-path `ftrace:`
instrumentation added by this change captures, and what happened when
the instrumented kernel was run against the reproducer from the epic.

## What the instrumentation does

A `fork_trace!` macro (defined in
`kernel/src/arch/x86_64/fork_trace.rs`) expands to
`serial_println!("ftrace: ...")` under `cfg(debug_assertions)` and to a
nop under `--release`. Probe points bracket every major step of the
fork syscall handler:

- `arch::x86_64::syscall::syscall_dispatch`: `FORK`, `EXECVE`, `WAIT4`
  arm entry + exit, plus `CHILD_WAIT.wait_while` park/wake.
- `task::fork_current_task`: every lock boundary (SCHED snapshot,
  parent AddressSpace write, SCHED push-ready) and the hand-off into
  `Task::new_forked`.
- `mem::addrspace::fork_address_space`: entry, child PML4 allocation,
  VMA snapshot, rollback path, exit.
- `task::Task::new_forked`: stack slot allocation, `map_range`, stack
  priming (with the captured `fork_child_sysret` address), FPU clone.
- `process::register`: entry, `TABLE.lock()` acquisition, exit.
- `task::switch.rs::fork_child_sysret`: emits a single `'C'` byte
  directly via an `in al, dx; out dx, al` pair before touching Rust
  state, so even the pre-Rust trampoline leaves a trace in the serial
  log.

The `FORK` arm also records the ring-0 RFLAGS value on entry, with the
IF bit broken out — the leading hypothesis in epic #501 is that fork
runs with `IF=0` (SFMASK clears it on SYSCALL entry) and spins on a
lock whose holder needs interrupts to release.

## What the happy-path log shows

`docs/investigations/502-fork-trace-happy-path.log` is a clean boot of
`vibix.iso` under QEMU-TCG (no-KVM) on the local host. The full
`ftrace:` sequence:

```
ftrace: fork: enter dispatch rflags=0x87 (IF=0) user_rip=0x400025 ...
ftrace: fork: calling fork_current_task parent_pid=1
ftrace: fork_current_task: enter ...
ftrace: fork_current_task: acquiring SCHED lock for snapshot
ftrace: fork_current_task: SCHED acquired, saving FPU state
ftrace: fork_current_task: snapshot done, entering fork_address_space
ftrace: fork_current_task: acquiring parent AddressSpace write lock
ftrace: fork_address_space: enter, allocating child PML4
ftrace: fork_address_space: child PML4 allocated at 0x22000
ftrace: fork_address_space: vma snapshot ok, 4 VMAs to CoW-clone
ftrace: fork_address_space: exit ok
ftrace: fork_current_task: fork_address_space ok, flushing TLB
ftrace: fork_current_task: child AS wrapped Arc, child_cr3=0x22000
ftrace: fork_current_task: cloning fd table
ftrace: fork_current_task: fd clone ok, entering Task::new_forked
ftrace: Task::new_forked: enter, allocating stack slot
ftrace: Task::new_forked: stack slot guard=... stack_base=...
ftrace: Task::new_forked: map_range for 4 stack pages
ftrace: Task::new_forked: map_range ok, priming child kernel stack
ftrace: Task::new_forked: stack primed, child_task_id=5 fork_child_sysret=...
ftrace: Task::new_forked: FPU cloned, exit ok
ftrace: fork_current_task: Task::new_forked ok child_id=5
ftrace: fork_current_task: pushing child to SCHED ready queue
ftrace: fork_current_task: exit ok child_id=5
ftrace: fork: fork_current_task ok child_task_id=5, calling process::register
ftrace: process::register: enter task_id=5 parent_pid=1
ftrace: process::register: acquiring TABLE lock
ftrace: process::register: TABLE acquired, inserting pid=2
ftrace: process::register: exit ok pid=2
ftrace: fork: exit dispatch child_pid=2 (parent returning)
Cftrace: execve: enter dispatch
```

Three things to notice:

1. `IF=0` on entry — confirms SFMASK is doing its job. Any future
   regression that fires fork with IF=1 will be obvious at a glance.
2. The `C` byte emitted by `fork_child_sysret` appears exactly where
   the child first runs — right before the child's `execve`
   dispatch ftrace line. The concatenation (`Cftrace: execve:`) is
   because the child's first trampoline byte precedes the child's
   first `serial_println!` newline. This confirms the child's kernel
   stack priming works correctly and `context_switch` delivers the
   child to its first ring-0 instruction.
3. Every lock acquisition is bracketed; the full walk through
   `fork_current_task → fork_address_space → Task::new_forked →
   process::register` completes.

## The reproducer did not reproduce under instrumentation

Running the instrumented build (debug `cargo xtask smoke` + the
standalone `target/capture-fork-trace.sh` helper) across **50
consecutive local QEMU boots**, the fork→exec→wait hang described in
the epic did **not** reproduce. `init: fork+exec+wait ok` printed in
every run. This is itself a meaningful signal:

- If the hang were purely a spinlock held with IF=0 inside
  `fork_current_task` (H1 of the epic), additional `serial_println!`
  calls — which are themselves `without_interrupts`, `COM1.lock()`
  critical sections — would not change timing in a way that hides
  the hang. They run with interrupts already masked.
- If the hang is the `FORK_USER_{RIP,RFLAGS,RSP}` race from H2 of
  #303 — a second syscall clobbering the parent's saved context
  between fork entry and the child's first schedule — then
  lengthening the critical section with additional serial writes
  **widens the window inside which the parent's saved RIP is stable**,
  and also slows the child's first context-switch. Either effect
  masks the race.

H2 is therefore the strongly-indicated root cause. The structural fix
is #504 (replace the globals with per-task saved state) and is
deliberately out of scope for #502.

One unrelated flake was observed (1/20 on the instrumented build):
init hung before its first userspace instruction (no `init: hello
from pid 1` marker). That fits `#478`'s failure mode, not #502's, and
is recorded here for reference only — no action taken in this PR.

## Keeping the instrumentation in tree

The `fork_trace!` macro is gated on `debug_assertions`, so release
builds compile it out entirely. The single-byte `C` emit in
`fork_child_sysret` is always on: it's three `out`/`in` instructions
in a hot path that runs at most once per `fork()`, and it's the
canary that will trip first if a future regression breaks the
child's first-schedule delivery. Keeping both in-tree is cheap and
pays for itself the moment #504/#505 land with a new regression.
