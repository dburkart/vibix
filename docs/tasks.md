# Task Subsystem

**Sources:** `kernel/src/task/`, `kernel/src/sync/`
- `task/mod.rs` — public API, `init`, `spawn`, `preempt_tick`, `block_current`, `wake`
- `task/task.rs` — `Task` struct: kernel stack allocation, saved register context, scheduling state
- `task/scheduler.rs` — `Scheduler`: current task + FIFO ready queue + parked-task side-table
- `task/switch.rs` — `context_switch` in hand-written assembly
- `sync/` — blocking primitives (mutex, waitqueue, SPSC + MPMC channels) built on `block_current` / `wake`

## Overview

The task subsystem implements preemptive kernel-mode multitasking. Tasks
are kernel threads — they share the kernel address space and run entirely
in ring 0. Each task has its own kernel stack and a saved register context
that `context_switch` restores on re-entry.

There is no userspace and no per-task address space. Tasks that need to
wait on a condition block via `sync::WaitQueue` / `sync::BlockingMutex` /
`sync::spsc::channel` / `sync::mpmc::channel`, which park the task on the scheduler's `parked`
side-table until a wake arrives. Tasks that simply want to idle call
`hlt` with IRQs enabled; the PIT preempt tick rotates them out when
anyone else has work.

## Design

### Scheduler State

A single `Lazy<Mutex<Scheduler>>` holds:
- `current: Option<Box<Task>>` — the running task, `None` before `task::init`.
- `ready: VecDeque<Box<Task>>` — FIFO queue of ready-to-run tasks.
- `parked: BTreeMap<usize, Box<Task>>` — blocked tasks keyed by task id, invisible to the round-robin rotation until `wake(id)` migrates them back to `ready`.

### Task Struct

Each `Task` contains:
- A mapped kernel stack region (via `paging::map_range`, see constants below).
- An unmapped guard page at the base of the stack.
- `rsp: usize` — the saved stack pointer, updated by `context_switch`.
- `slice_remaining_ms: u32` — remaining preemption budget in milliseconds.
- `state: TaskState` — `Running` / `Ready` / `Blocked`, maintained by the scheduler transitions.
- `wake_pending: AtomicBool` — cure for the wake-before-park race: set by `wake(id)` if the target task is still Running or Ready, consumed by the next `block_current`.

Stacks are carved from a dedicated virtual address range
(`TASK_STACKS_VA_BASE`), one slot per task. Each slot is
`TASK_SLOT_SIZE = GUARD_SIZE + STACK_SIZE` bytes. The guard page is the lowest
page of the slot; the usable stack sits above it.

### `Task::bootstrap()`

Wraps the currently-executing thread (the `_start` / init thread) as a task.
The `rsp` is left at `0` — `context_switch` writes a real value when this task
is first switched away from. This avoids the need to fake a stack frame for the
initial thread.

### `Task::new(entry)`

Allocates a stack, maps it via `paging::map_range`, and builds a fake initial
stack frame so that when `context_switch` restores registers and returns, it
jumps to `entry`. The trampoline frame enables interrupts on the new task's
first run.

## Context Switch (`switch.rs`)

`context_switch(prev_rsp_ptr, next_rsp)` is written in inline assembly. It:

1. Pushes all callee-saved registers onto the current stack.
2. Writes `RSP` to `*prev_rsp_ptr`.
3. Loads `next_rsp` into `RSP`.
4. Pops the callee-saved registers from the new stack.
5. Returns — which enters the new task at its saved return address.

For a brand-new task this return address is the trampoline; for a previously
preempted or parked task it is the instruction after the call to
`context_switch` inside `preempt_tick` or `block_current`.

## Public API

### `task::init()`

Wraps the current thread as the bootstrap task. Must be called once after
`mem::init()` (stacks are mapped via `paging::map_range`). Safe to run
either before or after interrupts are enabled: `preempt_tick` short-
circuits on `sched.current.is_none()`, so a stray PIT tick that arrives
before the bootstrap task exists simply returns. Integration tests
initialize tasks first and then enable IRQs; `main.rs` does the reverse
for historical reasons and both work.

### `task::spawn(entry: fn() -> !)`

Allocates a new task and appends it to the ready queue. The task does not run
until the scheduler reaches it.

### `task::block_current()`

Park the current task until a matching `wake(id)` fires. Used exclusively
by the `sync` primitives; callers register themselves with a wakeup source
(e.g. push their id onto a `WaitQueue`) before calling.

1. Disable IRQs.
2. Under the `SCHED` lock, check the task's `wake_pending` flag. If set,
   clear it and return without parking — this closes the wake-before-park
   race.
3. Otherwise, pop the next task from `ready`, move `current` into
   `parked` keyed by its id, make the popped task `current`.
4. Release the lock, then call `context_switch`.
5. Restore the IRQ state of the caller on return.

Panics if `ready` is empty — blocking the sole runnable task would halt
the kernel. Integration tests always keep the bootstrap task alive.

### `task::wake(id)`

Transition a parked task back to `ready`, or — if the target is still
Running or Ready — set its `wake_pending` flag so its next
`block_current` returns immediately. Task-context only: acquires the
same `SCHED` lock that `preempt_tick` takes with `try_lock`, so calling
from an ISR risks deadlock. If an IRQ needs to wake a task, defer
through a lock-free queue drained by a kernel task (see
`kernel/src/input.rs` for the pattern).

### `task::preempt_tick()`

Called from the timer ISR (with IRQs already masked by the interrupt gate):
- `try_lock` the scheduler — bail on contention so the ISR never blocks.
- Decrement `slice_remaining_ms` by `TICK_MS`. If it reaches zero and a ready
  task exists, rotate and call `context_switch`.

### `task::find_stack_overflow(addr) -> Option<usize>`

Lock-free check: given a fault address, determine whether it falls inside a
kernel task's guard page. Returns the slot index (zero-based) if so. Called
from the `#PF` and `#DF` exception handlers.

## Constants

| Constant | Value | Meaning |
|---|---|---|
| `DEFAULT_SLICE_MS` | 10 | Preemption time slice per task |
| `GUARD_SIZE` | 4096 | Guard page size (one 4 KiB page) |
| `STACK_SIZE` | 16 KiB | Usable kernel stack per task |
| `TASK_SLOT_SIZE` | `GUARD_SIZE + STACK_SIZE` | VA bytes reserved per task |
| `TASK_STACKS_VA_BASE` | (higher-half) | Base VA for the task stack window |

## Limitations

- Single-CPU only; no SMP or per-CPU runqueues.
- No task priorities — pure round-robin.
- No per-task address spaces — all tasks share the kernel PML4.
- No task exit — spawned tasks must park on `hlt` forever once done.