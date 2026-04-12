# Task Subsystem

**Sources:** `kernel/src/task/`
- `mod.rs` — public API, `init`, `spawn`, `yield_now`, `preempt_tick`
- `task.rs` — `Task` struct: kernel stack allocation, saved register context
- `scheduler.rs` — `Scheduler`: current task + FIFO ready queue
- `switch.rs` — `context_switch` in hand-written assembly

## Overview

The task subsystem implements cooperative and preemptive kernel-mode
multitasking. Tasks are kernel threads — they share the kernel address space
and run entirely in ring 0. Each task has its own kernel stack and a saved
register context that `context_switch` restores on re-entry.

There is no userspace, no per-task address space, and no blocking primitives.
Cooperative code yields explicitly; the PIT timer drives preemption.

## Design

### Scheduler State

A single `Lazy<Mutex<Scheduler>>` holds:
- `current: Option<Box<Task>>` — the running task, `None` before `task::init`.
- `ready: VecDeque<Box<Task>>` — FIFO queue of ready-to-run tasks.

### Task Struct

Each `Task` contains:
- A mapped kernel stack region (via `paging::map_range`, see constants below).
- An unmapped guard page at the base of the stack.
- `rsp: usize` — the saved stack pointer, updated by `context_switch`.
- `slice_remaining_ms: u32` — remaining preemption budget in milliseconds.

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
preempted or yielded task it is the instruction after the call to
`context_switch` inside `yield_now` or `preempt_tick`.

## Public API

### `task::init()`

Wraps the current thread as the bootstrap task. Must be called once, after
`mem::init()` (stacks are mapped via `paging::map_range`) and after interrupts are enabled (so
preemption ticks can arrive).

### `task::spawn(entry: fn() -> !)`

Allocates a new task and appends it to the ready queue. The task does not run
until the scheduler reaches it.

### `task::yield_now()`

The cooperative yield point:
1. Disable IRQs to prevent the timer ISR from re-entering the scheduler.
2. Under the `SCHED` lock, pop the next task from `ready`, move `current` to
   the back of `ready`, make the popped task `current`.
3. Release the lock, then call `context_switch`.
4. Restore the IRQ state of the caller on return.

If `ready` is empty, `yield_now` returns immediately (the running task keeps
the CPU).

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
- No blocking primitives — sleeping tasks must poll and yield.
- No per-task address spaces — all tasks share the kernel PML4.