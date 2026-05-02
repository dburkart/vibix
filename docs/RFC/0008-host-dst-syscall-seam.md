# RFC 0008: Host-side DST syscall-entry seam

| Status   | Accepted (Phase 2.1)                          |
|----------|-----------------------------------------------|
| Authors  | dburkart                                      |
| Driver   | [#790](https://github.com/dburkart/vibix/issues/790) |
| Parent   | [RFC 0006](0006-host-dst-simulator.md) §"Failure-injection scope" / §"Open questions" |
| Sibling  | [`docs/design/dst-478-investigation.md`](../design/dst-478-investigation.md) (Phase 2.1 RFC #1, #3) |

## Motivation

[#721](https://github.com/dburkart/vibix/issues/721) shipped the v1
seam-level regression for the [#501](https://github.com/dburkart/vibix/issues/501)
fork/exec/wait flake (`simulator/tests/regression_501.rs`). That
regression models the parent's `wait4` wakeup and the child's
`mark_zombie` exit-notify wakeup as two `MockClock::enqueue_wakeup`
entries at the same deadline; `FaultEvent::WakeupReorder` permutes the
drain order. The captured `(seed=14, FaultPlan)` reproduces a
seam-level analogue of #501 deterministically.

What the seam-level regression does **not** do: exercise the kernel's
real `sys_fork` / `sys_execve` / `sys_wait4` handlers. Those live in
`kernel/src/arch/x86_64/syscall.rs::syscall_dispatch` under
`cfg(target_os = "none")` because the SYSCALL trampoline pulls
FxSAVE / `swapgs` / IRETQ / kernel-stack-swap state that has no host
analogue. RFC 0006 §"Failure-injection scope" deferred the
syscall-entry seam to Phase 2.1 RFC #2 with the trade-off: *"a faked
syscall driver is feasible but is its own design — which calling
convention does the simulator pretend to use? how does it resolve
user pointers?"*

This RFC answers those questions and lands the seam.

## Surface

Three deliverables make up the seam, all in
`simulator/src/syscall_seam.rs`:

```rust
pub trait UaccessAdapter: Send + Sync {
    fn check_user_write(&self, dst: usize, len: usize) -> Result<(), i64>;
    unsafe fn copy_from_user(&self, dst: &mut [u8], src: usize) -> Result<(), i64>;
    unsafe fn copy_to_user(&self, dst: usize, src: &[u8]) -> Result<(), i64>;
}

pub struct HostUaccess;
impl UaccessAdapter for HostUaccess { /* dereference + range-check */ }

pub unsafe fn dispatch_syscall(nr: u64, args: [u64; 6], ua: &dyn UaccessAdapter) -> i64;

pub fn install_init_process(task_id: usize);
pub fn set_current_task_id(task_id: usize) -> usize;
```

`check_user_write` is the **preflight validator** the bare-metal
`WAIT4` arm already has at its entry (`uaccess::check_user_range(wstatus_ptr, 4)`).
The host arm needs the same shape so a custom `UaccessAdapter` that
returns `-EFAULT` on a bad pointer cannot lose the zombie:
without the preflight, the dispatch shim would call `reap_child()`
first, consume the exit status, then fail at `copy_to_user`, leaving
a phantom-collected child.

Recognised numbers: `FORK` (57), `EXECVE` (59), `EXIT` (60), `WAIT4`
(61). Anything else returns `-ENOSYS` (`-38`).

The dispatch arms route to host-side wrappers around the kernel's
real `process::register` / `process::mark_zombie` /
`process::reap_child` / `process::has_children` /
`process::reparent_children` / `process::exit_event_count` /
`process::CHILD_WAIT.wait_while`. Those reach unchanged from
`kernel/src/process/mod.rs` — including the [#710] atomic-publish
fix (PR [#795]) — because `process` is now host-buildable under
`feature = "sched-mock"` (RFC 0008 §"Slim host arm").

[#710]: https://github.com/dburkart/vibix/issues/710
[#795]: https://github.com/dburkart/vibix/pull/795

## User-pointer model — design choice

Two options were on the table from RFC 0006:

(a) **Plumb host-allocated buffers through the dispatch shim's args**
   and have the shim adapt by-reference args to the kernel's
   pointer-arg shape. Each user-pointer argument grows a sibling
   `&[u8]` in the dispatch signature; `dispatch_syscall` translates
   between the two.

(b) **`UaccessAdapter` trait** — a host-only abstraction the kernel's
   `copy_from_user` / `copy_to_user` callers go through, with a host
   impl that just dereferences after a range check.

**This RFC picks (b).** Rationale:

1. **Kernel call sites stay unchanged.** The bare-metal
   `copy_from_user` / `copy_to_user` retain their `(usize, &mut [u8])`
   shape. (b) routes the host arm through the trait at the *adapter*
   layer rather than mutating every syscall arm to accept a sibling
   buffer slot.

2. **Future Phase 2.1 surfaces plug in cleanly.** The page-fault
   injection seam (RFC 0006 §"Open questions" / `docs/design/dst-478-investigation.md`)
   and the ring-3 trap-frame seam both need their own user-pointer
   adaptation: the page-fault seam wants pointer dereferences to
   surface `Event::FaultInjected { kind: PageFault }` records when
   the simulator has armed a fault at that VA; the trap-frame seam
   wants reads to come out of a synthetic ring-3 mapping. Each of
   those is its own `impl UaccessAdapter for …`. With (a), each
   would have to re-cut the dispatch signature.

3. **The trait surface stays narrow.** Today `UaccessAdapter`
   exposes only the byte-buffer `copy_*_user` shape — no typed
   accessors, no `check_user_range`. The wait4 rendezvous is the
   only host caller, and it copies one `u32` (the encoded
   `wstatus`). When a future seam needs typed accessors, that's a
   new method on the trait, not a redesign.

The `HostUaccess` impl is twelve lines: range-check `ptr != 0`,
loop, `core::ptr::read` / `core::ptr::write` for each byte. No SMAP,
no CR3 swap — those have no host analogue.

## Slim host arm — kernel-side cfg gates

The simulator calls into `kernel::process::*` and
`kernel::sync::WaitQueue` for the wait4 rendezvous, plus
`kernel::task::current_id` / `wake` / `block_current` so
`WaitQueue::wait_while` can compile. None of those modules were
host-buildable before this RFC (every one was gated to
`cfg(target_os = "none")`).

The minimum cfg-extension needed:

| Module | Old gate | New gate | Notes |
|--------|----------|----------|-------|
| `process` | `target_os = "none"` | `any(target_os = "none", feature = "sched-mock")` | tty/signal helpers gated to bare-metal via `bare_metal_only!` macro inside the file; the wait4 rendezvous + signal-state-accessor are host-buildable |
| `signal` | `target_os = "none"` | `any(target_os = "none", feature = "sched-mock")` | `frame.rs`, `arch::x86_64::uaccess` use, every signal-delivery / restart-decision / sigaction syscall is gated to bare-metal via `bare_metal_only!` macro; only `SignalState` + sig number constants + `Disposition` are host-buildable |
| `sync` | `target_os = "none"` | `any(target_os = "none", feature = "sched-mock")` | `WaitQueue` is host-buildable; every other primitive (`BlockingMutex`, `BlockingRwLock`, `Semaphore`, `spsc`, `mpmc`, `IrqLock`) stays bare-metal-only inside `sync/mod.rs` |
| `task` | `target_os = "none"` | (mostly unchanged) | `host_stub` submodule under `cfg(all(not(target_os = "none"), feature = "sched-mock"))` exposes `current_id` / `wake` / `block_current` |

The host arm of `ProcessEntry` elides the `controlling_tty` field
(it's `cfg(target_os = "none")`); session_id / pgrp_id are kept as
plain `u32` (the bare-metal arm aliases them through `tty::SessionId`
/ `tty::ProcessGroupId`, both of which are themselves `pub type … = u32`).

## Single-thread parking semantics

`WaitQueue::wait_while` calls `task::current_id`, enqueues self,
checks `cond()`, then calls `task::block_current`. On bare metal
`block_current` parks the task and the scheduler picks another;
`mark_zombie`'s `notify_all` later pops the parked task off the queue
and calls `task::wake`, which unparks it.

On host with `sched-mock` there is no second thread to schedule. The
host stub for `block_current` is a no-op that consumes the
`wake_pending` flag; `task::wake` sets the flag if the target id
matches the current id. The wait4 caller's `wait_while` predicate is
`|| process::exit_event_count() == snap`. Two cases:

1. **Child exits before parent waits** (the simulator's typical
   single-thread dispatch order at `T_EXIT`). Parent calls `wait4`,
   takes its `snap`, calls `reap_child` and gets `Some(child)`. Never
   reaches `wait_while`. `block_current` is never called.

2. **Parent enters `wait_while` before child has exited.** Predicate
   is true (`exit_event_count` still equals `snap`), parent enqueues
   on `CHILD_WAIT`, drops the queue lock, calls the host stub
   `block_current` (which clears `wake_pending` and returns), then
   re-locks the queue and removes its stale self-entry. Loops back,
   re-checks `cond()` — still true, since child hasn't exited yet.
   Spins forever.

Case 2 is **not modelled** by the host shim. The simulator's run
loop is single-threaded by construction (RFC 0006 §"The driver
loop"); a layered test that requires the parent to park and the
child to wake from a different thread would need a multi-threaded
host runtime, which is out of scope for v1. The layered repro in
`simulator/tests/regression_501.rs` is structured to dispatch
`sys_exit` (child) **before** `sys_wait4` (parent) at `T_EXIT`,
which guarantees case 1 and exercises the full
`mark_zombie`/`reap_child`/`exit_event_count` code path without
needing case 2.

## Layered repro

`simulator/tests/regression_501.rs::layered_repro_real_handlers_pass_under_fixed_mark_zombie`
is the sister test the issue body asks for. It:

1. Constructs a `Simulator` with the captured `(seed=14, FaultPlan)`.
2. Calls `install_init_process(1)` to prime PID 1.
3. At `T_FORK`: dispatches `sys_fork`, captures the returned child
   PID + child task id.
4. At `T_EXEC`: switches the simulator's "current task id" to the
   child, dispatches `sys_execve` (host stub returns 0).
5. At `T_EXIT`: dispatches `sys_exit(7)` — calls `mark_zombie`
   under TABLE, bumps `EXIT_EVENT.fetch_add(1, Release)`, drops
   TABLE, calls `CHILD_WAIT.notify_all`. Then switches back to the
   parent, dispatches `sys_wait4(-1, &wstatus)` — runs the
   snapshot-and-park loop, reaps the zombie, encodes `wstatus`
   through `HostUaccess::copy_to_user`.
6. Asserts `wait4` returned the child PID and the encoded `wstatus`
   matches `(7 & 0xFF) << 8 = 0x700`.

**Acceptance**: under the captured plan, the v1 seam-level invariant
(`child_exit_observed_before_parent_wake`) does NOT trip. This is
expected: the [#710] atomic-publish fix collapses the drain-order
window the seam-level test still detects via `WakeupReorder`. If
this layered test were ever to fail, the #710 fix would be
incomplete and `mark_zombie` would need another look.

## Coverage for the seam itself

Three layers of regression catch a future regression of the seam:

1. `simulator/src/syscall_seam.rs::tests` (host unit tests) —
   `numbers_match_kernel_table`, `host_uaccess_round_trips`,
   `host_uaccess_rejects_null`, `unrecognised_syscall_returns_enosys`.
2. `simulator/tests/regression_501.rs::layered_repro_baseline_no_faults_also_passes`
   — sanity: the layered scenario completes under the empty plan
   too. Catches a regression where the layered shape itself breaks
   independently of fault injection.
3. `simulator/tests/regression_501.rs::layered_repro_real_handlers_pass_under_fixed_mark_zombie`
   — the captured `(seed=14, FaultPlan)` test. Catches both a
   regression of the [#710] fix and a regression of the seam's
   wait4 dispatch wiring.

The seam-level test (`captured_seed_and_plan_reproduce_501_deterministically`)
remains as the trace-level analogue — it asserts the v1 surface
itself still detects drain-order-dependence at `T_EXIT`.

## Out of scope

- `sys_execve` image swap. Host stub returns 0 unconditionally.
  Would need `mem::userspace_hello`, `AddressSpace`, `Cr3::write`
  to all be host-buildable — none of those are in v1.
- `sys_kill` / signal delivery. The full signal-mask /
  signal-frame / sigaction layer stays bare-metal-only.
- Multi-thread wait4 (case 2 above). Requires a multi-threaded host
  runtime; tracked as a follow-up.
- The bare-metal `current_pid` IF=1 invariant
  (`debug_assert!(is_if_set())`). Host stub for `is_if_set` returns
  `true` because the host has no real RFLAGS.IF state; the
  invariant is bare-metal-only.
- Per-test TABLE isolation **as a deliberate dependency on
  `panic-abort-tests`**. The host arm of `process::TABLE` is a
  process-global `Lazy<Mutex<Table>>` (and `NEXT_PID` is a
  process-global `AtomicU32`). The workspace's `.cargo/config.toml`
  sets `[unstable] panic-abort-tests = true` (see `kernel/Cargo.toml`
  comment) so every `#[test]` runs in its own subprocess. That
  side-effect provides per-test TABLE isolation for free: each
  layered test gets a fresh kernel-static TABLE / `NEXT_PID = 2`,
  so the layered repro can assert `wait4_rv == 2` (child PID 2)
  without an explicit reset hook. If `panic-abort-tests` ever flips
  off, the layered tests will start cross-contaminating; an explicit
  `simulator::reset_kernel_state_for_test()` accessor is the
  follow-up that closes that hole.

  **Defence in depth: `seam_lock`.** Independently of
  `panic-abort-tests`, the seam takes a process-global
  `OnceLock<Mutex<()>>` at every entry through `install_init_process` /
  `dispatch_syscall` / `set_current_task_id`. Two concurrent host
  threads serialize through that lock rather than racing on the
  kernel-static TABLE. The lock answers CodeRabbit's pre-merge
  concern about "host runs aliasing each other in `process::pid_of` /
  `current_pid`" — parallel runs will still observe each other's
  TABLE entries (the lock alone doesn't reset state), but they will
  not race; combined with `panic-abort-tests` providing per-test
  subprocess isolation, deterministic per-run state holds.

## References

- [#790](https://github.com/dburkart/vibix/issues/790) — this RFC's driver
- [#501](https://github.com/dburkart/vibix/issues/501) — source flake
- [#710](https://github.com/dburkart/vibix/issues/710) /
  [#795](https://github.com/dburkart/vibix/pull/795) — atomic-publish fix
- [#721](https://github.com/dburkart/vibix/issues/721) — seam-level regression
- [RFC 0005](0005-scheduler-irq-seam.md) — `MockClock` / `MockTimerIrq` seam
- [RFC 0006](0006-host-dst-simulator.md) — host-side simulator
- [`docs/design/dst-478-investigation.md`](../design/dst-478-investigation.md) — Phase 2.1 RFC #1 / #3 (page-fault + ring-3 trap-frame seams)
