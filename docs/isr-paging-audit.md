# ISR-reachable paging audit

Tracks every function reachable from interrupt / exception context and
classifies the synchronisation primitives it touches. The north star is
that **no ISR-reachable path may acquire a `BlockingMutex` or a
`BlockingRwLock`** — those primitives park the caller on a `WaitQueue`,
and an ISR has nowhere safe to park (no task context, and it may have
interrupted a thread that already holds the very lock it wants). An
accidental blocking-lock acquisition on an ISR path produces a
silent deadlock the first time the primitive is ever contended.

Origin: issue #306 (follow-up to #147, whose item 1 was resolved by #305
moving the reaper off the timer ISR).

## Entry points

Every vector installed in `kernel/src/arch/x86_64/idt.rs` plus the three
hardware IRQs wired in `kernel/src/arch/x86_64/interrupts.rs`:

| Vector | Handler | File | Notes |
|---|---|---|---|
| #DE | `divide_error` | `arch/x86_64/idt.rs` | log + hang; no lock acquisitions |
| #UD | `invalid_opcode` | `arch/x86_64/idt.rs` | log + hang |
| #GP | `general_protection` | `arch/x86_64/idt.rs` | log + hang |
| #DF | `double_fault` | `arch/x86_64/idt.rs` | runs on IST stack; log + hang |
| #PF | `page_fault` | `arch/x86_64/idt.rs` | resolver — primary audit target |
| IRQ 0 (timer) | `timer_interrupt` | `arch/x86_64/interrupts.rs` | EOI + `preempt_tick` |
| IRQ 1 (keyboard) | `keyboard_interrupt` | `arch/x86_64/interrupts.rs` | `push_scancode_from_isr` + EOI |
| IRQ 4 (serial) | `serial_interrupt` | `arch/x86_64/interrupts.rs` | `drain_rx_hardware` + EOI |

The non-#PF CPU exceptions all terminate in `hang()` and touch no
shared state; they are trivially safe and excluded from the lint.

## #PF call chain

The `page_fault` handler is the only exception that resolves rather
than hangs, so it has the largest reachable surface:

* `crate::test_hook::take_page_fault_expectation` — `AtomicU64::swap`; lock-free.
* `crate::mem::pf::is_smap_violation` / `is_rsvd_fault` / `is_user_va` — pure predicates.
* `crate::task::current_vma_lookup` — takes `SCHED.try_lock()` then `address_space.try_write()`, both `try_*`. Contention returns `None`; the handler falls through without touching further state.
* `crate::task::current_growsdown_lookup` — same `try_*` discipline.
* `crate::mem::paging::map_existing_in_pml4` — takes `MAPPER.lock()` (spin). May recurse into frame allocator (`frame::global()`, spin) if it needs a new page-table frame.
* `crate::mem::paging::cow_copy_and_remap` — same set of spin locks, plus `refcount::dec_refcount` on the old frame and `VmObject::fault` for the new one.
* `VmObject::fault` impls (`AnonObject`, etc.) — per-object state; no global locks.
* `crate::task::find_stack_overflow` — reads atomics.
* `crate::signal::deliver_fault_signal_iret` → `process::with_signal_state_for_task` → `process::mark_zombie` → `task::exit`. `task::exit` drops the current task's `Arc<RwLock<AddressSpace>>` reference; if this is the last reference the drop can call into `unmap_in_pml4` while still on the #PF frame, which in turn takes `MAPPER.lock()` (spin). See "Known gap 1" below.

## Timer / keyboard / serial call chains

* `timer_interrupt` → `time::on_tick` (atomics) → `notify_eoi` (PIC I/O) → `task::preempt_tick` → `SCHED.try_lock()` (spin; bails on contention). Also wakes the reaper `WaitQueue` if there are victims; `WaitQueue::wake_one` takes `SCHED.lock()`.
* `keyboard_interrupt` → `input::push_scancode_from_isr` (ring buffer behind a spin lock).
* `serial_interrupt` → `serial::drain_rx_hardware` (port I/O + spin-locked ring buffer).

## Lock inventory

Every global lock reachable from ISR context today, with the primitive
it uses:

| Symbol | File | Primitive | ISR-safe? |
|---|---|---|---|
| `MAPPER` | `mem/paging.rs:53` | `spin::Mutex` | yes (doesn't park) |
| `HHDM_OFFSET` | `mem/paging.rs:58` | `spin::Mutex` | yes |
| `LIMINE_PML4_PHYS` | `mem/paging.rs:63` | `spin::Mutex` | yes |
| `SCHED` | `task/mod.rs:65` | `spin::Mutex` | yes |
| `REAPER_VICTIMS` | `task/mod.rs:76` | `spin::Mutex` | yes |
| `frame::global()` | `mem/frame.rs` | `spin::Mutex` | yes |
| Per-task `address_space` | `Arc<spin::RwLock<AddressSpace>>` | `spin::RwLock` | yes (accessed via `try_write` from #PF) |
| `input` scancode ring | `input.rs` | `spin::Mutex` | yes |
| `serial::rx_ring` | `serial.rs` | `spin::Mutex` | yes |

No `BlockingMutex` or `BlockingRwLock` is reachable from any ISR
today. Every `BlockingMutex` site we have lives under `fs/vfs` —
inode state, open-file offsets, ramfs/tarfs bookkeeping — and the VFS
is not reached from any interrupt handler.

## Classification summary

* **Safe today.** All ISR-reachable locks are `spin::Mutex` or
  `spin::RwLock`. Spin locks never park, so no task can sleep holding
  one, so an interrupted holder will resume and release within a bounded
  time window.
* **Safe-via-routing.** The reaper worker (#305) is the canonical escape
  hatch for work that *would* need to block: enqueue on the spin-locked
  `REAPER_VICTIMS`, wake the reaper task, return from the ISR.
* **Dangerous.** None, as of this audit.

## Known gaps and future work

1. **`task::exit` from `#PF` drops the `AddressSpace` synchronously.**
   The last `Arc` reference drop walks the VMA tree and calls into
   `unmap_in_pml4`, which takes `MAPPER.lock()` (spin). That's fine
   today — `MAPPER` is spin — but if `MAPPER` ever migrates to
   `BlockingMutex` (see #314) this path will deadlock. Fix: route the
   final drop through the reaper, the same way task stack freeing is
   routed.
2. **Planned `spin::Mutex` → `IrqLock` migrations** tracked in #314 and
   #313. Those preserve ISR safety; the audit stays correct through
   that migration.
3. **Planned `spin::Mutex` → `BlockingMutex` migrations** would make
   new paths dangerous. The lint in `xtask/src/isr_audit.rs` is the
   guard rail: if anyone adds a blocking-lock acquisition to an
   ISR-reachable file it fails `cargo xtask lint`.

## Regression guard

`xtask/src/isr_audit.rs` scans a curated set of ISR-reachable source
files for:

* Any bare `BlockingMutex::new(` or `BlockingRwLock::new(` construction.
* Any `BlockingMutex<` or `BlockingRwLock<` type mention (field, return,
  static).

Either match fails the lint. The file allowlist lives in `isr_audit.rs`
and must be refreshed when the reachable surface grows — if this audit
doc and the lint disagree, the doc is authoritative; update both.

The lint runs as part of `cargo xtask lint`, which is a CI gate, so new
PRs that introduce blocking-lock acquisitions on ISR paths fail before
merge.

### Refreshing the allowlist

When a new ISR entry point lands or an existing handler gains a new
helper crate path:

1. Trace the reachable call chain by hand (start at the vector handler,
   follow every non-`try_*` function call).
2. Add every new reachable file to `ISR_REACHABLE_FILES` in
   `xtask/src/isr_audit.rs`.
3. Update the "Entry points" and "#PF call chain" sections above.
4. Re-run `cargo xtask lint` locally to confirm the lint still passes.
