# Issue prioritization playbook

This playbook defines the label taxonomy used across the vibix issue tracker and the rules
agents follow when triaging new issues or picking the next one to work on.

The north star is a **minimal useful kernel** — the earliest point at which vibix can load
a real userspace program off disk, drop it to ring 3, and service its syscalls. Everything
P0 exists to unblock that moment; everything else is ordered by how directly it supports the
four post-userspace milestones: userspace, filesystem, terminal, POSIX readiness.

## Label taxonomy

Every tracked issue should carry exactly one `priority:*` label and at least one `area:*`
label. `track:*` labels are optional and mark alignment to a named milestone.

### Priority — usefulness toward the minimal useful kernel

| Label | Meaning |
|---|---|
| `priority:P0` | On the critical path to the first useful userspace process. Blocks PID 1. |
| `priority:P1` | Required for POSIX readiness, real filesystem semantics, or a usable terminal. |
| `priority:P2` | Polish, quality-of-life, hardening — valuable but not blocking. |
| `priority:P3` | SMP, advanced hardware, optimization, benchmarks, long-term work. |

Pick the **highest** priority the issue honestly supports. When in doubt, go one step lower —
over-prioritizing P0 defeats the point of the ordering.

### Area — subsystem

`area:userspace`, `area:mem`, `area:fs`, `area:driver`, `area:console`, `area:smp`,
`area:debug`, `area:perf`, `area:security`, `area:time`. Multiple areas are fine when the
work genuinely spans subsystems (e.g. SMEP/SMAP is `area:security` + `area:mem`).

### Track — milestone alignment (optional)

| Label | What it marks |
|---|---|
| `track:userspace` | Required to land PID 1 loading `/init` from the ramdisk. |
| `track:filesystem` | Needed for real multi-level, writable, permission-aware filesystem. |
| `track:terminal` | Needed for a usable interactive shell/terminal experience. |
| `track:posix` | Needed for POSIX-compatible userspace (signals, threads, fd semantics, dynamic linking). |

An issue can carry more than one track label when it genuinely unblocks multiple milestones.

## P0 critical path (as of this writing)

The chain from today's kernel to PID 1 executing a statically-linked userspace binary:

1. **Discovery** — `#42` PCI enumeration.
2. **Storage** — `#43` virtio-blk driver + read-only ramdisk.
3. **Loading** — `#44` ELF64 loader (ring 0).
4. **Context safety** — `#115` x87/SSE/AVX save-restore on context switch (must land before
   any ring-3 task is allowed to run).
5. **Address-space plumbing** — `#132` task exit + resource reclaim; `#133` `VmaKind::Cow`
   + `VmaList::remove` (both required for fork and clean teardown).
6. **Process model** — `#123` process table + fork/exec/wait; `#124` per-process fd table;
   `#125` expanded syscall table (exit, read, open, close, mmap).
7. **Capstone** — `#121` PID 1 launches `/init` from the ramdisk.

Anything not on that chain is P1 or lower.

## Triage rules for new issues

When filing an issue (by hand or via an agent), the author must set labels before the issue
is considered triaged.

1. **Determine priority by asking, in order:**
   - Is it a CI flake, a build failure, or anything else that breaks the main branch's green
     status? → `priority:P0`. CI health is always P0 — flaky or broken CI stalls every
     auto-engineer and masks real regressions, so these jump to the front of the queue
     regardless of which subsystem they touch.
   - Does this block PID 1 loading and running a userspace binary? → `priority:P0`.
   - Is it required for POSIX readiness, a real FS, or a usable terminal? → `priority:P1`.
   - Is it a polish / hardening / QoL improvement on already-working code? → `priority:P2`.
   - Is it SMP, advanced hardware, optimization, or benchmarks? → `priority:P3`.
2. **Pick one or more areas** that match the subsystem boundaries in
   `docs/README.md`.
3. **Add a track label** only if the issue directly unblocks one of the four named
   milestones. Do not add speculative track labels.
4. **Cross-reference existing issues.** If the new issue is a follow-up of an open P0
   prerequisite, it almost certainly inherits that prerequisite's priority or lower. It
   rarely out-prioritizes the thing it depends on.
5. **Do not invent new priority or area labels.** If a new axis is genuinely needed, update
   this playbook in the same PR that introduces the label.

## Picking rules for agents

When an agent (auto-engineer, human, sub-skill) picks the next issue to work on, the
selection order is:

1. Filter to `state:open`, `no:assignee`, and **not** labeled `blocked`, `needs-discussion`,
   `question`, or `wontfix`.
2. Exclude issues whose body references an unresolved dependency (e.g. "blocked on `#NN`"
   where `#NN` is still open).
3. Sort the remainder by priority: `priority:P0` first, then `P1`, `P2`, `P3`. Issues with
   no priority label rank **after** `P3` — they are un-triaged and should be labeled before
   being worked.
4. Within a priority bucket, prefer issues with a `track:userspace` label, then
   `track:filesystem`, then `track:terminal`, then `track:posix`, then untracked.
5. Within an (priority, track) bucket, fall back to lowest-numbered first (oldest).

If the top candidate's prerequisites are all still open, move to the next candidate rather
than starting something that cannot land.

## Maintenance

This playbook — and the P0 critical path section specifically — goes stale as P0 work lands.
Whenever a P0 issue merges, the closing PR or the next triage pass should:

- Remove the merged item from the critical-path list above.
- Promote any `priority:P1` issue that now directly blocks the next P0 to `priority:P0`.
- If a new dependency is discovered, file it and label it immediately rather than letting it
  sit un-triaged.
