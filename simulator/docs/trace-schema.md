# Simulator trace JSON schema

This document is the stable contract for the JSON output of
`simulator::Trace::to_json` (RFC 0006, issue #717). Downstream
consumers — the future `replay` binary, CI artefact viewers,
property-test harnesses written against frozen failing seeds, and the
`auto-engineer` review tooling — parse against this schema. **Adding,
removing, or renaming any variant or field below is a `schema_version`
bump**, and a bump is a breaking change for those consumers.

## Top-level shape

```json
{
  "schema_version": 1,
  "records": [
    { "tick": 0, "event": { "type": "tick_advance", "from": 0, "to": 1 } }
  ]
}
```

- `schema_version` is the integer version of this schema. The current
  version is **1**. The parser refuses to deserialize an object whose
  `schema_version` does not match the version it was compiled against.
- `records` is a JSON array of `(tick, event)` pairs in emission order.
  Emission order is the order the simulator's run loop produced them
  on the recording thread. Reorder is not legal.

## Record shape

Every record is a JSON object with exactly two fields, in this order:

| field   | type     | meaning                                                |
| ------- | -------- | ------------------------------------------------------ |
| `tick`  | `u64`    | Value of `MockClock::now()` when the event was emitted |
| `event` | `object` | The event itself (variant tag in `type`)               |

Field ordering inside every object is fixed (`tick` then `event`); the
encoder emits no whitespace beyond a single space after each `:` and
`,`. This is what makes the round-trip property
*record → JSON → parse → re-record → byte-identical JSON* hold.

## Event variants

All events use a discriminator-tag layout — a `type` field whose
string value selects the variant — and a fixed field order matching
the corresponding Rust enum variant declaration order in
`simulator::trace::Event`.

### `tick_advance`

The mock clock advanced by one tick. Emitted before any wakeups for
the destination tick are drained, so a reader can correlate the new
`now` value with the wakeup list that follows.

```json
{ "type": "tick_advance", "from": 0, "to": 1 }
```

| field  | type  | meaning                          |
| ------ | ----- | -------------------------------- |
| `from` | `u64` | Tick value before the advance.   |
| `to`   | `u64` | Tick value after the advance.    |

### `timer_injected`

A virtual timer IRQ was injected by the simulator. Distinct from
`fault_injected` — that variant covers FaultPlan-driven IRQs and
faults landed by future #722 work.

```json
{ "type": "timer_injected" }
```

No payload fields.

### `timer_irq_acked`

The simulator acked the just-injected timer IRQ via the
`TimerIrq::ack_timer` seam method.

```json
{ "type": "timer_irq_acked" }
```

No payload fields.

### `wakeup_enqueued`

A wakeup was enqueued for `deadline`, naming task `id`. **Snapshot-
derived in v1**: the simulator does not synthesize `enqueue_wakeup`
calls, so this variant is currently never emitted by the live run
loop. Defined here so consumers parsing a trace from a future kernel
build (after #718's `sched_mock_trace!` macro lands the enqueue emit
point) can already speak the schema.

```json
{ "type": "wakeup_enqueued", "deadline": 12, "id": 7 }
```

| field      | type  | meaning                                            |
| ---------- | ----- | -------------------------------------------------- |
| `deadline` | `u64` | Tick at which the wakeup is scheduled to fire.     |
| `id`       | `u64` | Task id whose wakeup was enqueued.                 |

### `wakeup_fired`

A task became runnable because its deadline expired and the seam
returned its id from `drain_expired`. One event per drained id, in
the order the seam returned them.

```json
{ "type": "wakeup_fired", "id": 7 }
```

| field | type  | meaning                          |
| ----- | ----- | -------------------------------- |
| `id`  | `u64` | Task id whose deadline fired.    |

### `task_scheduled`

A task was scheduled onto a CPU (one event per dispatch). Populated
by #718's emit point on the scheduler dispatch path; not yet emitted
by the live run loop.

```json
{ "type": "task_scheduled", "id": 7 }
```

| field | type  | meaning                          |
| ----- | ----- | -------------------------------- |
| `id`  | `u64` | Task id that was scheduled.      |

### `task_blocked`

A task entered the blocked state. Populated by #718's emit point on
`sleep_ms` / `wait_event` / I/O block paths; not yet emitted by the
live run loop.

```json
{ "type": "task_blocked", "id": 7, "reason": "sleep" }
```

| field    | type     | meaning                                       |
| -------- | -------- | --------------------------------------------- |
| `id`     | `u64`    | Task id that blocked.                         |
| `reason` | `string` | One of `sleep`, `wait`, `io`, `other`.        |

### `syscall`

A syscall was entered. Populated by #718's emit point at the syscall
handler entry. `args` carries up to four register-passed argument
words — the SysV AMD64 syscall ABI uses six, but four covers every
syscall modeled by the v1 invariant set; truncating here keeps the
JSON small without losing information for the v1 flake catalogue.

```json
{ "type": "syscall", "nr": 60, "args": [1, 2, 3, 4] }
```

| field  | type        | meaning                                                  |
| ------ | ----------- | -------------------------------------------------------- |
| `nr`   | `u64`       | Syscall number (Linux-compatible numbering on x86_64).   |
| `args` | `[u64; 4]`  | First four argument registers, exactly four entries.     |

### `fault`

A CPU exception fired in user or kernel context. Populated by #718's
exception-trampoline emit point. `cr2` is only meaningful for
`page_fault`; carry zero for the others.

```json
{ "type": "fault", "kind": "page_fault", "rip": 4198400, "cr2": 32 }
```

| field  | type     | meaning                                                              |
| ------ | -------- | -------------------------------------------------------------------- |
| `kind` | `string` | One of `page_fault`, `general_protection`, `invalid_opcode`, `double_fault`, `other`. |
| `rip`  | `u64`    | Faulting instruction pointer.                                        |
| `cr2`  | `u64`    | Page-fault address (zero for non-page-fault kinds).                  |

### `fault_injected`

The simulator's FaultPlan injected a fault before the kernel observed
it. Distinct from `fault` so invariant checkers can correlate "we
asked for a fault" with "the kernel saw a fault." Populated by #722's
FaultPlan landing.

```json
{ "type": "fault_injected", "kind": "page_fault" }
```

| field  | type     | meaning                                              |
| ------ | -------- | ---------------------------------------------------- |
| `kind` | `string` | Same enum as `fault.kind`.                           |

## Parser strictness

The parser in `simulator::trace::Trace::from_json` enforces:

1. Exact `schema_version` match. Mismatch → `Err`.
2. Closed enum sets for `task_blocked.reason`, `fault.kind`, and
   `fault_injected.kind`. Unknown strings → `Err`.
3. Closed `event.type` set. Unknown event types → `Err`.
4. No string escapes (no `\n`, `\u0041`, etc.). The encoder never
   emits them; accepting them in the parser would mean two distinct
   strings could decode to the same `BlockReason` / `FaultKind`,
   breaking the byte-equality property of the round-trip test.
5. No trailing bytes after the closing `}`.

## Round-trip property

For every trace `T`:

```
let json = T.to_json_string();
let T2 = Trace::from_json(&json).unwrap();
assert_eq!(T.records(), T2.records());
assert_eq!(json, T2.to_json_string());
```

The simulator's CI gates on this property over a 200-tick smoke run
that exercises every variant currently emitted by the run loop, plus a
unit-test trace that exercises every variant in the schema. Variants
that are not yet emitted (`wakeup_enqueued`, `task_scheduled`,
`task_blocked`, `syscall`, `fault`, `fault_injected`) ride the
unit-test path until #718 / #722 wires them into the live run loop.

## Capacity bound

A trace constructed with `Trace::with_capacity_limit(N)` evicts its
oldest record once it holds `N` records, and emits a one-shot stderr
warning the first time eviction fires. The on-wire JSON does not
record the eviction event — a parsed trace is always unbounded, by
design: the use case for `from_json` is round-trip equivalence and the
future `replay` binary, neither of which want eviction firing on
parse.
