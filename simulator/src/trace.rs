//! `(Tick, Event)` trace stream — the simulator's primary observable.
//!
//! RFC 0006 §"State-machine model interface" calls the `(Tick, Event)`
//! stream out as the *external* surface every Phase 2 consumer
//! (`proptest`, `#390`'s stress runner, the `replay` binary, a human
//! grepping a CI-attached JSON trace) sees. Issue #717 lands the full
//! [`Event`] enum, the in-memory [`Trace`] container, and the stable
//! JSON schema (`schema_version = 1`) callers serialize against.
//!
//! ## Why a hand-rolled JSON encoder, not `serde_json`
//!
//! The simulator crate intentionally pulls *zero* transitive deps that
//! could reach `getrandom` / OS entropy (RFC 0006 §"Determinism
//! envelope") — see the `default-features = false` notes on
//! `rand_chacha` / `rand_core` in `simulator/Cargo.toml`. `serde_json`
//! itself is determinism-clean, but `serde`'s derive macros routinely
//! pick up `proc-macro2` / `quote` / `syn` and a default-features churn
//! during minor bumps that would force this crate onto a moving
//! transitive-dep target. The trace schema has eight enum variants and
//! at most three numeric fields per variant — the encoder fits in
//! ~120 lines, the parser in ~250, and both stay free of any dep that
//! could later sprout an entropy reader.
//!
//! The wire format is a strict subset of RFC 8259 JSON: ASCII-only
//! field names, integers up to `u64::MAX`, no floats, no arrays of
//! mixed type, no nested objects beyond `{ tick, event }`. Field
//! ordering inside every object is fixed and matches the
//! [`Event`] declaration order so byte-equality is preserved across
//! `record → JSON → parse → re-record`.
//!
//! ## Capacity bound
//!
//! Long-running invariant sweeps can drive the trace to millions of
//! records. RAM is bounded by the [`Trace::with_capacity_limit`]
//! constructor: once the limit is reached the oldest record is
//! evicted and a one-shot `eprintln!` warning fires. The default
//! constructor leaves the trace unbounded — callers that care about
//! RAM opt in deliberately.

use std::string::{String, ToString};

use vibix::task::env::TaskId;

/// Stable JSON schema version.
///
/// Bump when adding, removing, or renaming an [`Event`] variant or
/// field. Adding a new variant *and* preserving the existing variants'
/// wire shape is still a bump, because a downstream parser written
/// against schema_version=1 would now reject the new variant.
pub const SCHEMA_VERSION: u32 = 1;

/// Reason a task entered the blocked state.
///
/// Wire form: bare ASCII string (e.g. `"sleep"`). The set is
/// closed — adding a variant is a [`SCHEMA_VERSION`] bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BlockReason {
    /// Task is waiting for a sleep deadline to expire.
    Sleep,
    /// Task is waiting on a wait-queue / synchronization primitive.
    Wait,
    /// Task is waiting for I/O completion.
    Io,
    /// Reserved for unmodelled or future block reasons.
    Other,
}

impl BlockReason {
    fn as_wire(self) -> &'static str {
        match self {
            BlockReason::Sleep => "sleep",
            BlockReason::Wait => "wait",
            BlockReason::Io => "io",
            BlockReason::Other => "other",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "sleep" => Some(BlockReason::Sleep),
            "wait" => Some(BlockReason::Wait),
            "io" => Some(BlockReason::Io),
            "other" => Some(BlockReason::Other),
            _ => None,
        }
    }
}

/// Kind of fault observed or injected.
///
/// Wire form: bare ASCII string. Closed set; adding a variant is a
/// [`SCHEMA_VERSION`] bump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultKind {
    /// Page fault (`#PF`).
    PageFault,
    /// General-protection fault (`#GP`).
    GeneralProtection,
    /// Invalid-opcode fault (`#UD`).
    InvalidOpcode,
    /// Double fault (`#DF`).
    DoubleFault,
    /// Reserved for unmodelled or future fault kinds.
    Other,
}

impl FaultKind {
    fn as_wire(self) -> &'static str {
        match self {
            FaultKind::PageFault => "page_fault",
            FaultKind::GeneralProtection => "general_protection",
            FaultKind::InvalidOpcode => "invalid_opcode",
            FaultKind::DoubleFault => "double_fault",
            FaultKind::Other => "other",
        }
    }

    fn from_wire(s: &str) -> Option<Self> {
        match s {
            "page_fault" => Some(FaultKind::PageFault),
            "general_protection" => Some(FaultKind::GeneralProtection),
            "invalid_opcode" => Some(FaultKind::InvalidOpcode),
            "double_fault" => Some(FaultKind::DoubleFault),
            "other" => Some(FaultKind::Other),
            _ => None,
        }
    }
}

/// One observable transition recorded by the simulator.
///
/// The variant set is the full RFC 0006 §"State-machine model
/// interface" enum, named per issue #717. Variants split into two
/// classes by emit point (RFC 0006 §"Event emit points"):
///
/// **Driver-loop emitted** (populated today by [`crate::Simulator::step`]):
/// - [`Event::TickAdvance`] — clock advanced one tick.
/// - [`Event::TimerIrqAcked`] — virtual timer IRQ ack'd.
/// - [`Event::WakeupFired`] — a deadline drained; one event per
///   `(deadline, id)` returned by the seam.
///
/// **Snapshot-derived / kernel-emit-required** (defined here, not yet
/// populated; populated by #718's `sched_mock_trace!` macro and by
/// future invariant-checker snapshots):
/// - [`Event::WakeupEnqueued`], [`Event::TaskScheduled`],
///   [`Event::TaskBlocked`], [`Event::Syscall`], [`Event::Fault`],
///   [`Event::FaultInjected`].
///
/// `#[non_exhaustive]` per RFC 0006 §"Open questions resolution"
/// (UserSpace-A1): downstream consumers must `match _ =>` so adding a
/// variant is a non-breaking change at the type level; the JSON
/// schema_version still bumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// The mock clock advanced from `from` to `to`. Emitted before any
    /// wakeups for the destination tick are drained so a reader can
    /// correlate the new `now` value with the wakeup list that
    /// follows.
    TickAdvance {
        /// Tick value before the advance.
        from: u64,
        /// Tick value after the advance.
        to: u64,
    },
    /// A virtual timer IRQ was injected by the simulator. Distinct
    /// from [`Event::FaultInjected`] (which covers FaultPlan-driven
    /// IRQs and faults landed by future #722 work).
    TimerInjected,
    /// The simulator acked the just-injected IRQ via the
    /// [`vibix::task::env::TimerIrq::ack_timer`] seam method.
    TimerIrqAcked,
    /// A wakeup was enqueued for `deadline`, naming task `id`.
    ///
    /// Snapshot-derived in v1 (the simulator does not synthesize
    /// `enqueue_wakeup` calls), populated when #718's
    /// `sched_mock_trace!` macro lands on the kernel-side enqueue
    /// path.
    #[allow(dead_code)]
    WakeupEnqueued {
        /// Tick at which the wakeup is scheduled to fire.
        deadline: u64,
        /// Task id whose wakeup was enqueued.
        id: TaskId,
    },
    /// A task became runnable because its deadline expired and the
    /// seam returned its id from `drain_expired`.
    WakeupFired {
        /// Task id whose deadline fired.
        id: TaskId,
    },
    /// A task was scheduled onto a CPU (one event per dispatch).
    ///
    /// Populated by #718's emit point on the scheduler dispatch path.
    #[allow(dead_code)]
    TaskScheduled {
        /// Task id that was scheduled.
        id: TaskId,
    },
    /// A task entered the blocked state.
    ///
    /// Populated by #718's emit point on `sleep_ms` /
    /// `wait_event` / I/O block paths.
    #[allow(dead_code)]
    TaskBlocked {
        /// Task id that blocked.
        id: TaskId,
        /// Reason the task is blocked.
        reason: BlockReason,
    },
    /// A syscall was entered.
    ///
    /// Populated by #718's emit point at the syscall handler entry.
    /// `args` carries up to four register-passed argument words (the
    /// SysV AMD64 syscall ABI uses six, but four covers every syscall
    /// modeled by the v1 invariant set; truncating here keeps the
    /// trace JSON small without losing information for the v1 flake
    /// catalogue).
    #[allow(dead_code)]
    Syscall {
        /// Syscall number (Linux-compatible numbering on x86_64).
        nr: u64,
        /// First four argument registers.
        args: [u64; 4],
    },
    /// A CPU exception fired in user or kernel context.
    ///
    /// Populated by #718's exception-trampoline emit point. `cr2` is
    /// only meaningful for [`FaultKind::PageFault`]; carry zero for
    /// the others.
    #[allow(dead_code)]
    Fault {
        /// Fault classification.
        kind: FaultKind,
        /// Faulting instruction pointer.
        rip: u64,
        /// Page-fault address (zero for non-page-fault kinds).
        cr2: u64,
    },
    /// The simulator's FaultPlan injected a fault before the kernel
    /// observed it. Distinct from [`Event::Fault`] so invariant
    /// checkers can correlate "we asked for a fault" with "the kernel
    /// saw a fault." Populated by #722's FaultPlan landing.
    #[allow(dead_code)]
    FaultInjected {
        /// Fault classification injected.
        kind: FaultKind,
    },
}

/// One `(tick, event)` row in the trace stream.
///
/// `tick` is the value of `MockClock::now()` *at the time the event
/// was emitted*. For [`Event::TickAdvance`] the recorded tick is `to`;
/// for [`Event::TimerInjected`] / [`Event::TimerIrqAcked`] /
/// [`Event::WakeupFired`] it is `now()` after the owning `step` call
/// has advanced the clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceRecord {
    /// Tick at which this record was emitted.
    pub tick: u64,
    /// The transition itself.
    pub event: Event,
}

/// A `(Tick, Event)` trace stream emitted by a simulator run.
///
/// Storage is a `Vec<TraceRecord>`; iteration order is the emission
/// order, which is also the deterministic order imposed by the run
/// loop. Capacity is unbounded by default — opt into eviction via
/// [`Trace::with_capacity_limit`].
#[derive(Clone, Debug, Default)]
pub struct Trace {
    records: Vec<TraceRecord>,
    /// `Some(N)` means evict-from-head once `records.len() == N`.
    /// `None` is unbounded.
    capacity_limit: Option<usize>,
    /// One-shot eviction-warning latch. Prevents `eprintln!` spam when
    /// every push past the cap evicts; the human reader only needs to
    /// know once per trace that the cap was hit.
    eviction_warned: bool,
}

impl Trace {
    /// Construct an empty unbounded trace.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct an empty trace that evicts the oldest record once it
    /// holds `limit` records. `limit == 0` panics — a zero-cap trace
    /// is never useful and almost certainly a logic bug at the call
    /// site.
    pub fn with_capacity_limit(limit: usize) -> Self {
        assert!(
            limit > 0,
            "Trace::with_capacity_limit: limit must be > 0 (got 0)"
        );
        Self {
            records: Vec::new(),
            capacity_limit: Some(limit),
            eviction_warned: false,
        }
    }

    /// Number of records in the trace.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` if the trace has no records.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Borrow the records as a slice.
    pub fn records(&self) -> &[TraceRecord] {
        &self.records
    }

    /// Append `rec`. Honours [`Trace::with_capacity_limit`] by
    /// evicting from the head once the cap is reached.
    pub(crate) fn push(&mut self, rec: TraceRecord) {
        if let Some(cap) = self.capacity_limit {
            if self.records.len() >= cap {
                // Evict the oldest record. `Vec::remove(0)` is O(n) but
                // a capacity-bounded trace is opt-in and the warning
                // below tells the operator to use a larger cap.
                self.records.remove(0);
                if !self.eviction_warned {
                    self.eviction_warned = true;
                    if !suppress_eviction_warn() {
                        eprintln!(
                            "simulator::Trace: capacity limit ({cap}) reached; \
                             evicting oldest records. The earliest portion of the \
                             trace is now lost; raise the cap if the head matters."
                        );
                    }
                }
            }
        }
        self.records.push(rec);
    }

    /// Returns the index of the first record at which `self` and
    /// `other` differ, or `None` if the two traces are identical.
    ///
    /// Used by the round-trip / replay-equivalence assertions: if
    /// `record → JSON → parse → re-record` ever drifts, `diff` returns
    /// the exact index to focus debugging on.
    ///
    /// Records past the shorter trace's length count as a difference
    /// at the shorter length.
    pub fn diff(&self, other: &Trace) -> Option<usize> {
        let n = self.records.len().min(other.records.len());
        for i in 0..n {
            if self.records[i] != other.records[i] {
                return Some(i);
            }
        }
        if self.records.len() != other.records.len() {
            Some(n)
        } else {
            None
        }
    }

    /// Serialize the trace as JSON to `writer`.
    ///
    /// The output is a single JSON object with a stable shape:
    ///
    /// ```json
    /// {
    ///   "schema_version": 1,
    ///   "records": [
    ///     {"tick": 1, "event": {"type": "tick_advance", "from": 0, "to": 1}},
    ///     {"tick": 1, "event": {"type": "timer_injected"}},
    ///     ...
    ///   ]
    /// }
    /// ```
    ///
    /// Field ordering inside every object is fixed (so two equal
    /// traces produce byte-identical JSON), no whitespace beyond the
    /// single space after each `:` / `,` is emitted, and only the
    /// integer / string subset of JSON is used (no floats, no `null`).
    pub fn to_json(&self, writer: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(
            writer,
            "{{\"schema_version\": {SCHEMA_VERSION}, \"records\": ["
        )?;
        for (i, rec) in self.records.iter().enumerate() {
            if i > 0 {
                writer.write_str(", ")?;
            }
            write!(writer, "{{\"tick\": {}, \"event\": ", rec.tick)?;
            write_event_json(writer, &rec.event)?;
            writer.write_char('}')?;
        }
        writer.write_str("]}")
    }

    /// Convenience wrapper around [`Trace::to_json`] returning a
    /// `String`.
    pub fn to_json_string(&self) -> String {
        let mut s = String::new();
        // `String` implements `core::fmt::Write` infallibly.
        self.to_json(&mut s).expect("String write cannot fail");
        s
    }

    /// Parse a JSON string produced by [`Trace::to_json`] back into a
    /// [`Trace`]. Returns `Err` with a human-readable message on any
    /// schema or syntax violation.
    ///
    /// The capacity limit is *not* preserved across the round-trip:
    /// parsed traces are unbounded. The use case for `from_json` is
    /// the round-trip property test and the future `replay` binary,
    /// neither of which want eviction firing on parse.
    pub fn from_json(input: &str) -> Result<Self, String> {
        parse_trace(input)
    }
}

// ---------------------------------------------------------------------
// JSON encoder
// ---------------------------------------------------------------------

fn write_event_json(w: &mut dyn core::fmt::Write, event: &Event) -> core::fmt::Result {
    match event {
        Event::TickAdvance { from, to } => write!(
            w,
            "{{\"type\": \"tick_advance\", \"from\": {from}, \"to\": {to}}}"
        ),
        Event::TimerInjected => w.write_str("{\"type\": \"timer_injected\"}"),
        Event::TimerIrqAcked => w.write_str("{\"type\": \"timer_irq_acked\"}"),
        Event::WakeupEnqueued { deadline, id } => write!(
            w,
            "{{\"type\": \"wakeup_enqueued\", \"deadline\": {deadline}, \"id\": {id}}}"
        ),
        Event::WakeupFired { id } => {
            write!(w, "{{\"type\": \"wakeup_fired\", \"id\": {id}}}")
        }
        Event::TaskScheduled { id } => {
            write!(w, "{{\"type\": \"task_scheduled\", \"id\": {id}}}")
        }
        Event::TaskBlocked { id, reason } => write!(
            w,
            "{{\"type\": \"task_blocked\", \"id\": {id}, \"reason\": \"{}\"}}",
            reason.as_wire()
        ),
        Event::Syscall { nr, args } => write!(
            w,
            "{{\"type\": \"syscall\", \"nr\": {nr}, \"args\": [{}, {}, {}, {}]}}",
            args[0], args[1], args[2], args[3]
        ),
        Event::Fault { kind, rip, cr2 } => write!(
            w,
            "{{\"type\": \"fault\", \"kind\": \"{}\", \"rip\": {rip}, \"cr2\": {cr2}}}",
            kind.as_wire()
        ),
        Event::FaultInjected { kind } => write!(
            w,
            "{{\"type\": \"fault_injected\", \"kind\": \"{}\"}}",
            kind.as_wire()
        ),
    }
}

// ---------------------------------------------------------------------
// JSON parser
//
// Hand-rolled recursive-descent over the strict subset of JSON the
// encoder above emits. Errors carry a byte offset so a malformed
// trace dumped from CI is greppable.
// ---------------------------------------------------------------------

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn err(&self, msg: &str) -> String {
        format!("trace JSON parse error at byte {}: {}", self.pos, msg)
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos += 1;
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        self.skip_ws();
        match self.bump() {
            Some(c) if c == b => Ok(()),
            Some(c) => Err(self.err(&format!("expected '{}', got '{}'", b as char, c as char))),
            None => Err(self.err(&format!("expected '{}', got EOF", b as char))),
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.skip_ws();
        self.expect(b'"')?;
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b == b'"' {
                let s = core::str::from_utf8(&self.input[start..self.pos])
                    .map_err(|_| self.err("non-UTF-8 byte in string"))?
                    .to_string();
                self.pos += 1;
                return Ok(s);
            }
            if b == b'\\' {
                return Err(self.err("escapes not supported in trace JSON strings"));
            }
            self.pos += 1;
        }
        Err(self.err("unterminated string"))
    }

    fn parse_u64(&mut self) -> Result<u64, String> {
        self.skip_ws();
        let start = self.pos;
        while let Some(b) = self.peek() {
            if b.is_ascii_digit() {
                self.pos += 1;
            } else {
                break;
            }
        }
        if start == self.pos {
            return Err(self.err("expected integer"));
        }
        let s = core::str::from_utf8(&self.input[start..self.pos])
            .map_err(|_| self.err("non-UTF-8 byte in integer"))?;
        s.parse::<u64>()
            .map_err(|_| self.err(&format!("integer out of range or invalid: {s}")))
    }

    fn expect_field_name(&mut self, name: &str) -> Result<(), String> {
        let got = self.parse_string()?;
        if got != name {
            return Err(self.err(&format!("expected field \"{name}\", got \"{got}\"")));
        }
        self.expect(b':')
    }
}

fn parse_trace(input: &str) -> Result<Trace, String> {
    let mut p = Parser::new(input);
    p.expect(b'{')?;
    p.expect_field_name("schema_version")?;
    let v = p.parse_u64()?;
    if v != u64::from(SCHEMA_VERSION) {
        return Err(format!(
            "trace JSON schema_version mismatch: expected {SCHEMA_VERSION}, got {v}"
        ));
    }
    p.expect(b',')?;
    p.expect_field_name("records")?;
    p.expect(b'[')?;

    let mut records = Vec::new();
    p.skip_ws();
    if p.peek() != Some(b']') {
        loop {
            records.push(parse_record(&mut p)?);
            p.skip_ws();
            match p.peek() {
                Some(b',') => {
                    p.pos += 1;
                }
                Some(b']') => break,
                Some(c) => return Err(p.err(&format!("expected ',' or ']', got '{}'", c as char))),
                None => return Err(p.err("unexpected EOF in records array")),
            }
        }
    }
    p.expect(b']')?;
    p.expect(b'}')?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(p.err("trailing bytes after JSON object"));
    }
    Ok(Trace {
        records,
        capacity_limit: None,
        eviction_warned: false,
    })
}

fn parse_record(p: &mut Parser<'_>) -> Result<TraceRecord, String> {
    p.expect(b'{')?;
    p.expect_field_name("tick")?;
    let tick = p.parse_u64()?;
    p.expect(b',')?;
    p.expect_field_name("event")?;
    let event = parse_event(p)?;
    p.expect(b'}')?;
    Ok(TraceRecord { tick, event })
}

fn parse_event(p: &mut Parser<'_>) -> Result<Event, String> {
    p.expect(b'{')?;
    p.expect_field_name("type")?;
    let ty = p.parse_string()?;
    let event = match ty.as_str() {
        "tick_advance" => {
            p.expect(b',')?;
            p.expect_field_name("from")?;
            let from = p.parse_u64()?;
            p.expect(b',')?;
            p.expect_field_name("to")?;
            let to = p.parse_u64()?;
            Event::TickAdvance { from, to }
        }
        "timer_injected" => Event::TimerInjected,
        "timer_irq_acked" => Event::TimerIrqAcked,
        "wakeup_enqueued" => {
            p.expect(b',')?;
            p.expect_field_name("deadline")?;
            let deadline = p.parse_u64()?;
            p.expect(b',')?;
            p.expect_field_name("id")?;
            let id = p.parse_u64()? as TaskId;
            Event::WakeupEnqueued { deadline, id }
        }
        "wakeup_fired" => {
            p.expect(b',')?;
            p.expect_field_name("id")?;
            let id = p.parse_u64()? as TaskId;
            Event::WakeupFired { id }
        }
        "task_scheduled" => {
            p.expect(b',')?;
            p.expect_field_name("id")?;
            let id = p.parse_u64()? as TaskId;
            Event::TaskScheduled { id }
        }
        "task_blocked" => {
            p.expect(b',')?;
            p.expect_field_name("id")?;
            let id = p.parse_u64()? as TaskId;
            p.expect(b',')?;
            p.expect_field_name("reason")?;
            let r = p.parse_string()?;
            let reason = BlockReason::from_wire(&r)
                .ok_or_else(|| p.err(&format!("unknown block reason: {r}")))?;
            Event::TaskBlocked { id, reason }
        }
        "syscall" => {
            p.expect(b',')?;
            p.expect_field_name("nr")?;
            let nr = p.parse_u64()?;
            p.expect(b',')?;
            p.expect_field_name("args")?;
            p.expect(b'[')?;
            let a0 = p.parse_u64()?;
            p.expect(b',')?;
            let a1 = p.parse_u64()?;
            p.expect(b',')?;
            let a2 = p.parse_u64()?;
            p.expect(b',')?;
            let a3 = p.parse_u64()?;
            p.expect(b']')?;
            Event::Syscall {
                nr,
                args: [a0, a1, a2, a3],
            }
        }
        "fault" => {
            p.expect(b',')?;
            p.expect_field_name("kind")?;
            let k = p.parse_string()?;
            let kind = FaultKind::from_wire(&k)
                .ok_or_else(|| p.err(&format!("unknown fault kind: {k}")))?;
            p.expect(b',')?;
            p.expect_field_name("rip")?;
            let rip = p.parse_u64()?;
            p.expect(b',')?;
            p.expect_field_name("cr2")?;
            let cr2 = p.parse_u64()?;
            Event::Fault { kind, rip, cr2 }
        }
        "fault_injected" => {
            p.expect(b',')?;
            p.expect_field_name("kind")?;
            let k = p.parse_string()?;
            let kind = FaultKind::from_wire(&k)
                .ok_or_else(|| p.err(&format!("unknown fault kind: {k}")))?;
            Event::FaultInjected { kind }
        }
        other => return Err(p.err(&format!("unknown event type: {other}"))),
    };
    p.expect(b'}')?;
    Ok(event)
}

// ---------------------------------------------------------------------
// One-shot eviction-warning suppressor for tests. The capacity-bounded
// `eprintln!` in `Trace::push` is informational; the per-Trace
// `eviction_warned` latch keeps it from spamming. We additionally
// short-circuit it under `cfg(test)` via this `AtomicBool` so the
// trace-bound unit test below does not pollute `cargo test`'s stderr
// with an expected warning.
// ---------------------------------------------------------------------

#[cfg(test)]
static SUPPRESS_EVICTION_WARN: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(test)]
pub(crate) fn _set_suppress_eviction_warn(v: bool) {
    SUPPRESS_EVICTION_WARN.store(v, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn suppress_eviction_warn() -> bool {
    SUPPRESS_EVICTION_WARN.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(not(test))]
fn suppress_eviction_warn() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_trace() -> Trace {
        let mut t = Trace::new();
        t.push(TraceRecord {
            tick: 1,
            event: Event::TickAdvance { from: 0, to: 1 },
        });
        t.push(TraceRecord {
            tick: 1,
            event: Event::TimerInjected,
        });
        t.push(TraceRecord {
            tick: 1,
            event: Event::WakeupFired { id: 42 },
        });
        t.push(TraceRecord {
            tick: 1,
            event: Event::TimerIrqAcked,
        });
        // Snapshot/macro-emitted variants — exercised here so the
        // round-trip property covers them despite no production emit
        // points existing yet.
        t.push(TraceRecord {
            tick: 2,
            event: Event::WakeupEnqueued { deadline: 5, id: 7 },
        });
        t.push(TraceRecord {
            tick: 2,
            event: Event::TaskScheduled { id: 7 },
        });
        t.push(TraceRecord {
            tick: 3,
            event: Event::TaskBlocked {
                id: 7,
                reason: BlockReason::Sleep,
            },
        });
        t.push(TraceRecord {
            tick: 4,
            event: Event::Syscall {
                nr: 60,
                args: [1, 2, 3, 4],
            },
        });
        t.push(TraceRecord {
            tick: 5,
            event: Event::Fault {
                kind: FaultKind::PageFault,
                rip: 0xDEAD_BEEF,
                cr2: 0xCAFE_F00D,
            },
        });
        t.push(TraceRecord {
            tick: 5,
            event: Event::FaultInjected {
                kind: FaultKind::GeneralProtection,
            },
        });
        t
    }

    #[test]
    fn empty_trace_serializes_to_canonical_json() {
        let t = Trace::new();
        let s = t.to_json_string();
        assert_eq!(s, "{\"schema_version\": 1, \"records\": []}");
    }

    #[test]
    fn known_event_serializes_with_fixed_field_order() {
        let mut t = Trace::new();
        t.push(TraceRecord {
            tick: 7,
            event: Event::TickAdvance { from: 6, to: 7 },
        });
        let s = t.to_json_string();
        assert_eq!(
            s,
            "{\"schema_version\": 1, \"records\": [{\"tick\": 7, \"event\": \
             {\"type\": \"tick_advance\", \"from\": 6, \"to\": 7}}]}"
        );
    }

    #[test]
    fn round_trip_preserves_every_variant() {
        let original = sample_trace();
        let json = original.to_json_string();
        let parsed = Trace::from_json(&json).expect("parse round-trip");
        assert_eq!(parsed.records(), original.records());
        // re-record (re-serialize) produces byte-identical JSON
        let json2 = parsed.to_json_string();
        assert_eq!(json, json2, "JSON drifted across record→json→parse→record");
        // and diff agrees
        assert_eq!(original.diff(&parsed), None);
    }

    #[test]
    fn diff_returns_first_divergent_index() {
        let a = sample_trace();
        let mut b = sample_trace();
        // Mutate record 3.
        b.records[3] = TraceRecord {
            tick: 1,
            event: Event::WakeupFired { id: 999 },
        };
        assert_eq!(a.diff(&b), Some(3));
    }

    #[test]
    fn diff_returns_none_for_equal_traces() {
        assert_eq!(sample_trace().diff(&sample_trace()), None);
    }

    #[test]
    fn diff_reports_length_difference_when_one_is_a_prefix() {
        let a = sample_trace();
        let mut b = sample_trace();
        b.records.pop();
        // `a` is longer by one; first divergence is at the shorter
        // length.
        assert_eq!(a.diff(&b), Some(b.records.len()));
        assert_eq!(b.diff(&a), Some(b.records.len()));
    }

    #[test]
    fn capacity_limit_evicts_oldest() {
        // Suppress the one-shot eprintln so test output stays clean.
        _set_suppress_eviction_warn(true);
        let mut t = Trace::with_capacity_limit(3);
        for i in 0..5 {
            t.push(TraceRecord {
                tick: i,
                event: Event::TimerInjected,
            });
        }
        assert_eq!(t.len(), 3);
        // Oldest two ticks (0, 1) are gone; ticks 2,3,4 remain.
        let ticks: Vec<u64> = t.records().iter().map(|r| r.tick).collect();
        assert_eq!(ticks, vec![2, 3, 4]);
        _set_suppress_eviction_warn(false);
    }

    #[test]
    #[should_panic(expected = "limit must be > 0")]
    fn capacity_limit_zero_panics() {
        let _ = Trace::with_capacity_limit(0);
    }

    #[test]
    fn parse_rejects_wrong_schema_version() {
        let bad = "{\"schema_version\": 99, \"records\": []}";
        let err = Trace::from_json(bad).unwrap_err();
        assert!(
            err.contains("schema_version mismatch"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_unknown_event_type() {
        let bad =
            "{\"schema_version\": 1, \"records\": [{\"tick\": 0, \"event\": {\"type\": \"bogus\"}}]}";
        let err = Trace::from_json(bad).unwrap_err();
        assert!(
            err.contains("unknown event type"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_unknown_block_reason() {
        let bad = "{\"schema_version\": 1, \"records\": [{\"tick\": 0, \"event\": \
                   {\"type\": \"task_blocked\", \"id\": 1, \"reason\": \"bogus\"}}]}";
        let err = Trace::from_json(bad).unwrap_err();
        assert!(
            err.contains("unknown block reason"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let bad = "{\"schema_version\": 1, \"records\": []}garbage";
        let err = Trace::from_json(bad).unwrap_err();
        assert!(err.contains("trailing bytes"), "unexpected error: {err}");
    }

    #[test]
    fn parse_rejects_string_escapes() {
        // Escapes are explicitly out of scope of the simulator's JSON
        // subset; the parser must reject them rather than silently
        // mis-interpret. (No emitted event contains a backslash.)
        let bad = r#"{"schema_version": 1, "records": [{"tick": 0, "event": {"type": "task_blocked", "id": 1, "reason": "sl\u0065ep"}}]}"#;
        let err = Trace::from_json(bad).unwrap_err();
        assert!(err.contains("escapes"), "unexpected error: {err}");
    }
}
