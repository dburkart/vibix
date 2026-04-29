//! Seeded fault-injection plan (RFC 0006 §"Failure-injection scope").
//!
//! Issue #719 lands the v1 fault-injection surface: an ordered
//! `Vec<(Tick, FaultEvent)>` that the simulator consumes during
//! [`crate::Simulator::step`]. Each due [`FaultEvent`] dispatches a
//! deterministic perturbation against the seam mocks and emits a
//! [`crate::Event::FaultInjected`] record into the trace so invariant
//! checkers can correlate "we asked for a fault" with the kernel's
//! observable response.
//!
//! ## v1 surface
//!
//! [`FaultEvent`] carries exactly three variants in v1:
//!
//! - [`FaultEvent::SpuriousTimerIrq`] — call
//!   [`vibix::task::env::TimerIrq::inject_timer`] one extra time at
//!   `tick`. Models LAPIC/PIT lost-edge retries (RFC 0006
//!   §"Failure-injection scope": "Spurious timer IRQs").
//! - [`FaultEvent::TimerDrift { ticks }`] — advance the mock clock by
//!   `ticks` extra ticks at `tick`. Models delayed timer IRQs (RFC
//!   §"Timer drift").
//! - [`FaultEvent::WakeupReorder { within_tick }`] — the next
//!   `WakeupFired` batch at the current tick is rotated by
//!   `within_tick` positions before being emitted. Models "did the
//!   parent's `wait` see the child's `exit` first?" (RFC §"Wakeup
//!   re-ordering inside a tick" — the lever flagged for the #501
//!   fork/exec/wait flake).
//!
//! ## What v1 *cannot* generate
//!
//! Hardware-fault variants (`InjectPageFault`, `InjectGeneralProtection`,
//! `InjectDoubleFault`) are deliberately absent. RFC 0006 defers them
//! to Phase 2.1 (issues #728/#729/#730/#731) — synthesizing a #PF /
//! #GP / #DF on the host requires kernel-side trampoline work that
//! does not exist yet. To make this an *enforced* deferral rather than
//! a "we'll add it later" promise, the [`FaultEvent`] enum's variant
//! set is the entire generated surface, and a `compile_fail` doctest
//! pins the constraint at the type level. Any future patch that adds
//! a `FaultEvent::InjectPageFault` variant will fail the doctest until
//! the v1 surface is officially expanded — a decision that requires
//! re-opening RFC 0006 §"Failure-injection scope".
//!
//! ```compile_fail
//! # use simulator::FaultEvent;
//! // RFC 0006 v1 forbids host-side hardware-fault injection. Adding a
//! // page-fault variant must be a deliberate RFC change; this line
//! // must therefore fail to compile against any v1 simulator.
//! let _ = FaultEvent::InjectPageFault;
//! ```
//!
//! ```compile_fail
//! # use simulator::FaultEvent;
//! let _ = FaultEvent::InjectGeneralProtection;
//! ```
//!
//! ```compile_fail
//! # use simulator::FaultEvent;
//! let _ = FaultEvent::InjectDoubleFault;
//! ```
//!
//! ## JSON round-trip
//!
//! [`FaultPlan::to_json`] / [`FaultPlan::from_json`] produce a stable
//! schema (`fault_plan_schema_version = 1`) with the same
//! field-ordering discipline as [`crate::trace`]. The replay binary
//! and the proptest shrinker both consume the JSON form: a flake
//! recorded under one seed survives `record → JSON → parse → re-replay`
//! without bit drift.

use std::string::{String, ToString};
use std::vec::Vec;

use rand_chacha::ChaCha8Rng;
use rand_core::Rng;

/// Stable JSON schema version for [`FaultPlan`] serialization.
///
/// Bump when adding, removing, or renaming a [`FaultEvent`] variant or
/// field. v1 is the surface RFC 0006 §"Failure-injection scope" pins;
/// every subsequent change is an RFC review.
pub const FAULT_PLAN_SCHEMA_VERSION: u32 = 1;

/// One injectable fault.
///
/// The variant set is the v1 fault-injection surface from RFC 0006:
/// timer jitter, spurious IRQs, and within-tick wakeup re-ordering.
/// Hardware faults (`#PF` / `#GP` / `#DF`) are deferred to Phase 2.1
/// per RFC §"Failure-injection scope" and are *not* representable in
/// this enum — callers that try to construct a `InjectPageFault`
/// variant get a compile error (see the crate-level doctests in
/// [this module](crate::fault_plan)).
///
/// `#[non_exhaustive]` so adding a v2 fault is a non-breaking source
/// change at the type level; the JSON `fault_plan_schema_version`
/// still bumps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FaultEvent {
    /// Inject one extra timer IRQ at the scheduled tick. Models a
    /// LAPIC/PIT lost-edge retry where the same edge fires the ISR
    /// twice within one logical tick.
    SpuriousTimerIrq,
    /// Advance the mock clock by `ticks` extra ticks at the scheduled
    /// tick. Models a delayed timer IRQ where the kernel's notion of
    /// `now` jumps forward by more than one between two consecutive
    /// `preempt_tick` calls.
    ///
    /// `ticks == 0` is permitted but a no-op against the clock; it is
    /// still recorded in the trace for replay parity.
    TimerDrift {
        /// Number of additional ticks to advance the clock by, on top
        /// of the canonical one-tick advance the run loop performs.
        ticks: u64,
    },
    /// Rotate the *next* drained wakeup batch by `within_tick`
    /// positions before the simulator emits the corresponding
    /// [`crate::Event::WakeupFired`] records. Models a `BTreeMap`
    /// drain order that disagrees with the kernel's expected
    /// dispatch order — the most direct lever on fork/exec/wait
    /// races (#501).
    ///
    /// If the drain batch has fewer than two entries the rotation is
    /// a no-op against the trace but still recorded as an injected
    /// fault for replay parity.
    WakeupReorder {
        /// Number of positions to rotate the wakeup batch by. The
        /// simulator computes `within_tick % batch.len()` so any
        /// `u64` is a valid value (the wire form is stable across
        /// batch-size changes).
        within_tick: u64,
    },
}

impl FaultEvent {
    /// Wire-form classification used by [`crate::Event::FaultInjected`]'s
    /// existing `kind: FaultKind` field.
    ///
    /// v1 does not own a dedicated `FaultKind` variant per fault event
    /// (the trace's `FaultKind` enum was designed before #719 against
    /// the hardware-fault catalogue: `page_fault`, `general_protection`,
    /// etc.). Mapping every v1 [`FaultEvent`] to
    /// [`crate::FaultKind::Other`] keeps the schema stable while
    /// still letting callers correlate the `FaultInjected` record
    /// with the next plan entry; the [`crate::trace::Event`] stream
    /// remains the canonical evidence and downstream invariant
    /// checkers consume the [`FaultEvent`] directly via
    /// [`FaultPlan::events`].
    pub fn fault_kind(self) -> crate::FaultKind {
        match self {
            FaultEvent::SpuriousTimerIrq
            | FaultEvent::TimerDrift { .. }
            | FaultEvent::WakeupReorder { .. } => crate::FaultKind::Other,
        }
    }

    /// Stable wire string used in the JSON serialization. Closed set;
    /// adding a [`FaultEvent`] variant is a [`FAULT_PLAN_SCHEMA_VERSION`]
    /// bump.
    fn type_tag(self) -> &'static str {
        match self {
            FaultEvent::SpuriousTimerIrq => "spurious_timer_irq",
            FaultEvent::TimerDrift { .. } => "timer_drift",
            FaultEvent::WakeupReorder { .. } => "wakeup_reorder",
        }
    }
}

/// Ordered `(tick, FaultEvent)` schedule consumed during a simulator
/// run.
///
/// **Ordering contract.** Entries are kept sorted by `tick` (ascending,
/// stable for ties). The simulator's `step()` consumes every entry whose
/// `tick` matches the current post-advance tick value, in vector order;
/// two entries that share a `tick` dispatch in the order they were
/// inserted. This stability is load-bearing for replay: a recorded plan
/// that fires `SpuriousTimerIrq` *then* `TimerDrift` at the same tick
/// must fire in that order on every replay.
///
/// **Mutability.** A `FaultPlan` is constructed via [`FaultPlan::new`]
/// or [`FaultPlanBuilder`] and is normally immutable for the duration
/// of a simulator run. The [`FaultPlan::push`] method exists for the
/// proptest-state-machine integration: each `InjectFault` transition
/// appends one entry to the simulator's currently-installed plan via
/// [`crate::Simulator::push_fault_event`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FaultPlan {
    /// `(tick, event)` entries, sorted by `tick` ascending; ties
    /// preserved in insertion order.
    entries: Vec<(u64, FaultEvent)>,
}

impl FaultPlan {
    /// Construct an empty fault plan. Useful as the default for runs
    /// that don't need any injection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a fault plan from a pre-built entry list. The list is
    /// sorted by `tick` (stable on ties) before being stored — so
    /// callers that produce entries in non-monotonic order still get
    /// the documented dispatch contract.
    pub fn from_entries<I>(entries: I) -> Self
    where
        I: IntoIterator<Item = (u64, FaultEvent)>,
    {
        let mut v: Vec<(u64, FaultEvent)> = entries.into_iter().collect();
        // Stable sort preserves insertion order within equal-tick
        // groups, which is the dispatch contract.
        v.sort_by_key(|(t, _)| *t);
        Self { entries: v }
    }

    /// Number of `(tick, event)` entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// `true` if the plan has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Borrow the plan's entries as a slice, ordered by `tick`
    /// ascending.
    pub fn entries(&self) -> &[(u64, FaultEvent)] {
        &self.entries
    }

    /// Iterate the [`FaultEvent`] values in plan order. Convenience
    /// for tests that don't care about the tick column.
    pub fn events(&self) -> impl Iterator<Item = FaultEvent> + '_ {
        self.entries.iter().map(|(_, e)| *e)
    }

    /// Append a new entry, preserving the sort-by-tick (stable on
    /// ties) invariant. Used by the proptest-state-machine
    /// integration's `InjectFault` transition.
    pub fn push(&mut self, tick: u64, event: FaultEvent) {
        // Find the first index whose tick is *strictly greater* than
        // ours, then insert before it. This preserves stable ordering
        // within an equal-tick group: the new entry sorts after every
        // existing entry at the same tick.
        let pos = self
            .entries
            .iter()
            .position(|(t, _)| *t > tick)
            .unwrap_or(self.entries.len());
        self.entries.insert(pos, (tick, event));
    }

    /// Remove and return every `(tick, event)` whose tick equals
    /// `current_tick`. The simulator calls this once per `step` to
    /// drain the entries due at the just-advanced tick.
    ///
    /// Returns events in their stored order — the v1 dispatch
    /// contract.
    pub fn drain_due(&mut self, current_tick: u64) -> Vec<FaultEvent> {
        // Two-pointer split: collect every leading entry whose tick is
        // <= current_tick (entries strictly *less* than the current
        // tick belong to a tick we already passed without firing them
        // — that is a logic bug in the run loop and we surface it by
        // dispatching the late entries here rather than silently
        // dropping; replay-equivalence is preserved either way).
        let mut due = Vec::new();
        let mut keep = Vec::with_capacity(self.entries.len());
        for (t, e) in self.entries.drain(..) {
            if t <= current_tick {
                due.push(e);
            } else {
                keep.push((t, e));
            }
        }
        self.entries = keep;
        due
    }

    /// Serialize the plan as canonical JSON (matching the [`crate::trace`]
    /// encoder discipline: fixed field ordering, integer-only, no
    /// floats / nulls / arrays of mixed type).
    pub fn to_json(&self, w: &mut dyn core::fmt::Write) -> core::fmt::Result {
        write!(
            w,
            "{{\"fault_plan_schema_version\": {FAULT_PLAN_SCHEMA_VERSION}, \"entries\": ["
        )?;
        for (i, (tick, ev)) in self.entries.iter().enumerate() {
            if i > 0 {
                w.write_str(", ")?;
            }
            write!(w, "{{\"tick\": {tick}, \"event\": ")?;
            write_event(w, ev)?;
            w.write_char('}')?;
        }
        w.write_str("]}")
    }

    /// Convenience: serialize to a `String`.
    pub fn to_json_string(&self) -> String {
        let mut s = String::new();
        self.to_json(&mut s).expect("String write cannot fail");
        s
    }

    /// Parse a JSON string produced by [`FaultPlan::to_json`].
    pub fn from_json(input: &str) -> Result<Self, String> {
        parse_plan(input)
    }
}

fn write_event(w: &mut dyn core::fmt::Write, ev: &FaultEvent) -> core::fmt::Result {
    match *ev {
        FaultEvent::SpuriousTimerIrq => {
            write!(w, "{{\"type\": \"{}\"}}", ev.type_tag())
        }
        FaultEvent::TimerDrift { ticks } => {
            write!(w, "{{\"type\": \"{}\", \"ticks\": {ticks}}}", ev.type_tag())
        }
        FaultEvent::WakeupReorder { within_tick } => write!(
            w,
            "{{\"type\": \"{}\", \"within_tick\": {within_tick}}}",
            ev.type_tag()
        ),
    }
}

// ---------------------------------------------------------------------
// JSON parser — same hand-rolled recursive-descent shape as
// `trace.rs`. Kept independent of `trace.rs`'s `Parser` to avoid
// re-exporting `pub(crate)` machinery across modules; the duplication
// is < 60 lines and keeps the determinism envelope (no serde) clear.
// ---------------------------------------------------------------------

struct PlanParser<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> PlanParser<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    fn err(&self, msg: &str) -> String {
        format!("fault plan JSON parse error at byte {}: {}", self.pos, msg)
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
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
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
                return Err(self.err("escapes not supported in fault plan JSON strings"));
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

    fn expect_field(&mut self, name: &str) -> Result<(), String> {
        let got = self.parse_string()?;
        if got != name {
            return Err(self.err(&format!("expected field \"{name}\", got \"{got}\"")));
        }
        self.expect(b':')
    }
}

fn parse_plan(input: &str) -> Result<FaultPlan, String> {
    let mut p = PlanParser::new(input);
    p.expect(b'{')?;
    p.expect_field("fault_plan_schema_version")?;
    let v = p.parse_u64()?;
    if v != u64::from(FAULT_PLAN_SCHEMA_VERSION) {
        return Err(format!(
            "fault plan JSON schema_version mismatch: expected {FAULT_PLAN_SCHEMA_VERSION}, got {v}"
        ));
    }
    p.expect(b',')?;
    p.expect_field("entries")?;
    p.expect(b'[')?;

    let mut entries: Vec<(u64, FaultEvent)> = Vec::new();
    p.skip_ws();
    if p.peek() != Some(b']') {
        loop {
            entries.push(parse_entry(&mut p)?);
            p.skip_ws();
            match p.peek() {
                Some(b',') => {
                    p.pos += 1;
                }
                Some(b']') => break,
                Some(c) => return Err(p.err(&format!("expected ',' or ']', got '{}'", c as char))),
                None => return Err(p.err("unexpected EOF in entries array")),
            }
        }
    }
    p.expect(b']')?;
    p.expect(b'}')?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(p.err("trailing bytes after JSON object"));
    }
    // The on-wire form already preserves order; no re-sort needed
    // here — that would be lossy if a future schema bump permits
    // unsorted input.
    Ok(FaultPlan { entries })
}

fn parse_entry(p: &mut PlanParser<'_>) -> Result<(u64, FaultEvent), String> {
    p.expect(b'{')?;
    p.expect_field("tick")?;
    let tick = p.parse_u64()?;
    p.expect(b',')?;
    p.expect_field("event")?;
    let event = parse_event(p)?;
    p.expect(b'}')?;
    Ok((tick, event))
}

fn parse_event(p: &mut PlanParser<'_>) -> Result<FaultEvent, String> {
    p.expect(b'{')?;
    p.expect_field("type")?;
    let ty = p.parse_string()?;
    let event = match ty.as_str() {
        "spurious_timer_irq" => FaultEvent::SpuriousTimerIrq,
        "timer_drift" => {
            p.expect(b',')?;
            p.expect_field("ticks")?;
            let ticks = p.parse_u64()?;
            FaultEvent::TimerDrift { ticks }
        }
        "wakeup_reorder" => {
            p.expect(b',')?;
            p.expect_field("within_tick")?;
            let within_tick = p.parse_u64()?;
            FaultEvent::WakeupReorder { within_tick }
        }
        other => {
            return Err(p.err(&format!(
                "unknown fault event type: {other}; \
                 RFC 0006 v1 surface is spurious_timer_irq / timer_drift / wakeup_reorder"
            )));
        }
    };
    p.expect(b'}')?;
    Ok(event)
}

// ---------------------------------------------------------------------
// Builder
// ---------------------------------------------------------------------

/// Builder for randomized [`FaultPlan`]s seeded from a [`crate::SimRng`]
/// `rng_for("faults")` sub-stream.
///
/// The builder exists separately from `FaultPlan::new` so the
/// "construct a hand-rolled plan" path (used by replay tests) and the
/// "construct a randomized plan from a master seed" path (used by the
/// proptest harness) stay textually distinct — replay tests must
/// never accidentally consume an RNG byte that perturbs a future
/// random plan.
///
/// Tunables are conservative: tests want a moderate number of faults
/// per run, not a flood. The exact knobs ([`FaultPlanBuilder::density`],
/// [`FaultPlanBuilder::max_tick`], [`FaultPlanBuilder::variants`]) are
/// public so a flake reproduction can dial them up to widen the
/// search.
#[derive(Debug)]
pub struct FaultPlanBuilder<'a> {
    rng: &'a mut ChaCha8Rng,
    density: f64,
    max_tick: u64,
    variants: VariantMask,
}

/// Bitmask selecting which [`FaultEvent`] variants the builder may
/// emit. v1 has three; tests that want to isolate one variant (e.g.
/// "show me a divergence caused only by `WakeupReorder`") flip the
/// others off.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VariantMask {
    /// Allow [`FaultEvent::SpuriousTimerIrq`].
    pub spurious_timer_irq: bool,
    /// Allow [`FaultEvent::TimerDrift`].
    pub timer_drift: bool,
    /// Allow [`FaultEvent::WakeupReorder`].
    pub wakeup_reorder: bool,
}

impl VariantMask {
    /// All v1 variants enabled. The default the builder ships with.
    pub const fn all() -> Self {
        Self {
            spurious_timer_irq: true,
            timer_drift: true,
            wakeup_reorder: true,
        }
    }

    /// No variants enabled. Combined with [`FaultPlanBuilder::density`]
    /// this produces the empty plan; useful as a control in
    /// trace-divergence tests.
    pub const fn none() -> Self {
        Self {
            spurious_timer_irq: false,
            timer_drift: false,
            wakeup_reorder: false,
        }
    }

    /// Only [`FaultEvent::SpuriousTimerIrq`].
    pub const fn only_spurious() -> Self {
        Self {
            spurious_timer_irq: true,
            timer_drift: false,
            wakeup_reorder: false,
        }
    }

    /// Only [`FaultEvent::TimerDrift`].
    pub const fn only_drift() -> Self {
        Self {
            spurious_timer_irq: false,
            timer_drift: true,
            wakeup_reorder: false,
        }
    }

    /// Only [`FaultEvent::WakeupReorder`].
    pub const fn only_reorder() -> Self {
        Self {
            spurious_timer_irq: false,
            timer_drift: false,
            wakeup_reorder: true,
        }
    }

    /// Number of variants enabled. Used by the builder to pick a
    /// uniformly-distributed variant when more than one is allowed.
    fn count(self) -> u32 {
        u32::from(self.spurious_timer_irq)
            + u32::from(self.timer_drift)
            + u32::from(self.wakeup_reorder)
    }
}

impl<'a> FaultPlanBuilder<'a> {
    /// Construct a builder backed by `rng`. The caller is expected to
    /// have already named the sub-stream — typically by calling
    /// [`crate::SimRng::rng_for`] with `"faults"` and passing the
    /// returned `ChaCha8Rng` here.
    ///
    /// Default tunables: `density = 0.05` (≈5% of ticks carry a
    /// fault), `max_tick = 1024`, all v1 variants enabled.
    pub fn new(rng: &'a mut ChaCha8Rng) -> Self {
        Self {
            rng,
            density: 0.05,
            max_tick: 1024,
            variants: VariantMask::all(),
        }
    }

    /// Set the per-tick fault density (probability that a given tick
    /// carries a fault). Clamped to `[0.0, 1.0]`.
    pub fn density(mut self, density: f64) -> Self {
        self.density = density.clamp(0.0, 1.0);
        self
    }

    /// Set the inclusive upper bound on the ticks the builder may
    /// schedule a fault at. Defaults to 1024.
    pub fn max_tick(mut self, max_tick: u64) -> Self {
        self.max_tick = max_tick;
        self
    }

    /// Set the [`VariantMask`].
    pub fn variants(mut self, variants: VariantMask) -> Self {
        self.variants = variants;
        self
    }

    /// Consume the builder and produce a [`FaultPlan`].
    ///
    /// The RNG byte stream consumed is `O(max_tick)` — one
    /// `next_u64()` per candidate tick to decide "fault here?" plus a
    /// handful per chosen tick to pick the variant and parameters.
    /// Because the builder consumes from a *named* sub-stream
    /// (`rng_for("faults")`), adding or removing a different sub-stream
    /// elsewhere does not perturb the bytes the builder sees; the
    /// determinism contract from RFC 0006 §RNG is preserved.
    pub fn build(self) -> FaultPlan {
        let count = self.variants.count();
        if count == 0 || self.density == 0.0 {
            return FaultPlan::new();
        }

        let density_u64 = (self.density * (u64::MAX as f64)) as u64;
        let mut entries: Vec<(u64, FaultEvent)> = Vec::new();

        // Sample one random `u64` per candidate tick. We fold it into
        // a Bernoulli trial against `density_u64`; on success we draw
        // additional bytes for the variant + parameters. This shape
        // means changing `density` from 0.05 to 0.10 doubles the
        // expected fault count without re-shuffling the *positions*
        // already drawn — the underlying ChaCha8 stream byte index
        // stays one-to-one with the tick index.
        let rng = self.rng;
        for tick in 0..=self.max_tick {
            let trial = rng.next_u64();
            if trial >= density_u64 {
                continue;
            }
            // Pick a variant uniformly among the enabled ones.
            let variant_pick = rng.next_u64() % u64::from(count);
            let event = pick_variant(self.variants, variant_pick, rng);
            entries.push((tick, event));
        }
        FaultPlan::from_entries(entries)
    }
}

/// Map an enabled-variant index to the corresponding [`FaultEvent`],
/// drawing parameter bytes from `rng` as needed.
fn pick_variant(mask: VariantMask, idx: u64, rng: &mut ChaCha8Rng) -> FaultEvent {
    let mut remaining = idx;
    for (enabled, factory) in [
        (
            mask.spurious_timer_irq,
            (|_: &mut ChaCha8Rng| FaultEvent::SpuriousTimerIrq)
                as fn(&mut ChaCha8Rng) -> FaultEvent,
        ),
        (
            mask.timer_drift,
            (|r: &mut ChaCha8Rng| FaultEvent::TimerDrift {
                // 1..=4 ticks of drift — small enough to not trivially
                // wedge the run, large enough to flush most ordering
                // hazards.
                ticks: 1 + (r.next_u64() % 4),
            }) as fn(&mut ChaCha8Rng) -> FaultEvent,
        ),
        (
            mask.wakeup_reorder,
            (|r: &mut ChaCha8Rng| FaultEvent::WakeupReorder {
                within_tick: r.next_u64() % 8,
            }) as fn(&mut ChaCha8Rng) -> FaultEvent,
        ),
    ] {
        if !enabled {
            continue;
        }
        if remaining == 0 {
            return factory(rng);
        }
        remaining -= 1;
    }
    // Unreachable in practice (idx < mask.count() by construction);
    // guard with a deterministic fallback rather than panic so the
    // determinism envelope stays clean.
    FaultEvent::SpuriousTimerIrq
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimRng;

    #[test]
    fn empty_plan_serializes_canonically() {
        let p = FaultPlan::new();
        assert_eq!(
            p.to_json_string(),
            "{\"fault_plan_schema_version\": 1, \"entries\": []}"
        );
    }

    #[test]
    fn round_trip_through_json_preserves_every_variant() {
        let plan = FaultPlan::from_entries(vec![
            (0, FaultEvent::SpuriousTimerIrq),
            (3, FaultEvent::TimerDrift { ticks: 2 }),
            (3, FaultEvent::WakeupReorder { within_tick: 1 }),
            (7, FaultEvent::TimerDrift { ticks: 0 }),
        ]);
        let json = plan.to_json_string();
        let parsed = FaultPlan::from_json(&json).expect("parse");
        assert_eq!(parsed, plan);
        // Re-serialize and demand byte-identical JSON.
        assert_eq!(parsed.to_json_string(), json);
    }

    #[test]
    fn parse_rejects_unknown_event_type() {
        let bad = "{\"fault_plan_schema_version\": 1, \"entries\": [\
                   {\"tick\": 0, \"event\": {\"type\": \"page_fault\"}}]}";
        let err = FaultPlan::from_json(bad).unwrap_err();
        assert!(
            err.contains("unknown fault event type"),
            "unexpected error: {err}"
        );
        // The error message must mention the v1 surface so a developer
        // who tries `page_fault` knows it's deferred to Phase 2.1.
        assert!(
            err.contains("spurious_timer_irq"),
            "error should hint at v1 variants: {err}"
        );
    }

    #[test]
    fn parse_rejects_wrong_schema_version() {
        let bad = "{\"fault_plan_schema_version\": 99, \"entries\": []}";
        let err = FaultPlan::from_json(bad).unwrap_err();
        assert!(err.contains("schema_version mismatch"), "{err}");
    }

    #[test]
    fn from_entries_sorts_by_tick_stably() {
        let plan = FaultPlan::from_entries(vec![
            (5, FaultEvent::SpuriousTimerIrq),
            (1, FaultEvent::TimerDrift { ticks: 1 }),
            (5, FaultEvent::TimerDrift { ticks: 2 }),
            (1, FaultEvent::WakeupReorder { within_tick: 3 }),
        ]);
        let ticks: Vec<u64> = plan.entries().iter().map(|(t, _)| *t).collect();
        assert_eq!(ticks, vec![1, 1, 5, 5]);
        // Stable: TimerDrift{1} came before WakeupReorder{3} at tick 1.
        assert_eq!(
            plan.entries()[0].1,
            FaultEvent::TimerDrift { ticks: 1 },
            "stable sort preserved"
        );
        assert_eq!(
            plan.entries()[1].1,
            FaultEvent::WakeupReorder { within_tick: 3 }
        );
    }

    #[test]
    fn push_preserves_sort_stably() {
        let mut p = FaultPlan::new();
        p.push(5, FaultEvent::SpuriousTimerIrq);
        p.push(1, FaultEvent::TimerDrift { ticks: 1 });
        p.push(5, FaultEvent::TimerDrift { ticks: 2 });
        let ticks: Vec<u64> = p.entries().iter().map(|(t, _)| *t).collect();
        assert_eq!(ticks, vec![1, 5, 5]);
        // Tick-5 entries are in insertion order: SpuriousTimerIrq first.
        assert_eq!(p.entries()[1].1, FaultEvent::SpuriousTimerIrq);
        assert_eq!(p.entries()[2].1, FaultEvent::TimerDrift { ticks: 2 });
    }

    #[test]
    fn drain_due_takes_only_matching_tick() {
        let mut p = FaultPlan::from_entries(vec![
            (1, FaultEvent::SpuriousTimerIrq),
            (3, FaultEvent::TimerDrift { ticks: 1 }),
            (3, FaultEvent::WakeupReorder { within_tick: 0 }),
            (5, FaultEvent::SpuriousTimerIrq),
        ]);
        // Tick 0: nothing due.
        assert!(p.drain_due(0).is_empty());
        assert_eq!(p.len(), 4);
        // Tick 1: drains the first entry.
        assert_eq!(p.drain_due(1), vec![FaultEvent::SpuriousTimerIrq]);
        assert_eq!(p.len(), 3);
        // Tick 3: drains both tick-3 entries in order.
        assert_eq!(
            p.drain_due(3),
            vec![
                FaultEvent::TimerDrift { ticks: 1 },
                FaultEvent::WakeupReorder { within_tick: 0 },
            ]
        );
        assert_eq!(p.len(), 1);
        // Tick 6: drains the late tick-5 entry (cannot leave stale
        // entries behind — replay equivalence preserved).
        assert_eq!(p.drain_due(6), vec![FaultEvent::SpuriousTimerIrq]);
        assert!(p.is_empty());
    }

    #[test]
    fn builder_is_deterministic_across_master_seeds() {
        // Same master seed → same fault plan, byte-for-byte.
        let r1 = SimRng::new(0xCAFE_F00D);
        let mut s1 = r1.rng_for("faults");
        let p1 = FaultPlanBuilder::new(&mut s1).max_tick(256).build();

        let r2 = SimRng::new(0xCAFE_F00D);
        let mut s2 = r2.rng_for("faults");
        let p2 = FaultPlanBuilder::new(&mut s2).max_tick(256).build();

        assert_eq!(p1, p2);
        // The plan must contain at least one fault — `density = 0.05`
        // over 257 candidate ticks gives an expected count of ~13;
        // a zero-fault outcome would mean either the RNG is broken
        // or the density math regressed.
        assert!(
            !p1.is_empty(),
            "expected at least one fault under default density"
        );
    }

    #[test]
    fn builder_named_substream_does_not_share_bytes_with_other_streams() {
        // Adding a `rng_for("scheduler")` consumer must not perturb
        // the bytes `rng_for("faults")` emits — the property RFC
        // 0006 §RNG pins as load-bearing for shrinking.
        let r = SimRng::new(0x1111);

        let mut faults_a = r.rng_for("faults");
        let plan_a = FaultPlanBuilder::new(&mut faults_a).max_tick(64).build();

        // Burn bytes on a different sub-stream.
        let mut sched = r.rng_for("scheduler");
        for _ in 0..100 {
            let _ = sched.next_u64();
        }

        let mut faults_b = r.rng_for("faults");
        let plan_b = FaultPlanBuilder::new(&mut faults_b).max_tick(64).build();

        assert_eq!(plan_a, plan_b);
    }

    #[test]
    fn builder_variant_mask_filters() {
        let r = SimRng::new(0x2222);
        let mut s = r.rng_for("faults");
        let plan = FaultPlanBuilder::new(&mut s)
            .max_tick(512)
            .density(0.1)
            .variants(VariantMask::only_reorder())
            .build();
        for ev in plan.events() {
            assert!(matches!(ev, FaultEvent::WakeupReorder { .. }));
        }
    }

    #[test]
    fn builder_zero_density_yields_empty_plan() {
        let r = SimRng::new(0x3333);
        let mut s = r.rng_for("faults");
        let plan = FaultPlanBuilder::new(&mut s).density(0.0).build();
        assert!(plan.is_empty());
    }

    #[test]
    fn builder_empty_mask_yields_empty_plan() {
        let r = SimRng::new(0x4444);
        let mut s = r.rng_for("faults");
        let plan = FaultPlanBuilder::new(&mut s)
            .variants(VariantMask::none())
            .build();
        assert!(plan.is_empty());
    }

    #[test]
    fn fault_kind_maps_v1_variants_to_other() {
        // RFC 0006 v1 fault kinds aren't represented in the trace's
        // FaultKind enum (which was designed against hardware faults);
        // every v1 variant therefore maps to FaultKind::Other.
        assert_eq!(
            FaultEvent::SpuriousTimerIrq.fault_kind(),
            crate::FaultKind::Other
        );
        assert_eq!(
            FaultEvent::TimerDrift { ticks: 1 }.fault_kind(),
            crate::FaultKind::Other
        );
        assert_eq!(
            FaultEvent::WakeupReorder { within_tick: 0 }.fault_kind(),
            crate::FaultKind::Other
        );
    }
}
