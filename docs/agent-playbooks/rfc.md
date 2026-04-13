# RFC Process

RFCs (Requests for Comments) are the primary mechanism for designing and socializing
significant changes to vibix **before** implementation begins. An RFC is not a commit
message or a GitHub issue — it is a design document that captures motivation,
architecture, trade-offs, and the shape of the work stream so that bad assumptions are
caught early, not mid-implementation.

## When to write an RFC

Write an RFC for changes that are:

- **New subsystems** — a scheduler, a filesystem, a device class, or any new kernel
  abstraction with its own state machine and public API.
- **Cross-cutting** — changes that touch ≥ 3 subsystems or alter a fundamental
  invariant (e.g., the interrupt-safety contract, the virtual memory layout, the syscall ABI).
- **ABI-visible** — new or changed syscall interfaces, `/proc`/`/sys` layouts, or binary
  formats that userspace will depend on.
- **Architecturally uncertain** — design points where two or more viable approaches
  exist and the choice has lasting consequences.

You do **not** need an RFC for:

- Bug fixes, performance improvements, or refactors within a single subsystem.
- Documentation-only changes.
- Feature additions with an obvious design that fits cleanly within an existing
  subsystem's API.

## Numbering

RFCs are numbered monotonically, zero-padded to four digits: `0001`, `0002`, etc.

To assign the next number:

1. List `docs/RFC/` and find the highest-numbered file (`NNNN-*.md`).
2. Next RFC = `NNNN + 1`, formatted as `%04d`.
3. If `docs/RFC/` is empty or does not exist, start at `0001`.

Never reuse or skip a number. If an RFC is abandoned, leave the file with
`status: Withdrawn` rather than deleting it.

## File location

```
docs/RFC/<NNNN>-<kebab-slug>.md
```

`<kebab-slug>` is a short (≤ 5 words), lowercase, hyphen-separated description.

Examples:
- `docs/RFC/0001-virtual-memory-map.md`
- `docs/RFC/0002-ext2-filesystem-driver.md`
- `docs/RFC/0003-posix-signals.md`

## Document template

Every RFC uses this template verbatim. Fill every section. If a section genuinely has
nothing to say, write `N/A — <one sentence explaining why>` rather than leaving it
blank. A blank section signals an incomplete design.

```markdown
---
rfc: <NNNN>
title: <Title Case Title>
status: Draft
created: <YYYY-MM-DD>
---

# RFC <NNNN>: <Title>

## Abstract

<2–4 sentences. What is being proposed and what does it achieve?>

## Motivation

<Why is this needed? What is currently broken or missing? What does vibix gain?>

## Background

<Prior art: relevant subsystems already in vibix, analogous designs in other OS
projects (Linux, SerenityOS, Redox), academic literature.>

## Design

<The architecture and technical specification. Use sub-sections freely.>

### Overview

### Key Data Structures

### Algorithms and Protocols

### Kernel–Userspace Interface

<Syscall numbers, argument layout, return values, errno codes, /proc or /sys layout.
Write N/A if the change is kernel-internal only.>

## Security Considerations

<Privilege model impact, new attack surface, information-disclosure risks, mitigations.>

## Performance Considerations

<Hot-path impact, memory overhead, lock contention, SMP scalability.>

## Alternatives Considered

<What else was considered and why it was rejected or deferred.>

## Open Questions

<Unresolved design points that need decisions before or during implementation.>

## Implementation Roadmap

<Independently-landable work items. These become GitHub issues when the RFC is
accepted.>

- [ ] <work item 1>
- [ ] <work item 2>
```

## Status lifecycle

| Status | Meaning |
|---|---|
| `Draft` | Being written; not ready for review. |
| `In Review` | PR open; peer review in progress. |
| `Accepted` | All blocking reviewer concerns addressed; PR merged. |
| `Implemented` | All implementation roadmap items closed. |
| `Withdrawn` | Abandoned; file kept for reference. |

Update the frontmatter `status` field at each transition. Do **not** retroactively
edit the `created` date.

## Research methodology

Before drafting an RFC, gather information from these canonical sources:

| Source | What it covers |
|---|---|
| `wiki.osdev.org` | Practical x86 kernel dev knowledge; hardware quirks; community-vetted patterns |
| `kernel.org/doc/html/latest/` | Linux subsystem design; locking discipline; driver model |
| Intel SDM (`intel.com`) | x86-64 instruction reference; MSR definitions; paging structures |
| AMD APM (`amd.com`) | AMD-specific extensions; SVM; IOMMU |
| `pubs.opengroup.org/onlinepubs/9699919799/` | POSIX.1-2017; syscall semantics; error codes |
| SerenityOS (`github.com/SerenityOS/serenity`) | C++ x86 kernel patterns; userspace-facing API design |
| Redox OS (`github.com/redox-os/redox`) | Rust kernel patterns; capability-based approach |
| Google Scholar / Semantic Scholar | Academic papers on OS design, scheduling, formal verification |
| `rfc-editor.org` | IETF RFCs for networking and protocol topics |

Delegate each source category to a **separate research sub-agent** running in parallel.
Each sub-agent should return:

- A 150–300 word summary of what it found.
- 3–5 key findings directly relevant to the topic.
- Direct quotes or data points worth citing in the RFC body.
- Gaps or contradictions across sources worth calling out.

The main agent synthesizes all sub-agent summaries before writing the RFC draft.

## Peer review archetypes

The `os-researcher` skill spawns four reviewer sub-agents in parallel after the RFC PR
is opened. Each reads the RFC and posts a structured PR comment identifying itself by
archetype.

### Security Researcher

**Focus:** Privilege model, attack surface, side-channels, memory-safety invariants,
TOCTOU, kernel-to-user data flows.

**Asks:** Can a user process trigger this path maliciously? What happens at bounds
violations? Are there information-disclosure risks in error codes or timing? Does the
design create a new privilege-escalation surface?

**Blocks on:** Any finding that could allow unprivileged code to gain elevated access,
corrupt kernel state, or leak kernel addresses/data.

### OS Engineer

**Focus:** Kernel correctness, interrupt safety, memory ordering, lock discipline, SMP
correctness, ABI stability, resource lifecycle (allocation/free symmetry).

**Asks:** Is this IRQ-safe? Does it hold under SMP? What is the locking order? Are
there hidden races? Is the data layout cache-friendly?

**Blocks on:** Any concurrency bug, undefined behaviour, or violation of the project's
existing invariants (interrupt-safety contract, memory model).

### User Space Staff Engineer

**Focus:** Syscall API ergonomics, POSIX compliance, composability with existing
interfaces, application developer experience, error reporting.

**Asks:** What is the exact syscall interface? How does this compose with `select` /
`poll` / `epoll`? What do errno values mean to a userspace programmer? Is this API
idiomatic for C and Rust callers?

**Blocks on:** Any interface that breaks POSIX semantics without a documented
exception, or that is impossible to implement correctly from userspace.

### Academic

**Focus:** Theoretical foundations, comparison to published research, formal
properties, correctness invariants, novelty vs. duplication of prior work.

**Asks:** Has this been studied formally? Which papers are directly relevant? Does the
design maintain the right formal invariants (deadlock-freedom, liveness, isolation)?
Is there a simpler or more principled approach in the literature?

**Blocks on:** A known published result that directly contradicts the design's safety
or liveness claims.

## Review comment format

Each reviewer sub-agent posts a **single PR comment** in this format. The opening
`### Review: …` header is load-bearing — the defense cycle uses it to attribute
findings to the right archetype.

```
### Review: <Archetype Name>

**Summary:** <1–2 sentence overall assessment.>

**Blocking findings:**
- [B1] <short label> — <explanation>

**Advisory findings:**
- [A1] <short label> — <explanation>

**Verdict:** CHANGES REQUESTED | LGTM
```

`CHANGES REQUESTED` means ≥ 1 blocking finding exists. `LGTM` means no blocking
findings (advisory findings are fine to ship with).

If the archetype finds nothing noteworthy, a `LGTM` with an empty blocking list is a
valid and complete review — do not pad it.

## Defense cycle

After all four reviewer comments are posted:

1. Collect every `[B*]` blocking finding across all archetypes.
2. For each blocking finding, update the RFC: add mitigations, redesign the affected
   section, or justify the original approach with cited evidence.
3. Commit and push the updated RFC to the PR branch.
4. Post a **single reply comment** listing which `[Bx]` items were addressed and how.
5. Re-spawn **only** the archetypes that had blocking findings; they re-read the
   updated RFC and post a new review comment replacing their previous verdict.

**Maximum 2 defense cycles.** After the 2nd cycle, if blocking findings remain, update
the RFC `status` to `Withdrawn`, close the PR with a comment explaining the unresolved
issues, and file a follow-up issue (via `file-issue`) for a human to resolve them.

## Approval criteria

An RFC is approved — and ready to merge — when **all** are true:

- All four archetype reviewers have issued `LGTM` (or never had blocking findings).
- The RFC's frontmatter `status` is updated to `Accepted`.
- The **Open Questions** section is updated: answered questions resolved, remaining
  ones explicitly flagged as "deferred to implementation."

## Post-approval

After merging:

1. Confirm `status: Accepted` is in the merged file.
2. For each `- [ ]` item in the **Implementation Roadmap** section, invoke the
   `file-issue` skill:
   - **Title:** the work item text, imperative phrase, ≤ 72 chars.
   - **Motivation:** "Implements RFC NNNN — <title>. <1 sentence on why this item matters.>"
   - **Work:** sub-tasks inferred from the RFC's Design section.
   - **Context:** `docs/RFC/NNNN-<slug>.md`, PR number, any related open issues.
   - **Labels:** follow `docs/agent-playbooks/prioritization.md` — exactly one
     `priority:*`, one or more `area:*`, optional `track:*`.
3. Report all filed issue URLs to the user.
