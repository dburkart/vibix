---
name: file-issue
description: File a new vibix GitHub issue with the correct priority/area/track labels applied up front. Use whenever an agent needs to capture a new unit of work — follow-ups from a merged PR, TODOs discovered while coding, or manually-requested issues. Invoked as `/file-issue`.
---

# file-issue

Files a single GitHub issue against `dburkart/vibix` with priority, area, and (when
applicable) track labels applied on creation. Keeps the backlog triaged in one step instead
of leaving un-labeled issues that pollute the auto-engineer candidate set.

Read `docs/agent-playbooks/prioritization.md` before running — the label taxonomy, the P0
critical path, and the triage rules all live there. This skill is the mechanical front-end
for that policy.

## When to invoke

- A merged PR surfaced out-of-scope follow-up work that needs its own issue (auto-engineer
  step 8, or a human reviewer deferring a nit).
- A `TODO`/`FIXME`/`unimplemented!()` was introduced that deserves tracking.
- The user says "file an issue for …" or invokes `/file-issue` directly.
- The issue-backfill workflow proposes new items during periodic triage.

Do **not** use this skill to edit an existing issue — use `mcp__github__issue_write` with
`method: "update"` for that.

## Inputs

Either accept them as free-form arguments after `/file-issue`, or infer from the invoking
context:

- **title** — imperative phrase, ≤ 72 chars, no emoji.
- **motivation** — 1–3 sentences on why this matters and what it unblocks.
- **work** — bulleted sub-tasks, concrete enough to act on cold in a week (file paths,
  struct names, function signatures when known).
- **context** — relevant commit SHAs, file paths, existing issue numbers, or the PR that
  surfaced the follow-up.

If any of those are missing and cannot be reasonably inferred, ask the user before filing.

## Cycle

### 1. Dedupe

Search open issues for overlap before filing:

```
mcp__github__search_issues(
  query="repo:dburkart/vibix is:open <keywords from title>",
)
```

If a strong duplicate exists, **do not** file. Instead, add a comment on the existing issue
linking the new context (via `mcp__github__add_issue_comment`) and return its URL.

### 2. Decide labels

Follow the triage rules in `docs/agent-playbooks/prioritization.md`:

1. Assign exactly one `priority:P0` / `P1` / `P2` / `P3` label. The rule of thumb:
   - Blocks PID 1 / first useful userspace → `priority:P0`.
   - Required for POSIX readiness, real FS, or usable terminal → `priority:P1`.
   - Polish / QoL / hardening → `priority:P2`.
   - SMP / advanced / optimization → `priority:P3`.
2. Assign one or more `area:*` labels matching the subsystem(s): `area:userspace`,
   `area:mem`, `area:fs`, `area:driver`, `area:console`, `area:smp`, `area:debug`,
   `area:perf`, `area:security`, `area:time`.
3. Add a `track:*` label **only** when the issue directly unblocks one of the named
   milestones (`track:userspace`, `track:filesystem`, `track:terminal`, `track:posix`).
4. If the issue is a bug rather than new work, also add `bug`. Otherwise prefer
   `enhancement` when the issue adds a capability.
5. Never invent a new label from this skill. If the taxonomy is missing a dimension, stop
   and update `docs/agent-playbooks/prioritization.md` in a separate PR first.

### 3. Compose the body

Use the canonical template — identical to the one used by the issue-backfill workflow so the
backlog stays uniform:

```
## Motivation
<1-3 sentences>

## Work
- [ ] <concrete sub-task 1>
- [ ] <concrete sub-task 2>

## Context
<PR/commit/issue references and file paths>
```

### 4. File

```
mcp__github__issue_write(
  method="create",
  owner="dburkart",
  repo="vibix",
  title="<title>",
  body="<templated body>",
  labels=["priority:PN", "area:...", "track:...", ...],
)
```

Report the new issue number and URL back to the caller.

### 5. Record

If the issue was filed from auto-engineer's follow-up capture pass (step 8), include it in
the "captured follow-ups" summary that auto-engineer emits before re-entering its loop.

## Never

- File an issue without at least one `priority:*` and one `area:*` label.
- File an issue that duplicates an open one.
- Invent new priority/area/track label values in-flight. Update the playbook first.
- File speculative "nice-to-have" items with no concrete motivation — they clutter the
  backlog and degrade the auto-engineer candidate set.
- Close, reassign, or relabel issues other than the one being filed.
