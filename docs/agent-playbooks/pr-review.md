# PR review playbook

This playbook captures repo-level PR readiness and review classification rules that apply across
agent runtimes.

## CI readiness

A PR is ready for a final review summary only when:

1. All required checks have reached a terminal state.
2. No check is waiting on manual approval.
3. The reviewer-facing summary clearly separates passing checks from failures or skipped jobs.

Do not report "all clear" while core CI is still pending.

## Review classification

Classify feedback into these buckets:

- **Actionable bugs**: correctness issues, broken invariants, panics, unsound behavior, or changes
  that can regress the expected kernel or tooling behavior
- **In-scope nits**: small improvements on code changed by the PR that are cheap to address without
  expanding scope
- **Out-of-scope nits**: architectural suggestions or cleanup requests that would materially expand
  the PR beyond its intended goal

## Response policy

- Fix actionable bugs before merge.
- Fix in-scope nits when the cost is low and the change improves the review outcome.
- Defer out-of-scope nits to a follow-up issue or handoff note.
- Prefer follow-up commits on the same branch instead of rewriting reviewed history.

## Review summary shape

A good summary includes:

- PR number and title
- CI results, grouped by pass/fail/skipped state
- Review findings, grouped by the buckets above
- Any explicit follow-up items that were deferred
