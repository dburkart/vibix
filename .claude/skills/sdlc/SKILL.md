---
name: sdlc
description: The vibix software-delivery workflow — how changes move from idea to merged on main. Use when starting a milestone/task, committing, or opening/updating a PR.
---

# vibix SDLC

Read `docs/agent-playbooks/sdlc.md` first for repo-level branch, commit, push, and PR policy.

Read `docs/agent-playbooks/pr-review.md` when the task includes CI interpretation or review response.

## When to use this skill

Use this skill when the task involves:

- starting a new cohesive change on its own branch
- deciding what checks to run before push
- preparing a PR body and opening a PR
- responding to review feedback without rewriting reviewed history

## Claude-specific notes

- Each commit must include the `Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>`
  trailer.
- When the runtime supports GitHub issue assignment or issue creation, you may use those features to
  reduce duplicate work and capture follow-up items; keep the shared SDLC playbook as the source of
  truth for the policy itself.
- If you open a PR from Claude, prefer the repo's standard summary-plus-testing structure from the
  shared playbook rather than embedding extra Claude-specific footer text.
- If CI or review follow-up is needed, hand off to `wait-for-pr` only for Claude-specific polling
  and automation. Review classification still comes from the shared playbook.

## Never

- Commit directly to `main`.
- Force-push or rewrite reviewed commits unless the user explicitly approves that change in workflow.
- Merge a PR on the user's behalf unless asked.
