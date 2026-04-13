---
name: cursor-cloud-auto-engineer
description: Drive one vibix issue-to-PR cycle inside Cursor Cloud — pick an unblocked issue, plan the change, implement it, validate it, push a branch, and open or update a PR. Use when the user says "auto-engineer", "auto-pilot", "go run the loop", or invokes `/cursor-cloud-auto-engineer`.
compatibility: Cursor Cloud agent with git push access, `ManagePullRequest`, and read-only `gh`.
disable-model-invocation: true
metadata:
  runtime: cursor-cloud
  source_skill: .claude/skills/auto-engineer/SKILL.md
---

# cursor-cloud-auto-engineer

Read these shared playbooks first:

- `docs/agent-playbooks/sdlc.md`
- `docs/agent-playbooks/build-run.md`
- `docs/agent-playbooks/testing.md`
- `docs/agent-playbooks/pr-review.md`
- `docs/agent-playbooks/prioritization.md`

This is the Cursor Cloud companion to `.claude/skills/auto-engineer/SKILL.md`. Keep the same
core loop — pick work, plan, implement, validate, push, and open a PR — but adapt it to Cursor
Cloud's actual tool surface:

- use Cursor-native tools such as `TodoWrite`, `Subagent`, and `ManagePullRequest`
- use `gh` only for read-only inspection of issues, PRs, CI, and review comments
- do not assume Claude-only primitives such as `ScheduleWakeup`, `/compact`, `/usage`, or GitHub
  write MCPs are available
- keep any wait loop bounded to the current turn instead of trying to self-reschedule

## When to invoke

- User explicitly asks to "auto-engineer", "auto-pilot", "run the loop", or similar in Cursor.
- User invokes `/cursor-cloud-auto-engineer`.
- User points at a specific issue (`#NN` or URL) and wants the agent to take it from branch to PR.

Because this workflow is broad and potentially expensive, keep it explicit. Do not trigger it
implicitly for ordinary coding requests.

## Success state

One invocation is successful when all of these are true:

1. A single cohesive issue or task is selected.
2. The change is implemented on its own topic branch from `main`.
3. The highest-signal checks for the scope have passed.
4. The branch is pushed.
5. A PR targeting `main` exists and includes a concise summary plus the exact checks that ran.

Unlike the Claude version, Cursor Cloud should normally stop at the PR handoff unless the user
explicitly asks for more follow-up.

## Cycle

### 1. Pick one unblocked issue

If the user already named an issue, use it. Otherwise inspect open issues with `gh issue list`
and choose one that is not obviously blocked.

Suggested query:

```sh
gh issue list --search 'no:assignee' --state open \
  --json number,title,labels,body,assignees,url
```

Filter out issues labeled `blocked`, `needs-discussion`, `question`, or `wontfix`, plus issues
whose body clearly references an unresolved dependency. Apply the pick-order policy from
`docs/agent-playbooks/prioritization.md`: sort `priority:P0` → `P1` → `P2` → `P3`, preferring
`track:userspace` / `track:filesystem` / `track:terminal` / `track:posix` in that order within a
priority bucket, and only fall back to lowest-numbered first inside a (priority, track) bucket.
Issues missing a `priority:*` label rank after `priority:P3`.

Cursor Cloud's `gh` access is read-only in this repo, so do not try to assign the issue. If
issue assignment matters, note that limitation in the final handoff or PR body.

### 2. Plan with Cursor tools

Gather context before editing:

- use `Subagent` with `explore` for broad readonly codebase discovery
- use `Subagent` with `generalPurpose` when you want a deeper implementation plan
- use `TodoWrite` to track the active cycle

Turn the result into a concrete implementation plan:

- files to change
- symbols to add or edit
- tests or validation steps to run
- risks and out-of-scope follow-ups

If the chosen issue is too broad for one coherent PR, narrow it before editing and state the
reduced scope in the PR.

### 3. Implement on a topic branch

Start from `main` on a dedicated branch. Follow the active environment's branch naming rules; in
Cursor Cloud that usually means a `cursor/<descriptive-slug>` branch, possibly with a required
suffix injected by the environment.

While editing:

- keep commits coherent
- do not touch unrelated dirty-worktree changes
- prefer the shared playbooks over improvised build or test commands
- use `cargo xtask` entry points instead of raw kernel build commands

### 4. Validate according to scope

Use the narrowest high-signal checks that match the change, then escalate if risk justifies it.

- Kernel or behavior changes: run `cargo xtask test` and `cargo xtask smoke`
- Build-system or tooling changes: run the most relevant `cargo xtask` or `cargo clippy` command
- Docs/process/skill-only changes: run a targeted validation step appropriate to the edit; a
  low-cost repo sanity check such as `cargo xtask build` is optional, not mandatory

Cursor Cloud runtime notes for this repo:

- trust `cargo clippy -p xtask --all-targets -- -D warnings` as the Cloud lint command
- when manually booting the kernel, prefer `timeout 6 cargo xtask run` or a tmux-backed session

Do not claim success based only on compilation or branch creation if the change merits stronger
validation.

### 5. Commit, push, and open the PR

Before the final handoff:

1. Stage the intended changes only.
2. Create coherent commits with a short imperative subject and a body explaining why.
3. Push with `git push -u origin <branch>`.
4. Open or update the PR with `ManagePullRequest` against `main`.

Use the repo's standard PR body shape:

```markdown
## Summary
- <what changed>
- <why it changed>

## Test plan
- [x] <exact command and result>
```

If the work maps cleanly to a GitHub issue, include `Closes #<N>` near the top of the PR body so
the issue closes when a human merges the PR.

Never use `gh` for write operations such as creating or editing PRs.

### 6. Handle follow-up within the current turn only

If the current turn still has room and the user asked for CI follow-up, run a bounded review round
against the PR using read-only GitHub commands such as:

```sh
gh pr view <PR>
gh pr checks <PR>
gh api "repos/{owner}/{repo}/issues/<PR>/comments"
```

Use this cadence:

1. Inspect immediately after opening or updating the PR.
2. If checks or review-bot feedback are still pending, sleep `180` seconds.
3. Re-check.
4. Repeat until everything reaches a terminal state or the round has spent `900` seconds total
   waiting.

Treat one such bounded poll window as a single review round. Within that round:

- fix actionable bugs or cheap in-scope nits as follow-up commits
- never amend or force-push reviewed history
- update the PR after each follow-up push

If checks are still pending after `900` seconds, a review bot has not posted yet, or manual
approval is required, stop with a concise status instead of trying to emulate Claude's wake-up
loop across turns.

## Cursor Cloud differences from Claude auto-engineer

- No self-rescheduling. One invocation handles one issue-to-PR cycle.
- Review polling is bounded: sleep 3 minutes between checks, for up to 15 minutes per review round.
- No `/compact` or `/usage` quota gate unless the active environment adds equivalents.
- No GitHub write MCPs for issue assignment, issue filing, issue comments, or merge.
- No self-merge. Leave the PR ready for a human reviewer unless the user explicitly grants a merge
  workflow and the environment provides a supported merge tool.

## Never

- Commit directly to `main`.
- Force-push or rewrite reviewed commits.
- Use `gh` for write actions.
- Claim checks passed without running them.
- Wait indefinitely on CI or review bots inside one Cursor Cloud turn.
