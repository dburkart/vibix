---
name: auto-manager
description: Drive a large body of work end-to-end — either from a single scoping issue or a fuzzy topic ("ship GA", "harden the review app") — by discovering scope in the backlog + codebase, filing sub-issues, iterating with the user, planning parallel workstreams, then spawning `/auto-engineer` subagents to ship the whole epic autonomously. Use when the user says "auto-manager", "manage this epic", "orchestrate /auto-engineer across…", or invokes `/auto-manager`.
---

# auto-manager

Takes either a specific scoping issue or a fuzzy topic, and drives it through to a merged epic without requiring the user to manually file each sub-issue, plan workstreams, or coordinate subagents. The skill owns five phases:

0. **Discover** (fuzzy input only) — explore the open backlog + codebase to gather candidate issues and surface gaps; present a scope proposal for the user to approve before doing anything destructive.
1. **Scope** — read the spec / approved scope, inspect the codebase, file well-scoped sub-issues.
2. **Refine** — iterate with the user on the filed plan (rescope, fold, drop).
3. **Plan** — partition issues into independent workstreams with a dependency graph.
4. **Orchestrate** — spawn `/auto-engineer` subagents in parallel (worktree-isolated, background) and respawn as predecessors land.

Read these playbooks before running:

- `docs/agent-playbooks/sdlc.md`
- `docs/agent-playbooks/prioritization.md`
- `docs/agent-playbooks/pr-review.md`

Also read the sibling skills you'll call into:

- `.claude/skills/file-issue/SKILL.md` — used in phase 1 for every sub-issue filed.
- `.claude/skills/auto-engineer/SKILL.md` — hard dependency; phase 4 is meaningless without it.

## Hard requirements

- `/auto-engineer` must exist in this project. If not, **stop** and tell the user.
- The repo must have `gh`, a code-review gate (CODEOWNERS + reviewers, a review bot, or equivalent), and CI wired up — auto-engineer's loop assumes these.

## When to invoke

- User points at a "scoping issue" / "epic" / spec doc and asks to "file everything / plan / manage it."
- User says "auto-manager", "orchestrate this", "file issues and run auto-engineer", or types `/auto-manager #NN` where NN is the parent issue.

## Inputs

Accept any of:
- **Hard scope** — a parent/epic issue number (`/auto-manager #18`).
- **Hard scope** — a pasted spec or file path if the spec is attached to an SSO-gated system the skill can't fetch.
- **Fuzzy scope** — a topic string (`/auto-manager ship GA refusal handling`, `"harden the review app"`, `"close out the factorial epic's P2 follow-ups"`). Run phase 0 first.

If the input is fuzzy, do not skip phase 0 — the user hasn't given you a filed anchor, so you have to build one.

---

## Phase 0 — Discover (fuzzy input only)

Goal: turn a vague topic into a concrete, user-approved scope before any issue is filed or edited.

No destructive actions in this phase. No `gh issue create`, `gh issue edit`, `gh issue close`, PR, or branch creation. Only read operations.

1. **List the open backlog.** `gh issue list --state open --limit 200 --json number,title,labels,body`. Sort by priority then recency.

2. **Explore the codebase** via an `Explore` subagent with the fuzzy topic as input. Ask for: what code exists in the topic area, which files/modules are implicated, which recent PRs touched the area (run `git log --oneline -n 50 -- <likely paths>` if useful). Keep ≤800 words.

3. **Intersect backlog ↔ codebase.** For each candidate backlog issue, judge:
   - **In scope** — clearly part of the topic.
   - **Adjacent** — related but not obviously required; flag for user to include/exclude.
   - **Out of scope** — unrelated.

4. **Identify gaps.** Topics rarely have complete backlog coverage. Use the same gap-review heuristics from phase 2 (assignment logic, rubrics, lifecycle, edge cases, reproducibility) to surface work that's implied but unfiled.

5. **Compose a scope proposal** for the user with three sections:
   - **Existing issues I'd pull in** (numbers + one-line summary each, grouped by why they fit).
   - **Adjacent — want me to include?** (user decides).
   - **Gaps I'd file as new issues** (one-line each, with proposed priority). Do **not** file them yet.

6. **Interview the user** to approve the scope. Use `AskUserQuestion` to batch up the judgment calls — typically: confirm adjacent issues in/out, confirm gaps to file, confirm priority defaults, confirm workstream boundaries if they're non-obvious. Keep it to ≤4 questions.

7. Once the scope is approved, either:
   - **Attach to an existing epic issue** if one already exists — use that as the parent for phase 1's summary comment.
   - **File a new epic issue** via `/file-issue` that enumerates the approved scope. This becomes the parent for phase 1.

Only now proceed to phase 1 with the approved scope.

---

## Phase 1 — Scope

Goal: turn the spec (or the approved phase-0 scope) into a triaged list of sub-issues under the parent.

1. **Fetch the spec.** `gh issue view $N --repo $OWNER/$REPO` for body. If the body links an attachment on an SSO-gated URL (enterprise attachments often return 404 via `GITHUB_TOKEN`), ask the user to paste the spec inline — don't fight the SSO. Fuzzy-scope entry point skips this step since phase 0 already produced the approved scope.

2. **Inspect the codebase.** Dispatch an `Explore` subagent with a structured prompt asking for: repo layout, existing infrastructure in the spec's problem area, adjacent conventions (schema libraries, test runners, CI), and which pieces clearly don't exist. Keep the report ≤800 words. The Explore agent's job is to surface *what exists and what's missing* — not to propose solutions. Skip this step if phase 0 already produced an equivalent codebase map for the same topic.

3. **Draft the sub-issue list.** One issue per meaningful unit of work. Rules of thumb:
   - Each issue fits a single engineer ~1–3 days of work.
   - Each issue names the specific files / functions / types to change when they exist.
   - Each issue calls out its testing expectation (unit + integration/E2E where relevant) — the user will expect this.
   - Dependencies between issues are mentioned inline ("blocks #NN", "depends on #NN").

4. **File each sub-issue via the `/file-issue` skill.** Don't use `gh issue create` directly — `file-issue` enforces the priority + classification labels. One invocation per issue. Include in the body:
   - **Motivation** (1–3 sentences, pointing at the parent epic).
   - **Work** (concrete checklist with file paths).
   - **Out of scope** (what lives in sibling issues — prevents scope creep).
   - **Testing** (unit + integration + E2E where they apply).
   - **Context** (parent epic #, related files, pairs-with issues).

5. **Post a summary comment on the parent epic** listing the filed issues with a dependency-ordered outline. This is the human-readable map of the epic.

Cross-repo work: when an issue belongs in a sibling repo (shared infra, different team), file an **advisory RFC**:
- Title prefix `[RFC]`.
- Labels: `question` (so sibling auto-engineer skips it) + an appropriate `priority:*`.
- Body notes "Advisory / RFC only — no action requested" at the top.

---

## Phase 2 — Refine

Goal: let the user reshape the plan with minimum friction.

After phase 1, stop and wait for feedback. When the user sends scope feedback:

- **Rescope**: `gh issue edit` the title + body. Post a comment explaining the rescope so history is legible.
- **Fold minor into existing**: `gh issue comment` the receiving issue to add the requirement. Don't open a new issue for work that's genuinely a clarification.
- **Drop**: `gh issue close` with a comment naming the replacement issue(s).
- **Add missing**: file via `/file-issue`.
- **Block one on another**: add a comment on the blocker and downstream. Don't rely on GitHub's native "linked issues" only — the comment is the durable signal.

When the user flags a cross-project preference ("use zod", "don't auto-run scorers"), save it as a **memory** (`feedback_*.md`) so it outlives the session. Then apply it to the relevant filed issues.

### Gap review

Before phase 3, offer a gap review: re-read the filed plan and identify **major / minor gaps** (missing work the spec implies but didn't spell out). Common categories:
- Assignment / balancing algorithms for multi-user workflows.
- Rubrics / instructions when human judgment is involved.
- Terminal / edge-case handling that retries don't cover.
- Lifecycle state machines when multiple subsystems need to coordinate.
- Statistical or correctness planning (power, invariants, migrations).
- Presentation-order bias, data versioning, reproducibility metadata.

File each major gap as a new issue. Fold minor gaps as comments on existing issues unless they're clearly standalone.

---

## Phase 3 — Plan

Goal: partition issues into **N independent workstreams** with a dependency graph so phase 4 can parallelize safely.

1. **Group by area**, not by priority. Typical workstreams:
   - **Foundations** (schema, shared types, rubrics) — critical path, usually one owner.
   - **Generation pipeline** (wiring, dispatchers, retries, failure handling).
   - **Review / UI** (user-facing surfaces).
   - **Scorers / automated evaluators**.
   - **Analysis / reporting**.
   - **Cross-cutting infrastructure** (lifecycle, observability, state machines).

2. **Order within each workstream** by blocker chain, earliest-startable first.

3. **Mark cross-workstream blockers** explicitly — phase 4 needs these to know when to respawn.

4. **Flag immediately-startable items** (no inter-workstream deps). These are phase 4's wave 1.

5. Output the plan as a textual table (workstream → ordered issue list) and post no artifact unless the user asks — the plan lives in your head for phase 4. (If the user asks for the workstream plan, print it but do not commit it to a file.)

---

## Phase 4 — Orchestrate

Goal: drive every filed issue to merge without further user input.

Default posture: **full autonomy**. Spawn wave 1 immediately, respawn as deps unblock, until every issue is merged or externally blocked. User is informed via status messages; they are not gated.

### Spawn rules

Every auto-engineer subagent call uses:

- `subagent_type: "general-purpose"` (the skill needs full tool surface).
- `isolation: "worktree"` (mandatory — concurrent agents must not share a working tree).
- `run_in_background: true` (don't block the orchestrator on any single agent).
- `description`: short, e.g. `"Auto-engineer: rubric draft"`.

The prompt to each subagent must include:

- **Which issue(s) to work on, in order.** One issue per agent is simplest; two is OK only when they're in the same workstream and would conflict if parallel.
- **Which predecessors have merged** (PR numbers) so the agent knows it can trust the new surface area.
- **Scope guidance for deferrable bits**: if an optional integration (e.g., wizard wiring, analysis piece) depends on an issue that hasn't landed, instruct the agent to **file a clean follow-up** and proceed rather than block. Give them the `gh` command to check dep state.
- **Pre-existing failures on main** (known tsc errors, migration journal anomalies) so the agent doesn't waste time trying to fix them.
- **Explicit autonomy grant**: *"Full autonomy: merge when code review + CI are both green. Do not pick up another issue after this one merges — exit after merge."* This prevents the agent's own auto-engineer loop from straying outside its assigned scope.
- **Completion report format**: PR URL, merge status, deferred follow-ups.

### Wave rules

- **Wave 1** = every immediately-startable issue (no blockers). Spawn them all at once in one message with multiple Agent tool calls.
- **Don't spawn agents on the same files.** If two issues would touch `shared/types.ts` heavily, sequence them — let the first merge, then spawn the second.
- **Hold agents on shared-metadata surfaces** until the predecessor lands. E.g., if A adds a field to a shared type and B adds another, run A first to avoid rebase pain.
- **Maximum concurrent agents**: as many as makes sense for the workstreams. In practice 4–6 is comfortable; above that, CI / review throughput becomes the bottleneck.
- **Respawn rule**: when a completion notification arrives, check every parked issue whose blockers now include the just-merged PR. Spawn the next batch immediately — don't wait for more notifications to cluster.

### Interview rule (phases 2 + 4)

Ask `AskUserQuestion` **only when human insight is genuinely required** — rubric content, sign-off on statistical thresholds, failure policy, identity model choices. Don't ask for stylistic defaults. Batch up to 4 questions in one call when multiple ambiguities cluster.

For anything that doesn't require judgment: file with a sensible default, document assumptions in an "Open questions" section of the issue body, and move on.

### Completion tracking

Each auto-engineer subagent returns a completion summary. When you receive one:

1. Update the internal task tracker (`TaskUpdate` the relevant task to `completed`).
2. Note any **deferred follow-ups** the subagent filed — these become phase 4's next-wave candidates only if they're in the epic's scope; otherwise defer them to user review after the epic closes.
3. Note any **pre-existing main issues** the subagent surfaced — same pre-existing issue will often be flagged by multiple agents; file it once against the repo after 3+ flags.
4. Spawn the next batch via the wave rules.

### Stop conditions

- **All primary issues merged** → report epic-complete. Print the list of filed follow-ups (P2/P3 from implementation) and ask the user whether to proceed into those or stop.
- **External blocker** (e.g., `<sibling-org>/<sibling-repo>#NN` is prerequisite to a remaining issue) → report which issues are parked on which external dep and stop.
- **Agent reports a structural failure** (e.g., merge conflict that auto-engineer can't resolve, persistent review-system failure) → surface it to the user; don't respawn a new agent on the same issue until the user acknowledges.

---

## What this skill is not

- **Not a replacement for human review.** Auto-engineer merges on green CI + required review approvals — it doesn't guarantee the work is strategically right. The scoping (phase 1–3) is where the user shapes the outcome; after that the skill is an execution engine.
- **Not a priority-queue picker.** Unlike `/auto-engineer` which picks the lowest-priority unblocked issue, this skill runs a *named* epic. It does not pick work from the global backlog.
- **Not for one-off issues.** If the user just wants one issue shipped, use `/auto-engineer #NN` directly.

## Never

- Spawn two agents that will touch overlapping files at the same time.
- Skip phase 1's codebase inspection — shipping an issue list without knowing what exists leads to duplicate scaffolding.
- Use `gh issue create` directly — always go through `/file-issue` so priority labels land correctly.
- Merge any PR yourself in the orchestrator — the auto-engineer subagent does the merge. The orchestrator only spawns and tracks.
- Proceed into follow-ups without confirming with the user after the primary epic closes.
