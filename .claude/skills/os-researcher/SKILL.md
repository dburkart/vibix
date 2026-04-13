---
name: os-researcher
description: Given an OS topic, deeply research it from canonical sources, draft an RFC, run it through simulated peer review, defend it, merge when approved, then break the work into tracked issues. Use when the user says "research <topic>", "write an RFC for <topic>", or invokes `/os-researcher <topic>`.
---

# os-researcher

Read `docs/agent-playbooks/rfc.md` before running — RFC numbering, the document
template, research sources, reviewer archetypes, review comment format, defense cycle
rules, approval criteria, and post-approval issue filing all live there.

Read `docs/agent-playbooks/sdlc.md` for branch, commit, and PR conventions.

Read `docs/agent-playbooks/prioritization.md` before the issue-filing phase.

## When to invoke

- User says "research X", "write an RFC for X", "design X for vibix", or similar.
- User types `/os-researcher <topic>` (optionally with `--skip-research` to jump
  straight to drafting if a research summary is already in context).

## Inputs

| Parameter | Source |
|---|---|
| `<topic>` | Required. Free-form OS topic (e.g. "virtual filesystem layer", "POSIX signals", "demand paging"). |
| `--skip-research` | Optional flag. If set, skip Phase 1 and use the research brief already in the conversation. |

If the topic is ambiguous or too broad, ask the user to narrow it before proceeding.

## Cycle

### Phase 1 — Research

*Skip if `--skip-research` is set.*

#### 1a. Identify research categories

For the given topic, identify 4–6 source categories from the canonical list in
`docs/agent-playbooks/rfc.md` (OSDev Wiki, Linux kernel docs, Intel/AMD manuals,
POSIX spec, reference OS projects, academic literature). Prune categories that clearly
don't apply (e.g., IETF RFCs for a memory-management topic).

#### 1b. Spawn parallel research sub-agents

Launch one sub-agent per source category **in parallel** using the `Agent` tool
(`subagent_type: "general-purpose"`). Each sub-agent:

- Searches and fetches its assigned source(s) using `WebSearch` and `WebFetch`.
- Returns a structured report with:
  - **Summary** (150–300 words): what this source covers for the topic.
  - **Key findings** (3–5 bullets): directly relevant facts, design patterns, or
    constraints.
  - **Citable data**: direct quotes, spec clause numbers, paper titles/authors, or
    concrete implementation details worth including in the RFC body.
  - **Gaps**: anything this source doesn't answer that another source might.

Prompt template to pass each sub-agent (fill in `<TOPIC>` and `<SOURCE>`):

```
You are a research assistant helping write an OS kernel RFC for vibix (an x86-64
Rust kernel) on the topic: <TOPIC>.

Your assigned source: <SOURCE>

Search and read that source deeply. Return a structured report:

## Summary
<150–300 words on what you found relevant to the topic>

## Key Findings
- <finding 1>
- <finding 2>
- <finding 3>

## Citable Data
<direct quotes, spec clauses, paper titles, concrete numbers worth citing>

## Gaps
<what this source doesn't cover that another source might>

Be specific and technical. This report will be synthesized with 3–5 other source
reports to produce an RFC for a real kernel project.
```

#### 1c. Synthesize into a research brief

When all sub-agents return, combine their reports into a single **Research Brief**
(≤ 600 words):

- Unified summary of what is known about the topic.
- Consolidated key findings (de-duplicated).
- Conflicts or trade-offs surfaced across sources.
- Gaps that remain unresolved (flag in the RFC's Open Questions).

Keep the research brief in context — the RFC draft is written directly from it.

---

### Phase 2 — Assign RFC number and draft

#### 2a. Assign the next RFC number

```sh
ls docs/RFC/ 2>/dev/null | sort | tail -1
```

Parse the leading digits from the filename. If the directory is empty or missing,
start at `0001`. Increment by 1 and zero-pad to 4 digits. Create `docs/RFC/` if it
doesn't exist.

#### 2b. Choose a slug

Derive a `<kebab-slug>` (≤ 5 words, lowercase, hyphens) from the topic title.

#### 2c. Write the RFC file

Write `docs/RFC/<NNNN>-<kebab-slug>.md` using the template from
`docs/agent-playbooks/rfc.md`. Fill every section from the research brief:

- **Abstract**: 2–4 sentences.
- **Motivation**: grounded in actual vibix gaps surfaced during research.
- **Background**: cite specific sources found in Phase 1.
- **Design**: the main section — be concrete about data structures, algorithms, and
  interfaces. Sub-sections are encouraged.
- **Security / Performance Considerations**: drawn from reviewer-archetype focus areas
  (pre-empt blocking findings where possible).
- **Alternatives Considered**: document the trade-offs surfaced during research.
- **Open Questions**: include any gaps from the research brief.
- **Implementation Roadmap**: 4–8 independently-landable work items, ordered
  dependency-first.

Set `status: Draft` and `created: <today's date>`.

---

### Phase 3 — Open the RFC PR

Branch and commit per `docs/agent-playbooks/sdlc.md`:

```sh
git checkout main && git pull
git checkout -b rfc/<NNNN>-<kebab-slug>
```

Stage and commit the RFC file:

```
git add docs/RFC/<NNNN>-<kebab-slug>.md
git commit -m "rfc(<NNNN>): <Title> [Draft]

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
```

Push and open the PR:

```sh
git push -u origin rfc/<NNNN>-<kebab-slug>
```

```
mcp__github__create_pull_request(
  owner="dburkart", repo="vibix",
  title="RFC <NNNN>: <Title>",
  head="rfc/<NNNN>-<kebab-slug>",
  base="main",
  body="""
## Summary

RFC <NNNN> proposes <1–2 sentence summary of the design>.

This PR contains a design document only — no kernel code changes. The RFC will be
reviewed by four archetype reviewers (security researcher, OS engineer, user space
staff engineer, academic), revised until all blocking findings are addressed, then
merged. Implementation issues will be filed from the roadmap section after merge.

## RFC sections

- Abstract
- Motivation
- Background
- Design (with sub-sections)
- Security Considerations
- Performance Considerations
- Alternatives Considered
- Open Questions
- Implementation Roadmap

## Test plan

- [ ] All four archetype reviewers post a review comment.
- [ ] All blocking findings are addressed in at most 2 defense cycles.
- [ ] RFC frontmatter updated to `status: Accepted` before merge.
"""
)
```

Record the PR number. Update the RFC frontmatter to `status: In Review`, commit, and
push.

---

### Phase 4 — Peer review

Spawn all four reviewer sub-agents **in parallel** using `Agent`
(`subagent_type: "general-purpose"`). Pass each:

- The full RFC content (read the file and include it verbatim in the prompt).
- Their archetype persona, focus areas, and what constitutes a blocking finding
  (from `docs/agent-playbooks/rfc.md`).
- The PR number and repo (`dburkart/vibix`).
- The exact review comment format required (from `docs/agent-playbooks/rfc.md`).
- Instructions to post the review via `mcp__github__add_issue_comment` with
  `owner="dburkart"`, `repo="vibix"`, `issue_number=<PR>`.

Prompt template (fill in `<ARCHETYPE>`, `<FOCUS>`, `<BLOCKS_ON>`, `<RFC_CONTENT>`,
`<PR_NUMBER>`):

```
You are a <ARCHETYPE> reviewing an OS kernel RFC for vibix (an x86-64 Rust kernel).

Your focus areas: <FOCUS>

You block on (i.e., must issue CHANGES REQUESTED for): <BLOCKS_ON>

Read the RFC below and post a structured review comment on GitHub PR #<PR_NUMBER>
in the repo dburkart/vibix. Use mcp__github__add_issue_comment with
owner="dburkart", repo="vibix", issue_number=<PR_NUMBER>.

Your comment MUST follow this exact format:

### Review: <ARCHETYPE>

**Summary:** <1–2 sentence overall assessment.>

**Blocking findings:**
- [B1] <short label> — <explanation>

**Advisory findings:**
- [A1] <short label> — <explanation>

**Verdict:** CHANGES REQUESTED | LGTM

---

RFC content:

<RFC_CONTENT>
```

After all four sub-agents complete, fetch the PR comments to confirm all four review
comments were posted:

```
mcp__github__pull_request_read(owner="dburkart", repo="vibix", pullNumber=<PR>)
```

---

### Phase 5 — Defense cycle

This phase repeats up to **2 times**. Track the cycle count.

#### 5a. Collect blocking findings

Fetch all PR comments. Extract every `[B*]` finding from comments whose header
matches `### Review: <Archetype Name>`. Group by archetype.

If zero blocking findings across all archetypes → skip to Phase 6 (Approval).

#### 5b. Update the RFC

For each blocking finding:

1. Decide: address in the RFC (add mitigations, redesign, justify with evidence) or
   classify as out-of-scope (requires clear reasoning).
2. Edit `docs/RFC/<NNNN>-<kebab-slug>.md` directly.
3. Prefer addressing over deferring — the RFC should be as complete as possible.

#### 5c. Commit and push the updated RFC

```
git add docs/RFC/<NNNN>-<kebab-slug>.md
git commit -m "rfc(<NNNN>): address review findings (defense cycle N)

Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
git push
```

#### 5d. Post a defense comment

Post a **single comment** on the PR via `mcp__github__add_issue_comment` listing:

- Which `[Bx]` findings were addressed and the specific change made.
- Which (if any) were classified as out-of-scope and why.

#### 5e. Re-spawn blocking-archetype reviewers

Only re-spawn the archetypes that had blocking findings. Provide them with the updated
RFC content and ask them to post a **new** review comment (same format) reflecting
the updated design. Their new `LGTM` or `CHANGES REQUESTED` supersedes the old one.

#### 5f. Check cycle count

- Cycle 1 complete → re-evaluate blocking findings from the new reviews (return to 5a).
- Cycle 2 complete with remaining blockers → **stop** (see Stopping).

---

### Phase 6 — Approval and merge

All four archetypes have issued `LGTM`. Proceed:

1. Update `docs/RFC/<NNNN>-<kebab-slug>.md` frontmatter: `status: Accepted`.
2. Update the **Open Questions** section: mark resolved ones answered, flag any
   remaining as "deferred to implementation."
3. Commit and push:
   ```
   git add docs/RFC/<NNNN>-<kebab-slug>.md
   git commit -m "rfc(<NNNN>): mark Accepted

   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>"
   git push
   ```
4. Merge via squash:
   ```
   mcp__github__merge_pull_request(
     owner="dburkart", repo="vibix",
     pullNumber=<PR>, mergeMethod="squash"
   )
   ```
5. Post-merge cleanup:
   ```sh
   git checkout main && git pull
   git branch -d rfc/<NNNN>-<kebab-slug>
   ```

---

### Phase 7 — Break out work

For each `- [ ]` item in the **Implementation Roadmap** section of the merged RFC,
invoke the `file-issue` skill. Pass:

- **Title:** the work item text, ≤ 72 chars, imperative form.
- **Motivation:** "Implements RFC <NNNN> — <RFC title>. <one sentence on why this
  item matters or what it unblocks.>"
- **Work:** sub-tasks inferred from the RFC's Design section, specific enough to act
  on cold in a week.
- **Context:** `docs/RFC/<NNNN>-<slug>.md`, merged PR number.
- **Labels:** follow `docs/agent-playbooks/prioritization.md` — exactly one
  `priority:*`, one or more `area:*`, optional `track:*`.

File all issues and report the full list of URLs to the user.

---

## Stopping

If the defense cycle limit (2 cycles) is exhausted with remaining blocking findings:

1. Update RFC frontmatter `status: Withdrawn`.
2. Commit and push: `"rfc(<NNNN>): withdraw — unresolved blocking findings"`.
3. Close the PR via `mcp__github__update_pull_request` with `state: "closed"`.
4. Post a closing comment listing the unresolved `[Bx]` items and which archetype
   raised each.
5. Invoke `file-issue` to create a follow-up issue titled
   `"Resolve blocked RFC <NNNN>: <Title>"` with `priority:P2`, appropriate `area:*`
   labels, and the list of unresolved findings as work items.
6. Report to the user with the issue URL.

## Never

- Open a PR to `main` directly (all RFC PRs use `rfc/<NNNN>-<slug>` branches).
- Skip the research phase unless `--skip-research` is explicitly set.
- Write the RFC before the research brief is complete — synthesis before drafting.
- Merge without all four archetypes posting `LGTM`.
- File implementation issues before the RFC is merged and `Accepted`.
- Invent new `priority:*` or `area:*` labels when filing issues — update the
  prioritization playbook first.
- Re-use or skip an RFC number.
