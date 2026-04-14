# Skill composition: calling skills from inside skills

## The core problem

The `Skill()` tool **replaces** the current skill's execution context. When a running skill
calls `Skill("foo")`, `foo` takes over and the original skill is gone — there is no return
path. This is correct for top-level user invocations, but it terminates any loop that tries
to call a skill as a helper mid-cycle.

**Broken pattern — terminates the loop:**
```
# In auto-engineer step 8:
Skill("file-issue", "file an issue for ...")   # ← loop dies here
# Nothing after this line ever runs
```

**Working pattern — loop continues:**
```
# Spawn a subagent; it runs, returns a result, and the loop picks up where it left off.
Agent(
  description="File follow-up issue: <title>",
  subagent_type="general-purpose",
  prompt="Read .claude/skills/file-issue/SKILL.md ... <full context>"
)
```

## Decision table

| Invocation site | Correct approach |
|---|---|
| Top-level user request (no loop) | `Skill("foo")` |
| Mid-loop, skill wraps shell commands only | Run the shell commands directly via `Bash` |
| Mid-loop, skill requires MCP calls or multi-step reasoning | `Agent()` with the skill's SKILL.md embedded in the prompt |

## How to wrap a skill in Agent()

The subagent starts cold — it has no conversation history and no ambient context.
Everything it needs must be in the prompt:

```
Agent(
  description="<short label for the work log>",
  subagent_type="general-purpose",    # or "Plan" for pure planning
  prompt="""
Read <path/to/SKILL.md> and any playbooks it references.
Then perform the following task:
  <exactly what you need done>
  <all relevant context: issue numbers, file paths, PR numbers, commit SHAs>
Return <what you need back — e.g. the new issue number and URL>.
"""
)
```

Keep these rules in mind:
- One Agent() per discrete unit of work — do not batch unrelated items.
- Include explicit file/resource references; do not assume the subagent can infer context.
- The result comes back as conversation text; parse it before proceeding.

## Skills that must never be called via Skill() from a loop

| Skill | Correct mid-loop approach |
|---|---|
| `file-issue` | `Agent()` with SKILL.md embedded (see auto-engineer § "Calling file-issue from a loop") |
| `usage` | Run `bash .claude/skills/usage/probe.sh` directly and parse the JSON |
| `wait-for-pr` | Never delegated from auto-engineer — use the embedded poll loop in step 6 |
| `build` / `test` | Run `cargo xtask build` / `cargo xtask test` directly |

## Guidance for new skill authors

If your skill is designed to be called from inside a loop (e.g. from auto-engineer), write
it so the *loop* can call it safely:

1. **Prefer shell-scriptable output** when the skill is a probe or report — emit
   machine-readable lines a parent can parse directly without spawning a subagent.
2. **Document how to call you from a loop** in your SKILL.md if the correct invocation
   differs from the top-level `Skill()` form.
3. **If your skill itself contains a loop** (poll, retry, reschedule), document that calling
   `Skill("your-skill")` from inside another loop would steal the `ScheduleWakeup` thread,
   and provide the Agent()-based alternative.
