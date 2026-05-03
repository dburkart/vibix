# vibix
*Pronounced VIBE-IX*

An experiment in autonomous software engineering: can AI agents, given a
backlog of issues and a set of tools, build a real kernel from scratch? vibix
is that kernel — written in Rust, running on x86_64, built almost entirely by
Claude and Cursor agents looping through plan → implement → PR → review →
merge. The long-term goal is a full operating system. The immediate goal is
to see how far autonomous agents can get before the wheels fall off.

## Instructions for Humans

vibix has assembled a tiny agentic bureaucracy to build itself. There is a
manager, a researcher, and an engineer. They all report to each other in a way
that would probably fail a compliance audit. They are, collectively, writing
a kernel.

- **`/auto-manager`** — the middle manager. Takes an epic issue or a vague
  hand-wave ("harden the boot path") and decides what to do. Design-heavy
  work gets punted to `/os-researcher`; execution work gets filed as sub-issues
  and handed off to a swarm of `/auto-engineer` subagents. It does not write
  any kernel code itself. It is, however, very good at spawning things that
  will.
- **`/os-researcher`** — the one with strong opinions about POSIX. Reads real
  kernel docs and academic papers, writes an RFC, convenes four imaginary
  reviewers to argue with it, revises until they all relent, then merges. Then
  it files implementation issues for someone else to do the actual work.
- **`/auto-engineer`** — the one holding the keyboard. Picks an unblocked
  issue, implements it, opens a PR, argues with the review bot, and loops.
  Stops when main is broken or CI is unreachable. Does not stop for lunch.

Any of the three can be summoned directly. `/auto-manager` is the usual entry
point when the work is bigger than one issue — it will figure out which of its
colleagues to bother.

### `/auto-manager` — the epic orchestrator

Defined in `.claude/skills/auto-manager/SKILL.md`. Accepts either a hard scope
(`/auto-manager #18` against an epic issue or spec) or a vibes-based topic
(`/auto-manager ship GA refusal handling`, `/auto-manager make wait4 less
embarrassing`). The skill:

1. **Discovers scope** — for fuzzy inputs, intersects the open backlog with a
   codebase scan and proposes a scope. You get to say "yes", "no", or "not
   like that" before anything is filed.
2. **Runs an RFC gate** — if the topic is novel or foundational (new VFS,
   scheduler rewrite, signals, IPC, ABI changes) or the design isn't locked,
   it spawns `/os-researcher` as a worktree-isolated subagent and blocks until
   the RFC merges. Execution-only grind and well-precedented changes get
   waved through without ceremony.
3. **Files sub-issues** via `/file-issue` — or, if `/os-researcher` ran, just
   inherits the issues it already filed, like a manager taking credit.
4. **Plans workstreams** — partitions issues into parallel tracks with an
   explicit dependency graph, so the engineers don't rebase each other into
   oblivion.
5. **Orchestrates `/auto-engineer` subagents** in parallel (worktree-isolated,
   background), respawning the next wave as predecessors land, until every
   issue merges or something explodes loudly enough to need a human.

Use `/auto-engineer` or `/os-researcher` directly when you want exactly one
thing shipped or exactly one RFC written. Use `/auto-manager` when you want to
close your laptop and come back later to find out whether a kernel now
exists that didn't before.

### `/auto-engineer` — the implementation loop

The workhorse. Defined in `.claude/skills/auto-engineer/SKILL.md`. Picks an
unblocked GitHub issue off the backlog, plans the change, implements it,
opens a PR, argues with CI and the review bot until both stop complaining,
and then — in a move that would alarm any sane engineering manager — picks
the next issue and does it again. A companion skill at
`.cursor/skills/cursor-cloud-auto-engineer/SKILL.md` mirrors the same flow
for Cursor Cloud, in case one autonomous agent writing your kernel felt
insufficient.

To run the loop yourself, you need Docker, a Claude Code login on the host
(`claude` logged in at least once, so `~/.claude.json` + `~/.claude/`
exist), and a GitHub token with repo write access. Also: the willingness to
find out what your credit card thinks of all this later.

```sh
# one-time: add yourself to the docker group so the wrapper doesn't need sudo
sudo usermod -aG docker "$USER" && newgrp docker

# each run
export GITHUB_TOKEN=ghp_...
./scripts/auto-engineer.sh
```

The wrapper builds a container image (first run ~5–10 min) that bundles every
build/test dep — Rust nightly, `qemu-system-x86_64`, `xorriso`, `gh`, and
Claude Code itself — then runs `claude --dangerously-skip-permissions` against
a fresh clone inside the container. The flag name is not a joke. Your host
`~/.claude` auth is bind-mounted in, so the container talks to Anthropic as
you and, when things go well, also merges PRs as you.

Under the hood:

- **`Dockerfile`** — Ubuntu 24.04 base, dep install, rustup pre-warm.
- **`scripts/docker-entrypoint.sh`** — clones the repo, wires up `gh` auth,
  execs `claude`.
- **`scripts/auto-engineer.sh`** — host wrapper: sources `.env`, builds the
  image, and runs the container with the right mounts + SELinux handling.

Ctrl-C at any time to stop the loop. You will probably need to.

### `/os-researcher` — design before implementation

Before a non-trivial subsystem gets built, this skill designs it — with the
solemnity of a real OS project and the staffing of a very small one. Defined
in `.claude/skills/os-researcher/SKILL.md`. Takes an OS topic (e.g. "virtual
filesystem layer", "POSIX signals", "demand paging") and runs a full
research-to-RFC pipeline:

1. **Research** — spawns parallel sub-agents to query OSDev Wiki, Linux
   kernel docs, Intel/AMD manuals, the POSIX spec, and academic literature,
   then synthesizes it all into a research brief. This is the part where the
   agent reads more of the Linux source than most people ever will.
2. **Draft** — writes a structured RFC under `docs/RFC/` covering motivation,
   design, security/performance considerations, alternatives, and an
   implementation roadmap. Looks suspiciously like a real RFC.
3. **Peer review** — four archetype reviewers (security researcher, OS
   engineer, user-space staff engineer, academic) — plus additional
   specialists the skill conjures up when the topic needs them — post
   structured review comments on the PR. The skill defends blocking findings
   across up to four revision cycles. The reviewers are imaginary. The
   feedback is disconcertingly real.
4. **Merge and file issues** — once every reviewer relents, the RFC is marked
   `Accepted`, merged, and each roadmap item is filed as a tracked GitHub
   issue for `/auto-engineer` to eventually pick up and ship.

Invoke it in a Claude Code session:

```
/os-researcher <topic>
```

Pass `--skip-research` to jump straight to drafting if a research summary is
already in context, or `--defense-cycles=<N>` to tell the imaginary reviewers
how many rounds they get.

## Requirements

- Rust nightly (auto-selected via `rust-toolchain.toml`)
- `qemu-system-x86_64`
- `xorriso` (for ISO assembly)
- `git`, `make`, a C compiler (first run builds the Limine host tool)

## Build & run

```sh
cargo xtask run              # build + iso + boot under QEMU (serial on stdio)
cargo xtask run --release    # optimized build
cargo xtask run --fault-test # trigger a ud2 to verify the #UD handler
cargo xtask run --panic-test # trigger a deliberate panic to test backtraces
cargo xtask iso              # produce target/vibix.iso without booting
cargo xtask test             # host unit tests + QEMU integration tests
cargo xtask smoke            # boot the kernel, assert on expected serial markers
cargo xtask lint             # clippy --all-targets with -D warnings
cargo xtask clean            # wipe target/ and build/
```

On first `iso`/`run`, xtask clones Limine (`v8.x-binary`) into
`build/limine/` and builds the host `limine` tool. After linking, xtask
strips debug sections and patches the embedded kernel symbol table in-place
before assembling the ISO.

Exit QEMU with `Ctrl-a x`.

## Testing

Five layers, all driven by xtask:

1. **Host unit tests** (`cargo xtask test`, first phase) — `cargo test
   --lib` over pure-logic modules (e.g. `mem::frame`, `input::RingBuffer`).
   The kernel crate is `#![cfg_attr(not(test), no_std)]` so these modules
   compile against host `std` under `cargo test`.
2. **In-kernel integration tests** (`cargo xtask test`, second phase) —
   each file under `kernel/tests/` is its own `no_std` + `no_main`
   kernel binary (116 at last count). `cargo test --target
   x86_64-unknown-none` builds each, and a custom runner (`xtask
   test-runner`) wraps each compiled ELF in an ISO and boots it under
   QEMU. Pass/fail comes from the `isa-debug-exit` protocol (Success =
   0x20 → process 65, Failure = 0x10 → process 33). `should_panic`
   inverts its panic handler to verify the panic path itself. Tests
   cover memory management, scheduling, VFS, ext2, syscalls, signals,
   userspace loading, fork/exec, TLS, TTY job control, and more.
   Integration tests support sharding (`--shard=I/N`) for parallel CI.
3. **POSIX conformance** (`cargo xtask pjdfstest`) — runs the
   [pjdfstest](https://github.com/pjd/pjdfstest) suite inside the
   kernel to validate filesystem syscall semantics (chmod, chown, link,
   mkdir, open, rename, rmdir, symlink, truncate, unlink, utimensat).
4. **Deterministic simulation** (`cargo test -p simulator`) — a
   host-side simulator (RFC 0006) replays the kernel's scheduler and
   concurrency paths under deterministic seeds, turning flaky
   concurrency bugs into reproducible failures. The fast suite (bounded
   seed corpus, 10k ticks each) gates every PR; a nightly sweep (10k
   randomized seeds × 100k ticks) explores deeper. Failing seeds are
   captured as regression fixtures in `tests/seeds/regression.txt`.
5. **End-to-end smoke** (`cargo xtask smoke`) — boots the full kernel
   with an ext2 root filesystem on virtio-blk, captures serial output,
   and asserts on a fixed list of markers covering the entire boot
   sequence: early boot, memory/paging init, ACPI/APIC/HPET/timer
   bringup, block device probe, VFS mounts (`/`, `/dev`, `/tmp`),
   scheduler online, userspace ELF loading, ring-3 entry, and a
   fork+exec+wait round-trip from the init process. Cheap regression
   lane: rename a log line and this goes red.

## License

Dual-licensed under MIT or Apache-2.0.
