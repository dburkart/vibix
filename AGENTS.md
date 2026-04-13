## Cursor Cloud specific instructions

vibix is a bare-metal x86_64 hobby kernel in Rust. There are no web services, databases, or containers — everything compiles to a bootable ISO and runs under QEMU.

### System dependencies (installed by the update script)

- `qemu-system-x86` — boots the kernel and runs all integration/smoke tests
- `xorriso` — assembles bootable ISO images
- `build-essential` — C compiler needed to build the Limine bootloader host tool on first run

### Build, test, lint, run

All commands are orchestrated through `cargo xtask`. See `README.md` → "Build & run" for the full list. Key commands:

| Task | Command |
|---|---|
| Build kernel | `cargo xtask build` |
| Build + boot in QEMU | `cargo xtask run` (serial on stdio; exit with `Ctrl-a x`) |
| Host unit tests + QEMU integration tests | `cargo xtask test` |
| End-to-end smoke (serial marker assertions) | `cargo xtask smoke` |
| Lint (CI-style, xtask only) | `cargo clippy -p xtask --all-targets -- -D warnings` |
| Format check | `cargo fmt --all -- --check` |

### Non-obvious caveats

- **`cargo xtask lint` vs CI clippy:** `cargo xtask lint` runs clippy on the kernel with `--all-targets`, which includes integration test crates that may trigger pre-existing warnings. CI only runs `cargo clippy -p xtask --all-targets -- -D warnings`. Use the CI command when checking lint.
- **First build clones Limine:** `cargo xtask iso` (and `run`/`test`/`smoke`) clones the Limine bootloader into `build/limine/` on first invocation and compiles it. This is a one-time ~10s step per fresh workspace.
- **QEMU runs headlessly in Cloud:** Tests and smoke use `-display none`. For `cargo xtask run` in Cloud, add a `timeout` wrapper or run in a tmux session since the kernel halts in `hlt_loop` forever: `timeout 6 cargo xtask run` or kill the QEMU process manually.
- **Rust nightly auto-selected:** `rust-toolchain.toml` pins the toolchain; `rustup show` triggers installation if needed.
- **`gh` CLI available:** Pre-installed and authenticated via `GITHUB_TOKEN`. Use for read-only GitHub queries (PR info, CI logs, etc.). Write operations (creating PRs) should use the `ManagePullRequest` tool instead.
