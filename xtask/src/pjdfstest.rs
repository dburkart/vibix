//! `cargo xtask pjdfstest` — build the vendored pjdfstest runner, embed it
//! into the deterministic ext2 image, boot vibix under QEMU with that image
//! as its root disk, scrape `TEST_PASS:<name>` / `TEST_FAIL:<name>:<reason>`
//! markers off the serial console, and emit both a human-readable summary and
//! a machine-readable JSON artefact at `target/pjdfstest-results.json`.
//!
//! This closes workstream G, phase P2 of RFC 0004 (ext2 filesystem driver).
//! Predecessors: #577 (boot-path `--root=ext2` plumbing), #579 (deterministic
//! ext2 image builder), #580 (vendored pjdfstest fork). CI wire-up is the
//! follow-up (#582) — this xtask is explicitly *not* invoked by the smoke
//! target.
//!
//! # Runner build model
//!
//! The vendored pjdfstest crate under `tests/pjdfstest/` is an ordinary
//! `std` Rust binary with a rich set of POSIX-platform dependencies (`nix`,
//! `tempfile`, `figment`, `inventory`, …). vibix has no `std`-capable
//! userspace target today — the sole userspace binaries (`userspace_init`,
//! `userspace_hello`, `userspace_repro_fork`) are `no_std` + inline-asm and
//! link at 0x400000. A real port of pjdfstest into vibix requires a
//! vibix-specific nix shim and at minimum a functioning `std`-on-vibix
//! target; that work is tracked separately in RFC 0004 §Workstream G.
//!
//! Until that lands, `cargo xtask pjdfstest` does everything downstream of
//! the runner build: stages a best-effort host build of the pjdfstest binary
//! into the ext2 image at `/bin/pjdfstest`, boots vibix with that image as
//! the root filesystem, and parses whatever markers the kernel (or a future
//! vibix-side pjdfstest shim) emits on the serial port. If no markers are
//! seen, the resulting summary is `0 passed / 0 failed / 0 total` and the
//! JSON artefact is still written so CI tooling written against this xtask
//! (#582) has a stable contract.
//!
//! The host build is **best-effort**: if `cargo build --release` inside
//! `tests/pjdfstest/` fails (missing nightly, missing system deps, …) we log
//! the failure and fall back to a placeholder `/bin/pjdfstest` so the
//! harness itself still runs end-to-end. A failed runner build is *not*
//! fatal to the xtask — the whole point of this issue is to establish the
//! plumbing, not gate on a runner that vibix can't execute yet.
//!
//! # Serial marker protocol
//!
//! The xtask parses lines matching either of:
//!
//! - `TEST_PASS:<name>`
//! - `TEST_FAIL:<name>:<reason>`
//!
//! where `<name>` is any non-`:`, non-newline run and `<reason>` is free-form
//! to end-of-line. Unrecognised lines are ignored. An explicit `TEST_DONE`
//! marker, if seen, cuts the boot short; otherwise the xtask waits for
//! QEMU to exit or its watchdog timer to fire.
//!
//! # Output
//!
//! Two artefacts:
//!
//! 1. Human summary printed to stdout: total/passed/failed counts plus a
//!    list of any failures with their reasons.
//! 2. `target/pjdfstest-results.json` — a stable JSON document (see
//!    [`Results`] below) with per-case entries plus aggregate counts. The
//!    schema is `{"total", "passed", "failed", "cases": [{"name",
//!    "status", "reason?"}]}`.
//!
//! The xtask exit code is 0 if no `TEST_FAIL:` markers were seen (even if
//! there were also no `TEST_PASS:` markers — the baseline at landing is
//! zero cases) and non-zero otherwise. This keeps the subcommand callable
//! from CI without forcing the wire-up that #582 will add.

use std::error::Error;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::ext2_image;

type R<T> = Result<T, Box<dyn Error>>;

/// Hard ceiling on QEMU boot for the pjdfstest subcommand. Sized to match
/// the `smoke` target's HARD_CAP since the boot path is identical; once a
/// real runner exists this will need to grow, but the pjdfstest suite as a
/// whole target runs in well under a minute on Linux today.
const HARD_CAP: Duration = Duration::from_secs(600);

/// Serial-line that, when observed, short-circuits the main loop instead of
/// waiting out `HARD_CAP`. Optional — a runner that doesn't emit this will
/// simply run to the watchdog.
const DONE_MARKER: &str = "TEST_DONE";

/// Kernel panic marker (see `kernel/src/main.rs`). If we see this, there is
/// no point waiting — bail out immediately and surface the captured serial.
const PANIC_MARKER: &str = "KERNEL PANIC:";

/// One parsed test case.
#[derive(Debug, Clone)]
pub struct CaseResult {
    pub name: String,
    pub status: Status,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Fail,
}

impl Status {
    fn as_str(&self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Fail => "fail",
        }
    }
}

/// Aggregate result, serialisable to JSON.
#[derive(Debug, Clone, Default)]
pub struct Results {
    pub cases: Vec<CaseResult>,
}

impl Results {
    pub fn passed(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == Status::Pass)
            .count()
    }

    pub fn failed(&self) -> usize {
        self.cases
            .iter()
            .filter(|c| c.status == Status::Fail)
            .count()
    }

    pub fn total(&self) -> usize {
        self.cases.len()
    }

    /// Serialise to a stable JSON representation. Hand-written (rather than
    /// via serde) so xtask doesn't need a new dependency for one call site.
    /// Field order and formatting are pinned — consumers may parse this
    /// textually.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        s.push_str("{\n");
        s.push_str(&format!("  \"total\": {},\n", self.total()));
        s.push_str(&format!("  \"passed\": {},\n", self.passed()));
        s.push_str(&format!("  \"failed\": {},\n", self.failed()));
        s.push_str("  \"cases\": [");
        for (i, c) in self.cases.iter().enumerate() {
            if i == 0 {
                s.push('\n');
            }
            s.push_str("    {");
            s.push_str(&format!("\"name\": {}", json_string(&c.name)));
            s.push_str(&format!(", \"status\": {}", json_string(c.status.as_str())));
            if let Some(reason) = &c.reason {
                s.push_str(&format!(", \"reason\": {}", json_string(reason)));
            }
            s.push('}');
            if i + 1 < self.cases.len() {
                s.push(',');
            }
            s.push('\n');
        }
        s.push_str("  ]\n");
        s.push_str("}\n");
        s
    }
}

/// RFC-8259 minimal string escaper — handles the control bytes, backslash,
/// and double-quote. Not an encoder for arbitrary Unicode (the serial
/// output is ASCII in practice), but safe for the byte ranges we actually
/// see in marker reasons.
fn json_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse one line of serial output. Returns `Some(case)` when the line
/// contains a `TEST_PASS:` or `TEST_FAIL:` marker.
pub fn parse_marker(line: &str) -> Option<CaseResult> {
    // Markers may be prefixed by log-level / timestamps depending on how the
    // runner writes them — accept any substring match. The first `:` after
    // the marker keyword separates name from reason.
    if let Some(idx) = line.find("TEST_PASS:") {
        let rest = &line[idx + "TEST_PASS:".len()..];
        let name = rest.split([':', '\n', '\r']).next().unwrap_or("").trim();
        if !name.is_empty() {
            return Some(CaseResult {
                name: name.to_string(),
                status: Status::Pass,
                reason: None,
            });
        }
        return None;
    }
    if let Some(idx) = line.find("TEST_FAIL:") {
        let rest = &line[idx + "TEST_FAIL:".len()..];
        // name ends at the next ':' or end-of-line; reason is everything
        // after that first ':' up to the line terminator.
        let (name, reason) = match rest.find(':') {
            Some(j) => {
                let name = rest[..j].trim();
                let reason = rest[j + 1..].trim_end_matches(['\n', '\r']).trim();
                (name, Some(reason.to_string()))
            }
            None => (rest.trim_end_matches(['\n', '\r']).trim(), None),
        };
        if !name.is_empty() {
            return Some(CaseResult {
                name: name.to_string(),
                status: Status::Fail,
                reason,
            });
        }
    }
    None
}

/// Parse an entire captured serial transcript into a [`Results`] bag. The
/// same marker may appear more than once (e.g. the kernel logs it twice for
/// diagnostic reasons); we deduplicate by `name`, with the **last** status
/// winning — matching the intuition that a `FAIL` after a `PASS` downgrades
/// the case.
pub fn parse_transcript(transcript: &str) -> Results {
    let mut cases: Vec<CaseResult> = Vec::new();
    for line in transcript.lines() {
        if let Some(case) = parse_marker(line) {
            if let Some(existing) = cases.iter_mut().find(|c| c.name == case.name) {
                *existing = case;
            } else {
                cases.push(case);
            }
        }
    }
    Results { cases }
}

// --------------------------- subcommand entry point ---------------------

/// Build the vendored pjdfstest binary as a best-effort host target. On
/// failure, return the error so the caller can choose to fall back to a
/// placeholder.
fn build_runner(workspace_root: &Path) -> R<PathBuf> {
    let crate_dir = workspace_root.join("tests").join("pjdfstest");
    if !crate_dir.join("Cargo.toml").is_file() {
        return Err(format!(
            "pjdfstest crate not found at {} (expected to be vendored by #580)",
            crate_dir.display()
        )
        .into());
    }

    println!("→ pjdfstest: building runner at {}", crate_dir.display());
    let status = Command::new("cargo")
        .current_dir(&crate_dir)
        .args(["build", "--release", "--bin", "pjdfstest"])
        .status()
        .map_err(|e| format!("cargo build: {e}"))?;
    if !status.success() {
        return Err(format!("pjdfstest runner build failed: {status}").into());
    }

    // The vendored crate is its own workspace, so the artefact lives under
    // `tests/pjdfstest/target/release/pjdfstest`, not the outer `target/`.
    let bin = crate_dir.join("target").join("release").join("pjdfstest");
    if !bin.is_file() {
        return Err(format!(
            "pjdfstest binary missing at {} after a successful build",
            bin.display()
        )
        .into());
    }
    Ok(bin)
}

/// Write a placeholder binary the ext2-image builder will stage as `/init`.
/// Used when the host build failed and we still want to exercise the boot
/// path. The placeholder content is stable so the ext2 image hash stays
/// stable across runs.
fn write_placeholder_init(workspace_root: &Path) -> R<PathBuf> {
    let path = workspace_root
        .join("target")
        .join("pjdfstest-init.placeholder");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        &path,
        b"#!vibix-pjdfstest-placeholder (runner build failed)\n",
    )?;
    Ok(path)
}

/// Serial capture + marker scrape. Mirrors the boot path in
/// `run_with_root(Some("ext2"))` but substitutes `stdio`-piped serial for
/// the default `-serial stdio` so we can read it line-by-line from this
/// process.
fn boot_and_capture(
    _workspace_root: &Path,
    iso: &Path,
    disk: &Path,
) -> R<(String, bool, Option<i32>)> {
    // Mirror the exact flag set in `run_with_root` / `test_runner`. The
    // virtio-blk device pins the legacy transport so the current driver
    // matches; `isa-debug-exit` lets the kernel terminate QEMU on
    // test-harness exit if it ever gets wired.
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-M",
        "q35",
        "-cpu",
        "max",
        "-m",
        "256M",
        "-serial",
        "stdio",
        "-display",
        "none",
        "-no-reboot",
        "-no-shutdown",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]);

    // virtio-blk, legacy transport pinned to match the current driver.
    let drive = format!("file={},if=none,id=vd0,format=raw", disk.display());
    cmd.arg("-drive")
        .arg(&drive)
        .arg("-device")
        .arg("virtio-blk-pci,drive=vd0,disable-modern=on,disable-legacy=off")
        .arg("-cdrom")
        .arg(iso);

    let mut child = cmd.stdout(Stdio::piped()).stderr(Stdio::null()).spawn()?;
    let pid = child.id();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    // Watchdog: kill QEMU after HARD_CAP even if no markers arrive.
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = cancel_rx.recv_timeout(HARD_CAP) {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    });

    // Stream the serial output on a reader thread so the main loop can
    // wake up promptly for the done-marker or panic-marker checks without
    // blocking inside a BufReader::read_line.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader = std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let deadline = Instant::now() + HARD_CAP;
    let mut transcript = String::new();
    let mut saw_done = false;
    let mut saw_panic = false;
    const TICK: Duration = Duration::from_millis(100);
    while Instant::now() < deadline {
        match rx.recv_timeout(TICK) {
            Ok(line) => {
                // Echo to stdout so the developer can watch progress.
                print!("{line}");
                let _ = std::io::stdout().flush();
                transcript.push_str(&line);
                if line.contains(PANIC_MARKER) {
                    saw_panic = true;
                    break;
                }
                if line.contains(DONE_MARKER) {
                    saw_done = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Clean up: kill the child (idempotent if the watchdog already fired),
    // unblock the watchdog, then join threads. Same pattern as
    // `main::smoke` — see #516.
    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(cancel_tx);
    let _ = watchdog.join();
    let _ = reader.join();
    let exit_status = child.wait().ok().and_then(|s| s.code());

    if saw_panic {
        return Err(format!(
            "pjdfstest: kernel panic detected in serial output\n--- transcript ---\n{transcript}\n---"
        )
        .into());
    }

    Ok((transcript, saw_done, exit_status))
}

/// Baseline-gating mode for `cargo xtask pjdfstest`.
///
/// See `main.rs` for the CLI surface — `--compare-baseline` maps to
/// [`BaselineMode::Compare`] (CI gate), `--update-baseline` maps to
/// [`BaselineMode::Update`] (explicit baseline bump), and no flag maps
/// to [`BaselineMode::None`] (the default developer flow, which only
/// writes the results artefact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaselineMode {
    /// Do not touch or compare against the baseline file. Default.
    None,
    /// Compare emitted results against the committed baseline; fail on
    /// any regression or silent upgrade.
    Compare,
    /// Overwrite the committed baseline with the current run's results.
    Update,
}

/// Canonical location of the committed expected-pass baseline. Relative
/// to the workspace root. Consumers may parse this textually.
pub const BASELINE_REL_PATH: &str = "tests/pjdfstest/baseline/expected.json";

/// Parse a results JSON document into a [`Results`] bag. Narrow
/// hand-written parser — paired with [`Results::to_json`], so the two
/// must agree on field names. Only the fields we actually consume
/// (`cases[].name`, `cases[].status`) are extracted; `total` / `passed`
/// / `failed` are recomputed from the case list.
///
/// This deliberately does not pull in serde to avoid bloating xtask's
/// dependency graph for one call site. The format is pinned; if we ever
/// need richer parsing this is the place to swap it out.
pub fn parse_results_json(s: &str) -> R<Results> {
    // Find the "cases" array, then iterate objects inside it. The
    // emitter pins one case per line, so a line-oriented scan is enough.
    let cases_start = s
        .find("\"cases\"")
        .ok_or("results JSON: missing \"cases\" key")?;
    let bracket = s[cases_start..]
        .find('[')
        .ok_or("results JSON: \"cases\" not followed by '['")?
        + cases_start;
    let end = s[bracket..]
        .find(']')
        .ok_or("results JSON: unterminated \"cases\" array")?
        + bracket;
    let body = &s[bracket + 1..end];

    let mut cases: Vec<CaseResult> = Vec::new();
    for raw in body.split('\n') {
        let line = raw.trim();
        if line.is_empty() || !line.starts_with('{') {
            continue;
        }
        let name = extract_json_string_field(line, "name")
            .ok_or_else(|| format!("results JSON: case missing \"name\": {line}"))?;
        let status_str = extract_json_string_field(line, "status")
            .ok_or_else(|| format!("results JSON: case missing \"status\": {line}"))?;
        let status = match status_str.as_str() {
            "pass" => Status::Pass,
            "fail" => Status::Fail,
            other => return Err(format!("results JSON: unknown status {other:?}").into()),
        };
        let reason = extract_json_string_field(line, "reason");
        cases.push(CaseResult {
            name,
            status,
            reason,
        });
    }
    Ok(Results { cases })
}

/// Extract the string value of a `"field": "..."` pair from one line of
/// the emitted JSON. Handles the escape sequences produced by
/// [`json_string`] above — `\"`, `\\`, `\n`, `\r`, `\t`, and `\uXXXX`.
fn extract_json_string_field(line: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let key_at = line.find(&needle)?;
    let after_key = &line[key_at + needle.len()..];
    let colon_at = after_key.find(':')?;
    let after_colon = &after_key[colon_at + 1..];
    // Skip whitespace, then require an opening quote.
    let trimmed = after_colon.trim_start();
    let mut chars = trimmed.chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut out = String::new();
    loop {
        let c = chars.next()?;
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let hex: String = (&mut chars).take(4).collect();
                    if hex.len() != 4 {
                        return None;
                    }
                    let code = u32::from_str_radix(&hex, 16).ok()?;
                    out.push(char::from_u32(code)?);
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
}

/// Diff the current results against the committed baseline and return
/// a list of human-readable failure reasons. An empty vec means the
/// run is CI-green.
///
/// Fail conditions (#582):
///   1. A case that was `pass` in the baseline is `fail` (or absent) in
///      the current run — this is a real regression.
///   2. A case that was `fail` in the baseline is `pass` in the current
///      run, **without** the baseline being updated in the same change.
///      This catches silent upgrades: a PR that accidentally fixes a
///      previously-failing test must commit the baseline bump so the
///      improvement is explicit in review.
///   3. A case present in the current run is absent from the baseline
///      — new test surface must be reflected in the baseline before it
///      can gate CI.
///
/// Returns `Vec<String>` of one line per violation.
pub fn diff_against_baseline(baseline: &Results, current: &Results) -> Vec<String> {
    let mut violations = Vec::new();

    // Index by name for O(n+m) lookup.
    let baseline_by_name: std::collections::BTreeMap<&str, &CaseResult> = baseline
        .cases
        .iter()
        .map(|c| (c.name.as_str(), c))
        .collect();
    let current_by_name: std::collections::BTreeMap<&str, &CaseResult> =
        current.cases.iter().map(|c| (c.name.as_str(), c)).collect();

    // Baseline PASSes that are now absent or failing, and baseline
    // FAILs that are now PASSing.
    for (name, b) in &baseline_by_name {
        match current_by_name.get(name) {
            None => {
                if b.status == Status::Pass {
                    violations.push(format!(
                        "regression: {name} was pass in baseline but is missing from current run"
                    ));
                }
                // A baseline-fail vanishing is tolerated — the test may
                // have been removed. It is NOT a silent-upgrade.
            }
            Some(cur) => match (b.status, cur.status) {
                (Status::Pass, Status::Fail) => {
                    let reason = cur.reason.as_deref().unwrap_or("<no reason>");
                    violations.push(format!("regression: {name} pass -> fail ({reason})"));
                }
                (Status::Fail, Status::Pass) => {
                    violations.push(format!(
                        "silent-upgrade: {name} fail -> pass — update the baseline in this PR with `cargo xtask pjdfstest --update-baseline`"
                    ));
                }
                _ => {}
            },
        }
    }

    // Cases present in current but absent from baseline — new surface.
    for (name, cur) in &current_by_name {
        if !baseline_by_name.contains_key(name) {
            let label = match cur.status {
                Status::Pass => "new-pass",
                Status::Fail => "new-fail",
            };
            violations.push(format!(
                "{label}: {name} is in current results but absent from baseline — update with `cargo xtask pjdfstest --update-baseline`"
            ));
        }
    }

    violations
}

/// `cargo xtask pjdfstest` entry point. Signature mirrors the other
/// subcommands so `main.rs` can dispatch uniformly.
pub fn run(
    workspace_root: &Path,
    build: impl FnOnce() -> R<PathBuf>,
    iso_root_name: &str,
    baseline_mode: BaselineMode,
) -> R<()> {
    // 1. Attempt to build the pjdfstest runner. Fall back to a placeholder
    //    if that fails — the rest of the harness is still useful to exercise.
    let runner = match build_runner(workspace_root) {
        Ok(p) => {
            println!("→ pjdfstest: runner built at {}", p.display());
            p
        }
        Err(e) => {
            eprintln!("⚠ pjdfstest: runner build failed: {e}");
            eprintln!("  falling back to a placeholder /init so the harness still runs.");
            eprintln!("  this is expected today — vibix has no std-capable userspace target yet.");
            write_placeholder_init(workspace_root)?
        }
    };

    // 2. Build the deterministic ext2 image, staging the runner (or
    //    placeholder) as `/init`. Passing `Some(&runner)` overrides the
    //    default `#!vibix-init placeholder` content so if a real runner
    //    binary is ever built for vibix, it lands at the same path the
    //    kernel's boot path expects.
    //
    //    NOTE on hash-drift: `ext2_image::build` compares the resulting
    //    image against the committed `tests/fixtures/ext2_image.sha256`
    //    fixture. Substituting a real multi-megabyte binary for the
    //    24-byte placeholder will drift that hash — callers who care about
    //    that fixture should run `ext2-image --update-hash` explicitly.
    //    For this xtask, we swallow the hash-drift error specifically so
    //    the harness runs end-to-end; a drift error on ext2-image is
    //    tracked by the fixture, not by this path.
    let image = match ext2_image::build(workspace_root, Some(&runner), false) {
        Ok(p) => p,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("ext2-image hash drift") {
                eprintln!("⚠ pjdfstest: ext2-image hash drift (expected — runner differs from placeholder).");
                eprintln!(
                    "  accepting the new hash for this run; the fixture file is NOT updated."
                );
                // Re-invoke with `update_hash=true`, then immediately
                // restore the committed fixture so this xtask doesn't
                // silently update VCS-tracked state.
                let fixture = ext2_image::expected_hash_path(workspace_root);
                let saved = fs::read_to_string(&fixture).ok();
                let img = ext2_image::build(workspace_root, Some(&runner), true)?;
                if let Some(saved) = saved {
                    fs::write(&fixture, saved)?;
                }
                img
            } else {
                return Err(e);
            }
        }
    };
    println!("→ pjdfstest: ext2 image at {}", image.display());

    // 3. Build the kernel + ISO with `root=/dev/vda` on the cmdline, the
    //    same glue `cargo xtask run --root=ext2` uses (#577). `build` is
    //    injected so we don't reach into `main.rs` internals from this
    //    module — the dispatcher in `main.rs` passes the `build` closure
    //    and the ISO staging directory name.
    let kernel = build()?;
    let iso = workspace_root.join("target").join("vibix-pjdfstest.iso");
    crate::make_iso_with_cmdline(&kernel, &iso, iso_root_name, "root=/dev/vda")?;
    println!("→ pjdfstest: iso at {}", iso.display());

    // 4. Boot and scrape.
    let (transcript, saw_done, exit_status) = boot_and_capture(workspace_root, &iso, &image)?;
    if saw_done {
        println!("→ pjdfstest: saw {DONE_MARKER}, stopping capture early.");
    } else {
        println!(
            "→ pjdfstest: no {DONE_MARKER} marker; capture terminated at QEMU exit (status {exit_status:?}) or watchdog."
        );
    }

    // 5. Parse + emit artefacts.
    let results = parse_transcript(&transcript);
    let json_path = workspace_root.join("target").join("pjdfstest-results.json");
    if let Some(parent) = json_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&json_path, results.to_json())?;
    println!("→ pjdfstest: results written to {}", json_path.display());

    println!();
    println!(
        "pjdfstest summary: {} passed, {} failed, {} total",
        results.passed(),
        results.failed(),
        results.total()
    );
    if results.failed() > 0 {
        println!("failures:");
        for c in results.cases.iter().filter(|c| c.status == Status::Fail) {
            let reason = c.reason.as_deref().unwrap_or("<no reason>");
            println!("  - {}: {}", c.name, reason);
        }
        // Fall through: even with raw-run failures, honour the baseline
        // mode first so --update-baseline can record the current (bad)
        // verdicts intentionally if a human is explicitly bumping the
        // expected set.
    }

    // Baseline-at-landing is zero cases: no vibix-side runner exists yet, so
    // a healthy boot produces no TEST_* markers. The harness is still green
    // in that case — #582 and the real port will drive the pass count up
    // from there.
    let baseline_path = workspace_root.join(BASELINE_REL_PATH);
    match baseline_mode {
        BaselineMode::None => {
            if results.failed() > 0 {
                return Err(format!("pjdfstest: {} case(s) failed", results.failed()).into());
            }
        }
        BaselineMode::Update => {
            if let Some(parent) = baseline_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&baseline_path, results.to_json())?;
            println!(
                "→ pjdfstest: baseline updated at {}",
                baseline_path.display()
            );
        }
        BaselineMode::Compare => {
            if !baseline_path.is_file() {
                return Err(format!(
                    "pjdfstest --compare-baseline: no baseline at {} (commit one with `cargo xtask pjdfstest --update-baseline`)",
                    baseline_path.display()
                )
                .into());
            }
            let baseline_text = fs::read_to_string(&baseline_path)?;
            let baseline = parse_results_json(&baseline_text).map_err(|e| {
                format!(
                    "pjdfstest --compare-baseline: baseline at {} is malformed: {e}",
                    baseline_path.display()
                )
            })?;
            let violations = diff_against_baseline(&baseline, &results);
            if !violations.is_empty() {
                println!();
                println!(
                    "pjdfstest --compare-baseline: {} violation(s) vs {}:",
                    violations.len(),
                    baseline_path.display()
                );
                for v in &violations {
                    println!("  - {v}");
                }
                return Err(format!(
                    "pjdfstest --compare-baseline: {} violation(s) vs committed baseline",
                    violations.len()
                )
                .into());
            }
            println!(
                "→ pjdfstest --compare-baseline: no regressions vs {}",
                baseline_path.display()
            );
            // A raw-run failure when every case was already expected-fail
            // in the baseline is still CI-green; only regressions / silent
            // upgrades are fatal in Compare mode.
        }
    }
    Ok(())
}

// ----------------------------- tests -----------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_pass_marker() {
        let c = parse_marker("TEST_PASS:foo::bar").unwrap();
        assert_eq!(c.name, "foo");
        assert_eq!(c.status, Status::Pass);
        assert!(c.reason.is_none());
    }

    #[test]
    fn parses_fail_marker_with_reason() {
        let c = parse_marker("TEST_FAIL:case.one:ENOENT on unlink").unwrap();
        assert_eq!(c.name, "case.one");
        assert_eq!(c.status, Status::Fail);
        assert_eq!(c.reason.as_deref(), Some("ENOENT on unlink"));
    }

    #[test]
    fn parses_fail_marker_no_reason() {
        let c = parse_marker("TEST_FAIL:case.two").unwrap();
        assert_eq!(c.name, "case.two");
        assert_eq!(c.status, Status::Fail);
        assert!(c.reason.is_none());
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(parse_marker("boot: hello").is_none());
        assert!(parse_marker("").is_none());
        assert!(parse_marker("TEST_PASS:").is_none());
    }

    #[test]
    fn accepts_prefixed_markers() {
        // Kernel log might prefix the serial line with a timestamp or level.
        let c = parse_marker("[123.456] TEST_PASS:prefixed").unwrap();
        assert_eq!(c.name, "prefixed");
        assert_eq!(c.status, Status::Pass);
    }

    #[test]
    fn transcript_dedupes_by_name_last_wins() {
        let t = "TEST_PASS:case\nmidline noise\nTEST_FAIL:case:broke\n";
        let r = parse_transcript(t);
        assert_eq!(r.cases.len(), 1);
        assert_eq!(r.cases[0].status, Status::Fail);
        assert_eq!(r.cases[0].reason.as_deref(), Some("broke"));
    }

    #[test]
    fn transcript_counts_match_cases() {
        let t = "TEST_PASS:a\nTEST_PASS:b\nTEST_FAIL:c:x\n";
        let r = parse_transcript(t);
        assert_eq!(r.total(), 3);
        assert_eq!(r.passed(), 2);
        assert_eq!(r.failed(), 1);
    }

    #[test]
    fn empty_transcript_is_zero_all() {
        let r = parse_transcript("");
        assert_eq!(r.total(), 0);
        assert_eq!(r.passed(), 0);
        assert_eq!(r.failed(), 0);
        let json = r.to_json();
        assert!(json.contains("\"total\": 0"));
        assert!(json.contains("\"cases\": ["));
    }

    #[test]
    fn results_json_round_trip() {
        let original = Results {
            cases: vec![
                CaseResult {
                    name: "case.a".to_string(),
                    status: Status::Pass,
                    reason: None,
                },
                CaseResult {
                    name: "case.b".to_string(),
                    status: Status::Fail,
                    reason: Some("ENOENT on unlink".to_string()),
                },
            ],
        };
        let json = original.to_json();
        let parsed = parse_results_json(&json).expect("parse must succeed");
        assert_eq!(parsed.cases.len(), 2);
        assert_eq!(parsed.cases[0].name, "case.a");
        assert_eq!(parsed.cases[0].status, Status::Pass);
        assert!(parsed.cases[0].reason.is_none());
        assert_eq!(parsed.cases[1].name, "case.b");
        assert_eq!(parsed.cases[1].status, Status::Fail);
        assert_eq!(parsed.cases[1].reason.as_deref(), Some("ENOENT on unlink"));
    }

    #[test]
    fn results_json_parses_empty_baseline() {
        // The committed baseline at landing has zero cases — the
        // compare path must handle it.
        let baseline =
            "{\n  \"total\": 0,\n  \"passed\": 0,\n  \"failed\": 0,\n  \"cases\": [\n  ]\n}\n";
        let r = parse_results_json(baseline).expect("parse must succeed");
        assert_eq!(r.cases.len(), 0);
    }

    #[test]
    fn diff_flags_pass_to_fail_as_regression() {
        let baseline = Results {
            cases: vec![CaseResult {
                name: "case.x".to_string(),
                status: Status::Pass,
                reason: None,
            }],
        };
        let current = Results {
            cases: vec![CaseResult {
                name: "case.x".to_string(),
                status: Status::Fail,
                reason: Some("broke".to_string()),
            }],
        };
        let violations = diff_against_baseline(&baseline, &current);
        assert_eq!(violations.len(), 1, "got: {violations:?}");
        assert!(
            violations[0].contains("regression") && violations[0].contains("case.x"),
            "got: {violations:?}"
        );
    }

    #[test]
    fn diff_flags_fail_to_pass_as_silent_upgrade() {
        let baseline = Results {
            cases: vec![CaseResult {
                name: "case.y".to_string(),
                status: Status::Fail,
                reason: None,
            }],
        };
        let current = Results {
            cases: vec![CaseResult {
                name: "case.y".to_string(),
                status: Status::Pass,
                reason: None,
            }],
        };
        let violations = diff_against_baseline(&baseline, &current);
        assert_eq!(violations.len(), 1, "got: {violations:?}");
        assert!(
            violations[0].contains("silent-upgrade"),
            "got: {violations:?}"
        );
    }

    #[test]
    fn diff_flags_missing_baseline_pass_as_regression() {
        let baseline = Results {
            cases: vec![CaseResult {
                name: "case.z".to_string(),
                status: Status::Pass,
                reason: None,
            }],
        };
        let current = Results { cases: vec![] };
        let violations = diff_against_baseline(&baseline, &current);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("regression"));
    }

    #[test]
    fn diff_flags_new_case_as_baseline_drift() {
        let baseline = Results { cases: vec![] };
        let current = Results {
            cases: vec![CaseResult {
                name: "case.new".to_string(),
                status: Status::Pass,
                reason: None,
            }],
        };
        let violations = diff_against_baseline(&baseline, &current);
        assert_eq!(violations.len(), 1);
        assert!(
            violations[0].contains("new-pass") && violations[0].contains("case.new"),
            "got: {violations:?}"
        );
    }

    #[test]
    fn diff_empty_vs_empty_is_clean() {
        // The at-landing 0/0/0 baseline must be CI-green.
        let baseline = Results { cases: vec![] };
        let current = Results { cases: vec![] };
        let violations = diff_against_baseline(&baseline, &current);
        assert!(violations.is_empty(), "got: {violations:?}");
    }

    #[test]
    fn diff_tolerates_removed_baseline_fail() {
        // A test that was expected-fail and has since been removed is
        // not a silent-upgrade — it's just gone. Don't flag it.
        let baseline = Results {
            cases: vec![CaseResult {
                name: "case.removed".to_string(),
                status: Status::Fail,
                reason: None,
            }],
        };
        let current = Results { cases: vec![] };
        let violations = diff_against_baseline(&baseline, &current);
        assert!(violations.is_empty(), "got: {violations:?}");
    }

    #[test]
    fn json_escapes_special_chars() {
        let r = Results {
            cases: vec![CaseResult {
                name: "quote\"name".to_string(),
                status: Status::Fail,
                reason: Some("backslash\\ and\ttab".to_string()),
            }],
        };
        let json = r.to_json();
        assert!(json.contains("quote\\\"name"), "got: {json}");
        assert!(json.contains("backslash\\\\"), "got: {json}");
        assert!(json.contains("\\t"), "got: {json}");
    }
}
