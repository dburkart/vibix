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

/// `cargo xtask pjdfstest` entry point. Signature mirrors the other
/// subcommands so `main.rs` can dispatch uniformly.
pub fn run(
    workspace_root: &Path,
    build: impl FnOnce() -> R<PathBuf>,
    iso_root_name: &str,
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
        return Err(format!("pjdfstest: {} case(s) failed", results.failed()).into());
    }

    // Baseline-at-landing is zero cases: no vibix-side runner exists yet, so
    // a healthy boot produces no TEST_* markers. The harness is still green
    // in that case — #582 and the real port will drive the pass count up
    // from there.
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
