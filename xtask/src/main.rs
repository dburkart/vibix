//! vibix build/run/test orchestrator.
//!
//! Subcommands:
//!   build         — cargo-build the kernel for x86_64-unknown-none
//!   initrd        — build target/rootfs.tar (minimal USTAR rootfs tarball)
//!   ext2-image    — build target/vibix-root.ext2 (deterministic ext2 rootfs; #579)
//!   pjdfstest     — build pjdfstest runner, embed into ext2 image, boot under
//!                   QEMU, parse TEST_PASS/TEST_FAIL serial markers (#581)
//!                   flags: --compare-baseline (CI gate; #582)
//!                          --update-baseline  (rewrite tests/pjdfstest/baseline/expected.json)
//!   iso           — build, fetch Limine, produce target/vibix.iso
//!   run           — iso, then boot under QEMU with serial-stdio
//!   test          — run host unit tests + QEMU integration tests
//!   test-runner   — (internal) boot a pre-built test kernel ELF in QEMU
//!   smoke         — boot the kernel and assert on expected serial markers
//!   repro-fork    — boot with the fork-loop reproducer harness as PID 1 (issue #506)
//!   repro-fork-build — build-only variant of `repro-fork`: warm kernel + ISO
//!                      without booting QEMU (issue #526, for CI pre-build)
//!   shell-pipeline — boot with the shell-pipeline integration binary as PID 1
//!                    and assert `SHELL_PIPELINE_OK: 4` on serial (issue #462)
//!   lint          — run clippy on xtask (host) and vibix (kernel, no_std)
//!   isr-audit     — scan ISR-reachable files for blocking-lock regressions
//!   fuzz          — bounded-iteration host fuzz of an FS layer (#677)
//!                   `cargo xtask fuzz ext2 [--iters=N]` (defaults to 2000)
//!   clean         — remove build artifacts
//!
//! Flags (apply where sensible): --release, --fault-test, --panic-test

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

mod ext2_image;
mod isr_audit;
mod lntab;
mod pjdfstest;

type R<T> = Result<T, Box<dyn Error>>;

const LIMINE_TAG: &str = "v8.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";

const KERNEL_TARGET: &str = "x86_64-unknown-none";
const KERNEL_BUILD_STD_ARGS: &[&str] = &[
    "--target",
    KERNEL_TARGET,
    "-Z",
    "build-std=core,compiler_builtins,alloc",
    "-Z",
    "build-std-features=compiler-builtins-mem",
];

// QEMU process exit codes produced by `isa-debug-exit` writing our
// QemuExitCode values. See kernel/src/test_harness.rs.
const QEMU_EXIT_SUCCESS: i32 = 65; // (0x20 << 1) | 1
const QEMU_EXIT_FAILURE: i32 = 33; // (0x10 << 1) | 1

/// Hard ceiling on an individual QEMU boot during tests — most real
/// tests finish in <1 s; this catches hangs. Sized for un-accelerated
/// QEMU on shared CI runners where boot + ~40 spawn/reap cycles
/// (`wait4_condvar_race::wait4_repeated_rounds_no_wedge`) can
/// legitimately take double-digit seconds under load (see #619).
const TEST_TIMEOUT: Duration = Duration::from_secs(90);

/// Expected markers on a healthy boot. Used by `smoke` and to guard
/// against regressions in the serial pipeline.
const SMOKE_MARKERS: &[&str] = &[
    "vibix booting",
    "memory map:",
    "hhdm offset:",
    "cpu: ",
    "GDT + IDT loaded",
    "heap: 1024 KiB",
    "paging: mapper online",
    "paging: IST guard installed",
    "paging: switched to kernel PML4",
    "PIC remapped",
    "acpi: MADT parsed",
    "apic: BSP online",
    "ioapic: initialized",
    "serial: rx irq enabled",
    "hpet: initialized",
    "hpet: periodic timer armed",
    "timer: 100 Hz",
    "rtc:",
    "block: virtio-blk ready",
    "block: lba0[0..16]=[56, 49, 42, 49, 58, 42, 4c, 4b, 30",
    "block: write+readback ok at lba 2047",
    // VFS init in `_start` (issue #631) consumes the cmdline-parsed
    // RootArgs and brings up `/`, `/dev`, `/tmp`. The init_with
    // confirmation line proves `_start` actually invoked it; the per-
    // mount lines below prove the namespace is populated. Without #631,
    // none of these would fire on the prod boot path.
    "vfs: mounted",
    "vfs: mounted devfs at /dev",
    "vfs: mounted ramfs at /tmp",
    "vfs: init_with consumed cmdline RootArgs",
    "vibix online.",
    "interrupts enabled",
    "tasks: scheduler online",
    // Front-anchored and includes the kernel release so a regression that
    // drops either the banner prefix or the release interpolation fails
    // smoke, not just one of the two. Relies on xtask + kernel sharing the
    // workspace version so CARGO_PKG_VERSION matches what build_info::RELEASE
    // stamps into the banner at build time.
    concat!("banner: vibix ", env!("CARGO_PKG_VERSION")),
    "userspace module ELF entry=",
    "userspace: loader mapping image",
    "syscall: SYSCALL/SYSRET enabled",
    // Kernel emits this immediately before IRETQ. If it fires but
    // "init: hello from pid 1" doesn't, the regression is in the ring-3
    // return path or the first userspace write, not kernel init.
    "init: iretq to ring-3",
    // #478 diagnostic: printed from `jump_to_ring3` just before the
    // `iretq` instruction with the full IRETQ frame (RIP/RSP/CS/SS/
    // RFLAGS). If this is absent in a failing run, the kernel never
    // reached the ring-3 return path at all — the regression is on
    // the scheduling/init-process side. If present but
    // `init: hello from pid 1` is missing, either the `iretq` itself
    // or the first userspace instruction faulted (see the
    // `ring3-first-fault:` diagnostic line emitted by the IDT fault
    // handlers in that case).
    "ring3-iretq: rip=",
    // #647: kernel emits `irq-pre-ring3: ticks=N` immediately before the
    // very first IRETQ to ring-3 and `irq-post-ring3: ticks=… delta=…`
    // on the first SYSCALL back from ring-3. The delta is the number of
    // timer ticks the kernel observed while userspace was first
    // executing — the #478 starvation signature has delta near zero.
    "irq-pre-ring3: ticks=",
    "irq-post-ring3: ticks=",
    // #478 diagnostic: emitted by userspace init on fd=2 as the very first
    // userspace action, immediately after ring-3 entry and before the first
    // `write(1, HELLO_MSG)`. Three-marker localization:
    //   - `ring3-iretq:` present, `pre-write marker` absent:
    //     first SYSCALL instruction or the kernel syscall-entry trampoline
    //     silently faulted before the Rust handler ran.
    //   - `pre-write marker` present, `init: hello from pid 1` absent:
    //     fd=1 write path (or state between the two writes) is the culprit,
    //     not ring-3 entry.
    //   - `init: hello from pid 1` present, `post-write marker` absent:
    //     SYSRET / user-context restore is the culprit, not the write itself.
    "init: pre-write marker",
    "init: hello from pid 1",
    // #478 diagnostic: emitted on fd=1 immediately after the first
    // `write(1, HELLO_MSG)` returns, before any further work (fork etc.).
    // Missing this while `init: hello from pid 1` fires is a signal that the
    // SYSRET / user-context restore after the first write is broken.
    "init: post-write marker",
    // Promoted back to required after #478 (PR #655 SYSCALL `sti`),
    // #527 (PR #662 latch placement), and #646 (PR #662 stack VA
    // free-list) closed the fork+exec flake era. The earlier demotion
    // to soft markers (PR #419) was a temporary measure while those
    // root causes were under investigation; they fire deterministically
    // now and missing them indicates a real regression in the fork /
    // exec / wait path. HARD_CAP is owned by #511 and tuned separately.
    "hello: hello from execed child",
    "init: fork+exec+wait ok",
];

// Note: an earlier draft of #647 added a delta floor parsed out of
// the `irq-post-ring3` marker. In practice the gap between IRETQ and
// the first SYSCALL is microseconds (well below one 10 ms tick) on
// real hardware, so a delta floor would flake. The marker's *presence*
// is the gate: when the #478 starvation hits, userspace never reaches
// its first SYSCALL and `irq-post-ring3:` simply never appears, which
// the existing missing-markers check catches. Soak detection lives
// kernel-side via `process::CURRENT_PID_SOAK_THRESHOLD`.

/// Soft markers — present but non-fatal if missing. Currently empty:
/// the previous fork+exec+wait soft markers were re-promoted to
/// `SMOKE_MARKERS` after #478/#527/#646 closed the flake era (#420).
/// The plumbing stays so a future flakey-but-diagnostic marker can be
/// added without re-introducing the `soft_remaining` machinery.
const SMOKE_SOFT_MARKERS: &[&str] = &[];

fn main() -> R<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let release = take_flag(&mut args, "--release");
    let fault_test = take_flag(&mut args, "--fault-test");
    let panic_test = take_flag(&mut args, "--panic-test");
    let bench = take_flag(&mut args, "--bench");
    let fork_trace = take_flag(&mut args, "--fork-trace");
    // `--root=<kind>` must be extracted before we index into `args` for
    // the subcommand, otherwise `cargo xtask --root=ext2 run` would
    // treat `--root=ext2` as the subcommand name and fail.
    let root_flag = take_value(&mut args, "--root=");

    let cmd = args
        .first()
        .map(String::as_str)
        .unwrap_or("run")
        .to_string();
    let rest: Vec<String> = args.into_iter().skip(1).collect();
    let opts = BuildOpts {
        release,
        fault_test,
        panic_test,
        bench,
        fork_trace,
    };

    match cmd.as_str() {
        "build" => {
            build(&opts)?;
        }
        "iso" => {
            iso(&opts)?;
        }
        "run" => {
            run(&opts, root_flag.as_deref())?;
        }
        "test" => test_all()?,
        "test-unit" => test_unit()?,
        "test-integration" => test_integration()?,
        "test-runner" => {
            let kernel = rest.first().ok_or("test-runner: missing kernel ELF path")?;
            test_runner(Path::new(kernel))?;
        }
        "smoke" => smoke(&opts)?,
        "repro-fork" => repro_fork(&opts)?,
        "repro-fork-build" => {
            repro_fork_build(&opts)?;
        }
        "shell-pipeline" => shell_pipeline(&opts)?,
        "lint" => lint()?,
        "isr-audit" => isr_audit::run(&workspace_root())?,
        "initrd" => {
            let path = ensure_initrd()?;
            println!("→ initrd: {}", path.display());
        }
        "ext2-image" => {
            // `--update-hash` accepts a new image hash into the
            // committed fixture. Callers intentionally changing the
            // fixture tree or bumping e2fsprogs pass this; CI never
            // does, so a drifting hash fails there loudly.
            let update_hash = rest.iter().any(|a| a == "--update-hash");
            let path = ext2_image::build(&workspace_root(), None, update_hash)?;
            println!("→ ext2-image: {}", path.display());
        }
        "pjdfstest" => {
            // Build closure is injected so the pjdfstest module doesn't
            // need to see the `BuildOpts` type — it just needs a kernel
            // ELF path.
            let opts_clone = BuildOpts {
                release: opts.release,
                fault_test: opts.fault_test,
                panic_test: opts.panic_test,
                bench: opts.bench,
                fork_trace: opts.fork_trace,
            };
            // --compare-baseline (#582): after the harness emits
            // target/pjdfstest-results.json, diff it against the
            // committed baseline at tests/pjdfstest/baseline/expected.json
            // and fail on any regression (pass → fail) or any silent
            // upgrade (fail → pass without the baseline being bumped in
            // the same change).
            //
            // --update-baseline (#582): after the harness emits results,
            // overwrite the committed baseline with the current run's
            // verdicts. Used by a human (or a follow-up PR that
            // intentionally changes expected verdicts) to bump the
            // baseline.
            let compare_baseline = rest.iter().any(|a| a == "--compare-baseline");
            let update_baseline = rest.iter().any(|a| a == "--update-baseline");
            let mode = match (compare_baseline, update_baseline) {
                (true, true) => {
                    return Err(
                        "pjdfstest: --compare-baseline and --update-baseline are mutually exclusive"
                            .into(),
                    );
                }
                (true, false) => pjdfstest::BaselineMode::Compare,
                (false, true) => pjdfstest::BaselineMode::Update,
                (false, false) => pjdfstest::BaselineMode::None,
            };
            pjdfstest::run(
                &workspace_root(),
                move || build(&opts_clone),
                "iso_pjdfstest",
                mode,
            )?;
        }
        "fuzz" => {
            // `xtask fuzz <target>`. Currently only `ext2` is wired
            // (#677); future targets will add more match arms.
            let which = rest
                .first()
                .ok_or("fuzz: missing target name (try `xtask fuzz ext2`)")?;
            match which.as_str() {
                "ext2" => {
                    // Pull `--iters=N` straight from the `rest` tail so the
                    // CI lane can throttle work. Default tuned for a
                    // ~few-second wall-clock on a cold runner.
                    let iters = rest
                        .iter()
                        .find_map(|a| {
                            a.strip_prefix("--iters=")
                                .and_then(|v| v.parse::<u64>().ok())
                        })
                        .unwrap_or(2000);
                    fuzz_ext2(iters)?;
                }
                other => {
                    return Err(
                        format!("fuzz: unknown target '{other}' (only 'ext2' is wired)").into(),
                    );
                }
            }
        }
        "clean" => clean()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!(
                "usage: cargo xtask [build|initrd|ext2-image|iso|run|test|test-unit|test-integration|smoke|pjdfstest|repro-fork|repro-fork-build|shell-pipeline|lint|isr-audit|fuzz|clean] [--release] [--fault-test] [--panic-test] [--bench] [--fork-trace]"
            );
            std::process::exit(2);
        }
    }
    Ok(())
}

fn take_flag(args: &mut Vec<String>, flag: &str) -> bool {
    if let Some(i) = args.iter().position(|a| a == flag) {
        args.remove(i);
        true
    } else {
        false
    }
}

/// Take a `--key=value` style flag out of the pre-subcommand args so
/// it can't be confused with the subcommand itself (e.g.
/// `cargo xtask --root=ext2 run` must not treat `--root=ext2` as the
/// subcommand). Returns the extracted value, if present.
fn take_value(args: &mut Vec<String>, prefix: &str) -> Option<String> {
    let pos = args.iter().position(|a| a.starts_with(prefix))?;
    let removed = args.remove(pos);
    removed.strip_prefix(prefix).map(str::to_string)
}

struct BuildOpts {
    release: bool,
    fault_test: bool,
    panic_test: bool,
    bench: bool,
    /// Compile the kernel with `--features fork-trace` to light up the
    /// serial-print instrumentation along the fork(2) syscall path (see
    /// `kernel/Cargo.toml`). Off by default; canary for epic #501 / #502.
    fork_trace: bool,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Magic bytes at LBA 0 of the test disk. The kernel's smoke-path
/// readback logs the first 16 bytes, which `SMOKE_MARKERS` assert on.
const TEST_DISK_MAGIC: &[u8] = b"VIBIXBLK0";
/// 1 MiB scratch disk — enough for any step-1 smoke test; the file is
/// regenerated if absent or the wrong size so it's safe to `rm -rf`.
const TEST_DISK_SIZE: u64 = 1024 * 1024;

fn test_disk_path() -> PathBuf {
    workspace_root().join("target").join("test-disk.img")
}

/// Create or refresh the test disk image. Idempotent: if the file is
/// already present and the right size, we leave it alone.
fn ensure_test_disk() -> R<PathBuf> {
    let path = test_disk_path();
    // Rebuild if absent, wrong size, or the magic prefix doesn't match.
    // Size alone isn't a strong enough check — an old disk image of the
    // right length but stale contents would silently fail the smoke
    // marker assertion, which is noisier to diagnose than a fresh write.
    let needs_write = match fs::metadata(&path) {
        Ok(m) if m.len() == TEST_DISK_SIZE => {
            let mut head = vec![0u8; TEST_DISK_MAGIC.len()];
            match fs::File::open(&path).and_then(|mut f| {
                use std::io::Read as _;
                f.read_exact(&mut head)
            }) {
                Ok(()) => head != TEST_DISK_MAGIC,
                Err(_) => true,
            }
        }
        _ => true,
    };
    if needs_write {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut data = vec![0u8; TEST_DISK_SIZE as usize];
        data[..TEST_DISK_MAGIC.len()].copy_from_slice(TEST_DISK_MAGIC);
        fs::write(&path, &data)?;
    }
    Ok(path)
}

/// QEMU args attaching the generated test disk as legacy virtio-blk.
/// `disable-modern=on,disable-legacy=off` pins the transport so the
/// step-1 legacy-only driver actually matches the device.
fn virtio_blk_args(disk: &Path) -> Vec<String> {
    let drive = format!("file={},if=none,id=vd0,format=raw", disk.display());
    vec![
        "-drive".to_string(),
        drive,
        "-device".to_string(),
        "virtio-blk-pci,drive=vd0,disable-modern=on,disable-legacy=off".to_string(),
    ]
}

/// Build a user-space binary package and strip its debug sections.
///
/// Setting RUSTFLAGS wholesale overrides the workspace
/// `[target.x86_64-unknown-none] rustflags` from .cargo/config.toml,
/// so we must re-supply every flag the kernel target still needs.
/// User-space binaries link at 0x400000 (lower half) and use the small
/// code model — no ±2 GiB kernel assumptions.
fn build_userspace_binary(package: &str, link_ld: &str) -> R<PathBuf> {
    let rustflags = [
        &format!("-C link-arg=-T{link_ld}"),
        "-C relocation-model=static",
        "-C code-model=small",
        "-C no-redzone=yes",
        "-C force-frame-pointers=yes",
    ]
    .join(" ");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .env("RUSTFLAGS", rustflags)
        .args(["build", "--package", package])
        .args(KERNEL_BUILD_STD_ARGS);
    check(cmd.status()?)?;
    let bin = workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join("debug")
        .join(package);
    if !bin.exists() {
        return Err(format!("userspace binary {package} missing at {}", bin.display()).into());
    }
    strip_debug(&bin)?;
    Ok(bin)
}

fn build_userspace_init() -> R<PathBuf> {
    build_userspace_binary("userspace_init", "userspace/init/link.ld")
}

/// Build the hello binary — the exec() target for the fork+exec+wait test.
/// Links at 0x400000 (lower half) just like init so load_user_elf accepts it.
fn build_userspace_hello() -> R<PathBuf> {
    build_userspace_binary("userspace_hello", "userspace/hello/link.ld")
}

/// Build the fork-loop reproducer harness (issue #506).
///
/// Shipped as `userspace_init.elf` when `cargo xtask repro-fork` is used —
/// this binary runs a tight fork+exec+wait loop as PID 1 to amplify the
/// ~50 %-rate flake bisected to PR #206 into a deterministic repro.
fn build_userspace_repro_fork() -> R<PathBuf> {
    build_userspace_binary("userspace_repro_fork", "userspace/repro_fork/link.ld")
}

/// Build the shell-pipeline integration binary (issue #462).
///
/// Shipped as `userspace_init.elf` when `cargo xtask shell-pipeline` is
/// used — the binary internally simulates `echo foo | cat | wc -c`
/// using pipe2/fork/dup2/close/wait4 and prints `SHELL_PIPELINE_OK: 4`
/// on success. See `userspace/shell_pipeline/src/main.rs` for the
/// rationale on why all three pipeline stages live in one binary.
fn build_userspace_shell_pipeline() -> R<PathBuf> {
    build_userspace_binary(
        "userspace_shell_pipeline",
        "userspace/shell_pipeline/link.ld",
    )
}

/// Build the no_std pjdfstest runner (#642 option 2). Shipped as
/// `/init` inside the deterministic ext2 image by
/// `cargo xtask pjdfstest`. Same link layout as `userspace_init` so
/// the kernel's ELF loader doesn't need any new code paths.
pub(crate) fn build_pjdfstest_runner() -> R<PathBuf> {
    build_userspace_binary("pjdfstest_runner", "userspace/pjdfstest_runner/link.ld")
}

fn kernel_binary(opts: &BuildOpts) -> PathBuf {
    let profile = if opts.release { "release" } else { "debug" };
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join(profile)
        .join("vibix")
}

fn build(opts: &BuildOpts) -> R<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .args(["build", "--package", "vibix", "--bin", "vibix"])
        .args(KERNEL_BUILD_STD_ARGS);
    if opts.release {
        cmd.arg("--release");
    }
    if opts.fault_test {
        cmd.arg("--features").arg("fault-test");
    }
    if opts.panic_test {
        cmd.arg("--features").arg("panic-test");
    }
    if opts.bench {
        cmd.arg("--features").arg("bench");
    }
    if opts.fork_trace {
        cmd.arg("--features").arg("fork-trace");
    }
    check(cmd.status()?)?;
    let bin = kernel_binary(opts);
    if !bin.exists() {
        return Err(format!("kernel binary missing at {}", bin.display()).into());
    }
    // embed_lntab must run before strip_debug — it parses the ELF's
    // own DWARF line tables, which strip_debug drops.
    lntab::embed(&bin, &workspace_root())?;
    strip_debug(&bin)?;
    embed_ksymtab(&bin)?;
    Ok(bin)
}

/// Strip DWARF debug sections from the kernel ELF. Without this, rust-lld
/// leaves `.debug_*` sections as orphans at VMA 0 which get pulled into
/// the rodata PT_LOAD segment's bounding box, computing a ~2 GiB MemSiz
/// that wraps past the kernel/user boundary and makes Limine reject the
/// image ("No higher half PHDRs exist"). `/DISCARD/` in the linker script
/// doesn't catch them reliably here, so strip post-link.
///
/// Prefers `llvm-objcopy` (from the rustup `llvm-tools` component bundled
/// with the active toolchain) over the system `objcopy`.  The system binary
/// is typically GNU objcopy for the host architecture, which cannot process
/// a cross-compiled ELF on a different host (e.g. aarch64 host, x86_64
/// kernel).  `llvm-objcopy` is architecture-agnostic and always correct.
fn strip_debug(kernel: &Path) -> R<()> {
    let tool = find_llvm_objcopy().unwrap_or_else(|| std::ffi::OsString::from("objcopy"));
    let status = Command::new(&tool)
        .arg("--strip-debug")
        .arg(kernel)
        .status()?;
    check(status)?;
    Ok(())
}

/// Locate `llvm-objcopy` from the active rustup toolchain's `llvm-tools`
/// component.  Returns `None` if `rustc` is not on PATH or the binary is not
/// found (caller falls back to system `objcopy`).
fn find_llvm_objcopy() -> Option<std::ffi::OsString> {
    // Ask rustc for its sysroot (e.g.
    // ~/.rustup/toolchains/nightly-aarch64-unknown-linux-gnu).
    let output = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sysroot = std::path::PathBuf::from(String::from_utf8(output.stdout).ok()?.trim());
    // llvm-tools are installed under
    // <sysroot>/lib/rustlib/<host-triple>/bin/llvm-objcopy.
    // Use a glob-style search so we don't need to hard-code the host triple.
    let bin_glob = sysroot.join("lib").join("rustlib");
    for entry in fs::read_dir(&bin_glob).ok()? {
        let entry = entry.ok()?;
        let candidate = entry.path().join("bin").join("llvm-objcopy");
        if candidate.exists() {
            return Some(candidate.into_os_string());
        }
    }
    None
}

/// Post-link step: read the freshly-linked ELF's own symbol table and
/// patch a compact (addr → name) blob into the reserved `.ksymtab`
/// section in-place. The kernel's runtime resolver parses it directly
/// through the linker-provided bounds, giving backtraces symbol names
/// without a second link pass.
fn embed_ksymtab(kernel: &Path) -> R<()> {
    use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
    use std::io::{Seek, SeekFrom, Write};

    let bytes = fs::read(kernel)?;
    let obj = object::File::parse(&*bytes)?;

    // Locate the reservation by symbol, not by section. We used to own a
    // dedicated `.ksymtab` output section, but that tripped rust-lld into
    // grouping `.data`/`.bss` under the read-only rodata PT_LOAD. Riding
    // in `.rodata` keeps the layout sane; we just need to convert the
    // reservation's VMA into a file offset via its containing section.
    let rsv = obj
        .symbols()
        .find(|s| {
            s.name()
                .map(|n| n == "KSYMTAB_RESERVATION")
                .unwrap_or(false)
        })
        .ok_or("KSYMTAB_RESERVATION symbol not found in kernel ELF")?;
    let rsv_vma = rsv.address();
    let rsv_size = rsv.size() as usize;
    if rsv_size == 0 {
        return Err("KSYMTAB_RESERVATION has zero size".into());
    }
    let section = obj
        .sections()
        .find(|s| {
            let (addr, size) = (s.address(), s.size());
            rsv_vma >= addr && rsv_vma + rsv_size as u64 <= addr + size
        })
        .ok_or("no section contains KSYMTAB_RESERVATION")?;
    let (sec_file_off, _sec_file_size) = section
        .file_range()
        .ok_or("section containing KSYMTAB_RESERVATION has no file bytes")?;
    let sec_off = sec_file_off + (rsv_vma - section.address());
    let sec_size = rsv_size;

    // Collect text-kind symbols with non-empty names. We keep all
    // function-like symbols, including compiler-generated ones —
    // names help even when they're mangled.
    let mut syms: Vec<(u64, String)> = Vec::new();
    for sym in obj.symbols() {
        if !matches!(sym.kind(), SymbolKind::Text | SymbolKind::Unknown) {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let addr = sym.address();
        if addr == 0 {
            continue;
        }
        // `{:#}` strips the trailing disambiguator hash — the goal is readable
        // names in backtraces, not round-trippable ones, and dropping the hash
        // saves ~17 bytes per Rust symbol in the strtab.
        syms.push((addr, format!("{:#}", rustc_demangle::demangle(name))));
    }
    syms.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.len().cmp(&b.1.len())));
    syms.dedup_by(|a, b| a.0 == b.0);

    // These must stay in sync with `size_of::<Header>()` and
    // `size_of::<Entry>()` in kernel/src/ksymtab.rs — that file pins
    // the layout with `const _: () = assert!(...)` so any drift
    // there breaks the kernel build before we can ship a bad blob.
    const HEADER_SIZE: usize = 20;
    const ENTRY_SIZE: usize = 16;

    let mut entries = Vec::with_capacity(syms.len() * ENTRY_SIZE);
    let mut strtab = Vec::<u8>::with_capacity(syms.len() * 24);
    for (addr, name) in &syms {
        let name_off = strtab.len() as u32;
        let name_len = name.len() as u32;
        strtab.extend_from_slice(name.as_bytes());
        entries.extend_from_slice(&addr.to_le_bytes());
        entries.extend_from_slice(&name_off.to_le_bytes());
        entries.extend_from_slice(&name_len.to_le_bytes());
    }

    let str_off = (HEADER_SIZE + entries.len()) as u32;
    let str_len = strtab.len() as u32;
    let count = syms.len() as u32;
    let used = HEADER_SIZE + entries.len() + strtab.len();

    if used > sec_size {
        return Err(format!(
            "ksymtab blob {used} bytes exceeds reservation {sec_size}; bump KSYMTAB_BYTES"
        )
        .into());
    }

    let mut blob = vec![0u8; sec_size];
    blob[0..4].copy_from_slice(b"KSYM");
    blob[4] = 1; // version
    blob[8..12].copy_from_slice(&count.to_le_bytes());
    blob[12..16].copy_from_slice(&str_off.to_le_bytes());
    blob[16..20].copy_from_slice(&str_len.to_le_bytes());
    blob[HEADER_SIZE..HEADER_SIZE + entries.len()].copy_from_slice(&entries);
    let str_start = HEADER_SIZE + entries.len();
    blob[str_start..str_start + strtab.len()].copy_from_slice(&strtab);

    drop(obj);
    let mut f = fs::OpenOptions::new().write(true).open(kernel)?;
    f.seek(SeekFrom::Start(sec_off))?;
    f.write_all(&blob)?;

    println!("→ ksymtab: {count} symbols, {used}/{sec_size} bytes");
    Ok(())
}

fn initrd_path() -> PathBuf {
    workspace_root().join("target").join("rootfs.tar")
}

/// Build one USTAR directory entry block (512 bytes).
///
/// USTAR format (IEEE 1003.1-1988):
/// - bytes   0..100  name (NUL-padded)
/// - bytes 100..108  mode (octal, NUL-terminated)
/// - bytes 108..116  uid  (octal, NUL-terminated)
/// - bytes 116..124  gid  (octal, NUL-terminated)
/// - bytes 124..136  size (octal, NUL-terminated, 0 for directories)
/// - bytes 136..148  mtime (octal, NUL-terminated, 0 = epoch)
/// - bytes 148..156  checksum (6 octal digits + NUL + space)
/// - byte  156       typeflag ('5' = directory, '0' = regular file)
/// - bytes 257..263  magic ("ustar\0")
/// - bytes 263..265  version ("00")
fn ustar_dir_block(name: &str) -> [u8; 512] {
    ustar_header_block(name, b'5', 0o755, 0)
}

/// Build one USTAR regular-file header block (512 bytes).
///
/// Callers must follow the returned header with `size` bytes of file
/// payload, padded with NULs to the next 512-byte boundary.
fn ustar_file_block(name: &str, size: u64) -> [u8; 512] {
    ustar_header_block(name, b'0', 0o644, size)
}

fn ustar_header_block(name: &str, typeflag: u8, mode: u16, size: u64) -> [u8; 512] {
    let mut block = [0u8; 512];

    // name field (bytes 0..100)
    let name_bytes = name.as_bytes();
    let copy_len = name_bytes.len().min(99);
    block[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    // mode: 7 octal digits + NUL
    let mode_str = format!("{mode:07o}");
    block[100..107].copy_from_slice(mode_str.as_bytes());

    // uid / gid: both 0
    block[108..115].copy_from_slice(b"0000000");
    block[116..123].copy_from_slice(b"0000000");

    // size: 11 octal digits + NUL
    let size_str = format!("{size:011o}");
    block[124..135].copy_from_slice(size_str.as_bytes());

    // mtime: 0 (epoch)
    block[136..147].copy_from_slice(b"00000000000");

    // typeflag
    block[156] = typeflag;

    // USTAR magic and version
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");

    // Checksum: sum of all bytes treating the checksum field (148..156) as spaces.
    // Write the result as a 6-digit octal number followed by NUL then space.
    let sum: u32 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                0x20u32
            } else {
                b as u32
            }
        })
        .sum();
    let chk = format!("{sum:06o}\0 ");
    block[148..156].copy_from_slice(chk.as_bytes());

    block
}

/// Build the minimal rootfs USTAR tarball at `target/rootfs.tar`.
///
/// The tarball contains:
///   - `dev/`, `tmp/`, `bin/`, `etc/` — stub mount points and directories
///     required by RFC 0002 §Initialization order.
///   - `etc/init/` — nested directory exercising multi-level path resolution
///     (issue #85).
///   - `etc/hostname` — top-level regular file whose content (`b"vibix\n"`)
///     is asserted by `kernel/tests/rootfs_module.rs` to prove the tar
///     payload survives end-to-end through `MountSource::RamdiskModule`.
///   - `etc/init/hello.txt` — nested regular file whose presence proves the
///     full `path_walk` chain resolves `/etc/init/hello.txt` end-to-end.
///
/// The tarball ends with two 512-byte all-zero blocks per the USTAR spec.
fn ensure_initrd() -> R<PathBuf> {
    let path = initrd_path();

    const DIRS: &[&str] = &["dev/", "tmp/", "bin/", "etc/", "etc/init/", "lib/"];
    const HOSTNAME_FILE: &str = "etc/hostname";
    const HOSTNAME_PAYLOAD: &[u8] = b"vibix\n";
    const NESTED_FILE: &str = "etc/init/hello.txt";
    const NESTED_PAYLOAD: &[u8] = b"nested\n";
    const MOTD_FILE: &str = "etc/motd";
    const MOTD_PAYLOAD: &[u8] = b"Welcome to vibix. Type `help` for builtins.\n";
    const LDSO_FILE: &str = "lib/ld-musl-x86_64.so.1";
    const LDSO_SIZE: u64 = 645_736;
    const LDSO_BLOCKS: u64 = LDSO_SIZE.div_ceil(512); // = 1262 blocks
                                                      // DIRS headers + 4 file headers + (3 small + LDSO_BLOCKS) data blocks + 2 end blocks.
    const EXPECTED_SIZE: u64 = (DIRS.len() as u64 + 4 + 3 + LDSO_BLOCKS + 2) * 512;

    let ldso_src = workspace_root().join("userspace/lib/ld-musl-x86_64.so.1");

    // Size + magic aren't sufficient — changing MOTD_PAYLOAD to another
    // equal-or-shorter string would leave the old payload on disk (same
    // length, same magic). Also compare the motd data block bytes so the
    // cache invalidates when the payload changes.
    // Layout offsets: DIRS.len() dir headers, then hostname hdr+data
    // (2 blocks), then nested hdr+data (2 blocks), then motd header
    // (1 block), then motd data.
    const MOTD_DATA_OFFSET: u64 = (DIRS.len() as u64 + 2 + 2 + 1) * 512;
    let needs_write = match fs::metadata(&path) {
        Ok(m) if m.len() == EXPECTED_SIZE => {
            let mut magic = [0u8; 6];
            let mut motd_block = [0u8; 512];
            fs::File::open(&path)
                .and_then(|mut f| {
                    use std::io::{Read, Seek, SeekFrom};
                    f.seek(SeekFrom::Start(257))?;
                    f.read_exact(&mut magic)?;
                    f.seek(SeekFrom::Start(MOTD_DATA_OFFSET))?;
                    f.read_exact(&mut motd_block)
                })
                .map(|()| {
                    if magic != *b"ustar\0" {
                        return true;
                    }
                    let plen = MOTD_PAYLOAD.len();
                    &motd_block[..plen] != MOTD_PAYLOAD
                        || motd_block[plen..].iter().any(|&b| b != 0)
                })
                .unwrap_or(true)
        }
        _ => true,
    };

    if needs_write {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let ldso_bytes = fs::read(&ldso_src)?;
        if ldso_bytes.len() as u64 != LDSO_SIZE {
            return Err(format!(
                "ld-musl-x86_64.so.1: expected {LDSO_SIZE} bytes, got {}",
                ldso_bytes.len()
            )
            .into());
        }
        let mut data: Vec<u8> = Vec::with_capacity(EXPECTED_SIZE as usize);
        for &dir in DIRS {
            data.extend_from_slice(&ustar_dir_block(dir));
        }
        data.extend_from_slice(&ustar_file_block(
            HOSTNAME_FILE,
            HOSTNAME_PAYLOAD.len() as u64,
        ));
        let mut hostname_block = [0u8; 512];
        hostname_block[..HOSTNAME_PAYLOAD.len()].copy_from_slice(HOSTNAME_PAYLOAD);
        data.extend_from_slice(&hostname_block);
        data.extend_from_slice(&ustar_file_block(NESTED_FILE, NESTED_PAYLOAD.len() as u64));
        let mut payload_block = [0u8; 512];
        payload_block[..NESTED_PAYLOAD.len()].copy_from_slice(NESTED_PAYLOAD);
        data.extend_from_slice(&payload_block);
        // etc/motd — user-facing banner line read by shell at startup.
        data.extend_from_slice(&ustar_file_block(MOTD_FILE, MOTD_PAYLOAD.len() as u64));
        let mut motd_block = [0u8; 512];
        motd_block[..MOTD_PAYLOAD.len()].copy_from_slice(MOTD_PAYLOAD);
        data.extend_from_slice(&motd_block);
        // lib/ld-musl-x86_64.so.1 — dynamic linker for musl-linked user binaries.
        data.extend_from_slice(&ustar_file_block(LDSO_FILE, LDSO_SIZE));
        let padded_len = ldso_bytes.len().div_ceil(512) * 512;
        let mut ldso_padded = vec![0u8; padded_len];
        ldso_padded[..ldso_bytes.len()].copy_from_slice(&ldso_bytes);
        data.extend_from_slice(&ldso_padded);
        // Two 512-byte zero blocks mark end-of-archive.
        data.extend_from_slice(&[0u8; 1024]);
        fs::write(&path, &data)?;
    }

    Ok(path)
}

fn ensure_limine() -> R<PathBuf> {
    let root = workspace_root().join("build").join("limine");
    if root.join("limine-bios.sys").exists() {
        return Ok(root);
    }
    fs::create_dir_all(root.parent().unwrap())?;
    println!("→ cloning limine {LIMINE_TAG}");
    check(
        Command::new("git")
            .args(["clone", "--depth=1", "--branch", LIMINE_TAG, LIMINE_REPO])
            .arg(&root)
            .status()?,
    )?;
    check(Command::new("make").arg("-C").arg(&root).status()?)?;
    Ok(root)
}

/// Assemble a bootable hybrid BIOS/UEFI ISO around the given kernel ELF.
/// `staging` names a subdirectory under `build/` to use as scratch
/// (so parallel test runs don't stomp each other).
/// Insert `cmdline: <value>` into `limine.conf` so the kernel's
/// `ExecutableCmdlineRequest` sees `value` at boot. Appends after the
/// first `protocol: limine` line (Limine keys are indentation-sensitive
/// to the 4-space block the committed file uses). Idempotent: if a
/// `cmdline:` line already exists under the target block it is
/// replaced.
fn inject_limine_cmdline(body: &str, value: &str) -> String {
    let indent = "    ";
    let mut out = String::with_capacity(body.len() + value.len() + 32);

    // Pre-scan: does a `cmdline:` line already exist inside a
    // `protocol: limine` block? If so the second pass *replaces* it
    // in-place (no duplicate). If not, we insert one right after the
    // `protocol: limine` line. Keeping the two cases disjoint avoids
    // the duplicate-line bug an earlier single-pass version shipped
    // with (flagged by CodeRabbit on PR #630).
    // A line terminates the current stanza when it's at column 0 and
    // isn't blank / a comment. Limine stanza headers are `/name` at
    // column 0; continuation lines inside a stanza are indented. This
    // matters because without it, a later top-level stanza could be
    // mistaken for still-being-inside the limine block and mutate
    // something we shouldn't touch.
    let ends_stanza = |line: &str| -> bool {
        let first = line.chars().next();
        match first {
            Some(c) if !c.is_whitespace() => {
                // Top-level line. A comment (`#`) doesn't count — those
                // can appear between stanzas without closing one.
                let t = line.trim_start();
                !t.is_empty() && !t.starts_with('#')
            }
            _ => false,
        }
    };

    let mut has_existing_cmdline = false;
    {
        let mut in_block = false;
        for line in body.lines() {
            let trimmed = line.trim_start();
            if trimmed == "protocol: limine" {
                in_block = true;
                continue;
            }
            if in_block && ends_stanza(line) {
                // Left the first limine stanza without seeing a
                // `cmdline:` — stop so a later stanza can't flip the
                // flag.
                break;
            }
            if in_block && trimmed.starts_with("cmdline:") {
                has_existing_cmdline = true;
                break;
            }
        }
    }

    let mut inserted = false;
    let mut in_block = false;
    for line in body.lines() {
        let trimmed_start = line.trim_start();
        // A new top-level stanza closes the previous one.
        if in_block && trimmed_start != "protocol: limine" && ends_stanza(line) {
            in_block = false;
        }
        // Replace an existing cmdline line in-place.
        if in_block && has_existing_cmdline && trimmed_start.starts_with("cmdline:") {
            out.push_str(indent);
            out.push_str("cmdline: ");
            out.push_str(value);
            out.push('\n');
            inserted = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
        if trimmed_start == "protocol: limine" && !inserted {
            in_block = true;
            // Only append a new cmdline line when there isn't one
            // downstream to replace. Otherwise the replace-in-place
            // branch above handles it on a later iteration.
            if !has_existing_cmdline {
                out.push_str(indent);
                out.push_str("cmdline: ");
                out.push_str(value);
                out.push('\n');
                inserted = true;
            }
        }
    }
    if !inserted {
        // No `protocol: limine` entry found — append at end as a last
        // resort. This keeps the function total even on a malformed
        // config.
        out.push_str("cmdline: ");
        out.push_str(value);
        out.push('\n');
    }
    out
}

fn make_iso(kernel: &Path, iso_out: &Path, staging: &str) -> R<()> {
    let userspace_init = build_userspace_init()?;
    make_iso_with_init(kernel, &userspace_init, iso_out, staging)
}

/// Variant of [`make_iso`] that injects `cmdline: <kernel_cmdline>`
/// into the Limine config so the kernel can read a `root=…` knob etc.
/// When `kernel_cmdline` is empty the Limine config is unchanged from
/// the committed `kernel/limine.conf`. See issue #577 for the consumer
/// (boot_cmdline::parse) that reads the resulting string from
/// Limine's `ExecutableCmdlineRequest` response.
fn make_iso_with_cmdline(
    kernel: &Path,
    iso_out: &Path,
    staging: &str,
    kernel_cmdline: &str,
) -> R<()> {
    let userspace_init = build_userspace_init()?;
    make_iso_inner(kernel, &userspace_init, iso_out, staging, kernel_cmdline)
}

/// Like [`make_iso_with_cmdline`] but publishes a caller-supplied
/// binary as `/boot/userspace_init.elf` (PID 1). Used by the
/// `pjdfstest` subcommand (#642) to swap the no_std runner in for
/// `userspace_init` without touching the Limine config or the
/// kernel's module-lookup path.
pub(crate) fn make_iso_with_cmdline_and_init(
    kernel: &Path,
    init_bin: &Path,
    iso_out: &Path,
    staging: &str,
    kernel_cmdline: &str,
) -> R<()> {
    make_iso_inner(kernel, init_bin, iso_out, staging, kernel_cmdline)
}

/// Variant of [`make_iso`] that publishes a caller-supplied binary as
/// `/boot/userspace_init.elf`.  Used by the `repro-fork` subcommand to
/// substitute the reproducer harness for the normal PID 1 init binary
/// without touching the kernel's module-lookup path or the Limine
/// config.  All other ISO contents (`userspace_hello.elf`, the rootfs
/// tarball, ld-musl) are identical to a normal boot.
fn make_iso_with_init(kernel: &Path, init_bin: &Path, iso_out: &Path, staging: &str) -> R<()> {
    make_iso_inner(kernel, init_bin, iso_out, staging, "")
}

fn make_iso_inner(
    kernel: &Path,
    init_bin: &Path,
    iso_out: &Path,
    staging: &str,
    kernel_cmdline: &str,
) -> R<()> {
    let limine = ensure_limine()?;
    let userspace_hello = build_userspace_hello()?;
    let initrd = ensure_initrd()?;
    let iso_root = workspace_root().join("build").join(staging);
    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(kernel, iso_root.join("boot/vibix"))?;
    fs::copy(init_bin, iso_root.join("boot/userspace_init.elf"))?;
    fs::copy(userspace_hello, iso_root.join("boot/userspace_hello.elf"))?;
    fs::copy(&initrd, iso_root.join("boot/rootfs.tar"))?;
    fs::copy(
        workspace_root().join("userspace/lib/ld-musl-x86_64.so.1"),
        iso_root.join("boot/ld-musl-x86_64.so.1"),
    )?;
    {
        let src = workspace_root().join("kernel/limine.conf");
        let dst = iso_root.join("boot/limine/limine.conf");
        if kernel_cmdline.is_empty() {
            fs::copy(&src, &dst)?;
        } else {
            // Inject `cmdline: <string>` under the existing
            // `protocol: limine` block so Limine passes it to the
            // kernel via `ExecutableCmdlineRequest`. The committed
            // config has no cmdline line today, so we append rather
            // than rewrite — append after the first `protocol: limine`
            // occurrence.
            let body = fs::read_to_string(&src)?;
            let injected = inject_limine_cmdline(&body, kernel_cmdline);
            fs::write(&dst, injected)?;
        }
    }
    for f in [
        "limine-bios.sys",
        "limine-bios-cd.bin",
        "limine-uefi-cd.bin",
    ] {
        fs::copy(limine.join(f), iso_root.join("boot/limine").join(f))?;
    }
    fs::copy(
        limine.join("BOOTX64.EFI"),
        iso_root.join("EFI/BOOT/BOOTX64.EFI"),
    )?;

    fs::create_dir_all(iso_out.parent().unwrap())?;
    check(
        Command::new("xorriso")
            .args([
                "-as",
                "mkisofs",
                "-b",
                "boot/limine/limine-bios-cd.bin",
                "-no-emul-boot",
                "-boot-load-size",
                "4",
                "-boot-info-table",
                "--efi-boot",
                "boot/limine/limine-uefi-cd.bin",
                "-efi-boot-part",
                "--efi-boot-image",
                "--protective-msdos-label",
            ])
            .arg(&iso_root)
            .arg("-o")
            .arg(iso_out)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?,
    )?;

    check(
        Command::new(limine.join("limine"))
            .arg("bios-install")
            .arg(iso_out)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?,
    )?;

    Ok(())
}

fn iso(opts: &BuildOpts) -> R<PathBuf> {
    let kernel = build(opts)?;
    let iso = workspace_root().join("target").join("vibix.iso");
    make_iso(&kernel, &iso, "iso_root")?;
    println!("→ iso: {}", iso.display());
    Ok(iso)
}

fn run(opts: &BuildOpts, root_flag: Option<&str>) -> R<()> {
    run_with_root(opts, root_flag, &[])
}

/// Shared QEMU boot path for `cargo xtask run` and its `--root=<kind>`
/// variants. `cmdline_extras` is merged straight into the kernel-cmdline
/// Limine passes through, so `--root=ext2` becomes a `cmdline:
/// root=/dev/vda` line in the generated Limine config. The `iso` is
/// rebuilt inside this function so the cmdline mutation lands in the
/// actual boot image.
///
/// `--root=ext2` replaces the scratch test-disk with the deterministic
/// ext2 image from `xtask ext2-image` (#579) and appends `root=/dev/vda`
/// to the kernel cmdline so `vfs::init` can choose ext2 on the
/// virtio-blk device. Any other value (including absent) keeps today's
/// behaviour: scratch test-disk, default-auto rootfs probe.
///
/// Note (tracked as a follow-up): the prod `_start` path in
/// `kernel/src/main.rs` parses the cmdline but does not yet call
/// `vfs::init::init_with(root_args)` — it calls the individual subsystem
/// bring-up functions without touching the VFS. So `--root=ext2` today
/// is primarily useful for QEMU-side verification (virtio disk, cmdline
/// plumbing) and the ext2 mount path continues to be exercised via the
/// integration tests that call `vibix::init` through `init_with`. Wiring
/// the prod boot path end-to-end is deferred so this PR stays small.
fn run_with_root(opts: &BuildOpts, root_flag: Option<&str>, cmdline_extras: &[&str]) -> R<()> {
    let (disk, mut extra_cmdline): (PathBuf, Vec<String>) = match root_flag {
        Some("ext2") => {
            let img = ext2_image::build(&workspace_root(), None, false)?;
            println!("→ root=ext2: booting {}", img.display());
            (img, vec!["root=/dev/vda".to_string()])
        }
        Some(other) => {
            return Err(format!(
                "unknown --root={}: accepted values are `ext2` (more land with future xtask waves)",
                other
            )
            .into());
        }
        None => (ensure_test_disk()?, Vec::new()),
    };
    for extra in cmdline_extras {
        extra_cmdline.push((*extra).to_string());
    }
    let cmdline = extra_cmdline.join(" ");

    let kernel = build(opts)?;
    let iso = workspace_root().join("target").join("vibix.iso");
    make_iso_with_cmdline(&kernel, &iso, "iso_root", &cmdline)?;

    let status = Command::new("qemu-system-x86_64")
        .args([
            "-M",
            "q35",
            "-cpu",
            "max",
            "-m",
            "256M",
            "-serial",
            "stdio",
            "-no-reboot",
            "-no-shutdown",
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .status()?;
    match status.code() {
        Some(c) if c == QEMU_EXIT_FAILURE => Err("kernel panic — see serial log above".into()),
        Some(c) if c == QEMU_EXIT_SUCCESS => Ok(()),
        Some(0) | None => Ok(()),
        Some(n) => {
            eprintln!("qemu exited with code {n}");
            Ok(())
        }
    }
}

/// Boot one test kernel in QEMU headlessly and report pass/fail based on
/// the exit-code protocol (Success=65, Failure=33).
fn test_runner(kernel: &Path) -> R<()> {
    let name = kernel.file_name().unwrap().to_string_lossy();
    // Mirror the build() post-link fixups so integration-test ELFs pass
    // Limine's PHDR validation and their panic-path backtraces resolve
    // to symbol names and source coordinates.
    lntab::embed(kernel, &workspace_root())?;
    strip_debug(kernel)?;
    embed_ksymtab(kernel)?;
    let iso = workspace_root().join("target").join(format!("{name}.iso"));
    make_iso(kernel, &iso, &format!("iso_{name}"))?;

    eprintln!("▶ {}", name);
    // Note: no `-no-shutdown` here — it would prevent `isa-debug-exit`
    // from actually terminating QEMU, defeating the exit-code protocol.
    let disk = ensure_test_disk()?;
    let mut child = Command::new("qemu-system-x86_64")
        .args([
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
            "-device",
            "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ])
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return match status.code() {
                Some(c) if c == QEMU_EXIT_SUCCESS => Ok(()),
                Some(c) if c == QEMU_EXIT_FAILURE => Err(format!("test {name} failed").into()),
                other => Err(format!("test {name}: unexpected qemu exit {other:?}").into()),
            };
        }
        if start.elapsed() > TEST_TIMEOUT {
            let _ = child.kill();
            return Err(format!("test {name} timed out after {:?}", TEST_TIMEOUT).into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Parse `[[test]]` target names from a `Cargo.toml` body, preserving
/// declaration order. Assumes each `[[test]]` block is followed by a
/// `name = "<ident>"` line before the next `[`-prefixed header. Blank
/// lines and comments between the header and the `name` key are
/// tolerated; inline comments on the `name` line itself are not.
///
/// Fails loudly if a `[[test]]` header is encountered without a parseable
/// `name = "..."` key before the next section or end-of-file — the
/// whole point of #292 is to avoid silently dropping tests.
fn parse_test_names(manifest: &str) -> R<Vec<String>> {
    let mut names = Vec::new();
    let mut in_test = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            if in_test {
                return Err("[[test]] block ended without a parseable `name = \"...\"`".into());
            }
            in_test = trimmed == "[[test]]";
            continue;
        }
        if !in_test {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(rest) = rest.strip_prefix('=') {
                let val = rest.trim();
                if let Some(inner) = val.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    names.push(inner.to_string());
                    in_test = false;
                }
            }
        }
    }
    if in_test {
        return Err("manifest ended inside a [[test]] block with no parseable `name`".into());
    }
    Ok(names)
}

/// Integration tests that parse from `kernel/Cargo.toml` but should
/// NOT be run by `cargo xtask test`. Each entry must name the
/// follow-up issue that tracks re-enabling it. Empty is the goal.
const TEST_SKIPLIST: &[&str] = &[];

/// Read `kernel/Cargo.toml` and return the declared integration-test
/// target names, minus anything in [`TEST_SKIPLIST`]. Derived
/// dynamically to avoid drift between the manifest and the xtask test
/// runner (see issue #292).
fn integration_test_names() -> R<Vec<String>> {
    let manifest_path = workspace_root().join("kernel").join("Cargo.toml");
    let body = fs::read_to_string(&manifest_path)?;
    let names = parse_test_names(&body)?;
    if names.is_empty() {
        return Err(format!("no [[test]] entries found in {}", manifest_path.display()).into());
    }
    let filtered: Vec<String> = names
        .into_iter()
        .filter(|n| !TEST_SKIPLIST.contains(&n.as_str()))
        .collect();
    if filtered.is_empty() {
        return Err(format!(
            "every [[test]] entry in {} is in TEST_SKIPLIST — nothing to run",
            manifest_path.display()
        )
        .into());
    }
    Ok(filtered)
}

fn test_unit() -> R<()> {
    // Host unit tests (--lib only; pure-logic modules).
    //
    // `--features ext2` is enabled so the ext2 driver's host unit
    // tests (`fs::ext2::fs::tests` — mount-sequence arithmetic and
    // feature-flag constants) are picked up. The on-disk type tests in
    // `fs::ext2::disk::tests` compile unconditionally and are included
    // either way.
    println!("→ host unit tests");
    check(
        Command::new("cargo")
            .current_dir(workspace_root())
            .args(["test", "--package", "vibix", "--lib", "--features", "ext2"])
            .status()?,
    )?;
    Ok(())
}

fn test_integration() -> R<()> {
    // QEMU integration tests. Each is invoked by name so cargo doesn't
    // also try to build the lib's no_std test harness (which would
    // require std). Cargo's runner config invokes us back as
    // `test-runner <binary>` per compiled test.
    //
    // The test list is derived from `kernel/Cargo.toml` `[[test]]`
    // entries so adding a new integration test in the manifest
    // automatically wires it into `cargo xtask test` (issue #292).
    //
    // `--features ext2` is passed unconditionally so any test gated on
    // the Workstream D/E driver (`required-features = ["ext2"]`) is
    // picked up. The feature is a compile-time gate around the
    // ext2-driver trait impls; enabling it in the test binary has no
    // effect on boot-path behaviour (those call sites stay gated even
    // with the feature on until an explicit registration hook lands in
    // a later wave).
    println!("→ integration tests under QEMU");
    let tests = integration_test_names()?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .args(["test", "--package", "vibix", "--features", "ext2"])
        .args(KERNEL_BUILD_STD_ARGS);
    for t in &tests {
        cmd.arg("--test").arg(t);
    }
    check(cmd.status()?)?;
    Ok(())
}

fn test_all() -> R<()> {
    test_unit()?;
    test_integration()?;
    Ok(())
}

fn smoke(opts: &BuildOpts) -> R<()> {
    use std::collections::HashSet;
    use std::time::Instant;

    let iso = iso(opts)?;
    let disk = ensure_test_disk()?;

    // #478 diagnostic step 1: capture QEMU's port-0xE9 debug console to a
    // file alongside serial. The kernel emits single-byte markers on 0xE9
    // immediately around the ring-0→ring-3 iretq (see
    // `kernel::arch::x86_64::syscall::jump_to_ring3`). Because the
    // debugcon path is independent of the serial mux, seeing e.g. `0xE1`
    // here when the "init: hello from pid 1" serial marker is missing
    // proves iretq was attempted; missing `0xE1` points at a pre-iretq
    // fault. Unconditional — the capture is cheap and always-on.
    let debugcon_log: PathBuf = {
        let mut p =
            PathBuf::from(env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into()));
        p.push("debugcon.log");
        // Truncate any stale log from a previous run.
        let _ = fs::remove_file(&p);
        p
    };
    let debugcon_arg = format!("file:{}", debugcon_log.display());

    // Boot QEMU with serial to stdio; stdout is piped so we can read it
    // incrementally.  -no-shutdown keeps the kernel in hlt_loop forever
    // (the kernel never calls isa-debug-exit), so we are responsible for
    // killing the process once we are done.
    let mut child = Command::new("qemu-system-x86_64")
        .args([
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
        ])
        .args(["-debugcon", &debugcon_arg])
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    // Hard ceiling: a watchdog thread kills QEMU after HARD_CAP so that a
    // blocking read_line() on a stalled kernel cannot hang indefinitely.
    // Successive bumps: 90 s → 180 s → 300 s → 600 s. On un-accelerated CI
    // QEMU (no KVM on ubuntu-latest) the boot path plus first ring-3 write()
    // syscall — the syscall that emits "init: hello from pid 1" — was still
    // arriving exactly at the 300 s cap on loaded GitHub runners. 600 s gives
    // ~4× the observed worst-case boot time. The loop exits as soon as every
    // marker appears or the kernel prints a panic marker, so a generous
    // ceiling only affects genuine hangs.
    const HARD_CAP: Duration = Duration::from_secs(600);
    // Kernel panic marker printed by the panic_handler in kernel/src/main.rs.
    // Seeing this means the kernel has already lost — don't wait out HARD_CAP.
    const PANIC_MARKER: &str = "KERNEL PANIC:";
    // Cancel-channel watchdog (same pattern as `repro_fork` — see #516).
    // `thread::sleep(HARD_CAP)` would block the join at the end of this
    // function for the full cap even when markers arrived in a few seconds,
    // dominating wall-clock on the happy path (the #507 nightly soak was
    // paying ~10 min per run for nothing). Replace with a `recv_timeout`
    // that the main loop wakes up by dropping `cancel_tx` on its way out:
    // the watchdog sees `Disconnected` and exits immediately. If the main
    // loop hangs or HARD_CAP elapses first, `recv_timeout` returns
    // `Timeout` and the watchdog kills QEMU — original fail-safe semantics
    // preserved.
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let watchdog = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = cancel_rx.recv_timeout(HARD_CAP) {
            let _ = Command::new("kill").arg(pid.to_string()).status();
        }
    });

    let deadline = Instant::now() + HARD_CAP;
    let mut remaining: HashSet<&'static str> = SMOKE_MARKERS.iter().copied().collect();
    let mut soft_remaining: HashSet<&'static str> = SMOKE_SOFT_MARKERS.iter().copied().collect();
    let mut accumulated = String::new();
    let mut panicked = false;

    // Read QEMU serial output off the main thread: `BufReader::read_line`
    // blocks until a newline arrives, so a completion check on the main
    // thread would park inside the read for up to HARD_CAP after the last
    // marker arrived. Offload reads to a thread and fan lines through an
    // mpsc channel; the main loop polls with a short timeout so it can
    // notice completion promptly without busy-waiting.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader_handle = std::thread::spawn(move || {
        use std::io::BufRead as _;
        let mut reader = std::io::BufReader::new(stdout);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break, // pipe closed (QEMU killed or exited)
                Ok(_) => {
                    if tx.send(line.clone()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    const TICK: Duration = Duration::from_millis(100);
    while Instant::now() < deadline {
        match rx.recv_timeout(TICK) {
            Ok(line) => {
                accumulated.push_str(&line);
                if line.contains(PANIC_MARKER) {
                    panicked = true;
                    break;
                }
                remaining.retain(|m| !accumulated.contains(m));
                soft_remaining.retain(|m| !accumulated.contains(m));
                if remaining.is_empty() && soft_remaining.is_empty() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Ensure QEMU is dead (idempotent if watchdog already fired). Killing
    // the child closes the pipe, which unblocks the reader thread. Drop
    // the cancel sender so the watchdog's `recv_timeout` wakes with
    // Disconnected and we don't block the join for the full HARD_CAP on
    // the success path — see #516.
    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(cancel_tx);
    let _ = watchdog.join();
    let _ = reader_handle.join();
    let _ = child.wait();

    // Drain any serial lines the reader thread queued after the main
    // loop exited (marker-completion path) but before the pipe closed.
    // Without this, a late residual signature like
    // `ring3-first-fault: #PF` printed in the final ms of the boot
    // can be silently dropped from `accumulated` and miss the
    // VIBIX_SMOKE_SERIAL_LOG persisted file (#648 nightly-soak relies
    // on every emitted line being inspectable).
    while let Ok(line) = rx.try_recv() {
        accumulated.push_str(&line);
    }

    // Optional always-on serial capture for the nightly soak (#648).
    // When `VIBIX_SMOKE_SERIAL_LOG` is set, persist the accumulated
    // serial output to that path on every exit (success and failure)
    // so the soak driver can pattern-match each run for residual
    // bug-class signatures (#478, #527, #646) without re-routing
    // QEMU's stdio. Best-effort: a write failure is logged to stderr
    // but does not change smoke's pass/fail outcome.
    if let Some(path) = env::var_os("VIBIX_SMOKE_SERIAL_LOG") {
        if let Err(e) = fs::write(&path, &accumulated) {
            eprintln!(
                "warning: failed to write VIBIX_SMOKE_SERIAL_LOG={}: {e}",
                Path::new(&path).display()
            );
        }
    }

    // Helper to dump the debugcon log (#478 diagnostic step 1) on any
    // failure path so CI log lines and uploaded artifacts both show it.
    let dump_debugcon = |log_path: &Path| match fs::read(log_path) {
        Ok(bytes) if !bytes.is_empty() => {
            let hex: String = bytes.iter().map(|b| format!("{b:02x} ")).collect();
            eprintln!(
                    "--- captured debugcon (port 0xE9, {} bytes) ---\n{}\n-----------------------------------",
                    bytes.len(),
                    hex.trim_end()
                );
        }
        Ok(_) => eprintln!("--- captured debugcon: <empty> ---"),
        Err(e) => eprintln!("--- captured debugcon: <unreadable: {e}> ---"),
    };

    if panicked {
        eprintln!("--- captured serial ---\n{accumulated}\n-----------------------");
        dump_debugcon(&debugcon_log);
        return Err("smoke: kernel panic detected".into());
    }

    if remaining.is_empty() {
        if soft_remaining.is_empty() {
            println!(
                "→ smoke: all {} markers present ✓",
                SMOKE_MARKERS.len() + SMOKE_SOFT_MARKERS.len()
            );
        } else {
            let mut missing_soft: Vec<&str> = soft_remaining.into_iter().collect();
            missing_soft.sort_unstable();
            println!(
                "→ smoke: all {} required markers present ✓ (soft markers missing: {:?} — flakey fork+exec path, not failing)",
                SMOKE_MARKERS.len(),
                missing_soft
            );
        }
        Ok(())
    } else {
        let mut missing: Vec<&str> = remaining.into_iter().collect();
        missing.sort_unstable();
        eprintln!("--- captured serial ---\n{accumulated}\n-----------------------");
        dump_debugcon(&debugcon_log);
        Err(format!("smoke: missing markers {:?}", missing).into())
    }
}

/// Warm the reproducer ISO without booting QEMU.  Issue #526.
///
/// Builds the kernel, the `userspace_repro_fork` binary, and the ISO
/// that ships the reproducer as `/boot/userspace_init.elf`.  Returns
/// the path to the completed ISO.
///
/// This is the build-only half of `repro_fork`.  It exists so that CI
/// can warm the artifacts (and catch build-step failures) in a distinct
/// workflow step, without also paying for a full QEMU run.  The 100×
/// smoke-soak workflow drives one `scripts/repro-fork.sh` boot per
/// iteration; without this split, the "Pre-build" step ended up running
/// the full harness and any first-boot flake prevented the soak loop
/// from executing (run 24593451935).
///
/// After this returns successfully, a subsequent `cargo xtask
/// repro-fork` (or `scripts/repro-fork.sh`) on the same workspace will
/// find every upstream artifact warm — cargo no-ops, the ISO staging
/// directory is re-assembled from already-built inputs, and the run
/// cost collapses to QEMU boot time.
fn repro_fork_build(opts: &BuildOpts) -> R<PathBuf> {
    // Build the kernel and the reproducer init binary, then assemble
    // an ISO with the reproducer substituted for userspace_init.elf.
    let kernel = build(opts)?;
    let repro_init = build_userspace_repro_fork()?;
    let iso = workspace_root().join("target").join("vibix-repro-fork.iso");
    make_iso_with_init(&kernel, &repro_init, &iso, "iso_repro_fork")?;
    // Also ensure the test disk is present so the per-run boot path
    // doesn't need to regenerate it.  `ensure_test_disk` is idempotent.
    ensure_test_disk()?;
    println!("→ repro-fork iso: {}", iso.display());
    Ok(iso)
}

/// Build + boot the fork-loop reproducer ISO under QEMU with a
/// heartbeat-aware watchdog.  Issue #506 / epic #501.
///
/// Replaces `/boot/userspace_init.elf` in the ISO with the
/// `userspace_repro_fork` binary (see `userspace/repro_fork/`).  That
/// binary runs `CYCLES` fork+exec+wait iterations, emitting
/// `repro: cycle K alive` every 50 cycles and `repro: fork loop
/// complete` on success.  The loop in this function follows those
/// markers and enforces a heartbeat-gap watchdog: if no new
/// `repro: ...` line appears within `REPRO_HEARTBEAT_GAP`, QEMU is
/// killed and the subcommand exits non-zero.
///
/// Returns `Ok(())` iff we saw `repro: fork loop complete` before any
/// stall/error marker.  Any `WATCHDOG`, `fork failed`, `wait4 failed`,
/// or `KERNEL PANIC:` line is a definitive failure.
fn repro_fork(opts: &BuildOpts) -> R<()> {
    use std::collections::VecDeque;
    use std::io::BufRead as _;
    use std::time::Instant;

    /// Any single gap between `repro:` heartbeat lines that exceeds
    /// this duration is a stall.  60 s is generous under unaccelerated
    /// CI QEMU (a single fork/exec/wait round has been measured at a
    /// few hundred ms there) and tight enough to fail fast on a real
    /// hang.
    const REPRO_HEARTBEAT_GAP: Duration = Duration::from_secs(60);

    /// Absolute ceiling for the whole reproducer boot.  Even 500 clean
    /// cycles finish well inside this; exceeding it means the last
    /// heartbeat watchdog somehow missed a stall (or CYCLES was
    /// bumped into the thousands).  Prevents a runaway CI job.
    const REPRO_HARD_CAP: Duration = Duration::from_secs(900);

    const SUCCESS_MARKER: &str = "repro: fork loop complete";
    const PANIC_MARKER: &str = "KERNEL PANIC:";
    /// Any line containing a terminal-failure token from the harness.
    const FAIL_TOKENS: &[&str] = &[
        "repro: WATCHDOG",
        "repro: fork failed",
        "repro: wait4 failed",
        "repro: execve returned in child",
        "repro: harness panic",
    ];

    // Build the kernel, the reproducer init binary, and the ISO.
    // Delegating to `repro_fork_build` keeps the build-only subcommand
    // and the full-harness subcommand on the exact same build path —
    // no drift risk between them.
    let iso = repro_fork_build(opts)?;

    let disk = ensure_test_disk()?;
    let mut child = Command::new("qemu-system-x86_64")
        .args([
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
        ])
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    // Absolute-deadline watchdog thread — independent of the
    // heartbeat-gap check below.  Kills QEMU if the whole run
    // somehow stretches past REPRO_HARD_CAP.  We can't `.join()` this
    // thread on the fast path (success tends to arrive well inside
    // REPRO_HARD_CAP), so we set up a cancel channel: the main loop
    // drops the sender on the way out, which wakes the watchdog's
    // `recv_timeout` with Disconnected and lets it exit cleanly.
    let hard_pid = pid;
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let hard_watchdog = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            cancel_rx.recv_timeout(REPRO_HARD_CAP)
        {
            let _ = Command::new("kill").arg(hard_pid.to_string()).status();
        }
    });

    // Reader thread: fan serial lines into an mpsc channel so the
    // main loop can poll with a short timeout and enforce the
    // heartbeat-gap watchdog without blocking inside read_line.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader_handle = std::thread::spawn(move || {
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

    let start = Instant::now();
    let mut last_heartbeat = Instant::now();
    let mut success = false;
    let mut failure: Option<String> = None;
    // Keep the last few lines of serial captured so a failure summary
    // has immediate context; the full log lives on stdout already.
    let mut tail: VecDeque<String> = VecDeque::with_capacity(32);
    const TICK: Duration = Duration::from_millis(200);

    loop {
        match rx.recv_timeout(TICK) {
            Ok(line) => {
                // Mirror the serial to our stdout so humans (and CI
                // log collectors) see the heartbeat stream live.
                print!("{line}");
                if tail.len() == 32 {
                    tail.pop_front();
                }
                tail.push_back(line.clone());

                if line.contains(PANIC_MARKER) {
                    failure = Some(format!("kernel panic: {}", line.trim_end()));
                    break;
                }
                if let Some(tok) = FAIL_TOKENS.iter().find(|t| line.contains(*t)) {
                    failure = Some(format!("harness failure ({}): {}", tok, line.trim_end()));
                    break;
                }
                if line.contains("repro:") {
                    last_heartbeat = Instant::now();
                }
                if line.contains(SUCCESS_MARKER) {
                    success = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if last_heartbeat.elapsed() > REPRO_HEARTBEAT_GAP {
                    failure = Some(format!(
                        "heartbeat stalled: no `repro:` marker in {:?}",
                        REPRO_HEARTBEAT_GAP
                    ));
                    break;
                }
                if start.elapsed() > REPRO_HARD_CAP {
                    failure = Some(format!(
                        "hard cap exceeded ({:?}) without success",
                        REPRO_HARD_CAP
                    ));
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if !success && failure.is_none() {
                    failure = Some("QEMU exited before `repro: fork loop complete`".to_string());
                }
                break;
            }
        }
    }

    // Ensure QEMU is dead whether we succeeded, failed, or timed out.
    // Kill first so the reader pipe closes and the reader thread's
    // `read_line` returns Ok(0); then drop the cancel sender so the
    // hard watchdog wakes and exits; then collect the threads and
    // reap the child.
    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(cancel_tx);
    let _ = hard_watchdog.join();
    let _ = reader_handle.join();
    let _ = child.wait();

    match (success, failure) {
        (true, _) => {
            println!(
                "→ repro-fork: fork loop completed in {:?} ✓",
                start.elapsed()
            );
            Ok(())
        }
        (false, Some(msg)) => {
            eprintln!("--- captured serial (tail) ---");
            for line in &tail {
                eprint!("{line}");
            }
            eprintln!("------------------------------");
            Err(format!("repro-fork: {msg}").into())
        }
        (false, None) => Err("repro-fork: terminated with no success and no failure marker".into()),
    }
}

/// Boot the shell-pipeline integration binary as PID 1 and assert
/// the `SHELL_PIPELINE_OK: 4` marker on serial (issue #462).
///
/// Mirrors the `repro-fork` plumbing: builds an ISO that swaps
/// `userspace_shell_pipeline` in for `userspace_init.elf`, boots it
/// under QEMU, mirrors serial to stdout, and watches for either the
/// success marker, a `SHELL_PIPELINE_FAIL:` line, or a kernel panic.
fn shell_pipeline(opts: &BuildOpts) -> R<()> {
    use std::collections::VecDeque;
    use std::io::BufRead as _;
    use std::time::Instant;

    /// Hard ceiling on the whole run. Three forks plus a few pipe
    /// reads should finish well inside one second on accelerated
    /// hardware, but un-accelerated CI QEMU plus first-boot kernel
    /// init can stretch to tens of seconds. 120 s is generous.
    const HARD_CAP: Duration = Duration::from_secs(120);

    const SUCCESS_MARKER: &str = "SHELL_PIPELINE_OK: 4";
    const FAIL_MARKER: &str = "SHELL_PIPELINE_FAIL:";
    const PANIC_MARKER: &str = "KERNEL PANIC:";

    let kernel = build(opts)?;
    let init_bin = build_userspace_shell_pipeline()?;
    let iso = workspace_root()
        .join("target")
        .join("vibix-shell-pipeline.iso");
    make_iso_with_init(&kernel, &init_bin, &iso, "iso_shell_pipeline")?;
    let disk = ensure_test_disk()?;

    let mut child = Command::new("qemu-system-x86_64")
        .args([
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
        ])
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    // Hard-cap watchdog (same cancel-channel pattern as repro_fork).
    let hard_pid = pid;
    let (cancel_tx, cancel_rx) = std::sync::mpsc::channel::<()>();
    let hard_watchdog = std::thread::spawn(move || {
        if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) = cancel_rx.recv_timeout(HARD_CAP) {
            let _ = Command::new("kill").arg(hard_pid.to_string()).status();
        }
    });

    // Reader thread → channel; main thread polls with a short timeout
    // so the absolute deadline stays accurate even if the kernel hangs
    // before any line arrives.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let reader_handle = std::thread::spawn(move || {
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

    let start = Instant::now();
    let mut success = false;
    let mut failure: Option<String> = None;
    let mut tail: VecDeque<String> = VecDeque::with_capacity(64);
    const TICK: Duration = Duration::from_millis(200);

    loop {
        match rx.recv_timeout(TICK) {
            Ok(line) => {
                print!("{line}");
                if tail.len() == 64 {
                    tail.pop_front();
                }
                tail.push_back(line.clone());

                if line.contains(PANIC_MARKER) {
                    failure = Some(format!("kernel panic: {}", line.trim_end()));
                    break;
                }
                if line.contains(FAIL_MARKER) {
                    failure = Some(format!("harness failure: {}", line.trim_end()));
                    break;
                }
                if line.contains(SUCCESS_MARKER) {
                    success = true;
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if start.elapsed() > HARD_CAP {
                    failure = Some(format!("hard cap exceeded ({HARD_CAP:?}) without success"));
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                if !success && failure.is_none() {
                    failure = Some(format!("QEMU exited before `{SUCCESS_MARKER}` marker"));
                }
                break;
            }
        }
    }

    let _ = Command::new("kill").arg(pid.to_string()).status();
    drop(cancel_tx);
    let _ = hard_watchdog.join();
    let _ = reader_handle.join();
    let _ = child.wait();

    match (success, failure) {
        (true, _) => {
            println!(
                "→ shell-pipeline: SHELL_PIPELINE_OK in {:?} ✓",
                start.elapsed()
            );
            Ok(())
        }
        (false, Some(msg)) => {
            eprintln!("--- captured serial (tail) ---");
            for line in &tail {
                eprint!("{line}");
            }
            eprintln!("------------------------------");
            Err(format!("shell-pipeline: {msg}").into())
        }
        (false, None) => {
            Err("shell-pipeline: terminated with no success and no failure marker".into())
        }
    }
}

/// Parsed view of the repro-fork harness start banner.
///
/// The harness emits a dedicated `repro: CYCLES=N\n` line before the
/// legacy `repro: starting fork loop cycles=N hb=K\n` banner so the
/// compiled cycle count is legible even when early kernel logs
/// interleave mid-banner on the shared serial (see issue #531).  This
/// struct captures both signals so the parser can cross-check them.
///
/// Only referenced from host unit tests today (`parse_repro_banner_*`);
/// the parser exists so a soak-step addition that wants to verify the
/// banner at runtime has a single tested entry point to call into.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReproBanner {
    /// Cycle count from the dedicated `repro: CYCLES=N` line.
    cycles_dedicated: u64,
    /// Cycle count from the combined `repro: starting fork loop
    /// cycles=N hb=K` line (legacy banner).  `None` if the line is
    /// absent or mangled (e.g. interleaved with kernel log output).
    cycles_combined: Option<u64>,
    /// Heartbeat interval from the legacy banner.  `None` if the line
    /// is mangled or missing.
    heartbeat: Option<u64>,
}

/// Parse the repro-fork start banner out of a captured serial log.
///
/// Returns `None` if the dedicated `repro: CYCLES=<N>` line is missing
/// or malformed; that line is the single source of truth for the
/// compiled cycle count, and its absence is the regression this
/// parser guards against (issue #531: if `REPRO_FORK_CYCLES` or
/// `option_env!` ever silently compiles to the wrong value again, the
/// xtask test will flag it in CI rather than silently running the
/// wrong number of iterations).
#[cfg_attr(not(test), allow(dead_code))]
fn parse_repro_banner(log: &str) -> Option<ReproBanner> {
    let cycles_dedicated = parse_dedicated_cycles(log)?;
    let (cycles_combined, heartbeat) = parse_combined_banner(log);
    Some(ReproBanner {
        cycles_dedicated,
        cycles_combined,
        heartbeat,
    })
}

/// Extract `N` from the first occurrence of `repro: CYCLES=<N>`.
///
/// Only accepts base-10 digits up to the next non-digit or end-of-line
/// so a mid-banner interleave (e.g. `repro: CYCLES=500ring3-iretq: ...`)
/// still yields the intended value.
#[cfg_attr(not(test), allow(dead_code))]
fn parse_dedicated_cycles(log: &str) -> Option<u64> {
    const MARKER: &str = "repro: CYCLES=";
    let start = log.find(MARKER)? + MARKER.len();
    let rest = &log[start..];
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Extract `(cycles, heartbeat)` from the legacy
/// `repro: starting fork loop cycles=<N> hb=<K>` banner.
///
/// Either element can be `None` if the banner was interleaved with
/// other serial output.  The dedicated `repro: CYCLES=` line is the
/// authoritative source; this helper exists for cross-checking and for
/// future banner-shape regressions.
#[cfg_attr(not(test), allow(dead_code))]
fn parse_combined_banner(log: &str) -> (Option<u64>, Option<u64>) {
    const MARKER: &str = "repro: starting fork loop cycles=";
    let Some(start) = log.find(MARKER) else {
        return (None, None);
    };
    let rest = &log[start + MARKER.len()..];
    let cycles: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let cycles = cycles.parse::<u64>().ok();

    // Look for " hb=<K>" on the same line (no newline in between).
    let line_end = rest.find('\n').unwrap_or(rest.len());
    let line = &rest[..line_end];
    let hb_marker = " hb=";
    let heartbeat = line.find(hb_marker).and_then(|idx| {
        let tail = &line[idx + hb_marker.len()..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        digits.parse::<u64>().ok()
    });
    (cycles, heartbeat)
}

fn lint() -> R<()> {
    println!("→ clippy: xtask (host)");
    check(
        Command::new("cargo")
            .current_dir(workspace_root())
            .args([
                "clippy",
                "--package",
                "xtask",
                "--all-targets",
                "--",
                "-D",
                "warnings",
            ])
            .status()?,
    )?;

    println!("→ clippy: vibix (kernel, {KERNEL_TARGET})");
    check(
        Command::new("cargo")
            .current_dir(workspace_root())
            .args(["clippy", "--package", "vibix"])
            .args(KERNEL_BUILD_STD_ARGS)
            .args(["--all-targets", "--", "-D", "warnings"])
            .status()?,
    )?;

    println!("→ isr-audit: scanning ISR-reachable files");
    isr_audit::run(&workspace_root())?;

    Ok(())
}

/// `xtask fuzz ext2` — bounded-iteration smoke run of the ext2 host
/// fuzz harness (#677). Drives `kernel/fuzz/src/bin/ext2_fuzz_runner`
/// over the committed seed corpus and a deterministic mutation
/// budget. Build is forced through `--release` so libstd-side cost
/// (read_dir, sorting) doesn't dominate the iteration budget.
///
/// The runner prints per-seed verdicts and the mutation total; this
/// xtask wrapper just translates `--iters` and surfaces the child
/// process exit status.
fn fuzz_ext2(iters: u64) -> R<()> {
    let root = workspace_root();
    let manifest = root.join("kernel").join("fuzz").join("Cargo.toml");
    if !manifest.exists() {
        return Err(format!(
            "fuzz: manifest not found at {} — kernel/fuzz crate missing?",
            manifest.display()
        )
        .into());
    }
    let corpus = root
        .join("kernel")
        .join("fuzz")
        .join("corpus")
        .join("ext2_mount");
    if !corpus.exists() {
        return Err(format!(
            "fuzz: corpus dir not found at {} — repo layout drift?",
            corpus.display()
        )
        .into());
    }
    let iters_arg = format!("--iters={iters}");

    println!("→ fuzz/ext2: corpus={} iters={}", corpus.display(), iters,);
    check(
        Command::new("cargo")
            .current_dir(root)
            .args([
                "run",
                "--manifest-path",
                manifest.to_str().unwrap(),
                "--bin",
                "ext2_fuzz_runner",
                "--release",
                "--",
                corpus.to_str().unwrap(),
                &iters_arg,
            ])
            .status()?,
    )?;
    Ok(())
}

fn clean() -> R<()> {
    let _ = fs::remove_dir_all(workspace_root().join("target"));
    let _ = fs::remove_dir_all(workspace_root().join("build"));
    check(
        Command::new("cargo")
            .current_dir(workspace_root())
            .arg("clean")
            .status()?,
    )?;
    Ok(())
}

fn check(status: ExitStatus) -> R<()> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed: {status}").into())
    }
}

#[cfg(test)]
mod tests_inject_cmdline {
    use super::inject_limine_cmdline;

    const BASE: &str = "\
timeout: 0
serial: yes

/vibix
    protocol: limine
    kernel_path: boot():/boot/vibix
    module_path: boot():/boot/userspace_init.elf
";

    #[test]
    fn appends_cmdline_after_protocol_line() {
        let out = inject_limine_cmdline(BASE, "root=/dev/vda");
        assert!(out.contains("    protocol: limine\n    cmdline: root=/dev/vda\n"));
        // kernel_path still present after the injection.
        assert!(out.contains("kernel_path: boot():/boot/vibix"));
    }

    #[test]
    fn replaces_existing_cmdline_line_in_block() {
        let existing = "\
/vibix
    protocol: limine
    cmdline: root=ramfs
    kernel_path: boot():/boot/vibix
";
        let out = inject_limine_cmdline(existing, "root=/dev/vda rootflags=ro");
        // New value present.
        assert!(out.contains("cmdline: root=/dev/vda rootflags=ro"));
        // Old value gone.
        assert!(!out.contains("cmdline: root=ramfs"));
        // Exactly one cmdline line (regression guard: an earlier
        // single-pass version produced two, one inserted after the
        // protocol marker plus one at the replace site).
        assert_eq!(
            out.matches("cmdline:").count(),
            1,
            "should have exactly one cmdline line, got:\n{out}",
        );
    }

    #[test]
    fn appends_at_end_if_no_protocol_line() {
        let out = inject_limine_cmdline("# no protocol here\n", "root=ramfs");
        assert!(out.ends_with("cmdline: root=ramfs\n"));
    }

    #[test]
    fn does_not_mutate_later_stanzas() {
        // A later top-level stanza (e.g. a second boot entry) must
        // not be treated as still-inside the first limine block.
        // Specifically: a `cmdline:` line inside an unrelated later
        // stanza should not be rewritten, and the new cmdline should
        // be inserted only under the first `protocol: limine`.
        let cfg = "\
/vibix
    protocol: limine
    kernel_path: boot():/boot/vibix

/other
    protocol: multiboot2
    cmdline: should-not-be-touched
";
        let out = inject_limine_cmdline(cfg, "root=/dev/vda");
        // New cmdline appears under /vibix.
        assert!(out.contains("    protocol: limine\n    cmdline: root=/dev/vda\n"));
        // The later stanza's cmdline is preserved verbatim.
        assert!(out.contains("cmdline: should-not-be-touched"));
        // Exactly two cmdline lines total: the injected one + the
        // untouched one in /other.
        assert_eq!(
            out.matches("cmdline:").count(),
            2,
            "expected exactly 2 cmdline lines (1 injected, 1 preserved), got:\n{out}",
        );
    }

    #[test]
    fn empty_cmdline_is_a_noop_caller_guarded() {
        // The caller short-circuits on empty cmdline; the function
        // itself still handles it without corrupting the file.
        let out = inject_limine_cmdline(BASE, "");
        // Injection still happens at the protocol line, just with an
        // empty value — this is why the call site in make_iso_inner
        // branches on `kernel_cmdline.is_empty()` and bypasses us.
        assert!(out.contains("    cmdline: \n"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ustar_dir_block_checksum_valid() {
        let block = ustar_dir_block("dev/");
        // USTAR magic present
        assert_eq!(&block[257..262], b"ustar");
        // typeflag is directory
        assert_eq!(block[156], b'5');
        // Parse stored checksum (6-digit octal string at bytes 148..154)
        let chk_str = std::str::from_utf8(&block[148..154]).unwrap();
        let stored: u32 = u32::from_str_radix(chk_str.trim(), 8).unwrap();
        // Recompute treating checksum field as spaces
        let computed: u32 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    0x20u32
                } else {
                    b as u32
                }
            })
            .sum();
        assert_eq!(computed, stored);
        // Checksum field is 6 octal digits + NUL + space (8 bytes total)
        assert_eq!(block[154], 0, "byte 154 must be NUL");
        assert_eq!(block[155], b' ', "byte 155 must be space");
    }

    #[test]
    fn ensure_initrd_creates_valid_archive() {
        let path = ensure_initrd().expect("ensure_initrd failed");
        assert!(path.exists());
        let data = fs::read(&path).unwrap();
        // Assert the archive is a positive multiple of 512 and ends in the
        // USTAR end-of-archive marker (two zero blocks). The exact length
        // changes whenever the payload set changes — the `ensure_initrd`
        // body computes `EXPECTED_SIZE` from the inputs, so we don't need
        // to duplicate that arithmetic here.
        assert!(data.len() >= 4 * 512);
        assert_eq!(data.len() % 512, 0);
        assert!(data[data.len() - 1024..].iter().all(|&b| b == 0));
        // Content checks: USTAR magic is present in the first header (so
        // we know a real tar got written, not 4 zero blocks), and the
        // `etc/motd` filename appears somewhere in the archive.
        assert_eq!(&data[257..263], b"ustar\0");
        assert!(
            data.windows(8).any(|w| w == b"etc/motd"),
            "archive missing etc/motd entry"
        );
    }

    #[test]
    fn smoke_markers_satisfied_only_when_every_hard_marker_seen() {
        // Mirrors the retain+contains loop in `fn smoke`: an accumulated
        // serial-capture string drives the hard/soft marker sets to empty.
        // The test keeps the bar honest by feeding a complete real-looking
        // capture and asserting drain, plus a partial capture that must
        // still leave at least one marker outstanding.
        use std::collections::HashSet;

        let full: String = SMOKE_MARKERS
            .iter()
            .chain(SMOKE_SOFT_MARKERS.iter())
            .map(|m| format!("{m}\n"))
            .collect();
        let mut hard: HashSet<&'static str> = SMOKE_MARKERS.iter().copied().collect();
        let mut soft: HashSet<&'static str> = SMOKE_SOFT_MARKERS.iter().copied().collect();
        hard.retain(|m| !full.contains(m));
        soft.retain(|m| !full.contains(m));
        assert!(hard.is_empty() && soft.is_empty());

        // Drop the last hard marker from the capture — drain must leave it.
        let last = SMOKE_MARKERS.last().copied().unwrap();
        let partial: String = SMOKE_MARKERS
            .iter()
            .filter(|m| **m != last)
            .chain(SMOKE_SOFT_MARKERS.iter())
            .map(|m| format!("{m}\n"))
            .collect();
        let mut hard: HashSet<&'static str> = SMOKE_MARKERS.iter().copied().collect();
        hard.retain(|m| !partial.contains(m));
        assert_eq!(hard.len(), 1);
        assert!(hard.contains(last));
    }

    #[test]
    fn demangles_legacy_rust_symbol() {
        let out = format!(
            "{:#}",
            rustc_demangle::demangle("_ZN6kernel4main17h1234567890abcdefE")
        );
        assert_eq!(out, "kernel::main");
    }

    #[test]
    fn demangles_v0_rust_symbol() {
        // v0 mangling (RFC 2603), the default scheme in modern rustc.
        let out = format!("{:#}", rustc_demangle::demangle("_RNvCs1234_6kernel4main"));
        assert_eq!(out, "kernel::main");
    }

    #[test]
    fn passes_through_non_rust_symbol() {
        assert_eq!(
            format!("{:#}", rustc_demangle::demangle("memcpy")),
            "memcpy"
        );
    }

    #[test]
    fn parse_test_names_extracts_declared_order() {
        let manifest = r#"
[package]
name = "vibix"

[[bin]]
name = "vibix"

[[test]]
name = "basic_boot"
harness = false

[[test]]
name = "heap_alloc"
harness = false

[[test]]
name = "should_panic"
harness = false
"#;
        assert_eq!(
            parse_test_names(manifest).unwrap(),
            vec!["basic_boot", "heap_alloc", "should_panic"]
        );
    }

    #[test]
    fn parse_test_names_errors_on_unterminated_test_block() {
        let manifest = r#"
[[test]]
harness = false

[[bin]]
name = "vibix"
"#;
        assert!(parse_test_names(manifest).is_err());
    }

    #[test]
    fn parse_test_names_ignores_bin_and_bench_names() {
        let manifest = r#"
[[bin]]
name = "vibix"
path = "src/main.rs"

[[bench]]
name = "my_bench"

[[test]]
name = "only_this"
harness = false
"#;
        assert_eq!(parse_test_names(manifest).unwrap(), vec!["only_this"]);
    }

    #[test]
    fn parse_test_names_live_manifest_contains_new_entries() {
        // Guards against silent drift: these were previously absent
        // from the hardcoded xtask array (issue #292).
        let raw = parse_test_names(
            &std::fs::read_to_string(workspace_root().join("kernel").join("Cargo.toml")).unwrap(),
        )
        .unwrap();
        for expected in &["execve_atomic", "fork_refcount", "syscall_mmap_family"] {
            assert!(
                raw.iter().any(|n| n == expected),
                "expected {expected} in manifest parse, got {raw:?}"
            );
        }
        let filtered = integration_test_names().expect("parse live manifest");
        for expected in &["execve_atomic", "fork_refcount", "syscall_mmap_family"] {
            assert!(
                filtered.iter().any(|n| n == expected),
                "expected {expected} in derived test list, got {filtered:?}"
            );
        }
        // Skiplist entries are filtered out of the runner list.
        for skipped in TEST_SKIPLIST {
            assert!(
                !filtered.iter().any(|n| n == skipped),
                "skiplist entry {skipped} must not appear in runner list"
            );
        }
    }

    /// Issue #526: `repro-fork-build` must be a pure build subcommand.
    /// If it ever grows a QEMU invocation, the smoke-soak Pre-build
    /// step would regress to the full-harness behavior that prompted
    /// this split in the first place.  We can't execute the subcommand
    /// from a host unit test (it drives cargo against a custom
    /// target), so we enforce the contract by inspecting its source.
    #[test]
    fn repro_fork_build_does_not_invoke_qemu() {
        let source =
            std::fs::read_to_string(workspace_root().join("xtask").join("src").join("main.rs"))
                .expect("read xtask main.rs");

        // Locate the `fn repro_fork_build` body.  The function opens
        // with `fn repro_fork_build(` and its body runs until the
        // next top-level `fn ` declaration.  This is brittle against
        // drastic reformatting but catches the bug we care about —
        // "someone added a qemu-system-x86_64 call" — with zero
        // false positives on the current source.
        let start = source
            .find("fn repro_fork_build(")
            .expect("repro_fork_build must exist");
        let after_start = &source[start..];
        let body_start = after_start
            .find('{')
            .expect("repro_fork_build must have a body");
        let search_region = &after_start[body_start..];
        // Find the matching close brace by brace-counting.
        let mut depth = 0i32;
        let mut end = None;
        for (i, ch) in search_region.char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        let body = &search_region[..end.expect("balanced braces")];

        for forbidden in &["qemu-system-x86_64", "qemu_system_x86_64"] {
            assert!(
                !body.contains(forbidden),
                "repro_fork_build body must not contain `{forbidden}` \
                 (build-only contract, issue #526)"
            );
        }

        // The repro-fork full-harness path is the one thing this
        // helper must never reach into — that path is what boots
        // QEMU.  Calling it would undo the whole split.  Check for
        // a call to `repro_fork(` at an identifier boundary so we
        // don't false-positive on `build_userspace_repro_fork()`.
        let mut prev: Option<char> = None;
        let mut hit = false;
        for (i, ch) in body.char_indices() {
            if body[i..].starts_with("repro_fork(") {
                let is_boundary = match prev {
                    None => true,
                    Some(c) => !(c.is_alphanumeric() || c == '_'),
                };
                if is_boundary {
                    hit = true;
                    break;
                }
            }
            prev = Some(ch);
        }
        assert!(
            !hit,
            "repro_fork_build body must not call `repro_fork(` \
             (build-only contract, issue #526)"
        );
    }

    /// Issue #526: the `repro-fork-build` subcommand must be wired
    /// into both the dispatcher and the usage string, otherwise CI's
    /// `cargo xtask repro-fork-build` call would hit the "unknown
    /// subcommand" arm.
    #[test]
    fn repro_fork_build_subcommand_is_registered() {
        let source =
            std::fs::read_to_string(workspace_root().join("xtask").join("src").join("main.rs"))
                .expect("read xtask main.rs");
        assert!(
            source.contains("\"repro-fork-build\" =>"),
            "main() must dispatch \"repro-fork-build\""
        );
        // CodeRabbit on PR #529: a bare `contains("repro-fork-build")`
        // check always passes because the dispatcher arm, comments,
        // and this very test all contain that substring.  Pin the
        // assertion to the literal usage-banner prefix plus the
        // `repro-fork-build` token *inside* that banner, so a future
        // edit that drops the token from the `eprintln!` arm actually
        // fails.  Extracting the banner substring instead of matching
        // the whole line keeps the check robust against cosmetic
        // edits elsewhere in the usage list (e.g. adding new
        // subcommands like `ext2-image` in #579).
        let banner_start = source
            .find("usage: cargo xtask [")
            .expect("usage banner missing");
        let banner_end = banner_start
            + source[banner_start..]
                .find(']')
                .expect("usage banner has no closing ']'");
        let banner = &source[banner_start..=banner_end];
        assert!(
            banner.contains("repro-fork-build"),
            "usage string must list repro-fork-build, got: {banner:?}"
        );
    }

    /// Issue #531: the repro-fork harness compiled CYCLES to a value
    /// far above 500 (the CI soak ran ~14,988 cycles per boot), which
    /// silently burned every soak iteration against the 900 s hard
    /// cap.  The fix makes CYCLES self-report on a dedicated
    /// `repro: CYCLES=<N>` line; this parser + test pin that contract
    /// so a regression (e.g. someone dropping the dedicated line, or
    /// `option_env!("REPRO_FORK_CYCLES")` silently parsing a typo'd
    /// build override as a huge number) fails a host unit test in CI
    /// before it ever reaches a soak run.
    #[test]
    fn parse_repro_banner_clean_log() {
        let log = "\
boot: ok
repro: CYCLES=500
repro: starting fork loop cycles=500 hb=50
repro: fork loop complete cycles=500
";
        let banner = parse_repro_banner(log).expect("parse must succeed");
        assert_eq!(banner.cycles_dedicated, 500);
        assert_eq!(banner.cycles_combined, Some(500));
        assert_eq!(banner.heartbeat, Some(50));
    }

    #[test]
    fn parse_repro_banner_tolerates_interleaved_combined_line() {
        // The #531 evidence log showed the combined banner mangled by
        // a child exec's `ring3-iretq` log interleaving on the shared
        // serial mid-line.  The dedicated `repro: CYCLES=` line is
        // emitted first and newline-terminated precisely so its value
        // is still recoverable even when the combined banner is
        // unreadable.
        let log = "\
repro: CYCLES=500
repro: starting fork loop cycles=ring3-iretq: rip=0x400000 rsp=0x7fffff58
hello: hello from execed child
";
        let banner = parse_repro_banner(log).expect("dedicated line must still parse");
        assert_eq!(banner.cycles_dedicated, 500);
        // Combined banner's `cycles=` was immediately followed by
        // non-digit text — parser yields None for that field.
        assert_eq!(banner.cycles_combined, None);
        assert_eq!(banner.heartbeat, None);
    }

    #[test]
    fn parse_repro_banner_missing_dedicated_line_returns_none() {
        // Only the legacy combined banner is present.  Parser must
        // fail closed — a missing dedicated line is the regression
        // we're guarding against.
        let log = "\
repro: starting fork loop cycles=500 hb=50
";
        assert!(parse_repro_banner(log).is_none());
    }

    #[test]
    fn parse_repro_banner_rejects_nondigit_value() {
        // Defensive: a malformed `repro: CYCLES=` line (no digits)
        // must not trip a false positive.
        let log = "repro: CYCLES=abc\n";
        assert!(parse_repro_banner(log).is_none());
    }

    /// Issue #531: the xtask source-level contract for the repro-fork
    /// userspace binary is "CYCLES compiles to 500 by default."  The
    /// harness is cross-compiled for `x86_64-unknown-none` so we can't
    /// exercise it from a host unit test directly, but we can inspect
    /// the source to pin the default literal; if someone bumps it to
    /// a huge number without updating the soak workflow, this test
    /// fails in CI before the soak burns 6 hours discovering it.
    #[test]
    fn repro_fork_default_cycles_is_500() {
        let source = std::fs::read_to_string(
            workspace_root()
                .join("userspace")
                .join("repro_fork")
                .join("src")
                .join("main.rs"),
        )
        .expect("read repro_fork main.rs");
        // The default is expressed as the `None => <literal>` arm of
        // the `match option_env!("REPRO_FORK_CYCLES")` block.  A
        // substring match is brittle across reformatting, but it
        // catches exactly the regression we care about: "someone
        // changed the default from 500 and forgot to update the soak
        // timing budget / this test."
        assert!(
            source.contains("None => 500,"),
            "userspace/repro_fork/src/main.rs must keep the default CYCLES=500; \
             if you genuinely need to change this, also update \
             .github/workflows/smoke-soak.yml timing budgets and issue #531's context"
        );
    }

    /// Issue #531 root cause: the userspace syscall inline-asm blocks
    /// declared only rcx/r11 as clobbered, but the vibix kernel's
    /// SYSCALL trampoline + Rust SysV dispatcher also trash rdi, rsi,
    /// rdx, r8, r9, r10 (and, via the C ABI, rax).  Loop counters held
    /// in r8 across the fork syscall never incremented, so the
    /// repro-fork harness ran until HARD_CAP every time.  Pin the
    /// fixed clobber pattern in source so a future edit that drops a
    /// clobber declaration fails a host unit test before it silently
    /// regresses the soak.
    #[test]
    fn repro_fork_syscall_blocks_clobber_all_sysv_caller_saved() {
        let source = std::fs::read_to_string(
            workspace_root()
                .join("userspace")
                .join("repro_fork")
                .join("src")
                .join("main.rs"),
        )
        .expect("read repro_fork main.rs");

        // Every `asm!(\"syscall\", ...)` block in this file that is
        // not a `noreturn` exit must declare lateout for each SysV
        // caller-saved register the kernel may trash on SYSRETQ:
        // r8, r9, r10, r11 (rax, rcx, rdx, rdi, rsi are handled via
        // the `inlateout`/`lateout` pattern documented in the ABI
        // header, so we grep for the r-class registers here as the
        // load-bearing signal).
        for reg in ["r8", "r9", "r10", "r11"] {
            let needle = format!("lateout(\"{reg}\")");
            let count = source.matches(&needle).count();
            // The module has 4 non-noreturn syscall sites in the
            // reproducer (fork, execve-in-child, wait4, write_line).
            // Every one of them must carry every r-class clobber.
            assert!(
                count >= 4,
                "expected at least 4 `{needle}` declarations in repro_fork/main.rs, \
                 found {count}.  If you added or removed a syscall site, update this \
                 lower bound; if you dropped a clobber, restore it (issue #531)."
            );
        }
    }
}
