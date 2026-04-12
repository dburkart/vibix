//! vibix build/run/test orchestrator.
//!
//! Subcommands:
//!   build         — cargo-build the kernel for x86_64-unknown-none
//!   iso           — build, fetch Limine, produce target/vibix.iso
//!   run           — iso, then boot under QEMU with serial-stdio
//!   test          — run host unit tests + QEMU integration tests
//!   test-runner   — (internal) boot a pre-built test kernel ELF in QEMU
//!   smoke         — boot the kernel and assert on expected serial markers
//!   clean         — remove build artifacts
//!
//! Flags (apply where sensible): --release, --fault-test

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

type R<T> = Result<T, Box<dyn Error>>;

const LIMINE_TAG: &str = "v8.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";

// QEMU process exit codes produced by `isa-debug-exit` writing our
// QemuExitCode values. See kernel/src/test_harness.rs.
const QEMU_EXIT_SUCCESS: i32 = 65; // (0x20 << 1) | 1
const QEMU_EXIT_FAILURE: i32 = 33; // (0x10 << 1) | 1

/// Hard ceiling on an individual QEMU boot during tests — real tests
/// should finish in <1 s; this catches hangs.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Expected markers on a healthy boot. Used by `smoke` and to guard
/// against regressions in the serial pipeline.
const SMOKE_MARKERS: &[&str] = &[
    "vibix booting",
    "memory map:",
    "hhdm offset:",
    "GDT + IDT loaded",
    "heap: 1024 KiB",
    "paging: mapper online",
    "paging: IST guard installed",
    "PIC remapped",
    "timer: 100 Hz",
    "vibix online.",
    "interrupts enabled",
];

fn main() -> R<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let release = take_flag(&mut args, "--release");
    let fault_test = take_flag(&mut args, "--fault-test");

    let cmd = args.get(0).map(String::as_str).unwrap_or("run").to_string();
    let rest: Vec<String> = args.into_iter().skip(1).collect();
    let opts = BuildOpts { release, fault_test };

    match cmd.as_str() {
        "build" => { build(&opts)?; }
        "iso" => { iso(&opts)?; }
        "run" => { run(&opts)?; }
        "test" => test_all()?,
        "test-runner" => {
            let kernel = rest
                .first()
                .ok_or("test-runner: missing kernel ELF path")?;
            test_runner(Path::new(kernel))?;
        }
        "smoke" => smoke(&opts)?,
        "clean" => clean()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("usage: cargo xtask [build|iso|run|test|smoke|clean] [--release] [--fault-test]");
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

struct BuildOpts {
    release: bool,
    fault_test: bool,
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn kernel_binary(opts: &BuildOpts) -> PathBuf {
    let profile = if opts.release { "release" } else { "debug" };
    workspace_root()
        .join("target")
        .join("x86_64-unknown-none")
        .join(profile)
        .join("vibix")
}

fn build(opts: &BuildOpts) -> R<PathBuf> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .arg("build")
        .arg("--package").arg("vibix")
        .arg("--bin").arg("vibix")
        .arg("--target").arg("x86_64-unknown-none")
        .arg("-Z").arg("build-std=core,compiler_builtins,alloc")
        .arg("-Z").arg("build-std-features=compiler-builtins-mem");
    if opts.release {
        cmd.arg("--release");
    }
    if opts.fault_test {
        cmd.arg("--features").arg("fault-test");
    }
    check(cmd.status()?)?;
    let bin = kernel_binary(opts);
    if !bin.exists() {
        return Err(format!("kernel binary missing at {}", bin.display()).into());
    }
    Ok(bin)
}

fn ensure_limine() -> R<PathBuf> {
    let root = workspace_root().join("build").join("limine");
    if root.join("limine-bios.sys").exists() {
        return Ok(root);
    }
    fs::create_dir_all(root.parent().unwrap())?;
    println!("→ cloning limine {LIMINE_TAG}");
    check(Command::new("git")
        .args(["clone", "--depth=1", "--branch", LIMINE_TAG, LIMINE_REPO])
        .arg(&root)
        .status()?)?;
    check(Command::new("make").arg("-C").arg(&root).status()?)?;
    Ok(root)
}

/// Assemble a bootable hybrid BIOS/UEFI ISO around the given kernel ELF.
/// `staging` names a subdirectory under `build/` to use as scratch
/// (so parallel test runs don't stomp each other).
fn make_iso(kernel: &Path, iso_out: &Path, staging: &str) -> R<()> {
    let limine = ensure_limine()?;
    let iso_root = workspace_root().join("build").join(staging);
    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(kernel, iso_root.join("boot/vibix"))?;
    fs::copy(
        workspace_root().join("kernel/limine.conf"),
        iso_root.join("boot/limine/limine.conf"),
    )?;
    for f in ["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"] {
        fs::copy(limine.join(f), iso_root.join("boot/limine").join(f))?;
    }
    fs::copy(limine.join("BOOTX64.EFI"), iso_root.join("EFI/BOOT/BOOTX64.EFI"))?;

    fs::create_dir_all(iso_out.parent().unwrap())?;
    check(Command::new("xorriso")
        .args(["-as", "mkisofs", "-b", "boot/limine/limine-bios-cd.bin",
               "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
               "--efi-boot", "boot/limine/limine-uefi-cd.bin",
               "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label"])
        .arg(&iso_root)
        .arg("-o").arg(iso_out)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .status()?)?;

    check(Command::new(limine.join("limine"))
        .arg("bios-install").arg(iso_out)
        .stdout(Stdio::null()).stderr(Stdio::null())
        .status()?)?;

    Ok(())
}

fn iso(opts: &BuildOpts) -> R<PathBuf> {
    let kernel = build(opts)?;
    let iso = workspace_root().join("target").join("vibix.iso");
    make_iso(&kernel, &iso, "iso_root")?;
    println!("→ iso: {}", iso.display());
    Ok(iso)
}

fn run(opts: &BuildOpts) -> R<()> {
    let iso = iso(opts)?;
    let status = Command::new("qemu-system-x86_64")
        .args(["-M", "q35", "-m", "256M",
               "-serial", "stdio",
               "-no-reboot", "-no-shutdown",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-cdrom").arg(&iso)
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
    let iso = workspace_root()
        .join("target")
        .join(format!("{name}.iso"));
    make_iso(kernel, &iso, &format!("iso_{name}"))?;

    eprintln!("▶ {}", name);
    // Note: no `-no-shutdown` here — it would prevent `isa-debug-exit`
    // from actually terminating QEMU, defeating the exit-code protocol.
    let mut child = Command::new("qemu-system-x86_64")
        .args(["-M", "q35", "-m", "256M",
               "-serial", "stdio",
               "-display", "none",
               "-no-reboot",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-cdrom").arg(&iso)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    let start = std::time::Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return match status.code() {
                Some(c) if c == QEMU_EXIT_SUCCESS => Ok(()),
                Some(c) if c == QEMU_EXIT_FAILURE => {
                    Err(format!("test {name} failed").into())
                }
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

fn test_all() -> R<()> {
    // Host unit tests (--lib only; pure-logic modules).
    println!("→ host unit tests");
    check(Command::new("cargo")
        .current_dir(workspace_root())
        .args(["test", "--package", "vibix", "--lib"])
        .status()?)?;

    // QEMU integration tests. Each is invoked by name so cargo doesn't
    // also try to build the lib's no_std test harness (which would
    // require std). Cargo's runner config invokes us back as
    // `test-runner <binary>` per compiled test.
    println!("→ integration tests under QEMU");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .args([
            "test", "--package", "vibix",
            "--target", "x86_64-unknown-none",
            "-Z", "build-std=core,compiler_builtins,alloc",
            "-Z", "build-std-features=compiler-builtins-mem",
        ]);
    for t in ["basic_boot", "heap_alloc", "should_panic", "timer_tick", "paging"] {
        cmd.arg("--test").arg(t);
    }
    check(cmd.status()?)?;

    Ok(())
}

fn smoke(opts: &BuildOpts) -> R<()> {
    let iso = iso(opts)?;

    // We run QEMU with serial to stdio, capture output, then kill after
    // a short delay — the kernel halts in hlt_loop forever.
    let child = Command::new("qemu-system-x86_64")
        .args(["-M", "q35", "-m", "256M",
               "-serial", "stdio",
               "-display", "none",
               "-no-reboot", "-no-shutdown",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"])
        .arg("-cdrom").arg(&iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let reader_handle = std::thread::spawn(move || -> std::io::Result<String> {
        use std::io::Read;
        let mut out = String::new();
        if let Some(mut s) = child.stdout { s.read_to_string(&mut out)?; }
        Ok(out)
    });

    std::thread::sleep(Duration::from_secs(4));
    // Kill QEMU so the reader thread can drain and return.
    let _ = Command::new("kill").arg(pid.to_string()).status();

    let output = reader_handle.join().map_err(|_| "reader thread panicked")??;

    let mut missing = Vec::new();
    for m in SMOKE_MARKERS {
        if !output.contains(m) {
            missing.push(*m);
        }
    }
    if missing.is_empty() {
        println!("→ smoke: all {} markers present ✓", SMOKE_MARKERS.len());
        Ok(())
    } else {
        eprintln!("--- captured serial ---\n{output}\n-----------------------");
        Err(format!("smoke: missing markers {:?}", missing).into())
    }
}

fn clean() -> R<()> {
    let _ = fs::remove_dir_all(workspace_root().join("target"));
    let _ = fs::remove_dir_all(workspace_root().join("build"));
    check(Command::new("cargo").current_dir(workspace_root()).arg("clean").status()?)?;
    Ok(())
}

fn check(status: ExitStatus) -> R<()> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed: {status}").into())
    }
}
