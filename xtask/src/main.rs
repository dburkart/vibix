//! vibix build/run orchestrator.
//!
//! Subcommands:
//!   build         — cargo-build the kernel for x86_64-unknown-none
//!   iso           — build, fetch Limine, produce target/vibix.iso
//!   run           — iso, then boot under QEMU with serial-stdio
//!   clean         — remove build artifacts
//!
//! Flags (apply to all): --release, --fault-test

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

type R<T> = Result<T, Box<dyn Error>>;

const LIMINE_TAG: &str = "v8.x-binary";
const LIMINE_REPO: &str = "https://github.com/limine-bootloader/limine.git";

fn main() -> R<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let release = take_flag(&mut args, "--release");
    let fault_test = take_flag(&mut args, "--fault-test");

    let cmd = args.get(0).map(String::as_str).unwrap_or("run");
    let opts = BuildOpts { release, fault_test };

    match cmd {
        "build" => { build(&opts)?; }
        "iso" => { iso(&opts)?; }
        "run" => { run(&opts)?; }
        "clean" => clean()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!("usage: cargo xtask [build|iso|run|clean] [--release] [--fault-test]");
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
    // xtask is in <root>/xtask, CARGO_MANIFEST_DIR points there.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
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

fn iso(opts: &BuildOpts) -> R<PathBuf> {
    let kernel = build(opts)?;
    let limine = ensure_limine()?;

    let iso_root = workspace_root().join("build").join("iso_root");
    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(&kernel, iso_root.join("boot/vibix"))?;
    fs::copy(workspace_root().join("kernel/limine.conf"), iso_root.join("boot/limine/limine.conf"))?;
    for f in ["limine-bios.sys", "limine-bios-cd.bin", "limine-uefi-cd.bin"] {
        fs::copy(limine.join(f), iso_root.join("boot/limine").join(f))?;
    }
    fs::copy(limine.join("BOOTX64.EFI"), iso_root.join("EFI/BOOT/BOOTX64.EFI"))?;

    let iso = workspace_root().join("target").join("vibix.iso");
    fs::create_dir_all(iso.parent().unwrap())?;
    check(Command::new("xorriso")
        .args(["-as", "mkisofs", "-b", "boot/limine/limine-bios-cd.bin",
               "-no-emul-boot", "-boot-load-size", "4", "-boot-info-table",
               "--efi-boot", "boot/limine/limine-uefi-cd.bin",
               "-efi-boot-part", "--efi-boot-image", "--protective-msdos-label"])
        .arg(&iso_root)
        .arg("-o").arg(&iso)
        .status()?)?;

    check(Command::new(limine.join("limine"))
        .arg("bios-install").arg(&iso)
        .status()?)?;

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
    // isa-debug-exit returns (code << 1) | 1 as the process exit code.
    // Our panic path writes 0x10 → exit 33. Treat 33 as failure, else ok.
    match status.code() {
        Some(33) => Err("kernel panic — see serial log above".into()),
        Some(0) | None => Ok(()),
        Some(n) => {
            eprintln!("qemu exited with code {n}");
            Ok(())
        }
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

// Touch `Path` so unused-import warnings don't fire in edge cfgs.
#[allow(dead_code)]
fn _p(_: &Path) {}
