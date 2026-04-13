//! vibix build/run/test orchestrator.
//!
//! Subcommands:
//!   build         — cargo-build the kernel for x86_64-unknown-none
//!   iso           — build, fetch Limine, produce target/vibix.iso
//!   run           — iso, then boot under QEMU with serial-stdio
//!   test          — run host unit tests + QEMU integration tests
//!   test-runner   — (internal) boot a pre-built test kernel ELF in QEMU
//!   smoke         — boot the kernel and assert on expected serial markers
//!   lint          — run clippy on xtask (host) and vibix (kernel, no_std)
//!   clean         — remove build artifacts
//!
//! Flags (apply where sensible): --release, --fault-test, --panic-test

use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::Duration;

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

/// Hard ceiling on an individual QEMU boot during tests — real tests
/// should finish in <1 s; this catches hangs.
const TEST_TIMEOUT: Duration = Duration::from_secs(30);

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
    "vibix online.",
    "interrupts enabled",
    "tasks: scheduler online",
    "userspace module ELF entry=",
    "userspace: loader mapping image",
    "syscall: SYSCALL/SYSRET enabled",
    "init: hello from pid 1",
];

fn main() -> R<()> {
    let mut args: Vec<String> = env::args().skip(1).collect();
    let release = take_flag(&mut args, "--release");
    let fault_test = take_flag(&mut args, "--fault-test");
    let panic_test = take_flag(&mut args, "--panic-test");
    let bench = take_flag(&mut args, "--bench");

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
    };

    match cmd.as_str() {
        "build" => {
            build(&opts)?;
        }
        "iso" => {
            iso(&opts)?;
        }
        "run" => {
            run(&opts)?;
        }
        "test" => test_all()?,
        "test-runner" => {
            let kernel = rest.first().ok_or("test-runner: missing kernel ELF path")?;
            test_runner(Path::new(kernel))?;
        }
        "smoke" => smoke(&opts)?,
        "lint" => lint()?,
        "clean" => clean()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!(
                "usage: cargo xtask [build|iso|run|test|smoke|lint|clean] [--release] [--fault-test] [--panic-test] [--bench]"
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

struct BuildOpts {
    release: bool,
    fault_test: bool,
    panic_test: bool,
    bench: bool,
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

fn userspace_init_binary() -> PathBuf {
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join("debug")
        .join("userspace_init")
}

fn build_userspace_init() -> R<PathBuf> {
    // Setting RUSTFLAGS wholesale overrides the workspace
    // `[target.x86_64-unknown-none] rustflags` from .cargo/config.toml,
    // so we must re-supply every flag the kernel target still needs.
    // The init binary links at 0x400000 (lower half, user space) and
    // uses the small code model — no ±2 GiB kernel assumptions.
    let rustflags = [
        "-C link-arg=-Tuserspace/init/link.ld",
        "-C relocation-model=static",
        "-C code-model=small",
        "-C no-redzone=yes",
        "-C force-frame-pointers=yes",
    ]
    .join(" ");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .env("RUSTFLAGS", rustflags)
        .args(["build", "--package", "userspace_init"])
        .args(KERNEL_BUILD_STD_ARGS);
    check(cmd.status()?)?;
    let bin = userspace_init_binary();
    if !bin.exists() {
        return Err(format!("userspace init binary missing at {}", bin.display()).into());
    }
    strip_debug(&bin)?;
    Ok(bin)
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
    check(cmd.status()?)?;
    let bin = kernel_binary(opts);
    if !bin.exists() {
        return Err(format!("kernel binary missing at {}", bin.display()).into());
    }
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
fn strip_debug(kernel: &Path) -> R<()> {
    let status = Command::new("objcopy")
        .arg("--strip-debug")
        .arg(kernel)
        .status()?;
    check(status)?;
    Ok(())
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
fn make_iso(kernel: &Path, iso_out: &Path, staging: &str) -> R<()> {
    let limine = ensure_limine()?;
    let userspace_init = build_userspace_init()?;
    let iso_root = workspace_root().join("build").join(staging);
    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(kernel, iso_root.join("boot/vibix"))?;
    fs::copy(userspace_init, iso_root.join("boot/userspace_init.elf"))?;
    fs::copy(
        workspace_root().join("kernel/limine.conf"),
        iso_root.join("boot/limine/limine.conf"),
    )?;
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

fn run(opts: &BuildOpts) -> R<()> {
    let iso = iso(opts)?;
    let disk = ensure_test_disk()?;
    let status = Command::new("qemu-system-x86_64")
        .args([
            "-M",
            "q35",
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
    // to symbol names.
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

fn test_all() -> R<()> {
    // Host unit tests (--lib only; pure-logic modules).
    println!("→ host unit tests");
    check(
        Command::new("cargo")
            .current_dir(workspace_root())
            .args(["test", "--package", "vibix", "--lib"])
            .status()?,
    )?;

    // QEMU integration tests. Each is invoked by name so cargo doesn't
    // also try to build the lib's no_std test harness (which would
    // require std). Cargo's runner config invokes us back as
    // `test-runner <binary>` per compiled test.
    println!("→ integration tests under QEMU");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .args(["test", "--package", "vibix"])
        .args(KERNEL_BUILD_STD_ARGS);
    for t in [
        "basic_boot",
        "heap_alloc",
        "heap_grow",
        "should_panic",
        "timer_tick",
        "paging",
        "tasks",
        "preempt",
        "pml4_switch",
        "apic_online",
        "backtrace",
        "page_fault",
        "blocking_sync",
        "shell_smoke",
        "priority",
        "per_task_cr3",
        "demand_paging",
        "userspace_module",
        "userspace_loader",
        "sleep",
        "pci_enum",
        "serial_rx",
        "cow_vma",
        "fpu_context_switch",
        "task_exit",
        "addrspace",
        "addrspace_drop",
        "fork_cow",
        "tlb_flusher",
    ] {
        cmd.arg("--test").arg(t);
    }
    check(cmd.status()?)?;

    Ok(())
}

fn smoke(opts: &BuildOpts) -> R<()> {
    let iso = iso(opts)?;
    let disk = ensure_test_disk()?;

    // We run QEMU with serial to stdio, capture output, then kill after
    // a short delay — the kernel halts in hlt_loop forever.
    let child = Command::new("qemu-system-x86_64")
        .args([
            "-M",
            "q35",
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
    let reader_handle = std::thread::spawn(move || -> std::io::Result<String> {
        use std::io::Read;
        let mut out = String::new();
        if let Some(mut s) = child.stdout {
            s.read_to_string(&mut out)?;
        }
        Ok(out)
    });

    std::thread::sleep(Duration::from_secs(4));
    // Kill QEMU so the reader thread can drain and return.
    let _ = Command::new("kill").arg(pid.to_string()).status();

    let output = reader_handle
        .join()
        .map_err(|_| "reader thread panicked")??;

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
mod tests {
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
}
