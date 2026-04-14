//! vibix build/run/test orchestrator.
//!
//! Subcommands:
//!   build         — cargo-build the kernel for x86_64-unknown-none
//!   initrd        — build target/rootfs.tar (minimal USTAR rootfs tarball)
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
    "block: write+readback ok at lba 2047",
    "vibix online.",
    "interrupts enabled",
    "tasks: scheduler online",
    "userspace module ELF entry=",
    "userspace: loader mapping image",
    "syscall: SYSCALL/SYSRET enabled",
    "init: hello from pid 1",
    "hello: hello from execed child",
    "init: fork+exec+wait ok",
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
        "initrd" => {
            let path = ensure_initrd()?;
            println!("→ initrd: {}", path.display());
        }
        "clean" => clean()?,
        other => {
            eprintln!("unknown subcommand: {other}");
            eprintln!(
                "usage: cargo xtask [build|initrd|iso|run|test|smoke|lint|clean] [--release] [--fault-test] [--panic-test] [--bench]"
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

fn userspace_hello_binary() -> PathBuf {
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join("debug")
        .join("userspace_hello")
}

/// Build the hello binary — the exec() target for the fork+exec+wait test.
/// Links at 0x400000 (lower half) just like init so load_user_elf accepts it.
fn build_userspace_hello() -> R<PathBuf> {
    let rustflags = [
        "-C link-arg=-Tuserspace/hello/link.ld",
        "-C relocation-model=static",
        "-C code-model=small",
        "-C no-redzone=yes",
        "-C force-frame-pointers=yes",
    ]
    .join(" ");
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .env("RUSTFLAGS", rustflags)
        .args(["build", "--package", "userspace_hello"])
        .args(KERNEL_BUILD_STD_ARGS);
    check(cmd.status()?)?;
    let bin = userspace_hello_binary();
    if !bin.exists() {
        return Err(format!("userspace hello binary missing at {}", bin.display()).into());
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

    const DIRS: &[&str] = &["dev/", "tmp/", "bin/", "etc/", "etc/init/"];
    const HOSTNAME_FILE: &str = "etc/hostname";
    const HOSTNAME_PAYLOAD: &[u8] = b"vibix\n";
    const NESTED_FILE: &str = "etc/init/hello.txt";
    const NESTED_PAYLOAD: &[u8] = b"nested\n";
    // DIRS headers + 2 file headers + 2 padded data blocks + 2 end blocks.
    const EXPECTED_SIZE: u64 = ((DIRS.len() + 2 + 2 + 2) * 512) as u64;

    let needs_write = match fs::metadata(&path) {
        Ok(m) => m.len() != EXPECTED_SIZE,
        Err(_) => true,
    };

    if needs_write {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
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
fn make_iso(kernel: &Path, iso_out: &Path, staging: &str) -> R<()> {
    let limine = ensure_limine()?;
    let userspace_init = build_userspace_init()?;
    let userspace_hello = build_userspace_hello()?;
    let initrd = ensure_initrd()?;
    let iso_root = workspace_root().join("build").join(staging);
    let _ = fs::remove_dir_all(&iso_root);
    fs::create_dir_all(iso_root.join("boot/limine"))?;
    fs::create_dir_all(iso_root.join("EFI/BOOT"))?;

    fs::copy(kernel, iso_root.join("boot/vibix"))?;
    fs::copy(userspace_init, iso_root.join("boot/userspace_init.elf"))?;
    fs::copy(userspace_hello, iso_root.join("boot/userspace_hello.elf"))?;
    fs::copy(&initrd, iso_root.join("boot/rootfs.tar"))?;
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
fn parse_test_names(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_test = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
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
    names
}

/// Integration tests that parse from `kernel/Cargo.toml` but should
/// NOT be run by `cargo xtask test`. Each entry must name the
/// follow-up issue that tracks re-enabling it. Empty is the goal.
///
/// - `syscall_mmap_family`: `mmap_shared_anon_succeeds` hangs under
///   QEMU (>30s timeout). Predates #292 and was silently skipped by
///   the previous hardcoded allowlist; surfaced once the list became
///   manifest-driven. Tracked in the follow-up opened alongside #292.
const TEST_SKIPLIST: &[&str] = &["syscall_mmap_family"];

/// Read `kernel/Cargo.toml` and return the declared integration-test
/// target names, minus anything in [`TEST_SKIPLIST`]. Derived
/// dynamically to avoid drift between the manifest and the xtask test
/// runner (see issue #292).
fn integration_test_names() -> R<Vec<String>> {
    let manifest_path = workspace_root().join("kernel").join("Cargo.toml");
    let body = fs::read_to_string(&manifest_path)?;
    let names = parse_test_names(&body);
    if names.is_empty() {
        return Err(format!("no [[test]] entries found in {}", manifest_path.display()).into());
    }
    Ok(names
        .into_iter()
        .filter(|n| !TEST_SKIPLIST.contains(&n.as_str()))
        .collect())
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
    //
    // The test list is derived from `kernel/Cargo.toml` `[[test]]`
    // entries so adding a new integration test in the manifest
    // automatically wires it into `cargo xtask test` (issue #292).
    println!("→ integration tests under QEMU");
    let tests = integration_test_names()?;
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .args(["test", "--package", "vibix"])
        .args(KERNEL_BUILD_STD_ARGS);
    for t in &tests {
        cmd.arg("--test").arg(t);
    }
    check(cmd.status()?)?;

    Ok(())
}

fn smoke(opts: &BuildOpts) -> R<()> {
    use std::collections::HashSet;
    use std::io::BufRead as _;
    use std::time::Instant;

    let iso = iso(opts)?;
    let disk = ensure_test_disk()?;

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
        .args(virtio_blk_args(&disk))
        .arg("-cdrom")
        .arg(&iso)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let pid = child.id();
    let stdout = child.stdout.take().ok_or("no stdout pipe")?;

    // Hard ceiling: a watchdog thread kills QEMU after 30 s so that a
    // blocking read_line() on a stalled kernel cannot hang indefinitely.
    const HARD_CAP: Duration = Duration::from_secs(30);
    let watchdog = std::thread::spawn(move || {
        std::thread::sleep(HARD_CAP);
        let _ = Command::new("kill").arg(pid.to_string()).status();
    });

    let deadline = Instant::now() + HARD_CAP;
    let mut remaining: HashSet<&'static str> = SMOKE_MARKERS.iter().copied().collect();
    let mut accumulated = String::new();
    let mut reader = std::io::BufReader::new(stdout);
    let mut line = String::new();

    // Read QEMU serial output one line at a time.  read_line() blocks until
    // a newline arrives or the pipe closes (after kill).  We check for
    // early exit after every line — typical runs complete in a few seconds.
    loop {
        if Instant::now() >= deadline {
            break;
        }
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => break, // pipe closed (QEMU killed by watchdog or exited)
            Ok(_) => {
                accumulated.push_str(&line);
                remaining.retain(|m| !accumulated.contains(m));
                if remaining.is_empty() {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    // Ensure QEMU is dead (idempotent if watchdog already fired).
    let _ = Command::new("kill").arg(pid.to_string()).status();
    let _ = watchdog.join();
    let _ = child.wait();

    if remaining.is_empty() {
        println!("→ smoke: all {} markers present ✓", SMOKE_MARKERS.len());
        Ok(())
    } else {
        let mut missing: Vec<&str> = remaining.into_iter().collect();
        missing.sort_unstable();
        eprintln!("--- captured serial ---\n{accumulated}\n-----------------------");
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
    }

    #[test]
    fn ensure_initrd_creates_valid_archive() {
        let path = ensure_initrd().expect("ensure_initrd failed");
        assert!(path.exists());
        let data = fs::read(&path).unwrap();
        // 5 dir headers + 2 file headers + 2 padded file data blocks +
        // 2 end-of-archive zero blocks = 11 * 512
        assert_eq!(data.len(), 11 * 512);
        // Last 1024 bytes are the end-of-archive marker (all zeros)
        assert!(data[data.len() - 1024..].iter().all(|&b| b == 0));
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
            parse_test_names(manifest),
            vec!["basic_boot", "heap_alloc", "should_panic"]
        );
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
        assert_eq!(parse_test_names(manifest), vec!["only_this"]);
    }

    #[test]
    fn parse_test_names_live_manifest_contains_new_entries() {
        // Guards against silent drift: these were previously absent
        // from the hardcoded xtask array (issue #292). `syscall_mmap_family`
        // is tracked in the manifest but currently in TEST_SKIPLIST,
        // so assert it via the raw parser rather than the filtered list.
        let raw = parse_test_names(
            &std::fs::read_to_string(workspace_root().join("kernel").join("Cargo.toml")).unwrap(),
        );
        for expected in &["execve_atomic", "fork_refcount", "syscall_mmap_family"] {
            assert!(
                raw.iter().any(|n| n == expected),
                "expected {expected} in manifest parse, got {raw:?}"
            );
        }
        let filtered = integration_test_names().expect("parse live manifest");
        for expected in &["execve_atomic", "fork_refcount"] {
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
}
