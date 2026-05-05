//! Integration test for #884: path-aware execve() syscall.
//!
//! Validates that `resolve_execve_binary`:
//!
//! 1. Returns `ENOENT` for a path that does not exist anywhere (neither
//!    in the VFS nor as a Limine boot module).
//! 2. Resolves `/boot/userspace_hello.elf` via the Limine module
//!    fallback path, returning a non-empty ELF slice whose first four
//!    bytes are the ELF magic.
//! 3. Resolves an absolute path for a VFS-resident file (e.g.
//!    `/etc/hostname`) — this file exists in the rootfs tarball and is
//!    NOT an ELF, but `resolve_execve_binary` should still return its
//!    bytes (the ELF validation happens in the caller, not in resolve).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::syscall::resolve_execve_binary;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    x86_64::instructions::interrupts::enable();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "resolve_nonexistent_returns_enoent",
            &(resolve_nonexistent_returns_enoent as fn()),
        ),
        (
            "resolve_limine_module_finds_hello_elf",
            &(resolve_limine_module_finds_hello_elf as fn()),
        ),
        (
            "resolve_vfs_file_returns_bytes",
            &(resolve_vfs_file_returns_bytes as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

/// A path that matches no VFS entry and no Limine module must yield ENOENT.
fn resolve_nonexistent_returns_enoent() {
    let result = resolve_execve_binary(b"/nonexistent/binary");
    assert_eq!(result.unwrap_err(), -2, "expected ENOENT (-2)");
}

/// `/boot/userspace_hello.elf` is loaded as a Limine boot module. The
/// basename `userspace_hello.elf` should match via `module_bytes_for_path`.
fn resolve_limine_module_finds_hello_elf() {
    let bytes = resolve_execve_binary(b"/boot/userspace_hello.elf")
        .expect("resolve should find userspace_hello.elf via Limine module");
    assert!(bytes.len() > 4, "module bytes must be non-trivial");
    assert_eq!(
        &bytes[..4],
        b"\x7fELF",
        "first 4 bytes must be ELF magic"
    );
}

/// `/etc/hostname` exists in the rootfs tarball. `resolve_execve_binary`
/// should find it via VFS and return its raw content (which is not ELF —
/// the caller validates ELF separately).
fn resolve_vfs_file_returns_bytes() {
    let bytes = resolve_execve_binary(b"/etc/hostname")
        .expect("resolve should find /etc/hostname via VFS");
    // The rootfs hostname file contains "vibix\n".
    assert_eq!(bytes, b"vibix\n", "hostname file should contain 'vibix\\n'");
}
