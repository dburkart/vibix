//! Integration test: `help` and `help <cmd>` route through the dispatch
//! table without panicking, and `help unknown` produces an error
//! (still no panic).
//!
//! UART loopback would be needed to assert the printed text byte-for-byte,
//! but the full `help` listing is several hundred bytes — well past the
//! 16-byte 16550 RX FIFO that integrity-tests like `shell_introspection`
//! rely on. We follow the introspection-test convention of
//! "larger outputs are smoke-only" and verify only that each path
//! dispatches cleanly.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::{
    exit_qemu, serial_println,
    shell::dispatch_for_test,
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
            "help_no_args_lists_builtins",
            &(help_no_args_lists_builtins as fn()),
        ),
        (
            "help_help_describes_itself",
            &(help_help_describes_itself as fn()),
        ),
        (
            "help_known_builtins_dispatch",
            &(help_known_builtins_dispatch as fn()),
        ),
        (
            "help_unknown_does_not_panic",
            &(help_unknown_does_not_panic as fn()),
        ),
        (
            "help_with_extra_whitespace",
            &(help_with_extra_whitespace as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn help_no_args_lists_builtins() {
    dispatch_for_test("help");
}

fn help_help_describes_itself() {
    // `help help` exercises the recursive lookup path — `help` is itself
    // a `BUILTINS` entry, so this should resolve cleanly rather than
    // taking the unknown-command branch.
    dispatch_for_test("help help");
}

fn help_known_builtins_dispatch() {
    for cmd in [
        "help tasks",
        "help echo",
        "help mem",
        "help uname",
        "help clear",
    ] {
        dispatch_for_test(cmd);
    }
}

fn help_unknown_does_not_panic() {
    // ENOENT-style error message; must not abort the kernel.
    dispatch_for_test("help nosuch");
    dispatch_for_test("help ");
    // Whitespace-only argument trims to empty → falls back to the
    // listing path, not the unknown-command path.
}

fn help_with_extra_whitespace() {
    // `cmd_help` trims its argument, so trailing spaces and collapsed
    // multi-space separators between `help` and its argument must still
    // resolve to the same builtin rather than falling through to the
    // unknown-command branch.
    dispatch_for_test("help tasks ");
    dispatch_for_test("help  tasks");
    dispatch_for_test("help tasks   ");
}
