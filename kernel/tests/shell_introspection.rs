//! Integration test: every introspection builtin dispatches without
//! panicking, `build_info` constants are populated, and `whoami`'s
//! serial output is captured end-to-end via UART loopback.
//!
//! Serial loopback is only used for the tiny `whoami` output (5 bytes)
//! so the transmission fits inside the UART's 16-byte hardware FIFO
//! during the `without_interrupts` window `serial_println!` takes.
//! Larger outputs (`uname -a`, `version`) would race FIFO drain vs.
//! IRQ4 re-enable, so they're verified only for "does not panic" +
//! `build_info` value plumbing.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::{
    build_info, exit_qemu, serial, serial_println,
    shell::dispatch_for_test,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::instructions::port::Port;

const COM1_BASE: u16 = 0x3F8;
const UART_REG_MCR: u16 = 4;
const MCR_LOOPBACK_BITS: u8 = 0x1A;

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
            "build_info_constants_populated",
            &(build_info_constants_populated as fn()),
        ),
        (
            "uname_default_does_not_panic",
            &(uname_default_does_not_panic as fn()),
        ),
        (
            "uname_flag_combos_do_not_panic",
            &(uname_flag_combos_do_not_panic as fn()),
        ),
        ("version_does_not_panic", &(version_does_not_panic as fn())),
        ("clear_does_not_panic", &(clear_does_not_panic as fn())),
        ("date_does_not_panic", &(date_does_not_panic as fn())),
        ("whoami_prints_root", &(whoami_prints_root as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn build_info_constants_populated() {
    assert_eq!(build_info::KERNEL_NAME, "vibix");
    assert!(
        !build_info::ARCH.is_empty(),
        "ARCH should be set from CARGO_CFG_TARGET_ARCH via build.rs"
    );
    assert!(
        !build_info::RELEASE.is_empty(),
        "RELEASE should come from CARGO_PKG_VERSION"
    );
    assert!(
        !build_info::GIT_SHA.is_empty(),
        "GIT_SHA should be set (build.rs fallback is \"unknown\")"
    );
    assert!(
        !build_info::BUILD_TIMESTAMP.is_empty(),
        "BUILD_TIMESTAMP should be set by build.rs"
    );
    assert!(
        !build_info::PROFILE.is_empty(),
        "PROFILE should be set from cargo PROFILE env"
    );
}

fn uname_default_does_not_panic() {
    dispatch_for_test("uname");
}

fn uname_flag_combos_do_not_panic() {
    dispatch_for_test("uname -a");
    dispatch_for_test("uname -s");
    dispatch_for_test("uname -r");
    dispatch_for_test("uname -v");
    dispatch_for_test("uname -m");
    dispatch_for_test("uname -srm");
    // Bad flag path: must print an error line, not panic.
    dispatch_for_test("uname -Z");
}

fn version_does_not_panic() {
    dispatch_for_test("version");
}

fn clear_does_not_panic() {
    dispatch_for_test("clear");
}

fn date_does_not_panic() {
    dispatch_for_test("date");
}

fn whoami_prints_root() {
    // Drain any pre-existing bytes in the ring.
    while serial::try_read_byte().is_some() {}

    let mut mcr: Port<u8> = Port::new(COM1_BASE + UART_REG_MCR);
    let saved_mcr = unsafe { mcr.read() };

    // Enter loopback. "root\n" is 5 bytes → fits in the 16-byte
    // 16550 RX FIFO during the single `without_interrupts` window
    // `serial_println!` takes.
    unsafe { mcr.write(MCR_LOOPBACK_BITS) };
    dispatch_for_test("whoami");

    // Give IRQ4 time to drain the FIFO into RX_RING.
    let mut collected = alloc::vec::Vec::<u8>::new();
    for _ in 0..200 {
        while let Some(b) = serial::try_read_byte() {
            collected.push(b);
        }
        if collected.len() >= 5 {
            break;
        }
        x86_64::instructions::hlt();
    }

    // Restore MCR before emitting anything — otherwise pass/fail logs
    // never leave the chip.
    unsafe { mcr.write(saved_mcr) };

    assert_eq!(
        core::str::from_utf8(&collected).unwrap_or("<non-utf8>"),
        "root\n",
        "whoami should emit exactly \"root\\n\" (got {:?})",
        collected
    );
}
