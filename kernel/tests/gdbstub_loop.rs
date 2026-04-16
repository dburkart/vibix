//! Integration test: drive `gdbstub::debug_entry` end-to-end with an
//! in-memory transport. Verifies packet framing and dispatch compile
//! and run on the `x86_64-unknown-none` target, and that the packet
//! loop terminates cleanly on a `D` detach.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use vibix::{
    exit_qemu,
    gdbstub::{debug_entry, framer, transport::VecTransport},
    serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!("gdbstub_loop: init ok");
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("framer_checksum", &(framer_checksum as fn())),
        ("question_then_detach", &(question_then_detach as fn())),
        ("unknown_returns_empty", &(unknown_returns_empty as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn framer_checksum() {
    assert_eq!(framer::checksum(b"S05"), 0xb8);
    assert_eq!(framer::checksum(b"OK"), 0x9a);
    assert_eq!(framer::checksum(b"?"), 0x3f);
}

fn question_then_detach() {
    let mut t = VecTransport::with_rx(b"+$?#3f+$D#44");
    debug_entry(&mut t);
    let first = find(&t.tx, b"$S05#b8").expect("missing S05 reply");
    let second = find(&t.tx, b"$OK#9a").expect("missing detach reply");
    assert!(first < second, "detach reply must follow S05 reply");
}

fn unknown_returns_empty() {
    let mut t = VecTransport::with_rx(b"$g#67$D#44");
    debug_entry(&mut t);
    assert!(find(&t.tx, b"$#00").is_some(), "missing empty reply");
    assert!(find(&t.tx, b"$OK#9a").is_some(), "missing detach reply");
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
