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
    gdbstub::{
        debug_entry, debug_entry_with_regs, framer,
        regs::{GdbRegs, GDB_REGS_HEX},
        transport::VecTransport,
    },
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
        ("g_reply_is_hex_blob", &(g_reply_is_hex_blob as fn())),
        ("big_g_writes_regs", &(big_g_writes_regs as fn())),
        (
            "big_g_rejects_unsupported_fields",
            &(big_g_rejects_unsupported_fields as fn()),
        ),
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
    // `q` with no sub-command is not implemented → empty reply.
    // checksum('q') = 0x71.
    let mut t = VecTransport::with_rx(b"$q#71$D#44");
    debug_entry(&mut t);
    assert!(find(&t.tx, b"$#00").is_some(), "missing empty reply");
    assert!(find(&t.tx, b"$OK#9a").is_some(), "missing detach reply");
}

fn g_reply_is_hex_blob() {
    // `g` = read all registers. checksum('g') = 0x67.
    // With a default (all-zero) GdbRegs, the reply payload is
    // `GDB_REGS_HEX` ASCII '0's framed as `$<hex>#<xx>`.
    let mut t = VecTransport::with_rx(b"$g#67$D#44");
    let mut regs = GdbRegs::default();
    debug_entry_with_regs(&mut t, &mut regs);

    // Find the `$` that starts the `g` reply, then verify its payload
    // is exactly GDB_REGS_HEX bytes of lowercase '0'.
    let start = find(&t.tx, b"$").expect("no outbound frame");
    let hash = start + 1 + GDB_REGS_HEX;
    assert!(
        t.tx.len() > hash + 2,
        "tx too short: {} bytes, need >{}",
        t.tx.len(),
        hash + 2
    );
    assert_eq!(t.tx[hash], b'#', "EOP not at expected offset");
    for (k, &b) in t.tx[start + 1..hash].iter().enumerate() {
        assert_eq!(b, b'0', "non-zero at offset {k} in g reply");
    }
    assert!(find(&t.tx, b"$OK#9a").is_some(), "missing detach reply");
}

fn big_g_writes_regs() {
    // Build a `G<hex>` packet that changes only `rip` (the 17th u64, so
    // hex offset 256 in the payload, i.e. index 257 with the leading
    // `G`). Every other field hex-encodes whatever the caller seeded,
    // which for a default-zero `GdbRegs` is all '0's — so the only
    // mutation in flight is `rip`. The stub should reply `OK` and
    // actually update `regs.rip`.
    let mut payload = [b'0'; 1 + GDB_REGS_HEX];
    payload[0] = b'G';
    // rip LE first byte = 0x01 → "01" at [257..259]. All other rip
    // bytes stay '0' → rip = 0x0000_0000_0000_0001.
    payload[1 + 256 + 1] = b'1';
    let mut frame = [0u8; 2 * (1 + GDB_REGS_HEX) + 4];
    let wire = framer::encode(&payload, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }

    let mut regs = GdbRegs::default();
    debug_entry_with_regs(&mut t, &mut regs);
    assert_eq!(regs.rip, 0x01, "G did not write rip");
    assert!(find(&t.tx, b"$OK#9a").is_some(), "missing OK reply");
}

fn big_g_rejects_unsupported_fields() {
    // `G` that tries to change `rax` (bytes [1..3] of the payload hex)
    // must be rejected with `E01`: the int3 handler only honors writes
    // to `rip` and `eflags`, so silently accepting other changes would
    // lie to the debugger.
    let mut payload = [b'0'; 1 + GDB_REGS_HEX];
    payload[0] = b'G';
    payload[2] = b'1';
    let mut frame = [0u8; 2 * (1 + GDB_REGS_HEX) + 4];
    let wire = framer::encode(&payload, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }

    let mut regs = GdbRegs::default();
    debug_entry_with_regs(&mut t, &mut regs);
    assert_eq!(regs.rax, 0, "unsupported G must not mutate rax");
    // checksum("E01") = b'E' + b'0' + b'1' = 0x45 + 0x30 + 0x31 = 0xa6.
    assert!(find(&t.tx, b"$E01#a6").is_some(), "missing E01 reply");
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
