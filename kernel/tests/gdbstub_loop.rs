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
        ("big_g_writes_rax", &(big_g_writes_rax as fn())),
        ("m_reads_known_bytes", &(m_reads_known_bytes as fn())),
        ("m_unmapped_returns_e01", &(m_unmapped_returns_e01 as fn())),
        ("big_m_writes_buffer", &(big_m_writes_buffer as fn())),
        (
            "big_m_unmapped_returns_e01",
            &(big_m_unmapped_returns_e01 as fn()),
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

fn big_g_writes_rax() {
    // With the int3 trampoline capturing full GPR state (#482), `G`
    // writes to rax..r15 are honored — they round-trip through the
    // dispatch path and a subsequent `g` reads back the mutated value.
    // Build a `G` that sets rax = 0x01 (byte 0 of the payload hex).
    let mut payload = [b'0'; 1 + GDB_REGS_HEX];
    payload[0] = b'G';
    payload[2] = b'1';
    let mut frame = [0u8; 2 * (1 + GDB_REGS_HEX) + 4];
    let wire = framer::encode(&payload, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }
    // Append a `D` detach so the loop terminates cleanly.
    let mut detach = [0u8; 8];
    for &b in framer::encode(b"D", &mut detach) {
        t.rx.push_back(b);
    }

    let mut regs = GdbRegs::default();
    debug_entry_with_regs(&mut t, &mut regs);
    assert_eq!(regs.rax, 0x01, "G must write rax");
    assert!(find(&t.tx, b"$OK#9a").is_some(), "missing OK reply");
}

fn m_reads_known_bytes() {
    // Put a known pattern on the stack. The test function's stack is
    // mapped and readable, so `m` must succeed.
    let buf: [u8; 4] = [0xDE, 0xAD, 0xBE, 0xEF];
    let addr = buf.as_ptr() as usize as u64;

    // Build `m <addr>,4` packet.
    let mut req = alloc::vec::Vec::new();
    req.push(b'm');
    // Lowercase hex addr, no 0x prefix.
    push_hex_u64(&mut req, addr);
    req.push(b',');
    req.push(b'4');

    let mut frame = [0u8; 64];
    let wire = framer::encode(&req, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }
    // Detach after.
    let mut detach = [0u8; 8];
    for &b in framer::encode(b"D", &mut detach) {
        t.rx.push_back(b);
    }

    debug_entry(&mut t);
    assert!(
        find(&t.tx, b"$deadbeef#").is_some(),
        "expected hex-encoded bytes in reply, got {:?}",
        core::str::from_utf8(&t.tx).unwrap_or("<non-utf8>")
    );
}

fn m_unmapped_returns_e01() {
    // Lower-half address well past anything the kernel maps.
    let mut t = VecTransport::with_rx(b"$m6000000000,4#00$D#44");
    // The checksum on the `m` packet doesn't matter — decode failure
    // would NAK, but let's make it plausible anyway:
    let mut req = alloc::vec::Vec::new();
    req.extend_from_slice(b"m6000000000,4");
    let mut frame = [0u8; 32];
    let wire = framer::encode(&req, &mut frame);
    t.rx.clear();
    for &b in wire {
        t.rx.push_back(b);
    }
    let mut detach = [0u8; 8];
    for &b in framer::encode(b"D", &mut detach) {
        t.rx.push_back(b);
    }

    debug_entry(&mut t);
    assert!(
        find(&t.tx, b"$E01#").is_some(),
        "expected E01 for unmapped read, got {:?}",
        core::str::from_utf8(&t.tx).unwrap_or("<non-utf8>")
    );
}

fn big_m_writes_buffer() {
    let mut buf: [u8; 4] = [0; 4];
    let addr = buf.as_mut_ptr() as usize as u64;

    let mut req = alloc::vec::Vec::new();
    req.push(b'M');
    push_hex_u64(&mut req, addr);
    req.push(b',');
    req.push(b'4');
    req.push(b':');
    req.extend_from_slice(b"cafebabe");

    let mut frame = [0u8; 64];
    let wire = framer::encode(&req, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }
    let mut detach = [0u8; 8];
    for &b in framer::encode(b"D", &mut detach) {
        t.rx.push_back(b);
    }

    debug_entry(&mut t);
    assert!(
        find(&t.tx, b"$OK#9a").is_some(),
        "expected OK for valid M, got {:?}",
        core::str::from_utf8(&t.tx).unwrap_or("<non-utf8>")
    );
    assert_eq!(
        buf,
        [0xca, 0xfe, 0xba, 0xbe],
        "M did not land in the target buffer"
    );
}

fn big_m_unmapped_returns_e01() {
    let mut req = alloc::vec::Vec::new();
    req.extend_from_slice(b"M6000000000,2:abcd");
    let mut frame = [0u8; 32];
    let wire = framer::encode(&req, &mut frame);

    let mut t = VecTransport::new();
    for &b in wire {
        t.rx.push_back(b);
    }
    let mut detach = [0u8; 8];
    for &b in framer::encode(b"D", &mut detach) {
        t.rx.push_back(b);
    }

    debug_entry(&mut t);
    assert!(
        find(&t.tx, b"$E01#").is_some(),
        "expected E01 for unmapped write, got {:?}",
        core::str::from_utf8(&t.tx).unwrap_or("<non-utf8>")
    );
}

fn push_hex_u64(out: &mut alloc::vec::Vec<u8>, mut v: u64) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    if v == 0 {
        out.push(b'0');
        return;
    }
    // Count nibbles, emit high→low.
    let mut buf = [0u8; 16];
    let mut i = 0;
    while v != 0 {
        buf[i] = HEX[(v & 0xF) as usize];
        v >>= 4;
        i += 1;
    }
    for j in (0..i).rev() {
        out.push(buf[j]);
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
