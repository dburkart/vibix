//! Integration test: COM1 RX IRQ path delivers bytes into `RX_RING`.
//!
//! Drives the test entirely in-guest by flipping the 16550 into
//! loopback mode (MCR.LOOP | MCR.OUT2), transmitting a byte, and
//! waiting for IRQ4 → `serial_interrupt` → `drain_rx_hardware` to
//! push it to the software ring. MCR is restored before the test
//! emits its result so serial output leaves the chip again.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::{
    exit_qemu, serial, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::instructions::port::Port;

const COM1_BASE: u16 = 0x3F8;
const UART_REG_THR: u16 = 0;
const UART_REG_MCR: u16 = 4;
const MCR_LOOPBACK_BITS: u8 = 0x1A; // LOOP (bit4) | OUT2 (bit3) | RTS (bit1)

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
    let tests: &[(&str, &dyn Testable)] = &[(
        "serial_loopback_irq_delivers_byte",
        &(serial_loopback_irq_delivers_byte as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn serial_loopback_irq_delivers_byte() {
    // Drop any stray bytes that landed in the ring during boot/init.
    while serial::try_read_byte().is_some() {}
    let overflows_before = serial::rx_overflows();

    let mut mcr: Port<u8> = Port::new(COM1_BASE + UART_REG_MCR);
    let mut thr: Port<u8> = Port::new(COM1_BASE + UART_REG_THR);
    let saved_mcr = unsafe { mcr.read() };

    // Enter loopback and transmit the probe byte.
    unsafe {
        mcr.write(MCR_LOOPBACK_BITS);
        thr.write(b'X');
    }

    // Wait up to ~1 s for IRQ4 to push the looped byte into the ring.
    let mut observed: Option<u8> = None;
    for _ in 0..200 {
        if let Some(b) = serial::try_read_byte() {
            observed = Some(b);
            break;
        }
        x86_64::instructions::hlt();
    }

    // Restore MCR *before* any serial output so logs leave the chip
    // again. Assertions come after so a failure message is visible.
    unsafe { mcr.write(saved_mcr) };

    assert_eq!(
        observed,
        Some(b'X'),
        "IRQ4 didn't deliver loopback byte — ring stayed empty"
    );
    assert_eq!(
        serial::rx_overflows(),
        overflows_before,
        "RX ring overflowed during single-byte loopback test"
    );
}
