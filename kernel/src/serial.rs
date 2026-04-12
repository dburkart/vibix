//! COM1 16550 UART — our primary log sink during early boot.

use core::fmt::{self, Write};
use spin::Mutex;
use uart_16550::SerialPort;

static COM1: Mutex<SerialPort> = Mutex::new(unsafe { SerialPort::new(0x3F8) });

pub fn init() {
    COM1.lock().init();
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    // Best-effort: if this fires from an interrupt that preempted a
    // print holding the lock we would deadlock — acceptable for now,
    // all our interrupt handlers halt anyway.
    let _ = COM1.lock().write_fmt(args);
}

#[macro_export]
macro_rules! serial_print {
    ($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
}

#[macro_export]
macro_rules! serial_println {
    () => ($crate::serial_print!("\n"));
    ($($arg:tt)*) => ($crate::serial_print!("{}\n", format_args!($($arg)*)));
}
