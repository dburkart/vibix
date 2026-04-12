//! In-kernel test harness. Each integration test binary under
//! `kernel/tests/*` brings its own `_start`, panic handler, and set of
//! `#[test_case]` functions; this module owns the shared machinery:
//! the `Testable` trait, the runner, and QEMU exit-code semantics.

use crate::{serial_print, serial_println};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x20,
    Failure = 0x10,
}

/// Exit QEMU via the `isa-debug-exit` device (port 0xf4). The host
/// process exit code comes back as `(code << 1) | 1`, i.e. Success → 65
/// and Failure → 33. The xtask runner translates those.
pub fn exit_qemu(code: QemuExitCode) -> ! {
    use x86_64::instructions::port::Port;
    unsafe {
        let mut port: Port<u32> = Port::new(0xf4);
        port.write(code as u32);
    }
    // Shouldn't return, but halt just in case the device isn't present.
    crate::hlt_loop()
}

pub trait Testable {
    fn run(&self);
}

impl<T: Fn()> Testable for T {
    fn run(&self) {
        serial_print!("{} ... ", core::any::type_name::<T>());
        self();
        serial_println!("[ok]");
    }
}

pub fn runner(tests: &[&dyn Testable]) {
    serial_println!("running {} tests", tests.len());
    for t in tests {
        t.run();
    }
    exit_qemu(QemuExitCode::Success);
}

/// Shared panic handler body for integration tests. Prints failure to
/// serial and exits QEMU with Failure.
pub fn test_panic_handler(info: &core::panic::PanicInfo) -> ! {
    serial_println!("[failed]");
    serial_println!("Error: {}", info);
    exit_qemu(QemuExitCode::Failure)
}
