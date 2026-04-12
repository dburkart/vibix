//! Integration test: the panic-path backtrace walker emits a
//! `backtrace:` marker on serial and its frame addresses resolve to
//! real kernel symbols via the embedded `.ksymtab`. We drive this via
//! the should-panic pattern — a deliberate panic activates our custom
//! panic handler, which validates the backtrace machinery and then
//! reports pass/fail via QEMU's isa-debug-exit.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU32, Ordering};
use vibix::{arch::backtrace, exit_qemu, ksymtab, serial_println, QemuExitCode};

static RESOLVED_FRAMES: AtomicU32 = AtomicU32::new(0);

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    serial_println!(
        "backtrace test: ksymtab populated = {}, symbols = {}",
        ksymtab::is_populated(),
        ksymtab::len()
    );
    if !ksymtab::is_populated() {
        serial_println!("ksymtab missing — did xtask run embed_ksymtab?");
        exit_qemu(QemuExitCode::Failure);
    }
    trigger_panic();
    serial_println!("no panic triggered");
    exit_qemu(QemuExitCode::Failure);
}

#[inline(never)]
fn trigger_panic() {
    panic!("deliberate panic for backtrace test");
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // Walk the stack and count how many addresses resolve to a symbol.
    // Success criterion: backtrace emitted at least one frame AND at
    // least one frame resolved via ksymtab — that exercises both the
    // walker and the resolver end-to-end.
    serial_println!("backtrace:");
    let mut emitted = 0u32;
    let mut resolved = 0u32;
    backtrace::walk(1, |frame| {
        emitted += 1;
        match ksymtab::resolve(frame.return_addr) {
            Some((name, off)) => {
                serial_println!("  {:#018x} {}+{:#x}", frame.return_addr, name, off);
                resolved += 1;
            }
            None => {
                serial_println!("  {:#018x} ?", frame.return_addr);
            }
        }
    });
    RESOLVED_FRAMES.store(resolved, Ordering::SeqCst);
    serial_println!("backtrace: {emitted} frames, {resolved} resolved");
    if emitted == 0 || resolved == 0 {
        exit_qemu(QemuExitCode::Failure);
    }
    exit_qemu(QemuExitCode::Success);
}
