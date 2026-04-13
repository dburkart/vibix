//! PID 1 init binary — the first userspace process on vibix.
//!
//! This minimal binary demonstrates ring-3 execution and the syscall path:
//! 1. Makes one `write(1, msg, len)` syscall to print to the serial console.
//! 2. Loops forever (busy-spins without issuing any more syscalls).
//!
//! The marker line `init: hello from pid 1` is asserted by `cargo xtask smoke`.
//!
//! Syscall ABI (Linux x86_64 convention used by the vibix kernel):
//! - rax = syscall number
//! - rdi = arg0,  rsi = arg1,  rdx = arg2
//! - rcx and r11 are clobbered by SYSCALL/SYSRET
//! - Return value in rax

#![no_std]
#![no_main]

use core::panic::PanicInfo;

const MSG: &[u8] = b"init: hello from pid 1\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // write(fd=1, buf=MSG.as_ptr(), len=MSG.len())
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 1u64,
            in("rdi") 1u64,
            in("rsi") MSG.as_ptr() as u64,
            in("rdx") MSG.len() as u64,
            lateout("rcx") _,  // SYSCALL saves user RIP here
            lateout("r11") _,  // SYSCALL saves user RFLAGS here
            options(nostack, preserves_flags),
        );
    }
    // Park forever — no exit syscall needed for the smoke test.
    loop {
        core::hint::spin_loop();
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
