//! Hello binary — the exec() target for the fork+exec+wait integration test.
//!
//! Loaded by the kernel's execve() syscall (nr=59) into the child process's
//! address space. Writes a marker to stdout (serial fd 1) and exits with
//! status 0 so the parent's waitpid() can verify the exit code.
//!
//! Uses the same Linux x86_64 syscall ABI as the init binary.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

const MSG: &[u8] = b"hello: hello from execed child\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // write(1, MSG, MSG.len())
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 1u64,
            in("rdi") 1u64,
            in("rsi") MSG.as_ptr() as u64,
            in("rdx") MSG.len() as u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    // exit(0)
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 60u64,
            in("rdi") 0u64,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
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
