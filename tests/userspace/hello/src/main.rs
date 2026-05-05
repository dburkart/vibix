//! Hello binary — the exec() target for the fork+exec+wait integration test.
//!
//! Loaded by the kernel's execve() syscall (nr=59) into the child process's
//! address space. Writes a marker to stdout (serial fd 1) and exits with
//! status 0 so the parent's waitpid() can verify the exit code.
//!
//! Uses the same Linux x86_64 syscall ABI as the init binary.  See
//! `userspace/init/src/main.rs` for the full clobber rationale — the
//! vibix kernel does not preserve `rdi`/`rsi`/`rdx`/`r8`/`r9`/`r10`
//! across a syscall, so every asm block below declares the full SysV
//! caller-saved GPR set as `inlateout`/`lateout` (issue #531).

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
            inlateout("rax") 1u64 => _,
            inlateout("rdi") 1u64 => _,
            inlateout("rsi") MSG.as_ptr() as u64 => _,
            inlateout("rdx") MSG.len() as u64 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    // exit(0)
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 60u64 => _,
            inlateout("rdi") 0u64 => _,
            lateout("rcx") _,
            lateout("rdx") _,
            lateout("rsi") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
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
