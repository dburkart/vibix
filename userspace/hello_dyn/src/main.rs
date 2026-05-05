//! Dynamically-linked hello world — test binary for the vibix dynamic linker.
//!
//! This binary has `PT_INTERP = /lib/ld-vibix.so` in its program headers.
//! When execve'd, the kernel loads ld-vibix.so at INTERP_LOAD_BASE and
//! transfers control to it. The dynamic linker processes relocations and
//! then jumps to this binary's _start.
//!
//! Writes a marker to serial (fd 1) and exits. The marker is checked by
//! the integration test to confirm end-to-end dynamic linking works.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// PT_INTERP path — placed in .interp section by the linker script.
#[used]
#[link_section = ".interp"]
static INTERP: [u8; 17] = *b"/lib/ld-vibix.so\0";

const MSG: &[u8] = b"hello_dyn: hello from dynamically-linked binary\n";

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
