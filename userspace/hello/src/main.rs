//! Tiny userspace ELF payload for the ring-0 loader smoke test.
//!
//! Runs with the kernel's descriptors still active (we don't yet have
//! ring-3). The only contract is: write the "USRHELLO\n" marker to the
//! COM1 serial port so `xtask smoke` can observe control transfer, then
//! park via `hlt`.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

const COM1: u16 = 0x3F8;
const MARKER: &[u8] = b"USRHELLO\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    for &b in MARKER {
        unsafe {
            // Spin on the THR-empty bit (LSR.5) so bytes don't get
            // dropped if the UART isn't drained yet.
            while (inb(COM1 + 5) & 0x20) == 0 {}
            outb(COM1, b);
        }
    }
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    val
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
    }
}
