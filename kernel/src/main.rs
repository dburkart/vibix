#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]

mod arch;
mod boot;
mod framebuffer;
mod serial;

use core::panic::PanicInfo;

use crate::boot::{BASE_REVISION, FRAMEBUFFER_REQUEST, HHDM_REQUEST, MEMMAP_REQUEST};
use crate::framebuffer::Console;

/// Shut QEMU down with exit code 0x11 (= (0x10 << 1) | 1) via the
/// `isa-debug-exit` device so test/panic flows return non-zero from
/// `cargo xtask run`. Harmless if the device isn't present.
fn qemu_exit_failure() {
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0xf4_u16, in("al") 0x10_u8);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    serial::init();
    serial_println!("vibix booting…");

    assert!(BASE_REVISION.is_supported(), "Limine base revision unsupported");

    if let Some(fb_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            serial_println!(
                "framebuffer: {}x{} @ {} bpp, pitch={} bytes",
                fb.width(),
                fb.height(),
                fb.bpp(),
                fb.pitch()
            );
            let console = unsafe {
                Console::new(fb.addr(), fb.width(), fb.height(), fb.pitch())
            };
            framebuffer::init(console);
            println!("vibix: framebuffer online");
        } else {
            serial_println!("no framebuffer reported by Limine");
        }
    } else {
        serial_println!("no framebuffer response");
    }

    if let Some(memmap) = MEMMAP_REQUEST.get_response() {
        let entries = memmap.entries();
        let usable: u64 = entries
            .iter()
            .filter(|e| e.entry_type == limine::memory_map::EntryType::USABLE)
            .map(|e| e.length)
            .sum();
        serial_println!(
            "memory map: {} entries, {} MiB usable",
            entries.len(),
            usable / (1024 * 1024)
        );
    }

    if let Some(hhdm) = HHDM_REQUEST.get_response() {
        serial_println!("hhdm offset: {:#x}", hhdm.offset());
    }

    arch::init();
    serial_println!("GDT + IDT loaded");
    println!("vibix online.");
    serial_println!("vibix online.");

    #[cfg(feature = "fault-test")]
    {
        serial_println!("fault-test: triggering #UD via ud2");
        unsafe { core::arch::asm!("ud2") };
    }

    loop {
        x86_64::instructions::hlt();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    qemu_exit_failure();
    loop {
        x86_64::instructions::hlt();
    }
}
