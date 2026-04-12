#![no_std]
#![no_main]

use core::panic::PanicInfo;

use vibix::boot::{BASE_REVISION, FRAMEBUFFER_REQUEST, HHDM_REQUEST, MEMMAP_REQUEST};
use vibix::framebuffer::Console;
use vibix::{exit_qemu, framebuffer, println, serial_print, serial_println, QemuExitCode};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::serial::init();
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
            let console = unsafe { Console::new(fb.addr(), fb.width(), fb.height(), fb.pitch()) };
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

    vibix::arch::init();
    serial_println!("GDT + IDT loaded");

    vibix::mem::init();
    vibix::time::init();

    println!("vibix online.");
    serial_println!("vibix online.");

    #[cfg(feature = "fault-test")]
    {
        serial_println!("fault-test: triggering #UD via ud2");
        unsafe { core::arch::asm!("ud2") };
    }

    x86_64::instructions::interrupts::enable();
    serial_println!("interrupts enabled");

    loop {
        match vibix::input::read_key() {
            pc_keyboard::DecodedKey::Unicode(c) => serial_print!("{}", c),
            pc_keyboard::DecodedKey::RawKey(key) => serial_print!("[{:?}]", key),
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    exit_qemu(QemuExitCode::Failure)
}
