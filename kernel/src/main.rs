#![no_std]
#![no_main]

use core::panic::PanicInfo;

use vibix::boot::{BASE_REVISION, FRAMEBUFFER_REQUEST, HHDM_REQUEST, MEMMAP_REQUEST, RSDP_REQUEST};
use vibix::framebuffer::Console;
use vibix::{exit_qemu, framebuffer, println, serial_println, QemuExitCode};

/// How many PIT ticks between cursor blink toggles (~500 ms at 100 Hz).
const CURSOR_BLINK_TICKS: u64 = 50;

#[no_mangle]
#[cfg_attr(
    any(feature = "ist-overflow-test", feature = "panic-test"),
    allow(unreachable_code)
)]
pub extern "C" fn _start() -> ! {
    vibix::serial::init();
    serial_println!("vibix booting…");

    assert!(
        BASE_REVISION.is_supported(),
        "Limine base revision unsupported"
    );

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

    let hhdm_offset = HHDM_REQUEST
        .get_response()
        .map(|h| h.offset())
        .expect("Limine HHDM response missing");
    serial_println!("hhdm offset: {:#x}", hhdm_offset);

    let rsdp_ptr = RSDP_REQUEST
        .get_response()
        .map(|r| r.address())
        .expect("Limine RSDP response missing");
    serial_println!("rsdp: {:#x}", rsdp_ptr);

    vibix::arch::init();
    serial_println!("GDT + IDT loaded");

    vibix::mem::init();
    if let Some((entry, load_segments)) = vibix::mem::userspace_module_elf_summary() {
        serial_println!(
            "userspace module ELF entry={:#x} load_segments={}",
            entry.as_u64(),
            load_segments
        );
    } else {
        serial_println!("userspace module ELF missing");
    }
    vibix::arch::init_apic(rsdp_ptr, hhdm_offset);
    match vibix::hpet::init() {
        Ok(()) => {}
        Err(e) => serial_println!("hpet: unavailable ({:?}), falling back to PIT", e),
    }
    vibix::time::init();
    vibix::pci::scan();

    // Console init must come after mem::init() — the character grid and
    // scrollback buffer are heap-allocated inside Console::new().
    if let Some(fb_response) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(fb) = fb_response.framebuffers().next() {
            serial_println!(
                "framebuffer: {}x{} @ {} bpp, pitch={} bytes",
                fb.width(),
                fb.height(),
                fb.bpp(),
                fb.pitch()
            );
            if fb.bpp() == 32 {
                let console =
                    unsafe { Console::new(fb.addr(), fb.width(), fb.height(), fb.pitch()) };
                framebuffer::init(console);
                println!("vibix: framebuffer online");
            } else {
                serial_println!("unsupported framebuffer format: {} bpp", fb.bpp());
            }
        } else {
            serial_println!("no framebuffer reported by Limine");
        }
    } else {
        serial_println!("no framebuffer response");
    }

    println!("vibix online.");
    serial_println!("vibix online.");

    #[cfg(feature = "fault-test")]
    {
        serial_println!("fault-test: triggering #UD via ud2");
        unsafe { core::arch::asm!("ud2") };
    }

    #[cfg(feature = "panic-test")]
    {
        serial_println!("panic-test: triggering deliberate panic");
        panic!("panic-test: eyeball the backtrace");
    }

    #[cfg(feature = "ist-overflow-test")]
    {
        // Trigger a real #DF so the CPU switches to the IST stack before
        // we recurse (recursion happens in the #DF handler itself, in
        // idt.rs, under the same feature). The cascade: bad RSP → ud2
        // raises #UD → the #UD handler preamble can't push its frame on
        // the invalid RSP → #PF → same — push fails again → #DF. The
        // #DF vector has an IST index, so the CPU finally switches to a
        // good stack and enters our handler, which then blows it.
        serial_println!("ist-overflow-test: forcing #DF via bad RSP + ud2");
        unsafe {
            core::arch::asm!(
                "mov rsp, {bad}",
                "ud2",
                bad = in(reg) 0xFFFF_FFFF_FFFE_F000u64,
                options(noreturn),
            );
        }
    }

    x86_64::instructions::interrupts::enable();
    serial_println!("interrupts enabled");

    // TSC calibration needs IRQs on so the PIT can advance TICKS under
    // the spin loop; runs before task::init() so sleep/bench callers
    // see the calibrated clock from their first tick.
    vibix::time::calibrate_tsc();

    vibix::task::init();
    vibix::task::spawn(vibix::shell::run);
    vibix::task::spawn(cursor_blink_task);

    #[cfg(feature = "bench")]
    vibix::task::spawn(vibix::bench::run_all);

    // Bootstrap task becomes the idle loop. `hlt` with IRQs on parks
    // the CPU until the next interrupt; the PIT `preempt_tick` then
    // rotates us to any other ready task (shell, cursor_blink).
    loop {
        x86_64::instructions::hlt();
    }
}

/// Blink the framebuffer cursor at approximately 1 Hz (toggle every 500 ms).
fn cursor_blink_task() -> ! {
    let mut next = vibix::time::ticks() + CURSOR_BLINK_TICKS;
    loop {
        while vibix::time::ticks() < next {
            // Wake on the next timer tick, recheck. Preemption
            // rotates other tasks in and out while we sleep.
            x86_64::instructions::hlt();
        }
        next = next.wrapping_add(CURSOR_BLINK_TICKS);
        vibix::framebuffer::toggle_cursor();
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_println!("KERNEL PANIC: {}", info);
    vibix::arch::backtrace::dump_to_serial(1);
    serial_println!("--- kernel log tail ---");
    vibix::klog::dump_tail_to_serial(32);
    serial_println!("--- end kernel log ---");
    exit_qemu(QemuExitCode::Failure)
}
