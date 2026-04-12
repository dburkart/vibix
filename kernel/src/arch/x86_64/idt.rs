//! IDT with handlers for the CPU exceptions most likely to actually fire
//! during early boot. Each handler logs to serial then halts — we don't
//! have a panic-unwind story yet, so there's nothing to return to.

use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};

use crate::arch::x86_64::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::arch::x86_64::interrupts::{keyboard_interrupt, timer_interrupt, InterruptIndex};
use crate::serial_println;

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error);
    idt.invalid_opcode.set_handler_fn(invalid_opcode);
    idt.general_protection_fault
        .set_handler_fn(general_protection);
    idt.page_fault.set_handler_fn(page_fault);
    unsafe {
        idt.double_fault
            .set_handler_fn(double_fault)
            .set_stack_index(DOUBLE_FAULT_IST_INDEX);
    }
    idt[InterruptIndex::Timer.as_u8()].set_handler_fn(timer_interrupt);
    idt[InterruptIndex::Keyboard.as_u8()].set_handler_fn(keyboard_interrupt);
    idt
});

pub fn init() {
    IDT.load();
}

fn hang() -> ! {
    loop {
        x86_64::instructions::hlt();
    }
}

extern "x86-interrupt" fn divide_error(frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: #DE (divide error)\n{:#?}", frame);
    hang();
}

extern "x86-interrupt" fn invalid_opcode(frame: InterruptStackFrame) {
    serial_println!("EXCEPTION: #UD (invalid opcode)\n{:#?}", frame);
    hang();
}

extern "x86-interrupt" fn general_protection(frame: InterruptStackFrame, code: u64) {
    serial_println!("EXCEPTION: #GP code={:#x}\n{:#?}", code, frame);
    hang();
}

extern "x86-interrupt" fn page_fault(frame: InterruptStackFrame, code: PageFaultErrorCode) {
    let addr = x86_64::registers::control::Cr2::read();
    serial_println!(
        "EXCEPTION: #PF addr={:?} code={:?}\n{:#?}",
        addr,
        code,
        frame
    );
    hang();
}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    serial_println!("EXCEPTION: #DF (double fault)\n{:#?}", frame);
    #[cfg(feature = "ist-overflow-test")]
    {
        // We're running on the IST stack now — the whole point. Burn
        // through it so overflow walks into the guard page below and
        // surfaces as a #PF with a fault address inside the guard.
        serial_println!("ist-overflow-test: recursing inside #DF handler");
        df_recurse(core::hint::black_box(0));
    }
    hang();
}

#[cfg(feature = "ist-overflow-test")]
#[inline(never)]
#[allow(unconditional_recursion)]
fn df_recurse(depth: u64) -> u64 {
    let buf = [depth; 64];
    let next = core::hint::black_box(depth).wrapping_add(1);
    df_recurse(next).wrapping_add(core::hint::black_box(buf[0]))
}
