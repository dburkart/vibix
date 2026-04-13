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
    let addr_u64 = x86_64::registers::control::Cr2::read_raw();

    if let Some(expected) = crate::test_hook::take_page_fault_expectation() {
        use crate::test_harness::{exit_qemu, QemuExitCode};
        if addr_u64 == expected {
            serial_println!("#PF oracle matched addr={:#x} code={:?}", expected, code);
            exit_qemu(QemuExitCode::Success);
        } else {
            serial_println!(
                "#PF oracle MISMATCH: expected {:#x}, got {:#x} code={:?}",
                expected,
                addr_u64,
                code
            );
            exit_qemu(QemuExitCode::Failure);
        }
    }

    // Demand-paging resolver: a not-present fault inside an installed
    // VMA is satisfied by allocating + zeroing a frame and mapping it
    // with the VMA's flags. Protection violations (P bit set in the
    // error code) fall through — those are real access-rights bugs,
    // not missing-page cases.
    if !code.contains(PageFaultErrorCode::PROTECTION_VIOLATION) {
        if let Some((kind, flags)) = crate::task::current_vma_lookup(addr_u64 as usize) {
            match kind {
                crate::mem::vma::VmaKind::AnonZero => {
                    use x86_64::structures::paging::{Page, Size4KiB};
                    use x86_64::VirtAddr;
                    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr_u64));
                    let active = x86_64::registers::control::Cr3::read().0;
                    match crate::mem::paging::map_in_pml4(active, page, flags) {
                        Ok(_) => return,
                        Err(e) => {
                            serial_println!(
                                "#PF demand-page resolve failed addr={:#x}: {:?}",
                                addr_u64,
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    // Check whether the fault address lands inside a kernel task's guard
    // page — if so, this is a stack overflow, not a generic fault.
    if let Some(task_id) = crate::task::find_stack_overflow(addr_u64 as usize) {
        serial_println!(
            "EXCEPTION: #PF task {} stack overflow addr={:#x} code={:?}\n{:#?}",
            task_id,
            addr_u64,
            code,
            frame
        );
        hang();
    }

    serial_println!(
        "EXCEPTION: #PF addr={:#x} code={:?}\n{:#?}",
        addr_u64,
        code,
        frame
    );
    hang();
}

extern "x86-interrupt" fn double_fault(frame: InterruptStackFrame, _code: u64) -> ! {
    // The most common task stack overflow pattern: PUSH/CALL walks RSP into
    // the guard page, the CPU cannot write the #PF frame there (also
    // unmapped), so it escalates to #DF. The #DF frame's stack_pointer
    // holds the faulted RSP — check it before the generic diagnostic.
    let faulted_rsp = frame.stack_pointer.as_u64() as usize;
    if let Some(task_id) = crate::task::find_stack_overflow(faulted_rsp) {
        serial_println!(
            "EXCEPTION: #DF task {} stack overflow rsp={:#x}\n{:#?}",
            task_id,
            faulted_rsp,
            frame
        );
        hang();
    }
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
