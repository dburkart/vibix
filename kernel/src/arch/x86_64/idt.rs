//! IDT with handlers for the CPU exceptions most likely to actually fire
//! during early boot. Each handler logs to serial then halts — we don't
//! have a panic-unwind story yet, so there's nothing to return to.

use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::structures::paging::PageTableFlags;

use crate::arch::x86_64::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::arch::x86_64::interrupts::{
    keyboard_interrupt, serial_interrupt, timer_interrupt, InterruptIndex,
};
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
    idt[InterruptIndex::Serial.as_u8()].set_handler_fn(serial_interrupt);
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

/// RFC 0001 Security A2: an SMAP violation is a kernel bug that could
/// be weaponised by an attacker-controlled user page, so the diagnostic
/// carries the faulting VA only — never PTE contents or frame physaddrs.
#[inline(never)]
fn panic_smap_violation(addr: u64) -> ! {
    serial_println!("EXCEPTION: #PF SMAP violation addr={:#x}", addr);
    hang();
}

/// RFC 0001 Security A2: a reserved-bit fault means the page-table
/// walker saw a PTE with bits set that the current MAXPHYADDR /
/// paging mode reserves — always a kernel-side corruption. Log the
/// VA only; the PTE word must not reach any user-reachable sink.
#[inline(never)]
fn panic_rsvd_corruption(addr: u64) -> ! {
    serial_println!("EXCEPTION: #PF RSVD corruption addr={:#x}", addr);
    hang();
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

    // RFC 0001 dispatch gates. Order is load-bearing: SMAP before any
    // decision that might trust user state; RSVD before canonical
    // because a corrupt walk could spoof a "bad address" signal; the
    // canonical/USER_VA_END check gates user faults only (pure kernel
    // faults fall through to the existing hang-with-diagnostic path).
    let err_raw = code.bits();
    let cpl = (frame.code_segment.0 & 0b11) as u8;
    let rflags_ac = frame.cpu_flags.contains(x86_64::registers::rflags::RFlags::ALIGNMENT_CHECK);

    if crate::mem::pf::is_smap_violation(cpl, err_raw, rflags_ac) {
        panic_smap_violation(addr_u64);
    }

    // Pure kernel faults (CPL=0, supervisor page) fall through to the
    // existing handler chain below. Nothing to do here beyond the
    // explicit no-op — the comment documents the RFC's step 2.

    if crate::mem::pf::is_rsvd_fault(err_raw) {
        panic_rsvd_corruption(addr_u64);
    }

    // Step 4: canonical / USER_VA_END check for user-mode faults. A
    // user fault whose cr2 lands in the kernel half (or non-canonical
    // region) is a SIGSEGV/MAPERR; we don't have signal delivery yet
    // so log and hang with the RFC-mandated marker.
    if cpl != 0 && !crate::mem::pf::is_user_va(addr_u64) {
        serial_println!(
            "EXCEPTION: #PF user addr={:#x} outside USER_VA_END (MAPERR) code={:?}",
            addr_u64,
            code,
        );
        hang();
    }

    // VMA-backed resolver. Two independent paths:
    //
    // * Not-present fault inside an installed VMA → install the page.
    //   AnonZero: alloc+zero a frame and map it writable per the
    //   VMA flags. Cow: map the shared source frame read-only (strip
    //   WRITABLE) so the *next* write takes a protection fault we
    //   resolve below.
    //
    // * Write protection fault on a Cow page → allocate a private
    //   frame, memcpy the source in, remap writable.
    //
    // Any other protection violation (read/exec fault on a present
    // page, or on a page outside any VMA) falls through to the
    // generic hang path — those are real access-rights bugs.
    if let Some((kind, flags)) = crate::task::current_vma_lookup(addr_u64 as usize) {
        use x86_64::structures::paging::{Page, Size4KiB};
        use x86_64::VirtAddr;
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr_u64));
        let active = x86_64::registers::control::Cr3::read().0;
        let is_write = code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
        let is_prot = code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
        match (kind, is_prot, is_write) {
            (crate::mem::vma::VmaKind::AnonZero, false, _) => {
                match crate::mem::paging::map_in_pml4(active, page, flags) {
                    Ok(_) => return,
                    Err(e) => serial_println!(
                        "#PF anon-zero resolve failed addr={:#x}: {:?}",
                        addr_u64,
                        e
                    ),
                }
            }
            (crate::mem::vma::VmaKind::Cow { frame }, false, _) => {
                // First touch: install the shared source read-only.
                // Strip WRITABLE so the next write triggers the
                // protection-fault path below.
                let ro = flags & !PageTableFlags::WRITABLE;
                match crate::mem::paging::map_existing_in_pml4(active, page, frame, ro) {
                    Ok(()) => return,
                    Err(e) => {
                        serial_println!("#PF cow map-source failed addr={:#x}: {:?}", addr_u64, e)
                    }
                }
            }
            (crate::mem::vma::VmaKind::Cow { frame }, true, true) => {
                match crate::mem::paging::cow_copy_and_remap(active, page, frame, flags) {
                    Ok(_) => return,
                    Err(e) => serial_println!(
                        "#PF cow copy-and-remap failed addr={:#x}: {:?}",
                        addr_u64,
                        e
                    ),
                }
            }
            _ => {}
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
