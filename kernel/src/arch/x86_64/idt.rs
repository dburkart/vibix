//! IDT with handlers for the CPU exceptions most likely to actually fire
//! during early boot. Each handler logs to serial then halts — we don't
//! have a panic-unwind story yet, so there's nothing to return to.

use core::sync::atomic::{AtomicBool, Ordering};

use spin::Lazy;
use x86_64::structures::idt::{InterruptDescriptorTable, InterruptStackFrame, PageFaultErrorCode};
use x86_64::structures::paging::PageTableFlags;

use crate::arch::x86_64::gdt::DOUBLE_FAULT_IST_INDEX;
use crate::arch::x86_64::interrupts::{
    keyboard_interrupt, serial_interrupt, timer_interrupt, InterruptIndex,
};
use crate::serial_println;

/// #478 diagnostic latch: the first *unrecoverable* CPL=3 fault of the
/// session logs a `ring3-first-fault:` line with full frame state.
/// Subsequent ring-3 faults are common (SIGSEGV delivery etc.) and
/// must not flood the log. One-shot by design.
///
/// For #PF specifically, the caller MUST wait until the resolution
/// attempt has either succeeded (and returned) or fallen through to a
/// terminal path (panic / hang / SIGSEGV) before invoking this helper:
/// a routine first-touch CoW write fault on a forked user-stack page
/// would otherwise trip the latch on every healthy boot, defeating the
/// nightly-soak gate added for #527 / #646.
static FIRST_RING3_FAULT_LOGGED: AtomicBool = AtomicBool::new(false);

/// Emit one `ring3-first-fault:` line on the first unrecoverable CPL=3
/// fault ever observed. `extra` is vector-specific trailer (e.g.
/// `code=0x0` for #GP, `cr2=0x400000 code=PROTECTION` for #PF) — no user
/// memory is touched while formatting, only scalars copied out of the
/// hardware frame.
fn log_first_ring3_fault(vector: &str, frame: &InterruptStackFrame, extra: core::fmt::Arguments) {
    if (frame.code_segment.0 & 0b11) == 0 {
        return;
    }
    if FIRST_RING3_FAULT_LOGGED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    serial_println!(
        "ring3-first-fault: {} rip={:#x} rsp={:#x} cs={:#x} ss={:#x} rflags={:#x} {}",
        vector,
        frame.instruction_pointer.as_u64(),
        frame.stack_pointer.as_u64(),
        frame.code_segment.0,
        frame.stack_segment.0,
        frame.cpu_flags.bits(),
        extra,
    );
}

static IDT: Lazy<InterruptDescriptorTable> = Lazy::new(|| {
    let mut idt = InterruptDescriptorTable::new();
    idt.divide_error.set_handler_fn(divide_error);
    // Breakpoint (#BP / int3) is wired to a naked asm trampoline so all
    // 15 GPRs are saved before Rust runs — the `x86-interrupt` calling
    // convention otherwise clobbers rax..r15 in the compiler-generated
    // prologue, making the values gdb sees useless. See #482.
    unsafe {
        idt.breakpoint.set_handler_addr(x86_64::VirtAddr::new(
            crate::arch::x86_64::gdb_trampoline::gdb_breakpoint_trampoline as *const () as usize
                as u64,
        ));
    }
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
    log_first_ring3_fault("#UD", &frame, format_args!(""));
    serial_println!("EXCEPTION: #UD (invalid opcode)\n{:#?}", frame);
    hang();
}

extern "x86-interrupt" fn general_protection(frame: InterruptStackFrame, code: u64) {
    log_first_ring3_fault("#GP", &frame, format_args!("code={:#x}", code));
    serial_println!("EXCEPTION: #GP code={:#x}\n{:#?}", code, frame);
    hang();
}

extern "x86-interrupt" fn page_fault(mut frame: InterruptStackFrame, code: PageFaultErrorCode) {
    // Clear RFLAGS.AC immediately so the handler runs with SMAP live,
    // even if we entered mid-`stac` bracket from `uaccess::copy_*`. The
    // IRET at exit restores the saved RFLAGS (and therefore AC) from
    // `frame`, so a legitimate user access inside the bracket retries
    // correctly. The `is_smap_violation` check below still inspects the
    // saved `frame.cpu_flags` AC bit — that's the ring-0 caller's AC,
    // which is what the RFC needs.
    //
    // SAFETY: `clac` is a single-instruction flag clear with no memory
    // effects; it's a no-op on CPUs without SMAP.
    if crate::cpu::has(crate::cpu::Feature::Smap) {
        unsafe { core::arch::asm!("clac", options(nomem, nostack)) };
    }
    // RFC 0007 §Page-fault IRQ discipline, step 1: sample CR2 into a
    // kernel-stack local **before** any path that could re-enable
    // interrupts. A nested fault that fires after `sti` will overwrite
    // CR2 in hardware; once we have `addr_u64` on our stack the value is
    // safe across re-entry. The error `code` parameter is already a
    // hardware-pushed local, so it survives the same way. The pure-logic
    // gates below (SMAP, RSVD, canonical, prot) all run with IRQs still
    // disabled (interrupt gate) — they don't block — and the verdict
    // they produce is the safe seam at which to reopen interrupts before
    // entering the `VmObject::fault` slow path.
    let addr_u64 = x86_64::registers::control::Cr2::read_raw();

    // Defer `log_first_ring3_fault` to the terminal paths below. A
    // first-touch CoW write fault on a forked user-stack page is a
    // routine, fully-resolved event and must not trip the diagnostic
    // latch — otherwise every nightly-soak run trips #527's gate on a
    // healthy boot. Fire the latch only when the fault genuinely could
    // not be resolved (SMAP / RSVD panic, unrecoverable user-mode
    // access violation, or hang fall-through).

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
    let rflags_ac = frame
        .cpu_flags
        .contains(x86_64::registers::rflags::RFlags::ALIGNMENT_CHECK);

    if crate::mem::pf::is_smap_violation(cpl, err_raw, rflags_ac) {
        panic_smap_violation(addr_u64);
    }

    // Pure kernel faults (CPL=0, supervisor page) fall through to the
    // existing handler chain below. Nothing to do here beyond the
    // explicit no-op — the comment documents the RFC's step 2.

    if crate::mem::pf::is_rsvd_fault(err_raw) {
        log_first_ring3_fault(
            "#PF",
            &frame,
            format_args!("cr2={:#x} code={:?}", addr_u64, code),
        );
        panic_rsvd_corruption(addr_u64);
    }

    // Step 4: canonical / USER_VA_END check for user-mode faults. A
    // user fault whose cr2 lands in the kernel half (or non-canonical
    // region) is a SIGSEGV/MAPERR; we don't have signal delivery yet
    // so log and hang with the RFC-mandated marker.
    if cpl != 0 && !crate::mem::pf::is_user_va(addr_u64) {
        log_first_ring3_fault(
            "#PF",
            &frame,
            format_args!("cr2={:#x} code={:?}", addr_u64, code),
        );
        serial_println!(
            "EXCEPTION: #PF user addr={:#x} outside USER_VA_END (MAPERR) code={:?}",
            addr_u64,
            code,
        );
        hang();
    }

    // VMA-backed resolver. Two paths:
    //
    // * Not-present fault inside an installed VMA → call VmObject::fault
    //   to obtain the backing physical frame (allocating lazily if
    //   needed), then map it with the VMA's cached PTE flags.
    //
    // * Write-protection fault on a Private + WRITABLE page → the page
    //   was previously installed read-only (CoW first-touch, set by the
    //   fork path). Fetch the source frame from the VmObject, copy it
    //   into a fresh private frame, and remap writable.
    //
    // Any other protection violation falls through to the generic hang
    // path — those are real access-rights bugs.
    if let Some((object, offset, prot_pte, _share)) =
        crate::task::current_vma_lookup(addr_u64 as usize)
    {
        use crate::mem::vmobject::Access;
        use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};
        use x86_64::{PhysAddr, VirtAddr};

        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(addr_u64));
        let active = x86_64::registers::control::Cr3::read().0;
        let is_write = code.contains(PageFaultErrorCode::CAUSED_BY_WRITE);
        let is_prot = code.contains(PageFaultErrorCode::PROTECTION_VIOLATION);
        let pte_flags = PageTableFlags::from_bits_truncate(prot_pte);

        if !is_prot {
            // Not-present fault: ask the VmObject for the backing frame.
            let access = if is_write {
                Access::Write
            } else {
                Access::Read
            };
            // RFC 0007 §Page-fault IRQ discipline steps 2–4: with the
            // pure-logic verdict already produced under IF=0, reopen
            // interrupts before entering the `VmObject::fault` slow
            // path. `obj.fault` can take a `BlockingMutex` (every
            // `FileObject::fault` does) and would deadlock against any
            // task already holding the same mutex if we left IRQs
            // disabled. Disable them again before the PTE install +
            // TLB flush below so IRET returns to the faulter with a
            // coherent IF=1 / IF=0 state per the saved RFLAGS.
            //
            // SAFETY: `sti` only sets IF in RFLAGS; the page-fault
            // gate is an interrupt gate (the `x86_64` crate's
            // `set_handler_fn` default), so IF was hardware-cleared on
            // entry and the saved `frame.cpu_flags` retains the
            // pre-fault value untouched.
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
            let fault_res = object.fault(offset, access);
            // SAFETY: `cli` only clears IF. We re-disable before the
            // PTE install below so the page-table mutator sees a
            // coherent ring-0/IF=0 environment matching the rest of
            // the kernel paging layer.
            unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
            match fault_res {
                Ok(phys) => {
                    let frame = PhysFrame::from_start_address(PhysAddr::new(phys))
                        .expect("#PF: VmObject returned unaligned phys");
                    match crate::mem::paging::map_existing_in_pml4(active, page, frame, pte_flags) {
                        Ok(()) => return,
                        Err(e) => {
                            // map_existing_in_pml4 failed (OOM allocating page-table
                            // frames). AnonObject::fault already called inc_refcount
                            // for the PTE we won't install; roll it back so the
                            // refcount stays balanced and AddressSpace::drop does not
                            // see a phantom PTE reference.
                            #[cfg(target_os = "none")]
                            crate::mem::refcount::dec_refcount(phys);
                            serial_println!("#PF demand map failed addr={:#x}: {:?}", addr_u64, e)
                        }
                    }
                }
                Err(e) => {
                    serial_println!("#PF VmObject::fault failed addr={:#x}: {:?}", addr_u64, e)
                }
            }
        } else if is_write && pte_flags.contains(PageTableFlags::WRITABLE) {
            // Write-protection fault on a CoW-eligible page: the VMA
            // wants WRITABLE but the PTE was installed read-only by the
            // fork path. `cow_copy_and_remap` copies out of whatever
            // frame the PTE currently points at — the right source in
            // every generation of a nested fork, and robust to the
            // child VMA having an empty `clone_private()` cache.
            //
            // RFC 0007 §Page-fault IRQ discipline: `cow_copy_and_remap`
            // allocates a fresh frame and memcpys 4 KiB — both can
            // contend on the frame allocator's `BlockingMutex`. STI
            // before, CLI after, same as the demand-fault path above.
            //
            // SAFETY: see the demand-fault arm.
            unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
            let cow_res = crate::mem::paging::cow_copy_and_remap(active, page, pte_flags);
            unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
            match cow_res {
                Ok(_) => return,
                Err(e) => serial_println!(
                    "#PF CoW copy-and-remap failed addr={:#x}: {:?}",
                    addr_u64,
                    e
                ),
            }
        }
    }

    // Growsdown stack extension: if the fault address is just below a
    // VMA_GROWSDOWN VMA and within the allowed gap, extend the VMA by one
    // page and install the demand-page frame (same path as a normal miss).
    // Note: grow_stack always installs the VMA at `vma_start - 4096`, not at
    // cr2, so we must map the PTE to that VMA page — not to addr_u64. When
    // cr2 is 2+ pages below vma_start (allowed by the 256-page guard gap),
    // mapping at cr2 would create an orphaned PTE with no VMA backing.
    if let Some((object, offset, prot_pte, new_vma_start)) =
        crate::task::current_growsdown_lookup(addr_u64 as usize)
    {
        use crate::mem::vmobject::Access;
        use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};
        use x86_64::{PhysAddr, VirtAddr};

        let page = Page::<Size4KiB>::from_start_address(VirtAddr::new(new_vma_start as u64))
            .expect("#PF growsdown: new_vma_start not page-aligned");
        let active = x86_64::registers::control::Cr3::read().0;
        let pte_flags = PageTableFlags::from_bits_truncate(prot_pte);
        // RFC 0007 §Page-fault IRQ discipline: same STI/CLI bracket as
        // the demand-fault arm above — `obj.fault` here is the
        // growsdown stack page's filler and may block on the frame
        // allocator's `BlockingMutex`.
        //
        // SAFETY: see the demand-fault arm.
        unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
        let fault_res = object.fault(offset, Access::Write);
        unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
        match fault_res {
            Ok(phys) => {
                let frame = PhysFrame::from_start_address(PhysAddr::new(phys))
                    .expect("#PF growsdown: VmObject returned unaligned phys");
                match crate::mem::paging::map_existing_in_pml4(active, page, frame, pte_flags) {
                    Ok(()) => return,
                    Err(e) => {
                        #[cfg(target_os = "none")]
                        crate::mem::refcount::dec_refcount(phys);
                        serial_println!("#PF growsdown map failed addr={:#x}: {:?}", addr_u64, e)
                    }
                }
            }
            Err(e) => serial_println!(
                "#PF growsdown VmObject::fault failed addr={:#x}: {:?}",
                addr_u64,
                e
            ),
        }
    }

    // Check whether the fault address lands inside a kernel task's guard
    // page — if so, this is a stack overflow, not a generic fault.
    if let Some(slot_idx) = crate::task::find_stack_overflow(addr_u64 as usize) {
        log_first_ring3_fault(
            "#PF",
            &frame,
            format_args!("cr2={:#x} code={:?}", addr_u64, code),
        );
        serial_println!(
            "EXCEPTION: #PF stack overflow slot={} addr={:#x} code={:?}\n{:#?}",
            slot_idx,
            addr_u64,
            code,
            frame
        );
        hang();
    }

    // Ring-3 access violation fall-through: every path above that *could*
    // legitimately resolve a user fault has either returned or fallen
    // through with a diagnostic. A user-mode fault reaching here is an
    // unrecoverable access violation (bad deref, write to a read-only
    // page that isn't CoW-eligible, exec on NX, etc.) — deliver SIGSEGV
    // with DefaultAction::Terminate. The helper calls `task::exit()`, so
    // IRETQ never runs; the scheduler context-switches to the next task.
    if cpl != 0 {
        // Do NOT call `log_first_ring3_fault` here: if the task has installed
        // a SIGSEGV handler, `deliver_fault_signal_iret` rewrites IRETQ to
        // the handler and the fault is *recoverable* — latching this site
        // would re-fire the diagnostic on every signal-handled fault. The
        // unrecoverable `Default`/`Ignore` path inside the signal layer
        // logs its own `signal: terminate` line before calling `exit()`.
        serial_println!(
            "#PF ring-3 access violation addr={:#x} code={:?}",
            addr_u64,
            code,
        );
        // SAFETY: we are in the #PF exception handler for the current task;
        // `frame` is the live hardware-pushed InterruptStackFrame.  Passing
        // `&mut frame` allows deliver_fault_signal_iret to rewrite RIP/RSP
        // if a handler is installed (IRETQ redirects to the handler).  For
        // Default/Ignore, deliver_fault_signal_iret calls task::exit() and
        // never returns — IRETQ does not fire.
        unsafe {
            crate::signal::deliver_fault_signal_iret(crate::signal::SIGSEGV, &mut frame, addr_u64)
        };
        return; // handler path: IRETQ fires the signal handler
    }

    // Kernel-mode (CPL=0) #PF that fell through every recovery path is a
    // genuine kernel bug. The `log_first_ring3_fault` helper is ring-3-only
    // (it short-circuits on CPL=0), so don't bother calling it here — the
    // EXCEPTION line below is the diagnostic of record.
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
    if let Some(slot_idx) = crate::task::find_stack_overflow(faulted_rsp) {
        serial_println!(
            "EXCEPTION: #DF stack overflow slot={} rsp={:#x}\n{:#?}",
            slot_idx,
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
