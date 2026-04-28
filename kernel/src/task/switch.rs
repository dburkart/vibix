//! Low-level context switch and the trampoline that bootstraps a fresh
//! task's first run.
//!
//! `context_switch` saves the six System-V AMD64 callee-saved registers
//! (`rbx`, `rbp`, `r12`-`r15`) plus `rsp` of the outgoing task, then
//! loads the incoming task's state symmetrically. That's the entire
//! saved context — caller-saved registers belong to whichever function
//! called into the scheduler (`preempt_tick` or `block_current`) and
//! Rust/LLVM handle them for us.
//!
//! A new task's stack is primed so that the first `context_switch`
//! into it returns into `task_entry_trampoline`, which reads the entry
//! function pointer out of `r12` and calls it.

use core::arch::global_asm;

unsafe extern "C" {
    /// Save the outgoing task's callee-saved regs + rsp into
    /// `*prev_rsp`, then load `next_rsp` and the incoming task's regs,
    /// then load `next_cr3` into CR3.
    ///
    /// The CR3 write happens after the stack swap — kernel task stacks
    /// live in the shared upper half, so the new stack is reachable
    /// through either PML4 and the ordering is symmetric.
    ///
    /// # Safety
    /// - `prev_rsp` must be a valid, aligned, writable `*mut usize`
    ///   pointing at stable storage that outlives this call.
    /// - `next_rsp` must be a valid saved rsp produced either by a
    ///   prior `context_switch` or by `Task::new`'s stack priming.
    /// - `next_cr3` must be the physical address of a PML4 whose upper
    ///   half mirrors the current kernel PML4 (i.e. produced by
    ///   `paging::new_task_pml4` or captured from the kernel PML4
    ///   itself). A PML4 with a stale kernel upper half will fault on
    ///   the next kernel-space access.
    pub fn context_switch(prev_rsp: *mut usize, next_rsp: usize, next_cr3: u64);

    /// First-entry trampoline for a freshly primed task. The entry fn
    /// pointer is passed in `r12`; the trampoline just `call`s it.
    pub fn task_entry_trampoline();

    /// First-entry trampoline for a fork child. Called by `context_switch`
    /// when the child task is first scheduled.
    ///
    /// Stack layout primed by `Task::new_forked` (see
    /// `crate::fork_abi::prime_fork_child_stack`): on entry the
    /// `context_switch` `ret` has already loaded the SysV callee-saved
    /// registers (`rbx`, `rbp`, `r12`–`r15`) directly from the prime
    /// frame, so they already hold the parent's user values. The
    /// remaining 9 user GPRs (rip, rflags, rsp, rdi/rsi/rdx/r10/r8/r9)
    /// sit at `[rsp]..[rsp+0x40]` and this trampoline pops/reads them
    /// before issuing SYSRETQ.
    ///
    /// Returns to ring-3 with rax=0 so the child sees 0 from fork().
    pub fn fork_child_sysret();
}

// On `fork-trace` builds we emit a tiny COM1 poke as the very first
// instructions of `fork_child_sysret` so the captured serial log shows a
// distinct `[C]` marker if (and only if) the child task's kernel stack
// was successfully loaded by `context_switch` and we reached the sysret
// trampoline. This is the one probe that cannot be a `serial_println!`
// call — we are in a hand-written asm trampoline and must not clobber
// the callee-saved registers (r12/rbp/rbx) that hold the SYSRETQ state.
// The poll-TX sequence preserves every register it touches via push/pop;
// rax, rdx, rdi are temporaries that are either about to be clobbered by
// the existing trampoline (rax) or are not used by SYSRETQ (rdx, rdi).
// We still push/pop them defensively so the probe is a strict no-op from
// the user-visible-register perspective.
#[cfg(feature = "fork-trace")]
global_asm!(
    r#"
    .section .text
    .global context_switch
    .global task_entry_trampoline

context_switch:
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    mov cr3, rdx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

task_entry_trampoline:
    sti
    call r12
    ud2

    .global fork_child_sysret
fork_child_sysret:
    // #502 fork-trace probe: poke COM1 with a literal 'C' so the serial
    // log proves the child reached this trampoline. Preserves every
    // register (push/pop) so the subsequent SYSRETQ state is untouched.
    push rax
    push rdx
    push rdi
    // Wait for UART TX-holding-register-empty (LSR.THRE, bit 5 at 0x3FD).
    mov dx, 0x3FD
1:  in  al, dx
    test al, 0x20
    jz  1b
    // Write 'C' (0x43) to COM1 data port (0x3F8).
    mov dx, 0x3F8
    mov al, 0x43
    out dx, al
    // Also emit '\n' (0x0A) so the line appears on its own in the log.
2:  mov dx, 0x3FD
    in  al, dx
    test al, 0x20
    jz  2b
    mov dx, 0x3F8
    mov al, 0x0A
    out dx, al
    pop rdi
    pop rdx
    pop rax
    // Standard fork-child SYSRETQ tail (#690): pop the 9 user GPRs
    // primed below the context_switch frame, then SYSRETQ. rbx/rbp/r12-r15
    // already hold their user values from the context_switch pop sequence.
    pop rcx              // user RIP   → rcx
    pop r11              // user RFLAGS → r11
    // rsp now points at user_rsp slot. Load arg regs via [rsp+N] before
    // we abandon the kernel stack with `pop rsp`.
    mov rdi, [rsp + 8]   // user rdi
    mov rsi, [rsp + 16]  // user rsi
    mov rdx, [rsp + 24]  // user rdx
    mov r10, [rsp + 32]  // user r10
    mov r8,  [rsp + 40]  // user r8
    mov r9,  [rsp + 48]  // user r9
    pop rsp              // user RSP   (last, switches to user stack)
    xor eax, eax         // child fork() return value
    sysretq
"#
);

#[cfg(not(feature = "fork-trace"))]
global_asm!(
    r#"
    .section .text
    .global context_switch
    .global task_entry_trampoline

context_switch:
    // rdi = prev_rsp (*mut usize), rsi = next_rsp (usize), rdx = next_cr3 (u64)
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
    // Load the incoming task's PML4. Non-global kernel mappings are
    // flushed by the CR3 write; we use no PTE_GLOBAL today so this
    // alone is sufficient. New stack is already live; both PML4s agree
    // on upper-half mappings so the ongoing `ret` walk keeps working.
    mov cr3, rdx
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbp
    pop rbx
    ret

task_entry_trampoline:
    // Entry fn pointer was primed into r12. It's `fn() -> !`, so a
    // return here is a bug; `ud2` makes that loud. `sti` first so a
    // task entered for the first time from the preempt ISR (which
    // runs with IF=0 under an interrupt gate) still receives future
    // timer IRQs and can itself be preempted. `sti` when IF is
    // already set is a no-op.
    sti
    call r12
    ud2

    .global fork_child_sysret
fork_child_sysret:
    // Called as the first instruction of a fork child after context_switch
    // loads its primed kernel stack.
    //
    // On entry, context_switch's pop sequence has already loaded the
    // SysV callee-saved registers (rbx, rbp, r12-r15) directly with
    // their final user values from the prime frame. The remaining 9
    // user GPRs are stacked below us at [rsp]..[rsp+0x40] in this order:
    //
    //   [rsp+0x00] user RIP    → rcx (SYSRETQ jumps to rcx)
    //   [rsp+0x08] user RFLAGS → r11 (SYSRETQ restores RFLAGS from r11)
    //   [rsp+0x10] user RSP    → rsp (popped last to keep kernel stack
    //                                  reachable while we load the rest)
    //   [rsp+0x18] user rdi
    //   [rsp+0x20] user rsi
    //   [rsp+0x28] user rdx
    //   [rsp+0x30] user r10
    //   [rsp+0x38] user r8
    //   [rsp+0x40] user r9
    //
    // SYSRETQ: rcx → RIP, r11 → RFLAGS, CS/SS switched to ring-3 selectors.
    //
    // Do NOT sti here: r11 will hold the parent's saved RFLAGS which
    // includes IF=1 (user mode runs with interrupts enabled). SYSRETQ
    // restores RFLAGS from r11, so IF is re-enabled atomically when the CPU
    // transitions to ring-3. An explicit sti before the RSP switch would
    // allow an IRQ to fire with a kernel-mode CS but a user-mode RSP,
    // corrupting the user stack.
    pop rcx              // user RIP
    pop r11              // user RFLAGS (IF=1 → re-enabled by SYSRETQ)
    // rsp now at user_rsp slot; load remaining args via [rsp+N] before
    // pop rsp abandons the kernel stack.
    mov rdi, [rsp + 8]
    mov rsi, [rsp + 16]
    mov rdx, [rsp + 24]
    mov r10, [rsp + 32]
    mov r8,  [rsp + 40]
    mov r9,  [rsp + 48]
    pop rsp              // user RSP — switches to user stack
    xor eax, eax         // child fork() return value
    sysretq
"#
);
