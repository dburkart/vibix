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
    /// `*prev_rsp`, then load `next_rsp` and the incoming task's regs.
    ///
    /// # Safety
    /// - `prev_rsp` must be a valid, aligned, writable `*mut usize`
    ///   pointing at stable storage that outlives this call.
    /// - `next_rsp` must be a valid saved rsp produced either by a
    ///   prior `context_switch` or by `Task::new`'s stack priming.
    pub fn context_switch(prev_rsp: *mut usize, next_rsp: usize);

    /// First-entry trampoline for a freshly primed task. The entry fn
    /// pointer is passed in `r12`; the trampoline just `call`s it.
    pub fn task_entry_trampoline();
}

global_asm!(
    r#"
    .section .text
    .global context_switch
    .global task_entry_trampoline

context_switch:
    // rdi = prev_rsp (*mut usize), rsi = next_rsp (usize)
    push rbx
    push rbp
    push r12
    push r13
    push r14
    push r15
    mov [rdi], rsp
    mov rsp, rsi
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
"#
);
