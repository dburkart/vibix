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
    /// when the child task is first scheduled. Callee-saved registers are
    /// primed by `Task::new_forked` with the user-space context:
    ///   r12 = user RIP  (→ rcx for SYSRETQ)
    ///   rbp = user RSP  (→ rsp before SYSRETQ)
    ///   rbx = user RFLAGS (→ r11 for SYSRETQ)
    ///
    /// Returns to ring-3 with rax=0 so the child sees 0 from fork().
    pub fn fork_child_sysret();
}

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
    // Register state set by Task::new_forked priming:
    //   r12 = user RIP   → loaded into rcx for SYSRETQ
    //   rbp = user RSP   → loaded into rsp before SYSRETQ
    //   rbx = user RFLAGS → loaded into r11 for SYSRETQ
    //
    // SYSRETQ: rcx → RIP, r11 → RFLAGS, CS/SS switched to ring-3 selectors.
    //
    // Do NOT sti here: rbx already holds the parent's saved RFLAGS which
    // includes IF=1 (user mode runs with interrupts enabled). SYSRETQ
    // restores RFLAGS from r11, so IF is re-enabled atomically when the CPU
    // transitions to ring-3. An explicit sti before the RSP switch would
    // allow an IRQ to fire with a kernel-mode CS but a user-mode RSP,
    // corrupting the user stack.
    mov rcx, r12      // user RIP
    mov r11, rbx      // user RFLAGS (IF=1 → interrupts re-enabled by SYSRETQ)
    xor eax, eax      // return 0 — fork() child path
    mov rsp, rbp      // restore user RSP (switch stack before SYSRETQ)
    sysretq
"#
);
