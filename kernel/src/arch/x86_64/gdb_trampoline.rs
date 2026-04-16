//! Naked asm trampoline for the `#BP` (int3) vector. Captures the full
//! GPR set on entry so `gdbstub` can show accurate register values —
//! the old `extern "x86-interrupt"` handler let the compiler-generated
//! prologue clobber rax..r15 before Rust ran, leaving them as zero.
//!
//! Layout on the kernel stack at trampoline entry (low→high address):
//!   [rsp+0]   RIP  (hw-pushed)
//!   [rsp+8]   CS
//!   [rsp+16]  RFLAGS
//!   [rsp+24]  RSP  (user/kernel rsp at faulting instruction)
//!   [rsp+32]  SS
//!
//! We push all 15 callee-/caller-saved GPRs high→low, so the resulting
//! block at [rsp] reads back as a `SavedRegs` in ascending-address order
//! with rax first. The Rust callee gets pointers to both blocks and
//! mirrors mutations back on resume.

use core::arch::global_asm;

use x86_64::VirtAddr;

/// Saved-register block produced by the trampoline's pushes. Must match
/// the push order in the asm below exactly — struct fields are listed
/// in ascending stack-address order.
#[repr(C)]
struct SavedRegs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
}

/// The CPU-pushed interrupt frame for a non-error-code vector.
#[repr(C)]
struct HwFrame {
    rip: u64,
    cs: u64,
    rflags: u64,
    rsp: u64,
    ss: u64,
}

/// Rust entry called from the trampoline. Returns via normal C ABI; the
/// trampoline's `pop`s + `iretq` resume the interrupted context.
///
/// `saved` points at the 15-u64 GPR block on the trampoline's stack.
/// `frame` points at the hardware-pushed 5-u64 interrupt frame just
/// above that block. Both blocks are live on the current kernel stack
/// and must not outlive this call.
#[no_mangle]
unsafe extern "sysv64" fn gdb_breakpoint_entry(saved: *mut SavedRegs, frame: *mut HwFrame) {
    let s = &mut *saved;
    let f = &mut *frame;

    // Historical int3 semantics unless the stub has been explicitly
    // armed, and user-mode #BP is never diverted into the kernel stub.
    if !crate::gdbstub::is_armed() {
        return;
    }
    if (f.cs & 0b11) != 0 {
        return;
    }

    let mut regs = crate::gdbstub::regs::GdbRegs {
        rax: s.rax,
        rbx: s.rbx,
        rcx: s.rcx,
        rdx: s.rdx,
        rsi: s.rsi,
        rdi: s.rdi,
        rbp: s.rbp,
        rsp: f.rsp,
        r8: s.r8,
        r9: s.r9,
        r10: s.r10,
        r11: s.r11,
        r12: s.r12,
        r13: s.r13,
        r14: s.r14,
        r15: s.r15,
        rip: f.rip,
        eflags: f.rflags as u32,
        cs: f.cs as u32,
        ss: f.ss as u32,
        ..Default::default()
    };

    let mut uart = crate::gdbstub::uart::Com1PollingTransport::new();
    crate::gdbstub::debug_entry_with_regs(&mut uart, &mut regs);

    // Mirror any debugger mutations back into the hardware frame + GPR
    // block so the trampoline's `pop`s and `iretq` resume at the new
    // values.
    s.rax = regs.rax;
    s.rbx = regs.rbx;
    s.rcx = regs.rcx;
    s.rdx = regs.rdx;
    s.rsi = regs.rsi;
    s.rdi = regs.rdi;
    s.rbp = regs.rbp;
    s.r8 = regs.r8;
    s.r9 = regs.r9;
    s.r10 = regs.r10;
    s.r11 = regs.r11;
    s.r12 = regs.r12;
    s.r13 = regs.r13;
    s.r14 = regs.r14;
    s.r15 = regs.r15;
    // Canonical-check rip: a hostile or buggy `G` could send a
    // non-canonical value that would #GP on iretq.
    if let Ok(va) = VirtAddr::try_new(regs.rip) {
        f.rip = va.as_u64();
    }
    f.rflags = regs.eflags as u64;
    // Intentionally not propagating cs/ss/rsp back to the hw frame:
    // changing those without a coordinated task switch is unsound, and
    // gdb rarely asks us to anyway. The stub still accepts the writes
    // into its in-memory snapshot (a subsequent `g` will read them
    // back), so we reply `OK` rather than `E01`.
}

global_asm!(
    ".globl gdb_breakpoint_trampoline",
    ".type  gdb_breakpoint_trampoline, @function",
    "gdb_breakpoint_trampoline:",
    // Push GPRs high→low so rax ends up at the lowest stack address,
    // matching SavedRegs field order.
    "push r15",
    "push r14",
    "push r13",
    "push r12",
    "push r11",
    "push r10",
    "push r9",
    "push r8",
    "push rbp",
    "push rdi",
    "push rsi",
    "push rdx",
    "push rcx",
    "push rbx",
    "push rax",
    // rdi = &SavedRegs (top of our pushes)
    "mov rdi, rsp",
    // rsi = &HwFrame (just above the 15 GPR pushes = 120 bytes)
    "lea rsi, [rsp + 15*8]",
    // Align stack to 16 bytes across the call. System V requires
    // rsp % 16 == 0 at the `call` instruction (call then pushes the
    // 8-byte return address, so inside the callee rsp % 16 == 8).
    // After the 15 GPR pushes (120 bytes) on top of the 5 hw pushes
    // (40 bytes), rsp % 16 == 8 — one 8-byte sub gets us to 0.
    "sub rsp, 8",
    "call gdb_breakpoint_entry",
    "add rsp, 8",
    // Restore in reverse order (low→high).
    "pop rax",
    "pop rbx",
    "pop rcx",
    "pop rdx",
    "pop rsi",
    "pop rdi",
    "pop rbp",
    "pop r8",
    "pop r9",
    "pop r10",
    "pop r11",
    "pop r12",
    "pop r13",
    "pop r14",
    "pop r15",
    "iretq",
    ".size gdb_breakpoint_trampoline, . - gdb_breakpoint_trampoline",
);

extern "C" {
    /// The naked trampoline symbol — the IDT breakpoint vector points
    /// directly at this address via `Entry::set_handler_addr`.
    pub fn gdb_breakpoint_trampoline();
}
