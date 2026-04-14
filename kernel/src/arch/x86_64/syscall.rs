//! SYSCALL/SYSRET entry gate and ring-3 launch trampoline.
//!
//! ## MSR setup
//!
//! `init()` programs three MSRs:
//! - `IA32_EFER`: sets the SCE (SysCall Enable) bit.
//! - `IA32_STAR`: encodes the kernel CS base (0x0008) and the user CS
//!   base for SYSRETQ (0x0010 → CS=0x20|3, SS=0x18|3 on return).
//! - `IA32_LSTAR`: address of `syscall_entry` — the naked asm trampoline.
//! - `IA32_FMASK`: masks IF, TF, DF, NT, and AC on SYSCALL entry so the
//!   handler always runs with interrupts and single-step disabled, DF=0
//!   (forward-direction string ops), and no stray NTAS/AC bits.
//!
//! ## Kernel stack
//!
//! A static 16 KiB array (`INIT_KERNEL_STACK`) serves two purposes:
//! 1. `TSS.rsp[0]` — used by the CPU when an IRQ or exception fires while
//!    the CPU is at ring-3.
//! 2. The SYSCALL kernel stack — `syscall_entry` switches RSP here before
//!    calling into Rust.
//!
//! On a single-CPU kernel, SFMASK disabling IF for the syscall lifetime
//! prevents re-entrant use of the same stack from a timer IRQ.
//!
//! ## ABI
//!
//! Linux x86_64 syscall ABI (used by the init binary):
//! - `rax` = syscall number
//! - `rdi` = arg0,  `rsi` = arg1,  `rdx` = arg2
//! - CPU saves: `rcx` = user RIP,  `r11` = user RFLAGS
//! - Return: `rax` = return value
//!
//! ## Ring-3 entry
//!
//! `jump_to_ring3(entry, stack_top)` builds an IRETQ frame on the current
//! kernel stack and executes `iretq` to drop privilege.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::registers::model_specific::Msr;

use super::gdt::{set_tss_rsp0, STAR_KERNEL_CS_BASE, STAR_USER_CS_BASE};
use super::gdt::{USER_CODE_SELECTOR, USER_DATA_SELECTOR};

/// MSR addresses.
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_FMASK: u32 = 0xC000_0084;

/// EFER.SCE — enables SYSCALL/SYSRET.
const EFER_SCE: u64 = 1 << 0;

/// RFLAGS bits cleared by SFMASK on SYSCALL entry.
/// TF (bit 8) — trap / single-step
/// IF (bit 9) — interrupts: disabled while handling syscall to prevent
///              IRQ re-use of the shared `INIT_KERNEL_STACK`
/// DF (bit 10) — direction: clear so string instructions run forward
/// NT (bit 14) — nested task: should never be set in 64-bit mode, clear defensively
/// AC (bit 18) — alignment check: clear to avoid spurious faults in handler
const RFLAGS_SYSCALL_MASK: u64 = (1 << 8) | (1 << 9) | (1 << 10) | (1 << 14) | (1 << 18);

/// Dedicated kernel stack for ring-3 privilege changes: IRQs/exceptions
/// (via TSS.rsp[0]) and SYSCALL (via SYSCALL_KERNEL_RSP below).
/// 16 KiB covers the timer-ISR + scheduler stack depth with room to spare.
///
/// Must be `static mut` (not an immutable `static`) so the Rust compiler
/// emits it into `.bss` (writable). An immutable `static` with a const
/// all-zeros initializer goes into `.rodata`, which is mapped read-only;
/// the very first `push` on the stack would then take a write-protection
/// `#PF` and escalate to `#DF`.
#[repr(C, align(16))]
struct AlignedStack([u8; 16 * 1024]);
static mut INIT_KERNEL_STACK: AlignedStack = AlignedStack([0u8; 16 * 1024]);

/// Top of `INIT_KERNEL_STACK`. Written by `setup_ring3_stacks` before
/// ring-3 entry; read by `syscall_entry` (via RIP-relative `lea`) to
/// switch off the user stack onto the dedicated kernel stack.
#[no_mangle]
pub static SYSCALL_KERNEL_RSP: AtomicU64 = AtomicU64::new(0);

/// Single-CPU scratch cell for the user's `r10` register on SYSCALL entry.
///
/// The Linux x86_64 ABI uses `r10` as the 4th syscall argument (flags for
/// `mmap`, etc.) because SYSCALL overwrites `rcx` with the user RIP.  Our
/// entry trampoline must clobber `r10` to temporarily hold the user RSP
/// while switching stacks; it saves the original `r10` here first so the
/// dispatcher can read it back as `a3`.  Safe on single-CPU because no
/// concurrent syscall can be in flight; SMP will need a per-CPU slot.
#[no_mangle]
pub static SYSCALL_A3_SCRATCH: AtomicU64 = AtomicU64::new(0);

/// Enable SYSCALL/SYSRET and point LSTAR at the entry trampoline.
/// Must be called after GDT is live.
pub fn init() {
    let stack_top = stack_top();
    SYSCALL_KERNEL_RSP.store(stack_top, Ordering::Relaxed);

    unsafe {
        // Set EFER.SCE.
        let mut efer = Msr::new(MSR_EFER);
        let cur = efer.read();
        efer.write(cur | EFER_SCE);

        // STAR: [63:48] = user base (0x0010), [47:32] = kernel base (0x0008).
        let star = ((STAR_USER_CS_BASE as u64) << 48) | ((STAR_KERNEL_CS_BASE as u64) << 32);
        Msr::new(MSR_STAR).write(star);

        // LSTAR: syscall entry point.
        let entry_fn: unsafe extern "C" fn() = syscall_entry;
        Msr::new(MSR_LSTAR).write(entry_fn as u64);

        // FMASK: clear TF, IF, DF, NT, AC on syscall entry.
        Msr::new(MSR_FMASK).write(RFLAGS_SYSCALL_MASK);
    }

    crate::serial_println!("syscall: SYSCALL/SYSRET enabled");
}

/// Configure TSS.rsp[0] and `SYSCALL_KERNEL_RSP` before entering ring-3.
/// Call once from the init task trampoline before `jump_to_ring3`.
pub fn setup_ring3_stacks() {
    let top = stack_top();
    SYSCALL_KERNEL_RSP.store(top, Ordering::Relaxed);
    set_tss_rsp0(top);
    crate::serial_println!("syscall: ring-3 kernel stack top={:#x}", top);
}

fn stack_top() -> u64 {
    // SAFETY: we only read the ADDRESS of INIT_KERNEL_STACK (not its
    // contents), which is safe via addr_of!. The addition of the fixed
    // length produces the top-of-stack pointer (stack grows downward).
    let base = core::ptr::addr_of!(INIT_KERNEL_STACK) as u64;
    base + core::mem::size_of::<AlignedStack>() as u64
}

/// Drop to ring-3 at `entry` with user RSP = `stack_top`.
///
/// Builds a 5-word IRETQ frame [SS, RSP, RFLAGS, CS, RIP] on the
/// current kernel stack and executes `iretq`. Never returns.
///
/// # Safety
/// - `entry` must be the ELF entry point of a valid lower-half ELF
///   loaded into the currently-active PML4.
/// - `stack_top` must point to a mapped, writable user-space page.
/// - `setup_ring3_stacks` must have been called so TSS.rsp[0] is valid.
pub unsafe fn jump_to_ring3(entry: u64, stack_top: u64) -> ! {
    core::arch::asm!(
        "push {ss}",      // SS  = user data selector (stack segment)
        "push {sp}",      // RSP = user stack top
        "push 0x202",     // RFLAGS: IF=1, bit-1 reserved=1
        "push {cs}",      // CS  = user code selector
        "push {rip}",     // RIP = user entry point
        "iretq",
        ss  = in(reg) USER_DATA_SELECTOR as u64,
        sp  = in(reg) stack_top,
        cs  = in(reg) USER_CODE_SELECTOR as u64,
        rip = in(reg) entry,
        options(noreturn),
    );
}

use super::uaccess;

/// Syscall handler called from the `syscall_entry` trampoline.
///
/// `a3` and `a4` are the 4th and 5th syscall arguments, supplied by the
/// trampoline from the user's `r10` (saved before it is clobbered) and the
/// user's `r8` respectively.  The 6th argument (`r9` / file offset) is not
/// yet forwarded — it is only meaningful for file-backed `mmap`, which is
/// not implemented in this issue.
///
/// # Safety
/// Called only from `syscall_entry` with the kernel stack active and
/// interrupts disabled. User pointer arguments are validated and
/// marshalled via `uaccess::copy_from_user` before any dereference.
#[no_mangle]
pub unsafe extern "C" fn syscall_dispatch(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
) -> i64 {
    match nr {
        // mmap(addr, len, prot, flags, fd, offset) — anon-private/shared only
        9 => crate::mem::mmap::sys_mmap(a0, a1, a2, a3, a4, 0),
        // mprotect(addr, len, prot)
        10 => crate::mem::mmap::sys_mprotect(a0, a1, a2),
        // munmap(addr, len)
        11 => crate::mem::mmap::sys_munmap(a0, a1),
        // madvise(addr, len, advice)
        28 => crate::mem::mmap::sys_madvise(a0, a1, a2),
        // write(fd, buf, len) — fd=1 (stdout/stderr) → serial
        1 => {
            let fd = a0;
            let buf_va = a1 as usize;
            let len = a2 as usize;
            // Validate the whole `[buf_va, buf_va + len)` range up
            // front regardless of fd, so a kernel-half or wrapping
            // pointer returns -EFAULT even for unsupported fds.
            // Zero-length writes skip the check (no pointer access).
            if len > 0 {
                if let Err(e) = uaccess::check_user_range(buf_va, len) {
                    return e.as_errno();
                }
            }
            if fd == 1 && len > 0 {
                // Chunk through a small kernel-stack bounce buffer so the
                // ring-0 access window stays short and bounded — a single
                // STAC/CLAC bracket per chunk, not per byte.
                let mut chunk = [0u8; 256];
                let mut off = 0;
                while off < len {
                    let n = core::cmp::min(chunk.len(), len - off);
                    match uaccess::copy_from_user(&mut chunk[..n], buf_va + off) {
                        Ok(()) => {}
                        Err(e) => return e.as_errno(),
                    }
                    for &b in &chunk[..n] {
                        uart_putc(b);
                    }
                    off += n;
                }
            }
            len as i64
        }
        // exit(status) — PID 1 calling exit panics the kernel.
        60 => {
            let status = a0 as i32;
            panic!("kernel panic: init exited with status {}", status);
        }
        _ => -38i64, // ENOSYS
    }
}

/// Write one byte to COM1 via port I/O, spinning until the transmitter
/// holding register is empty.
#[inline]
fn uart_putc(b: u8) {
    const COM1_DATA: u16 = 0x3F8;
    const COM1_LSR: u16 = 0x3F8 + 5;
    unsafe {
        // Spin on THRE (bit 5 of LSR).
        loop {
            let lsr: u8;
            core::arch::asm!(
                "in al, dx",
                out("al") lsr,
                in("dx") COM1_LSR,
                options(nomem, nostack, preserves_flags),
            );
            if lsr & 0x20 != 0 {
                break;
            }
        }
        core::arch::asm!(
            "out dx, al",
            in("dx") COM1_DATA,
            in("al") b,
            options(nomem, nostack, preserves_flags),
        );
    }
}

unsafe extern "C" {
    fn syscall_entry();
}

global_asm!(
    r#"
    .section .text
    .global syscall_entry
    .align 16

syscall_entry:
    // On SYSCALL entry (x86_64 Linux ABI):
    //   rax=nr  rdi=a0  rsi=a1  rdx=a2  r10=a3  r8=a4  r9=a5(unused)
    //   rcx=user_RIP  r11=user_RFLAGS  rsp=user_RSP
    // IF is cleared by SFMASK.

    // 1. Preserve user r10 (a3 — flags for mmap etc.) before clobbering
    //    it with user RSP.  Single-CPU scratch; SMP will need per-CPU slot.
    mov [{a3_scratch}], r10

    // 2. Save user RSP in r10, then switch to kernel stack.
    mov r10, rsp
    lea rsp, [rip + {kernel_rsp}]
    mov rsp, [rsp]

    // 3. Save return-to-user context on the kernel stack.
    push r10          // user RSP
    push r11          // user RFLAGS  (SYSRETQ restores RFLAGS from r11)
    push rcx          // user RIP     (SYSRETQ jumps to rcx)

    // 4. Build syscall_dispatch(nr, a0, a1, a2, a3, a4) in SysV AMD64 registers.
    //    Target ABI: rdi=nr, rsi=a0, rdx=a1, rcx=a2, r8=a3, r9=a4.
    //    r8 currently holds user a4 (fd); move it to r9 first so we can
    //    load a3 (flags) into r8 without clobbering a4.
    mov r9, r8                    // r9 = a4 (user fd, was r8)
    mov r8, [{a3_scratch}]        // r8 = a3 (user flags, saved above)
    mov rcx, rdx                  // a2 (prot)
    mov rdx, rsi                  // a1 (len)
    mov rsi, rdi                  // a0 (addr)
    mov rdi, rax                  // nr

    // 5. Call the Rust dispatcher. Align stack to 16 bytes first.
    sub rsp, 8
    call syscall_dispatch
    add rsp, 8
    // rax = return value

    // 6. Restore return-to-user context.
    pop rcx           // user RIP  → rcx  (for SYSRETQ)
    pop r11           // user RFLAGS → r11 (for SYSRETQ)
    pop r10           // user RSP  → r10

    // 7. Restore user RSP and return to ring-3.
    mov rsp, r10
    sysretq
    "#,
    kernel_rsp = sym SYSCALL_KERNEL_RSP,
    a3_scratch  = sym SYSCALL_A3_SCRATCH,
);
