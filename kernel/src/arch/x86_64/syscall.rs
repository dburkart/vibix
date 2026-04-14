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

/// Ring-3 RIP saved by the SYSCALL entry trampoline for use by fork().
/// Stashed before argument registers are remapped, so it reflects the
/// exact instruction the parent will resume at after fork() returns.
#[no_mangle]
pub static FORK_USER_RIP: AtomicU64 = AtomicU64::new(0);

/// Ring-3 RFLAGS (saved from r11 by the CPU) for use by fork().
#[no_mangle]
pub static FORK_USER_RFLAGS: AtomicU64 = AtomicU64::new(0);

/// Ring-3 RSP (saved before switching to kernel stack) for use by fork().
#[no_mangle]
pub static FORK_USER_RSP: AtomicU64 = AtomicU64::new(0);

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
/// # Safety
/// Called only from `syscall_entry` with the kernel stack active and
/// interrupts disabled. User pointer arguments are validated and
/// marshalled via `uaccess::copy_from_user` / `copy_to_user` before
/// any dereference.
#[no_mangle]
pub unsafe extern "C" fn syscall_dispatch(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    match nr {
        // read(fd, buf, len) — non-blocking; returns -EAGAIN if no data.
        0 => {
            let fd = a0 as u32;
            let buf_va = a1 as usize;
            let len = a2 as usize;
            if len == 0 {
                return 0;
            }
            if let Err(e) = uaccess::check_user_range(buf_va, len) {
                return e.as_errno();
            }
            // Get the backend without holding the fd-table lock during I/O.
            let backend = {
                let tbl = crate::task::current_fd_table();
                let x = match tbl.lock().get(fd) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                x
            };
            // Read into a kernel bounce buffer, then copy to user.
            let mut chunk = [0u8; 256];
            let n = core::cmp::min(chunk.len(), len);
            match backend.read(&mut chunk[..n]) {
                Ok(nread) => match uaccess::copy_to_user(buf_va, &chunk[..nread]) {
                    Ok(()) => nread as i64,
                    Err(e) => e.as_errno(),
                },
                Err(e) => e,
            }
        }

        // write(fd, buf, len) — routes through the per-process fd table.
        1 => {
            let fd = a0 as u32;
            let buf_va = a1 as usize;
            let len = a2 as usize;
            // Validate user range up front so a bad pointer returns
            // -EFAULT before any observable side-effect.
            if len > 0 {
                if let Err(e) = uaccess::check_user_range(buf_va, len) {
                    return e.as_errno();
                }
            }
            // Get the backend without holding the fd-table lock during I/O.
            let backend = {
                let tbl = crate::task::current_fd_table();
                let x = match tbl.lock().get(fd) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                x
            };
            if len == 0 {
                return 0;
            }
            // Chunk through a small kernel-stack bounce buffer.
            let mut chunk = [0u8; 256];
            let mut written = 0usize;
            while written < len {
                let n = core::cmp::min(chunk.len(), len - written);
                match uaccess::copy_from_user(&mut chunk[..n], buf_va + written) {
                    Ok(()) => {}
                    Err(e) => return e.as_errno(),
                }
                match backend.write(&chunk[..n]) {
                    Ok(nw) => written += nw,
                    Err(e) => return e,
                }
            }
            written as i64
        }

        // open(path, flags, mode) — VFS not yet available; stub.
        2 => -38i64, // ENOSYS

        // close(fd)
        3 => {
            let fd = a0 as u32;
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().close_fd(fd);
            match result {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        // dup(oldfd)
        32 => {
            let oldfd = a0 as u32;
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().dup(oldfd);
            match result {
                Ok(newfd) => newfd as i64,
                Err(e) => e,
            }
        }

        // dup2(oldfd, newfd)
        33 => {
            let oldfd = a0 as u32;
            let newfd = a1 as u32;
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().dup2(oldfd, newfd);
            match result {
                Ok(fd) => fd as i64,
                Err(e) => e,
            }
        }

        // fork() — clone the calling process; parent returns child PID, child returns 0.
        57 => {
            let user_rip = FORK_USER_RIP.load(Ordering::Relaxed);
            let user_rflags = FORK_USER_RFLAGS.load(Ordering::Relaxed);
            let user_rsp = FORK_USER_RSP.load(Ordering::Relaxed);

            let parent_pid = crate::process::current_pid();
            if parent_pid == 0 {
                return -1; // not a registered process
            }

            let child_task_id =
                match crate::task::fork_current_task(user_rip, user_rflags, user_rsp) {
                    Ok(id) => id,
                    Err(_) => return -12, // ENOMEM
                };
            let child_pid = crate::process::register(child_task_id, parent_pid);
            child_pid as i64
        }

        // execve(path, argv, envp) — path and argv/envp are ignored; the
        // kernel loads the `userspace_hello.elf` ramdisk module into the
        // current address space and jumps to ring-3. Never returns on
        // success.
        59 => {
            let elf_bytes = match crate::mem::userspace_hello_elf_bytes() {
                Some(b) => b,
                None => return -8, // ENOEXEC — hello module not present
            };

            // Clear all user VMAs and reset the address space.
            {
                crate::task::current_address_space()
                    .write()
                    .clear_for_exec();
            }

            // Close O_CLOEXEC fds as POSIX requires on exec.
            crate::task::current_fd_table().lock().close_cloexec();

            // Load the new ELF with VMA tracking so AddressSpace::drop can
            // reclaim the data frames when the exec'd process exits. Without
            // VMA entries the leaf frames are orphaned permanently.
            let pml4 = crate::task::current_cr3();
            let aspace = crate::task::current_address_space();
            let image = match crate::mem::loader::load_user_elf_with_vmas(
                elf_bytes,
                pml4,
                &mut aspace.write(),
            ) {
                Ok(img) => img,
                Err(_) => return -8, // ENOEXEC
            };

            // Map a fresh user stack page and register it as a VMA so the
            // exec'd process's stack frame is also reclaimed on exit.
            use crate::mem::vmatree::{Share, Vma};
            use crate::mem::vmobject::{AnonObject, VmObject};
            use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
            use x86_64::VirtAddr;
            let stack_flags = PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::USER_ACCESSIBLE
                | PageTableFlags::NO_EXECUTE;
            let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
                crate::init_process::USER_STACK_PAGE_VA,
            ));
            let stack_frame = crate::mem::paging::map_in_pml4(pml4, stack_page, stack_flags)
                .expect("exec: user stack mapping failed");

            let stack_obj = AnonObject::new(Some(1));
            stack_obj.insert_existing_frame(0, stack_frame.start_address().as_u64());
            let stack_start = crate::init_process::USER_STACK_PAGE_VA as usize;
            let stack_vma = Vma::new(
                stack_start,
                stack_start + 4096,
                0x3,
                stack_flags.bits(),
                Share::Private,
                stack_obj as alloc::sync::Arc<dyn VmObject>,
                0,
            );
            aspace.write().insert(stack_vma);

            // Switch to the new image — never returns.
            unsafe { jump_to_ring3(image.entry.as_u64(), crate::init_process::USER_STACK_TOP) }
        }

        // exit(status) — tear down the process and switch to the next task.
        60 => {
            let status = a0 as i32;
            let pid = crate::process::current_pid();
            if pid != 0 {
                crate::process::reparent_children(pid);
                crate::process::mark_zombie(pid, status);
            }
            crate::task::exit();
        }

        // wait4(pid, *wstatus, options, *rusage) — wait for a child.
        // options and rusage are ignored. `pid < 0` means any child.
        61 => {
            let target_pid = a0 as i32;
            let wstatus_ptr = a1 as usize;
            let parent_pid = crate::process::current_pid();

            if parent_pid == 0 {
                return -10; // ECHILD — not a registered process
            }
            if !crate::process::has_children(parent_pid) {
                return -10; // ECHILD
            }
            // Validate status pointer early (zero means "don't write").
            if wstatus_ptr != 0 {
                if let Err(e) = uaccess::check_user_range(wstatus_ptr, 4) {
                    return e.as_errno();
                }
            }

            // Wait until a zombie child exists or no children remain.
            // Snapshot EXIT_EVENT BEFORE the reap attempt so a child that
            // exits in the gap between reap_child returning None and the
            // wait_while park is not missed: if the event fires before snap
            // is read, the condition (count == snap) is immediately false and
            // wait_while returns at once, letting us loop back to reap.
            loop {
                let snap = crate::process::exit_event_count();
                if let Some((child_pid, exit_status)) =
                    crate::process::reap_child(parent_pid, target_pid)
                {
                    if wstatus_ptr != 0 {
                        // Linux wait4: wstatus = (exit_code & 0xFF) << 8
                        let encoded = ((exit_status & 0xFF) << 8) as u32;
                        let _ = uaccess::copy_to_user(wstatus_ptr, &encoded.to_ne_bytes());
                    }
                    return child_pid as i64;
                }
                if !crate::process::has_children(parent_pid) {
                    return -10; // ECHILD — last child was reaped by another path
                }
                // Park while no new exit event has occurred.
                crate::process::CHILD_WAIT
                    .wait_while(|| crate::process::exit_event_count() == snap);
            }
        }

        _ => -38i64, // ENOSYS
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
    // On SYSCALL entry (x86_64):
    //   rax=nr  rdi=a0  rsi=a1  rdx=a2
    //   rcx=user_RIP  r11=user_RFLAGS  rsp=user_RSP
    // IF is cleared by SFMASK; r10 is caller-saved and unused here.

    // 1. Save user RSP in r10 (caller-saved, not a syscall argument).
    mov r10, rsp

    // 2. Load kernel RSP: lea gives us the address of the static;
    //    the second mov dereferences it to get the stack-top value.
    lea rsp, [rip + {kernel_rsp}]
    mov rsp, [rsp]

    // 3. Save return-to-user context on the kernel stack.
    push r10          // user RSP
    push r11          // user RFLAGS  (SYSRETQ restores RFLAGS from r11)
    push rcx          // user RIP     (SYSRETQ jumps to rcx)

    // 3b. Stash user context in FORK_USER_* statics so fork() can prime
    //     the child's kernel stack. Must happen before rcx is clobbered
    //     in step 4.  r10 is user RSP, r11 is user RFLAGS, rcx is user RIP.
    mov [rip + {fork_rip}], rcx
    mov [rip + {fork_rflags}], r11
    mov [rip + {fork_rsp}], r10

    // 4. Build syscall_dispatch(nr, a0, a1, a2) in SysV AMD64 registers.
    //    rcx is now free (user RIP is on the stack).
    mov rcx, rdx      // a2
    mov rdx, rsi      // a1
    mov rsi, rdi      // a0
    mov rdi, rax      // nr

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
    fork_rip = sym FORK_USER_RIP,
    fork_rflags = sym FORK_USER_RFLAGS,
    fork_rsp = sym FORK_USER_RSP,
);
