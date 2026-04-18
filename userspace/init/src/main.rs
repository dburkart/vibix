//! PID 1 init binary — the first userspace process on vibix.
//!
//! Demonstrates the full fork+exec+wait lifecycle:
//! 1. Prints the smoke-test marker "init: hello from pid 1".
//! 2. Calls fork(). The child calls execve() to load the hello binary,
//!    which prints "hello: hello from execed child" and exits(0).
//! 3. The parent calls wait4() to collect the child's exit status, then
//!    prints "init: fork+exec+wait ok" and loops forever.
//!
//! Syscall ABI (Linux x86_64 convention used by the vibix kernel):
//! - rax = syscall number
//! - rdi = arg0,  rsi = arg1,  rdx = arg2,  r10 = arg3
//! - rcx and r11 are clobbered by SYSCALL/SYSRET
//! - Return value in rax
//!
//! ### Kernel-side register clobbers — see issue #531
//!
//! The vibix kernel's SYSCALL trampoline does **not** preserve the user
//! values of `rdi`, `rsi`, `rdx`, `r8`, `r9`, or `r10` across a
//! syscall.  After `syscall_entry` pushes them for restart handling and
//! calls the Rust `syscall_dispatch` (SysV C ABI), the dispatcher is
//! free to use them as scratch; the SYSRETQ path only restores `rcx`
//! and `r11`.  Every syscall block below therefore declares **all**
//! SysV caller-saved GPRs as `inlateout`/`lateout` — missing any of
//! them silently lets the compiler cache dead values across the
//! syscall and produces incorrect behavior (caught in #531 after a
//! loop counter in `r8` never incremented in the repro-fork harness).
//!
//! ## Syscall numbers and argument layout (pinned — do not renumber)
//!
//! These must stay in sync with the `match nr` arms in
//! `kernel/src/arch/x86_64/syscall.rs`.  A mismatch silently breaks
//! this binary (wrong arm executes or -ENOSYS is returned) and will
//! show up as missing smoke markers.  See issue #278.
//!
//! | Number | Name    | rdi          | rsi          | rdx     | r10     |
//! |--------|---------|--------------|--------------|---------|---------|
//! |      1 | write   | fd           | buf ptr      | len     | —       |
//! |     57 | fork    | —            | —            | —       | —       |
//! |     59 | execve  | path (0=ok)  | argv (0=ok)  | envp    | —       |
//! |     60 | exit    | status       | —            | —       | —       |
//! |     61 | wait4   | pid          | *wstatus     | options | *rusage |
//!
//! ### fork() invariants
//! The SYSCALL entry trampoline pushes the caller's user-mode register
//! context (user RIP/RFLAGS/RSP + the six syscall-arg regs) onto the
//! caller's own kernel stack as a `SyscallReturnContext`, and passes a
//! pointer to that struct as the first argument of `syscall_dispatch`.
//! The fork handler reads the parent's user RIP/RFLAGS/RSP straight out
//! of that struct, so the values are per-task by construction — no
//! cross-syscall global state, no races with other CPUs (see issue
//! #504). The child task resumes at the SYSRET return address with
//! rax=0; the parent gets the child PID.
//!
//! ### execve() invariants
//! The kernel ignores path/argv/envp (rdi/rsi/rdx) for now: it loads the
//! second Limine ramdisk module unconditionally.  If no second module is
//! present, execve returns -ENOEXEC.  On success, the call never returns.
//!
//! ### wait4() invariants
//! Blocks on a WaitQueue until a zombie child is reaped.  wstatus is a
//! kernel-mapped userspace pointer; bits 8..15 hold the child's exit code
//! (`(exit_status & 0xFF) << 8`).  Returns the reaped child PID on success,
//! -ECHILD if no children.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

/// Smoke-test marker — asserted by `cargo xtask smoke`.
const HELLO_MSG: &[u8] = b"init: hello from pid 1\n";

/// Emitted after the parent collects the child's exit status.
const DONE_MSG: &[u8] = b"init: fork+exec+wait ok\n";

#[no_mangle]
pub extern "C" fn _start() -> ! {
    write(1, HELLO_MSG);

    // fork() — child PID returned to parent; 0 returned to child.
    let fork_ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 57u64 => fork_ret,
            lateout("rcx") _,
            lateout("rdx") _,
            lateout("rdi") _,
            lateout("rsi") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }

    if fork_ret == 0 {
        // Child: exec the hello binary (execve ignores path/argv/envp,
        // loads userspace_hello.elf from the ramdisk module).
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 59u64 => _,   // execve
                inlateout("rdi") 0u64 => _,    // path (ignored)
                inlateout("rsi") 0u64 => _,    // argv (ignored)
                inlateout("rdx") 0u64 => _,    // envp (ignored)
                lateout("rcx") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );
        }
        // execve only returns on failure — exit with an error code.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 60u64 => _,   // exit
                inlateout("rdi") 1u64 => _,    // status 1 (exec failed)
                lateout("rcx") _,
                lateout("rdx") _,
                lateout("rsi") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r10") _,
                lateout("r11") _,
                options(nostack, preserves_flags),
            );
        }
        loop {
            core::hint::spin_loop();
        }
    }

    // Parent: wait for the child to exit.
    if fork_ret > 0 {
        let child_pid = fork_ret as u64;
        let mut wstatus: i32 = 0;
        let _waited: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") 61u64 => _waited,                         // wait4
                inlateout("rdi") child_pid => _,                            // pid
                inlateout("rsi") &mut wstatus as *mut i32 as u64 => _,      // *wstatus
                inlateout("rdx") 0u64 => _,                                 // options
                inlateout("r10") 0u64 => _,                                 // rusage
                lateout("rcx") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        write(1, DONE_MSG);
    }

    // Loop forever.
    loop {
        core::hint::spin_loop();
    }
}

fn write(fd: u64, buf: &[u8]) {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 1u64 => _,
            inlateout("rdi") fd => _,
            inlateout("rsi") buf.as_ptr() as u64 => _,
            inlateout("rdx") buf.len() as u64 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
