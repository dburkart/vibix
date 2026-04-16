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

/// Set to 1 by `sys_sigreturn` to tell `check_and_deliver_signals` to
/// overwrite the saved user context with the restored register values
/// rather than pushing a new signal frame.  Cleared after consumption.
#[no_mangle]
pub static SIGRETURN_PENDING: AtomicU64 = AtomicU64::new(0);

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
/// Takes the six Linux x86_64 syscall argument registers. Handlers
/// that only need fewer args simply ignore the extras.
///
/// # Safety
/// Called only from `syscall_entry` with the kernel stack active and
/// interrupts disabled. User pointer arguments are validated and
/// marshalled via `uaccess::copy_from_user` / `copy_to_user` before
/// any dereference.
#[no_mangle]
pub unsafe extern "C" fn syscall_dispatch(
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
) -> i64 {
    use syscall_nr::*;
    match nr {
        // read(fd, buf, len) — non-blocking; returns -EAGAIN if no data.
        READ => {
            let fd = a0 as u32;
            let buf_va = a1 as usize;
            let len = a2 as usize;
            // Validate the fd BEFORE checking len==0: POSIX requires
            // read(invalid_fd, buf, 0) to return EBADF, not 0.
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
            if let Err(e) = uaccess::check_user_range(buf_va, len) {
                return e.as_errno();
            }
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
        WRITE => {
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
                    Ok(0) => {
                        // Short-write / end-of-stream: return however many
                        // bytes we've written so far rather than looping
                        // forever. (A backend that always returns Ok(0) for
                        // non-empty input would loop indefinitely otherwise.)
                        break;
                    }
                    Ok(nw) => written += nw,
                    Err(e) => return e,
                }
            }
            written as i64
        }

        // open(path, flags, mode) — VFS-backed; see `sys_open`.
        OPEN => sys_open(a0, a1, a2),

        // stat(path, *statbuf) — follow symlinks, then write `struct stat`.
        4 => super::syscalls::vfs::sys_stat_impl(a0, a1, /* nofollow */ false),

        // fstat(fd, *statbuf)
        5 => super::syscalls::vfs::sys_fstat_impl(a0, a1),

        // lstat(path, *statbuf) — like stat but don't follow a final symlink.
        6 => super::syscalls::vfs::sys_stat_impl(a0, a1, /* nofollow */ true),

        // openat(dfd, path, flags, mode)
        257 => super::syscalls::vfs::sys_openat_impl(a0 as i32, a1, a2, a3),

        // newfstatat(dfd, path, *statbuf, flags)
        262 => super::syscalls::vfs::sys_newfstatat_impl(a0 as i32, a1, a2, a3 as u32),

        // getcwd(buf, len) — copy cwd absolute path to user buffer.
        GETCWD => super::syscalls::vfs::sys_getcwd(a0, a1),

        // chdir(path) — set the per-process current working directory.
        CHDIR => super::syscalls::vfs::sys_chdir(a0),

        // mmap(addr, len, prot, flags, fd, off) — anon-private and
        // anon-shared with full MAP_FIXED / MAP_GROWSDOWN support. See
        // `sys_mmap` for full validation.
        MMAP => sys_mmap(a0, a1, a2, a3, a4, a5),

        // mprotect(addr, len, prot)
        MPROTECT => sys_mprotect(a0, a1, a2),

        // munmap(addr, len)
        MUNMAP => sys_munmap(a0, a1),

        // madvise(addr, len, advice)
        MADVISE => sys_madvise(a0, a1, a2),

        // close(fd)
        CLOSE => {
            let fd = a0 as u32;
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().close_fd(fd);
            match result {
                Ok(()) => 0,
                Err(e) => e,
            }
        }

        // dup(oldfd)
        DUP => {
            let oldfd = a0 as i32;
            if oldfd < 0 {
                return crate::fs::EBADF;
            }
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().dup(oldfd as u32);
            match result {
                Ok(newfd) => newfd as i64,
                Err(e) => e,
            }
        }

        // lseek(fd, offset, whence) — reposition the shared open-file offset.
        //   whence: SEEK_SET=0, SEEK_CUR=1, SEEK_END=2.
        // Returns the new absolute offset on success, or a negated errno
        // (EBADF, EINVAL, ESPIPE, EOVERFLOW).
        LSEEK => {
            let fd = a0 as u32;
            let off = a1 as i64;
            let whence = a2 as i32;
            let backend = {
                let tbl = crate::task::current_fd_table();
                let x = match tbl.lock().get(fd) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                x
            };
            match backend.lseek(off, whence) {
                Ok(n) => n,
                Err(e) => e,
            }
        }

        // getdents64(fd, buf, len) — read directory entries into a
        // user buffer as packed `linux_dirent64` records. Advances the
        // shared open-file offset (the per-open cookie) by however many
        // entries were written. Returns bytes written, 0 at end-of-dir,
        // or a negated errno (EBADF, EFAULT, ENOTDIR, EINVAL).
        GETDENTS64 => {
            let fd = a0 as u32;
            let buf_va = a1 as usize;
            let len = a2 as usize;
            let backend = {
                let tbl = crate::task::current_fd_table();
                let x = match tbl.lock().get(fd) {
                    Ok(b) => b,
                    Err(e) => return e,
                };
                x
            };
            if len == 0 {
                return crate::fs::EINVAL;
            }
            if let Err(e) = uaccess::check_user_range(buf_va, len) {
                return e.as_errno();
            }
            // Kernel bounce buffer bounded by a fixed cap, matching Linux's
            // per-call ceiling. Userspace that needs more than a page of
            // dirents simply calls getdents64 again.
            let mut chunk = [0u8; 4096];
            let n = core::cmp::min(chunk.len(), len);
            match backend.getdents64(&mut chunk[..n]) {
                Ok(nw) => match uaccess::copy_to_user(buf_va, &chunk[..nw]) {
                    Ok(()) => nw as i64,
                    Err(e) => e.as_errno(),
                },
                Err(e) => e,
            }
        }

        // fcntl(fd, cmd, arg) — per-fd status / close-on-exec / dup-above.
        // Returns cmd-specific value on success, negated errno on error.
        FCNTL => {
            let fd = a0 as u32;
            let cmd = a1 as u32;
            let arg = a2;
            let tbl = crate::task::current_fd_table();
            let mut guard = tbl.lock();
            match cmd {
                crate::fs::F_GETFD => match guard.get_fd_flags(fd) {
                    Ok(v) => v as i64,
                    Err(e) => e,
                },
                crate::fs::F_SETFD => match guard.set_fd_flags(fd, arg as u32) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                crate::fs::F_GETFL => match guard.get_status_flags(fd) {
                    Ok(v) => v as i64,
                    Err(e) => e,
                },
                crate::fs::F_SETFL => match guard.set_status_flags(fd, arg as u32) {
                    Ok(()) => 0,
                    Err(e) => e,
                },
                crate::fs::F_DUPFD => match guard.dupfd_from(fd, arg as u32, false) {
                    Ok(new_fd) => new_fd as i64,
                    Err(e) => e,
                },
                crate::fs::F_DUPFD_CLOEXEC => match guard.dupfd_from(fd, arg as u32, true) {
                    Ok(new_fd) => new_fd as i64,
                    Err(e) => e,
                },
                _ => crate::fs::EINVAL,
            }
        }

        // dup2(oldfd, newfd)
        DUP2 => {
            let oldfd = a0 as i32;
            let newfd = a1 as i32;
            if oldfd < 0 || newfd < 0 {
                return crate::fs::EBADF;
            }
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().dup2(oldfd as u32, newfd as u32);
            match result {
                Ok(fd) => fd as i64,
                Err(e) => e,
            }
        }

        // dup3(oldfd, newfd, flags) — like dup2 but returns EINVAL if
        // oldfd == newfd and accepts an O_CLOEXEC flag for the new fd.
        DUP3 => {
            let oldfd = a0 as i32;
            let newfd = a1 as i32;
            let flags = a2 as u32;
            if oldfd < 0 || newfd < 0 {
                return crate::fs::EBADF;
            }
            let tbl = crate::task::current_fd_table();
            let result = tbl.lock().dup3(oldfd as u32, newfd as u32, flags);
            match result {
                Ok(fd) => fd as i64,
                Err(e) => e,
            }
        }

        // brk(addr) — set the program break; returns the new break on success
        // or the current (unchanged) break on failure.
        BRK => {
            let addr = a0;
            crate::task::current_address_space().write().sys_brk(addr) as i64
        }

        // fork() — clone the calling process; parent returns child PID, child returns 0.
        FORK => {
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
        // kernel loads the `userspace_hello.elf` ramdisk module into a
        // freshly-staged address space and atomically swaps it in on
        // success. On failure the old address space is preserved so the
        // caller continues running and observes the `-ENOEXEC` return.
        EXECVE => {
            let elf_bytes = match crate::mem::userspace_hello_elf_bytes() {
                Some(b) => b,
                None => return -8, // ENOEXEC — hello module not present
            };
            match exec_atomic(elf_bytes) {
                Ok(never) => match never {},
                Err(e) => e,
            }
        }

        // exit(status) — tear down the process and switch to the next task.
        EXIT => {
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
        WAIT4 => {
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

        // sigaction(sig, act, oldact) — register or query signal handler.
        SIGACTION => crate::signal::sys_sigaction(a0, a1, a2),

        // sigprocmask(how, set, oldset) — update signal mask.
        SIGPROCMASK => crate::signal::sys_sigprocmask(a0, a1, a2),

        // sigreturn() — restore context from signal frame.
        // The user RSP at syscall entry (saved by the trampoline in
        // FORK_USER_RSP) points at the SigFrame on the user stack.
        // We restore the saved [rip, rflags, rsp] and stash them in
        // FORK_USER_* so check_and_deliver_signals can apply them to
        // the kernel-stack-saved context before SYSRETQ.
        SIGRETURN => {
            let user_rsp = FORK_USER_RSP.load(Ordering::Relaxed);
            let restored = crate::signal::sys_sigreturn(user_rsp);
            FORK_USER_RIP.store(restored.rip, Ordering::Relaxed);
            FORK_USER_RFLAGS.store(restored.rflags, Ordering::Relaxed);
            FORK_USER_RSP.store(restored.rsp, Ordering::Relaxed);
            SIGRETURN_PENDING.store(1, Ordering::Relaxed);
            0i64
        }

        // kill(pid, sig) — send signal to process.
        KILL => crate::signal::sys_kill(a0, a1),

        // ioctl(fd, cmd, arg) — device-specific control. Only the tty-like
        // `SerialBackend` handles non-trivial `cmd`s today; all other
        // backends inherit the `-ENOTTY` default.
        IOCTL => super::syscalls::ioctl::sys_ioctl(a0, a1 as u32, a2 as usize),

        // pipe(pipefd) — create anonymous pipe; fds[0]=read, fds[1]=write.
        PIPE => crate::ipc::pipe::sys_pipe(a0),

        // pipe2(pipefd, flags) — like pipe() but with O_NONBLOCK/O_CLOEXEC.
        PIPE2 => crate::ipc::pipe::sys_pipe2(a0, a1 as u32),

        // mknod(path, mode, dev) — create a FIFO or regular file.
        MKNOD => super::syscalls::vfs::sys_mknod_impl(a0, a1, a2),

        // mknodat(dfd, path, mode, dev) — like mknod relative to dfd.
        MKNODAT => super::syscalls::vfs::sys_mknodat_impl(a0 as i32, a1, a2, a3),

        // poll(fds, nfds, timeout_ms) — wait for readiness on a set of fds.
        POLL => crate::poll::syscalls::sys_poll(a0, a1, a2 as i64),

        // ppoll(fds, nfds, tmo_p, sigmask) — like poll() with timespec.
        PPOLL => crate::poll::syscalls::sys_ppoll(a0, a1, a2, a3),

        // select(nfds, readfds, writefds, exceptfds, timeout).
        SELECT => crate::poll::syscalls::sys_select(a0, a1, a2, a3, a4),

        // pselect6(nfds, readfds, writefds, exceptfds, ts, sigmask).
        PSELECT6 => crate::poll::syscalls::sys_pselect6(a0, a1, a2, a3, a4, a5),

        // setsid() — create a new session with the caller as leader.
        SETSID => crate::process::sys_setsid(),

        // getsid(pid) — return the session id of `pid`, or the caller's
        // session when pid==0.
        GETSID => crate::process::sys_getsid(a0 as u32),

        // setpgid(pid, pgid) — move `pid` into process group `pgid`.
        SETPGID => crate::process::sys_setpgid(a0 as u32, a1 as u32),

        // getpgid(pid) — return the pgrp id of `pid`, or the caller's
        // pgrp when pid==0.
        GETPGID => crate::process::sys_getpgid(a0 as u32),

        _ => -38i64, // ENOSYS
    }
}

/// Atomic execve body: stage the new image into a fresh `AddressSpace`
/// and only commit it once the load has fully succeeded.
///
/// Returns `Err(-ENOEXEC)` (or `-ENOMEM`) on failure, leaving the
/// caller's address space untouched so the syscall return lands on
/// still-valid user code. Returns `Ok(_)` only by way of `jump_to_ring3`,
/// which never returns; the `Infallible` ok variant lets the caller
/// match exhaustively without a panic-on-unreachable arm.
///
/// The atomicity story: the new `AddressSpace` is built top-to-bottom
/// in a separate PML4 (own `try_new_empty`). If anything before the
/// CR3 swap fails, dropping the staged `AddressSpace` reclaims its
/// PML4 + intermediate page tables. (Leaf data frames mapped by a
/// partially-completed `load_user_elf` aren't tracked by the staged
/// VMA list yet, so they leak on early-segment failure — small and
/// bounded by ELF size; tracked separately as a follow-up.)
#[cfg(target_os = "none")]
pub fn exec_atomic(elf_bytes: &[u8]) -> Result<core::convert::Infallible, i64> {
    use crate::mem::addrspace::AddressSpace;
    use crate::mem::vmatree::{Share, Vma};
    use crate::mem::vmobject::{AnonObject, VmObject};
    use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
    use x86_64::VirtAddr;

    // 1. Build a fresh AddressSpace with its own PML4.
    let mut new_aspace = AddressSpace::try_new_empty().map_err(|_| -12i64)?;
    let new_pml4 = new_aspace.page_table_frame();

    // 2. Load the ELF into the new PML4 with VMA tracking. On Err the
    //    staged AddressSpace drops at the `?` boundary, freeing its
    //    page tables; the caller's address space is untouched.
    let image = crate::mem::loader::load_user_elf_with_vmas(elf_bytes, new_pml4, &mut new_aspace)
        .map_err(|_| -8i64)?;

    new_aspace.set_brk_start(VirtAddr::new(image.image_end));

    // 3. Map and register the user stack page in the staged space.
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(
        crate::init_process::USER_STACK_PAGE_VA,
    ));
    let stack_frame =
        crate::mem::paging::map_in_pml4(new_pml4, stack_page, stack_flags).map_err(|_| -12i64)?;

    let stack_obj = AnonObject::new(Some(1));
    stack_obj
        .insert_existing_frame(0, stack_frame.start_address().as_u64())
        .expect("execve: freshly-mapped user stack frame cannot be saturated");
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
    new_aspace.insert(stack_vma);

    // 4. Commit. After this point we cannot fail back to the caller —
    //    the old address space is still alive on the task until we
    //    write CR3 and drop the returned Arc.
    crate::task::current_fd_table().lock().close_cloexec();
    let new_aspace_arc = alloc::sync::Arc::new(spin::RwLock::new(new_aspace));
    let old_aspace = crate::task::replace_current_address_space(new_aspace_arc, new_pml4);

    unsafe {
        x86_64::registers::control::Cr3::write(
            new_pml4,
            x86_64::registers::control::Cr3Flags::empty(),
        );
    }
    // Now safe to release the old PML4 + its frames.
    drop(old_aspace);

    // Write the System V AMD64 initial stack layout (argc/argv/envp/auxv) into
    // the new stack frame via the HHDM window, matching what init_process does.
    // AT_RANDOM comes from RDRAND/RDSEED; falls back to an insecure XOR-splat
    // with a warning if the CPU supports neither.
    let stack_phys = stack_frame.start_address().as_u64();
    let random_bytes = match super::csprng::rdrand16() {
        Some(b) => b,
        None => {
            crate::serial_println!(
                "exec: WARNING — RDRAND/RDSEED unavailable, AT_RANDOM is deterministic"
            );
            super::csprng::deterministic_at_random_fallback(image.entry.as_u64() ^ stack_phys)
        }
    };
    let auxv_params = crate::mem::auxv::AuxvParams {
        entry: image.entry.as_u64(),
        interp_base: image.interp_base.unwrap_or(0),
        phdr_vaddr: image.phdr_vaddr,
        phdr_count: image.phdr_count as u64,
        phdr_entsize: image.phdr_entsize as u64,
    };
    let initial_rsp = crate::mem::auxv::write_initial_stack(
        stack_phys,
        crate::init_process::USER_STACK_PAGE_VA,
        &auxv_params,
        &random_bytes,
    );

    // If the binary has a dynamic interpreter (PT_INTERP), jump to the
    // interpreter's entry point; otherwise jump directly to the binary's entry.
    let effective_entry = image.interp_entry.unwrap_or(image.entry);
    // Never returns.
    unsafe { jump_to_ring3(effective_entry.as_u64(), initial_rsp) }
}

/// Public wrapper around `copy_path_from_user` for use by the VFS
/// syscall handlers in `super::syscalls::vfs`. Keeping one copy-in
/// implementation guarantees every path syscall uses identical
/// validation (user-range bound, NUL-termination, `ENAMETOOLONG`).
pub(super) unsafe fn copy_path_from_user_pub(uva: usize, buf: &mut [u8]) -> Result<usize, i64> {
    copy_path_from_user(uva, buf)
}

/// Copy a NUL-terminated path from user VA `uva` into `buf`. Returns
/// the slice (without the NUL) on success, or a negative errno on
/// failure. Mirrors Linux `strncpy_from_user` semantics: short path →
/// truncated slice; missing NUL within `buf` → `-ENAMETOOLONG`.
unsafe fn copy_path_from_user(uva: usize, buf: &mut [u8]) -> Result<usize, i64> {
    if buf.is_empty() {
        return Err(crate::fs::ENAMETOOLONG);
    }
    // Validate the full candidate range up front; then copy byte-by-byte
    // until we hit a NUL. Going byte-by-byte keeps the bound tight — a
    // short path backed by one page doesn't get rejected because the
    // full `OPEN_PATH_MAX` would overflow into an unmapped page.
    for (i, slot) in buf.iter_mut().enumerate() {
        match uaccess::copy_from_user(core::slice::from_mut(slot), uva + i) {
            Ok(()) => {}
            Err(e) => return Err(e.as_errno()),
        }
        if *slot == 0 {
            return Ok(i);
        }
    }
    Err(crate::fs::ENAMETOOLONG)
}

/// `open(path, flags, mode)` — VFS-backed `open`.
///
/// Equivalent to `openat(AT_FDCWD, path, flags, mode)`. Delegates to
/// [`crate::arch::x86_64::syscalls::vfs::sys_openat_impl`]; see that
/// function for the full semantics including the `/dev/{stdin,stdout,
/// stderr,serial}` legacy-compat fallback for callers that open before
/// `/dev/serial` has been wired into devfs.
unsafe fn sys_open(path_uva: u64, flags: u64, mode: u64) -> i64 {
    super::syscalls::vfs::sys_openat_impl(super::syscalls::vfs::AT_FDCWD, path_uva, flags, mode)
}

/// Build `prot_pte` from user-visible `prot_user` bits. `PROT_WRITE`
/// without `PROT_READ` installs `R|W` because x86 cannot separate the
/// two; `prot_user` preserves the original request.
fn prot_pte_from_prot_user(prot: u32) -> u64 {
    use crate::mem::pf::{PROT_EXEC, PROT_WRITE};
    use x86_64::structures::paging::PageTableFlags;
    let mut pte = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if prot & PROT_WRITE != 0 {
        pte |= PageTableFlags::WRITABLE;
    }
    if prot & PROT_EXEC == 0 {
        pte |= PageTableFlags::NO_EXECUTE;
    }
    pte.bits()
}

/// `mmap(addr, len, prot, flags, fd, off)` — anon-private + anon-shared.
///
/// Supports `MAP_PRIVATE` / `MAP_SHARED` (mutually exclusive) with
/// `MAP_ANONYMOUS`; honours `MAP_FIXED`, `MAP_FIXED_NOREPLACE`,
/// `MAP_GROWSDOWN`, and `MAP_STACK`. `fd != -1` returns `-ENODEV`
/// (file-backed path not implemented). Validation follows RFC 0001.
unsafe fn sys_mmap(addr: u64, len: u64, prot: u64, flags: u64, fd: u64, off: u64) -> i64 {
    use crate::fs::{EEXIST, EINVAL, ENODEV, ENOMEM};
    use crate::mem::pf::{
        validate_user_range, AddrAlign, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE,
        MAP_GROWSDOWN, MAP_PRIVATE, MAP_SHARED, MAP_STACK, PROT_EXEC, PROT_READ, PROT_WRITE,
    };
    use crate::mem::vmatree::{Share, Vma, VMA_GROWSDOWN};
    use crate::mem::vmobject::{AnonObject, VmObject};
    use alloc::sync::Arc;

    let flags = flags as u32;
    let prot = prot as u32;

    // Reject unknown prot bits.
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return EINVAL;
    }

    // File-backed path not implemented — Linux returns ENODEV for
    // "file type not supported by mmap", matching RFC 0001.
    if fd as i64 != -1 {
        return ENODEV;
    }
    if off != 0 {
        return EINVAL;
    }

    // Every supported bit must be one of the RFC set.
    let known = MAP_SHARED
        | MAP_PRIVATE
        | MAP_FIXED
        | MAP_FIXED_NOREPLACE
        | MAP_ANONYMOUS
        | MAP_GROWSDOWN
        | MAP_STACK;
    if flags & !known != 0 {
        return EINVAL;
    }

    // Anonymous-only for now.
    if flags & MAP_ANONYMOUS == 0 {
        return ENODEV;
    }

    // Exactly one of MAP_PRIVATE / MAP_SHARED must be set.
    let priv_bit = flags & MAP_PRIVATE != 0;
    let shared_bit = flags & MAP_SHARED != 0;
    if priv_bit == shared_bit {
        return EINVAL;
    }
    let share = if priv_bit {
        Share::Private
    } else {
        Share::Shared
    };

    // MAP_FIXED_NOREPLACE implies MAP_FIXED semantics for address handling.
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;

    // Validate the range: fixed → exact alignment required, hint → round down.
    let align = if fixed {
        AddrAlign::Exact
    } else {
        AddrAlign::RoundDown
    };
    let range = match validate_user_range(addr, len, align) {
        Ok(r) => r,
        Err(_) => return EINVAL,
    };

    let aspace = crate::task::current_address_space();
    let mut guard = aspace.write();

    let start = if fixed {
        if flags & MAP_FIXED_NOREPLACE != 0 && guard.range_overlaps_any(range.addr, range.len) {
            return EEXIST;
        }
        // Bare MAP_FIXED: evict any overlap so the new mapping can land.
        if flags & MAP_FIXED_NOREPLACE == 0 {
            guard.sys_munmap_range(range.addr, range.addr + range.len);
        }
        range.addr
    } else {
        match guard.find_unmapped_region(range.len) {
            Some(s) => s,
            None => return ENOMEM,
        }
    };

    let pte_bits = prot_pte_from_prot_user(prot);
    let pages = range.len / 4096;
    let obj = AnonObject::new(Some(pages));

    let mut vma = Vma::new(
        start,
        start + range.len,
        prot,
        pte_bits,
        share,
        obj as Arc<dyn VmObject>,
        0,
    );
    if flags & MAP_GROWSDOWN != 0 {
        vma.vma_flags |= VMA_GROWSDOWN;
    }
    guard.insert(vma);
    start as i64
}

/// `munmap(addr, len)` — POSIX-conformant: returns 0 on success and on
/// holes (partly-or-wholly unmapped ranges). `-EINVAL` only for the
/// validation failures in RFC 0001.
unsafe fn sys_munmap(addr: u64, len: u64) -> i64 {
    use crate::fs::EINVAL;
    use crate::mem::pf::{validate_user_range, AddrAlign};

    let range = match validate_user_range(addr, len, AddrAlign::Exact) {
        Ok(r) => r,
        Err(_) => return EINVAL,
    };

    let aspace = crate::task::current_address_space();
    let mut guard = aspace.write();
    guard.sys_munmap_range(range.addr, range.addr + range.len);
    0
}

/// `mprotect(addr, len, prot)` — Linux `mprotect_fixup` semantics.
/// `-EINVAL` on validation failure or unknown PROT bits; `-ENOMEM` only
/// when a sub-page of `[addr, addr+len)` is literally unmapped.
unsafe fn sys_mprotect(addr: u64, len: u64, prot: u64) -> i64 {
    use crate::fs::{EINVAL, ENOMEM};
    use crate::mem::pf::{validate_user_range, AddrAlign, PROT_EXEC, PROT_READ, PROT_WRITE};

    let prot = prot as u32;
    if prot & !(PROT_READ | PROT_WRITE | PROT_EXEC) != 0 {
        return EINVAL;
    }

    let range = match validate_user_range(addr, len, AddrAlign::Exact) {
        Ok(r) => r,
        Err(_) => return EINVAL,
    };

    let aspace = crate::task::current_address_space();
    let mut guard = aspace.write();

    if !guard.range_fully_covered(range.addr, range.len) {
        return ENOMEM;
    }

    let pte_bits = prot_pte_from_prot_user(prot);
    guard.sys_mprotect_range(range.addr, range.addr + range.len, prot, pte_bits);
    0
}

/// `madvise(addr, len, advice)`. `MADV_DONTNEED` on `MAP_PRIVATE |
/// MAP_ANONYMOUS` drops the covered PTEs and evicts the backing
/// `AnonObject`'s cached frames. Every other recognised advice value is
/// accepted as a no-op; unknown advice returns `-EINVAL`.
unsafe fn sys_madvise(addr: u64, len: u64, advice: u64) -> i64 {
    use crate::fs::EINVAL;
    use crate::mem::pf::{
        validate_user_range, AddrAlign, MADV_DONTNEED, MADV_FREE, MADV_NORMAL, MADV_RANDOM,
        MADV_SEQUENTIAL, MADV_WILLNEED,
    };

    let range = match validate_user_range(addr, len, AddrAlign::Exact) {
        Ok(r) => r,
        Err(_) => return EINVAL,
    };

    let advice = advice as i32;
    match advice {
        MADV_DONTNEED => {
            let aspace = crate::task::current_address_space();
            let mut guard = aspace.write();
            guard.sys_madvise_dontneed(range.addr, range.addr + range.len);
            0
        }
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED | MADV_FREE => 0,
        _ => EINVAL,
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
    //   rax=nr  rdi=a0  rsi=a1  rdx=a2  r10=a3  r8=a4  r9=a5
    //   rcx=user_RIP  r11=user_RFLAGS  rsp=user_RSP
    // IF is cleared by SFMASK. Every GP register that isn't rsp is
    // load-bearing: all Linux syscall args or SYSRETQ state.

    // 1. Stash user RSP straight into fork_rsp so we don't need a
    //    scratch register — r10 is the Linux syscall ABI's `a3` and
    //    must not be clobbered.
    mov [rip + {fork_rsp}], rsp

    // 2. Load kernel RSP: lea gives us the address of the static;
    //    the second mov dereferences it to get the stack-top value.
    lea rsp, [rip + {kernel_rsp}]
    mov rsp, [rsp]

    // 3. Save return-to-user context on the kernel stack.
    push [rip + {fork_rsp}]   // user RSP (already stashed above)
    push r11                  // user RFLAGS (SYSRETQ restores from r11)
    push rcx                  // user RIP    (SYSRETQ jumps to rcx)

    // 3b. Finish priming the FORK_USER_* statics so fork() can seed the
    //     child's kernel stack. fork_rsp was already written in step 1.
    mov [rip + {fork_rip}], rcx
    mov [rip + {fork_rflags}], r11

    // 4. Build syscall_dispatch(nr, a0, a1, a2, a3, a4, a5) in SysV AMD64
    //    registers. Linux syscall ABI:  rax=nr  rdi=a0 rsi=a1 rdx=a2
    //                                   r10=a3  r8=a4  r9=a5
    //    SysV C ABI (7 int args):       rdi=arg0 rsi=arg1 rdx=arg2
    //                                   rcx=arg3 r8=arg4  r9=arg5
    //                                   [rsp]=arg6 (passed on the stack)
    //
    //    Mapping (nr, a0..a5) → (arg0..arg6):
    //      nr:  rax → rdi   (arg0)
    //      a0:  rdi → rsi   (arg1)
    //      a1:  rsi → rdx   (arg2)
    //      a2:  rdx → rcx   (arg3)   rcx was user RIP, now on stack
    //      a3:  r10 → r8    (arg4)   trampled old Linux a4 — must save first
    //      a4:  r8  → r9    (arg5)   trampled old Linux a5 — must save first
    //      a5:  r9  → [rsp] (arg6)   passed on the stack
    //
    //    Save r9 (a5) into the arg6 slot before the remap clobbers it.
    //    SysV requires rsp to be 16-byte aligned immediately before the
    //    CALL instruction. The 3 preceding pushes (user RSP, RFLAGS, RIP)
    //    leave rsp at (top-24), i.e. 8 mod 16. Reserving one 8-byte slot
    //    for arg6 brings rsp to (top-32) — 0 mod 16, exactly what CALL
    //    needs.
    sub rsp, 8
    mov [rsp], r9     // a5 → stack slot for arg6
    mov r9, r8        // a4 → r9 (arg5)
    mov r8, r10       // a3 → r8 (arg4)
    mov rcx, rdx      // a2 → rcx (arg3)
    mov rdx, rsi      // a1 → rdx (arg2)
    mov rsi, rdi      // a0 → rsi (arg1)
    mov rdi, rax      // nr → rdi (arg0)

    // 5. Call the Rust dispatcher.
    call syscall_dispatch
    add rsp, 8
    // rax = return value

    // 5b. Check for pending signals before returning to user.
    //     Pass a pointer to the saved [user_rip, user_rflags, user_rsp]
    //     on the kernel stack so check_and_deliver_signals can redirect
    //     the return to a signal handler if needed.
    //     Save rax across the call (it holds the syscall return value).
    push rax
    lea rdi, [rsp + 8]   // pointer to saved [rip, rflags, rsp]
    call check_and_deliver_signals
    pop rax

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

/// Pinned Linux x86_64 syscall numbers used by `userspace/init`.
///
/// These are the numbers that appear in the `match nr` arms of
/// `syscall_dispatch`. A mismatch between this table and the match arms
/// will silently cause the wrong kernel operation to run (or -ENOSYS),
/// which manifests in CI as missing smoke markers. See issue #278.
pub mod syscall_nr {
    pub const READ: u64 = 0;
    pub const WRITE: u64 = 1;
    pub const IOCTL: u64 = 16;
    pub const BRK: u64 = 12;
    pub const FORK: u64 = 57;
    pub const EXECVE: u64 = 59;
    pub const EXIT: u64 = 60;
    pub const WAIT4: u64 = 61;
    pub const SIGACTION: u64 = 13;
    pub const SIGPROCMASK: u64 = 14;
    pub const KILL: u64 = 62;
    pub const SIGRETURN: u64 = 15;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const MPROTECT: u64 = 10;
    pub const MADVISE: u64 = 28;
    pub const GETDENTS64: u64 = 217;
    pub const OPEN: u64 = 2;
    pub const OPENAT: u64 = 257;
    pub const LSEEK: u64 = 8;
    pub const CLOSE: u64 = 3;
    pub const DUP: u64 = 32;
    pub const DUP2: u64 = 33;
    pub const DUP3: u64 = 292;
    pub const FCNTL: u64 = 72;
    pub const FSTAT: u64 = 5;
    pub const STAT: u64 = 4;
    pub const LSTAT: u64 = 6;
    pub const NEWFSTATAT: u64 = 262;
    pub const GETCWD: u64 = 79;
    pub const CHDIR: u64 = 80;
    pub const PIPE: u64 = 22;
    pub const PIPE2: u64 = 293;
    pub const MKNOD: u64 = 133;
    pub const MKNODAT: u64 = 259;
    pub const POLL: u64 = 7;
    pub const SELECT: u64 = 23;
    pub const PSELECT6: u64 = 270;
    pub const PPOLL: u64 = 271;
    pub const SETPGID: u64 = 109;
    pub const SETSID: u64 = 112;
    pub const GETPGID: u64 = 121;
    pub const GETSID: u64 = 124;
}

#[cfg(test)]
mod tests {
    use super::syscall_nr;

    /// Regression anchor for issue #278: changing any of these numbers
    /// breaks `userspace/init` silently (wrong syscall arm executes).
    /// Update both this table and the `match nr` arms atomically.
    #[test]
    fn syscall_numbers_match_linux_x86_64_abi() {
        // POSIX-required process management syscalls
        assert_eq!(syscall_nr::FORK, 57, "SYS_fork must be 57");
        assert_eq!(syscall_nr::EXECVE, 59, "SYS_execve must be 59");
        assert_eq!(syscall_nr::EXIT, 60, "SYS_exit must be 60");
        assert_eq!(syscall_nr::WAIT4, 61, "SYS_wait4 must be 61");

        // Basic I/O
        assert_eq!(syscall_nr::READ, 0, "SYS_read must be 0");
        assert_eq!(syscall_nr::WRITE, 1, "SYS_write must be 1");
        assert_eq!(syscall_nr::IOCTL, 16, "SYS_ioctl must be 16");
        assert_eq!(syscall_nr::CLOSE, 3, "SYS_close must be 3");
        assert_eq!(syscall_nr::DUP, 32, "SYS_dup must be 32");
        assert_eq!(syscall_nr::DUP2, 33, "SYS_dup2 must be 33");
        assert_eq!(syscall_nr::DUP3, 292, "SYS_dup3 must be 292");
        assert_eq!(syscall_nr::FCNTL, 72, "SYS_fcntl must be 72");
        assert_eq!(syscall_nr::LSEEK, 8, "SYS_lseek must be 8");

        // Memory management
        assert_eq!(syscall_nr::MMAP, 9, "SYS_mmap must be 9");
        assert_eq!(syscall_nr::MPROTECT, 10, "SYS_mprotect must be 10");
        assert_eq!(syscall_nr::MUNMAP, 11, "SYS_munmap must be 11");
        assert_eq!(syscall_nr::BRK, 12, "SYS_brk must be 12");
        assert_eq!(syscall_nr::MADVISE, 28, "SYS_madvise must be 28");

        // Filesystem
        assert_eq!(syscall_nr::OPEN, 2, "SYS_open must be 2");
        assert_eq!(syscall_nr::STAT, 4, "SYS_stat must be 4");
        assert_eq!(syscall_nr::FSTAT, 5, "SYS_fstat must be 5");
        assert_eq!(syscall_nr::LSTAT, 6, "SYS_lstat must be 6");
        assert_eq!(syscall_nr::GETDENTS64, 217, "SYS_getdents64 must be 217");
        assert_eq!(syscall_nr::OPENAT, 257, "SYS_openat must be 257");
        assert_eq!(syscall_nr::NEWFSTATAT, 262, "SYS_newfstatat must be 262");
        assert_eq!(syscall_nr::GETCWD, 79, "SYS_getcwd must be 79");
        assert_eq!(syscall_nr::CHDIR, 80, "SYS_chdir must be 80");

        // Signals
        assert_eq!(syscall_nr::SIGRETURN, 15, "SYS_rt_sigreturn must be 15");
        assert_eq!(syscall_nr::SIGACTION, 13, "SYS_rt_sigaction must be 13");
        assert_eq!(syscall_nr::SIGPROCMASK, 14, "SYS_rt_sigprocmask must be 14");
        assert_eq!(syscall_nr::KILL, 62, "SYS_kill must be 62");

        // Poll / select
        assert_eq!(syscall_nr::POLL, 7, "SYS_poll must be 7");
        assert_eq!(syscall_nr::SELECT, 23, "SYS_select must be 23");
        assert_eq!(syscall_nr::PSELECT6, 270, "SYS_pselect6 must be 270");
        assert_eq!(syscall_nr::PPOLL, 271, "SYS_ppoll must be 271");

        // Session / process group
        assert_eq!(syscall_nr::SETPGID, 109, "SYS_setpgid must be 109");
        assert_eq!(syscall_nr::SETSID, 112, "SYS_setsid must be 112");
        assert_eq!(syscall_nr::GETPGID, 121, "SYS_getpgid must be 121");
        assert_eq!(syscall_nr::GETSID, 124, "SYS_getsid must be 124");

        // IPC / FIFO
        assert_eq!(syscall_nr::PIPE, 22, "SYS_pipe must be 22");
        assert_eq!(syscall_nr::PIPE2, 293, "SYS_pipe2 must be 293");
        assert_eq!(syscall_nr::MKNOD, 133, "SYS_mknod must be 133");
        assert_eq!(syscall_nr::MKNODAT, 259, "SYS_mknodat must be 259");
    }
}
