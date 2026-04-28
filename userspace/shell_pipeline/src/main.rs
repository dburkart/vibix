//! Shell-pipeline integration test (issue #462) — verifies RFC 0003
//! end-to-end by running `echo foo | cat | wc -c` entirely inside one
//! ring-3 process tree.
//!
//! ## Why one binary, not three
//!
//! The vibix kernel's current `execve()` ignores its `path` argument and
//! always reloads `/boot/userspace_hello.elf` (see
//! `kernel/src/arch/x86_64/syscall.rs::EXECVE`). That makes a literal
//! three-binary pipeline impossible today: every child of `execve()`
//! ends up running the same hello-binary, not a real `cat` or `wc`.
//!
//! Rather than block this test on a multi-target ELF loader, this
//! binary plays all three stages itself:
//!
//! ```text
//!     PID 1 (this binary, "supervisor")
//!         ├── fork → child A: dup2 pipe1.write → fd 1; "echo" foo
//!         ├── fork → child B: dup2 pipe1.read → fd 0,
//!         │                   dup2 pipe2.write → fd 1; "cat" loop
//!         └── fork → child C: dup2 pipe2.read → fd 0; "wc -c" → fd 1
//!                                                  emits SHELL_PIPELINE_OK: <count>
//! ```
//!
//! All five real syscalls under test still get exercised on the
//! pipeline-shape they implement in a real shell:
//!   - `pipe2(2)` x2   — wires the three stages
//!   - `fork(2)` x3    — one per stage
//!   - `dup2(2)`       — re-points stdin/stdout per stage
//!   - `close(2)`      — drops the unused pipe ends so EOF propagates
//!   - `read/write(2)` — the bytes flow stage to stage
//!   - `wait4(2)` x3   — supervisor reaps all three children
//!
//! When the kernel grows path-aware execve (follow-up after #462), the
//! `stage_*` arms below can be split out into independent `cat`/`wc`
//! binaries without touching the supervisor's pipeline-wiring logic.
//!
//! ## Marker contract
//!
//! On a clean run the supervisor emits exactly one
//! `SHELL_PIPELINE_OK: 4` line on fd 1. Any failure path emits a
//! `SHELL_PIPELINE_FAIL: <reason>` line so the xtask wrapper can fail
//! fast with a concrete cause.
//!
//! ## Syscall ABI — see #531
//!
//! The vibix SYSCALL trampoline does **not** preserve user values of
//! `rdi`, `rsi`, `rdx`, `r8`, `r9`, or `r10` across a syscall: only
//! `rcx` (user RIP) and `r11` (user RFLAGS) are restored on SYSRETQ.
//! Every asm block below therefore declares the full SysV caller-saved
//! GPR set as `inlateout`/`lateout` so the compiler does not cache
//! dead values across the syscall.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

// ── Syscall numbers (Linux x86_64; pinned to kernel/src/arch/x86_64/syscall.rs)

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_PIPE2: u64 = 293;
const SYS_DUP2: u64 = 33;
const SYS_FORK: u64 = 57;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;

// ── Standard fds and constants

const STDIN: u64 = 0;
const STDOUT: u64 = 1;
const STDERR: u64 = 2;

// ── Pipeline payload — `echo foo` writes "foo\n" (4 bytes), so the
// final `wc -c` count must be exactly 4.

const ECHO_PAYLOAD: &[u8] = b"foo\n";
const EXPECTED_COUNT: u32 = 4;

// ── Markers asserted (or grepped for failure) by the xtask wrapper.

const FAIL_FORK_PIPE1: &[u8] = b"SHELL_PIPELINE_FAIL: pipe1\n";
const FAIL_FORK_PIPE2: &[u8] = b"SHELL_PIPELINE_FAIL: pipe2\n";
const FAIL_FORK_ECHO: &[u8] = b"SHELL_PIPELINE_FAIL: fork echo\n";
const FAIL_FORK_CAT: &[u8] = b"SHELL_PIPELINE_FAIL: fork cat\n";
const FAIL_FORK_WC: &[u8] = b"SHELL_PIPELINE_FAIL: fork wc\n";
const FAIL_WAIT_ECHO: &[u8] = b"SHELL_PIPELINE_FAIL: wait echo\n";
const FAIL_WAIT_CAT: &[u8] = b"SHELL_PIPELINE_FAIL: wait cat\n";
const FAIL_WAIT_WC: &[u8] = b"SHELL_PIPELINE_FAIL: wait wc\n";
const FAIL_NONZERO_ECHO: &[u8] = b"SHELL_PIPELINE_FAIL: echo nonzero\n";
const FAIL_NONZERO_CAT: &[u8] = b"SHELL_PIPELINE_FAIL: cat nonzero\n";
const FAIL_NONZERO_WC: &[u8] = b"SHELL_PIPELINE_FAIL: wc nonzero\n";

// ── _start: the supervisor

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Banner so a missing-marker run still has a recognizable starting
    // line for log triage.
    write_all(STDOUT, b"shell_pipeline: starting echo|cat|wc-c\n");

    // Pipe 1: echo → cat
    let mut p1: [i32; 2] = [-1, -1];
    if sys_pipe2(p1.as_mut_ptr(), 0) < 0 {
        write_all(STDERR, FAIL_FORK_PIPE1);
        sys_exit(2);
    }
    let p1r = p1[0] as u64;
    let p1w = p1[1] as u64;

    // Pipe 2: cat → wc
    let mut p2: [i32; 2] = [-1, -1];
    if sys_pipe2(p2.as_mut_ptr(), 0) < 0 {
        write_all(STDERR, FAIL_FORK_PIPE2);
        sys_exit(2);
    }
    let p2r = p2[0] as u64;
    let p2w = p2[1] as u64;

    // ── Stage A: echo (writes ECHO_PAYLOAD to its stdout)
    let pid_echo = sys_fork();
    if pid_echo < 0 {
        write_all(STDERR, FAIL_FORK_ECHO);
        sys_exit(2);
    }
    if pid_echo == 0 {
        // Child: stdout → p1w, then close every pipe fd we still hold.
        if sys_dup2(p1w, STDOUT) < 0 {
            sys_exit(11);
        }
        sys_close(p1r);
        sys_close(p1w);
        sys_close(p2r);
        sys_close(p2w);
        stage_echo();
    }

    // ── Stage B: cat (stdin from p1r, stdout to p2w)
    let pid_cat = sys_fork();
    if pid_cat < 0 {
        write_all(STDERR, FAIL_FORK_CAT);
        sys_exit(2);
    }
    if pid_cat == 0 {
        if sys_dup2(p1r, STDIN) < 0 {
            sys_exit(12);
        }
        if sys_dup2(p2w, STDOUT) < 0 {
            sys_exit(13);
        }
        sys_close(p1r);
        sys_close(p1w);
        sys_close(p2r);
        sys_close(p2w);
        stage_cat();
    }

    // ── Stage C: wc -c (stdin from p2r)
    let pid_wc = sys_fork();
    if pid_wc < 0 {
        write_all(STDERR, FAIL_FORK_WC);
        sys_exit(2);
    }
    if pid_wc == 0 {
        if sys_dup2(p2r, STDIN) < 0 {
            sys_exit(14);
        }
        sys_close(p1r);
        sys_close(p1w);
        sys_close(p2r);
        sys_close(p2w);
        stage_wc();
    }

    // Supervisor: drop every pipe fd. Each pipe end must be closed in
    // every process that still holds it for the readers to see EOF.
    sys_close(p1r);
    sys_close(p1w);
    sys_close(p2r);
    sys_close(p2w);

    // Wait for all three children. Order matters only insofar as the
    // pipeline must drain before the wc-stage exits; we wait in
    // pipeline order for predictability.
    if !wait_zero(pid_echo as u64, FAIL_WAIT_ECHO, FAIL_NONZERO_ECHO) {
        sys_exit(3);
    }
    if !wait_zero(pid_cat as u64, FAIL_WAIT_CAT, FAIL_NONZERO_CAT) {
        sys_exit(3);
    }
    if !wait_zero(pid_wc as u64, FAIL_WAIT_WC, FAIL_NONZERO_WC) {
        sys_exit(3);
    }

    // PID 1 must not exit. The wc-stage already emitted the marker.
    park()
}

/// echo: write the payload, exit 0.
fn stage_echo() -> ! {
    if write_all(STDOUT, ECHO_PAYLOAD) {
        sys_exit(0);
    }
    sys_exit(21);
}

/// cat: copy stdin → stdout until EOF, exit 0.
fn stage_cat() -> ! {
    let mut buf = [0u8; 64];
    loop {
        let n = sys_read(STDIN, buf.as_mut_ptr(), buf.len() as u64);
        if n == 0 {
            sys_exit(0);
        }
        if n < 0 {
            sys_exit(22);
        }
        let n = n as usize;
        if !write_all(STDOUT, &buf[..n]) {
            sys_exit(23);
        }
    }
}

/// wc -c: count stdin bytes, then write `SHELL_PIPELINE_OK: <count>` to
/// fd 1 if the count matches the expected value, otherwise emit a
/// failure line.
fn stage_wc() -> ! {
    let mut buf = [0u8; 64];
    let mut count: u32 = 0;
    loop {
        let n = sys_read(STDIN, buf.as_mut_ptr(), buf.len() as u64);
        if n == 0 {
            break;
        }
        if n < 0 {
            sys_exit(31);
        }
        // u32 is plenty — pipeline payload is 4 bytes.
        count = count.saturating_add(n as u32);
    }
    if count == EXPECTED_COUNT {
        write_all(STDOUT, b"SHELL_PIPELINE_OK: ");
        write_u32(count);
        write_all(STDOUT, b"\n");
        sys_exit(0);
    } else {
        write_all(STDOUT, b"SHELL_PIPELINE_FAIL: count=");
        write_u32(count);
        write_all(STDOUT, b"\n");
        sys_exit(32);
    }
}

// ── Supervisor helpers

/// Wait for `pid`, fail-marker on syscall error, separate fail-marker
/// on non-zero exit. Returns true iff the child exited with status 0.
fn wait_zero(pid: u64, syscall_err: &[u8], nonzero_err: &[u8]) -> bool {
    let mut wstatus: i32 = 0;
    let waited = sys_wait4(pid, &mut wstatus as *mut i32);
    if waited < 0 {
        write_all(STDERR, syscall_err);
        return false;
    }
    // Linux wait4: `(exit_status & 0xFF) << 8`.
    let exit_code = ((wstatus as u32) >> 8) & 0xFF;
    if exit_code != 0 {
        write_all(STDERR, nonzero_err);
        return false;
    }
    true
}

/// Park forever with `core::hint::spin_loop()` so PID 1 never exits
/// (which would otherwise panic the kernel).
fn park() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

// ── write helpers

/// Loop write_all — the kernel's pipe write may short-write on a full
/// pipe; we stay in the loop until the whole buffer is drained or an
/// error occurs. Returns true on success.
fn write_all(fd: u64, buf: &[u8]) -> bool {
    let mut off = 0;
    while off < buf.len() {
        let n = sys_write(
            fd,
            unsafe { buf.as_ptr().add(off) },
            (buf.len() - off) as u64,
        );
        if n <= 0 {
            return false;
        }
        off += n as usize;
    }
    true
}

fn write_u32(mut n: u32) {
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    if n == 0 {
        i -= 1;
        buf[i] = b'0';
    } else {
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
    }
    write_all(STDOUT, &buf[i..]);
}

// ── Raw syscall wrappers

fn sys_write(fd: u64, ptr: *const u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_WRITE => ret,
            inlateout("rdi") fd => _,
            inlateout("rsi") ptr as u64 => _,
            inlateout("rdx") len => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn sys_read(fd: u64, ptr: *mut u8, len: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_READ => ret,
            inlateout("rdi") fd => _,
            inlateout("rsi") ptr as u64 => _,
            inlateout("rdx") len => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn sys_close(fd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_CLOSE => ret,
            inlateout("rdi") fd => _,
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
    ret
}

fn sys_pipe2(fds: *mut i32, flags: u32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_PIPE2 => ret,
            inlateout("rdi") fds as u64 => _,
            inlateout("rsi") flags as u64 => _,
            lateout("rcx") _,
            lateout("rdx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn sys_dup2(oldfd: u64, newfd: u64) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_DUP2 => ret,
            inlateout("rdi") oldfd => _,
            inlateout("rsi") newfd => _,
            lateout("rcx") _,
            lateout("rdx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r10") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

fn sys_fork() -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_FORK => ret,
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
    ret
}

fn sys_wait4(pid: u64, wstatus: *mut i32) -> i64 {
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_WAIT4 => ret,
            inlateout("rdi") pid => _,
            inlateout("rsi") wstatus as u64 => _,
            inlateout("rdx") 0u64 => _,
            inlateout("r10") 0u64 => _,
            lateout("rcx") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    ret
}

fn sys_exit(status: i32) -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYS_EXIT,
            in("rdi") status as u64,
            options(nostack, noreturn),
        )
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    write_all(STDERR, b"SHELL_PIPELINE_FAIL: panic\n");
    loop {
        core::hint::spin_loop();
    }
}
