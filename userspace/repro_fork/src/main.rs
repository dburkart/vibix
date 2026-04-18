//! Deterministic reproducer harness for the fork+exec+wait flake tracked
//! by epic #501 (sub-issue #506, wave 1 of the quality sprint).
//!
//! Runs a tight `fork → child execve → parent wait4` loop for
//! [`CYCLES`] iterations with a heartbeat marker every
//! [`HEARTBEAT_INTERVAL`] cycles.  Each cycle's duration is measured in
//! TSC ticks; if any single cycle exceeds [`STALL_TSC_BUDGET`] ticks a
//! watchdog marker is printed and the process exits non-zero so the
//! QEMU wrapper can fail fast instead of timing out silently.
//!
//! This binary is a drop-in replacement for `userspace_init` when built
//! and shipped as `userspace_init.elf` in the ISO — which is what the
//! xtask `repro-fork` subcommand does.  The kernel's init-process path
//! is unchanged; it still loads `/boot/userspace_init.elf` as PID 1.
//!
//! ## Serial markers (contract with `scripts/repro-fork.sh`)
//!
//! | Marker                                         | Meaning                          |
//! |------------------------------------------------|----------------------------------|
//! | `repro: starting fork loop cycles=N hb=K`      | Harness started; PID 1 alive.    |
//! | `repro: cycle K alive`                         | Heartbeat tick (every K cycles). |
//! | `repro: fork loop complete cycles=N`           | Success — all cycles ran clean.  |
//! | `repro: WATCHDOG fork stuck cycle=K dtsc=...`  | A single cycle exceeded budget.  |
//! | `repro: fork failed cycle=K ret=...`           | fork() returned a negative errno.|
//! | `repro: wait4 failed cycle=K ret=...`          | wait4() returned an error.       |
//!
//! Any `WATCHDOG` / `fork failed` / `wait4 failed` line is terminal —
//! the wrapper script greps for them and fails the CI job.
//!
//! ## Syscall ABI
//!
//! Mirrors `userspace/init/src/main.rs` exactly.  See that file for the
//! full table of syscall numbers and argument conventions.
//!
//! ### Register clobbers — see issue #531
//!
//! The vibix kernel's SYSCALL entry trampoline does **not** preserve the
//! user-mode values of `rdi`, `rsi`, `rdx`, `r8`, `r9`, or `r10` across
//! a syscall.  After `syscall_entry` pushes them to the kernel stack and
//! calls the Rust `syscall_dispatch` (SysV C ABI), those registers are
//! free real-estate for the dispatcher, and the SYSRETQ path only
//! restores `rcx` (user RIP) and `r11` (user RFLAGS).  Every syscall
//! block below therefore declares **all** SysV caller-saved GPRs as
//! `lateout`/`inlateout` — missing any of them silently lets the
//! compiler cache dead values across the syscall and produces wildly
//! wrong behavior (issue #531: the fork-loop counter was held in `r8`
//! and never incremented, so the soak ran until HARD_CAP every time).

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use core::sync::atomic::{compiler_fence, Ordering};

/// Number of fork+exec+wait cycles to run before declaring success.
///
/// Override at build time with `REPRO_FORK_CYCLES=<N>` (consumed by the
/// xtask build, not by cargo directly).  Default 500 is high enough to
/// catch a 1 %-rate flake within a single boot (~1 – e^-5 ≈ 99.3 % hit
/// rate) without ballooning runtime on healthy kernels.
const CYCLES: u64 = match option_env!("REPRO_FORK_CYCLES") {
    Some(s) => parse_u64(s),
    None => 500,
};

/// Emit `repro: cycle K alive` every this many cycles.
const HEARTBEAT_INTERVAL: u64 = 50;

/// Per-cycle TSC-tick budget.  On the CI reference host the kernel
/// boot log reports `timer: TSC 2417 MHz`, so 5 s ≈ 1.2e10 ticks.
/// 30 s headroom (≈ 7.2e10) tolerates un-accelerated CI QEMU where a
/// single fork/exec/wait round can take seconds; any real hang blows
/// through this in one or two cycles.
const STALL_TSC_BUDGET: u64 = 72_000_000_000;

/// Minimal ASCII-number parser for compile-time env override.  Only
/// accepts digits; any malformed input falls through to the default in
/// the caller's `match` arm.  `const` so the literal is baked into the
/// image without a runtime `parse()`.
const fn parse_u64(s: &str) -> u64 {
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut n: u64 = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b < b'0' || b > b'9' {
            return 500; // fall back on bad input
        }
        n = n * 10 + (b - b'0') as u64;
        i += 1;
    }
    n
}

// Syscall numbers — keep in sync with kernel/src/arch/x86_64/syscall.rs.
const SYS_WRITE: u64 = 1;
const SYS_FORK: u64 = 57;
const SYS_EXECVE: u64 = 59;
const SYS_EXIT: u64 = 60;
const SYS_WAIT4: u64 = 61;

const STDOUT: u64 = 1;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Emit CYCLES on its own dedicated, newline-terminated line so a
    // future #531-shaped regression (CYCLES compiled to the wrong value
    // or the start banner getting serial-interleaved with early kernel
    // output) shows up as a clean `repro: CYCLES=N` marker the xtask
    // parser can pick up (see `xtask::tests::parse_cycles_banner`).
    // Kept before the combined banner below so it lands on its own
    // line even when the child's execve-ring3-iretq log interleaves
    // mid-banner under contention.
    write_line(b"repro: CYCLES=");
    write_u64(CYCLES);
    write_line(b"\n");

    write_line(b"repro: starting fork loop cycles=");
    write_u64(CYCLES);
    write_line(b" hb=");
    write_u64(HEARTBEAT_INTERVAL);
    write_line(b"\n");

    let mut cycle: u64 = 0;
    while cycle < CYCLES {
        let start = rdtsc_serialized();

        // fork()
        let fork_ret: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") SYS_FORK => fork_ret,
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
            // Child — exec the hello binary, which writes + exit(0).
            // If execve ever returns, it's a real failure; report it
            // on the child's stdout and exit(2) so the parent's wait4
            // sees a non-zero status and the wrapper script fails.
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") SYS_EXECVE => _,
                    inlateout("rdi") 0u64 => _,
                    inlateout("rsi") 0u64 => _,
                    inlateout("rdx") 0u64 => _,
                    lateout("rcx") _,
                    lateout("r8") _,
                    lateout("r9") _,
                    lateout("r10") _,
                    lateout("r11") _,
                    options(nostack, preserves_flags),
                );
            }
            // execve returned → exec failure. Shout and exit.
            write_line(b"repro: execve returned in child\n");
            sys_exit(2);
        } else if fork_ret < 0 {
            write_line(b"repro: fork failed cycle=");
            write_u64(cycle);
            write_line(b" ret=");
            write_i64(fork_ret);
            write_line(b"\n");
            sys_exit(3);
        }

        // Parent — wait for the child.
        let child_pid = fork_ret as u64;
        let mut wstatus: i32 = 0;
        let waited: i64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") SYS_WAIT4 => waited,
                inlateout("rdi") child_pid => _,
                inlateout("rsi") &mut wstatus as *mut i32 as u64 => _,
                inlateout("rdx") 0u64 => _,
                inlateout("r10") 0u64 => _,
                lateout("rcx") _,
                lateout("r8") _,
                lateout("r9") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        if waited < 0 {
            write_line(b"repro: wait4 failed cycle=");
            write_u64(cycle);
            write_line(b" ret=");
            write_i64(waited);
            write_line(b"\n");
            sys_exit(4);
        }

        // Watchdog — if any single cycle overran the TSC budget the
        // kernel was almost certainly stuck for seconds.  Print a
        // marker and fail fast; the wrapper script treats this as a
        // reproduction.  Use a compiler_fence on either side of the
        // RDTSC pair to keep the measurement ordered w.r.t. the
        // syscall instructions above.
        compiler_fence(Ordering::SeqCst);
        let end = rdtsc_serialized();
        let dtsc = end.wrapping_sub(start);
        if dtsc > STALL_TSC_BUDGET {
            write_line(b"repro: WATCHDOG fork stuck cycle=");
            write_u64(cycle);
            write_line(b" dtsc=");
            write_u64(dtsc);
            write_line(b"\n");
            sys_exit(5);
        }

        cycle += 1;
        if cycle % HEARTBEAT_INTERVAL == 0 {
            write_line(b"repro: cycle ");
            write_u64(cycle);
            write_line(b" alive\n");
        }
    }

    write_line(b"repro: fork loop complete cycles=");
    write_u64(CYCLES);
    write_line(b"\n");
    sys_exit(0);
}

/// write(1, buf).  Best-effort — the return value is ignored because
/// stdout is wired to the serial console and either succeeds or the
/// kernel is so broken that reporting the failure is hopeless anyway.
fn write_line(buf: &[u8]) {
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_WRITE => _,
            inlateout("rdi") STDOUT => _,
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

/// Write a u64 in base-10 ASCII via a single `write()`.  20 digits is
/// enough for `u64::MAX`.  Stack-only, no allocator — this binary runs
/// before any heap is available to it.
fn write_u64(mut n: u64) {
    let mut buf = [0u8; 20];
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
    write_line(&buf[i..]);
}

/// Signed-decimal helper.  Negative fork/wait4 returns are printed as
/// `-<N>` so the wrapper's grep can pick up the errno.
fn write_i64(n: i64) {
    if n < 0 {
        write_line(b"-");
        // `-i64::MIN` would overflow — cast to u64 via wrapping_neg.
        write_u64((n as u64).wrapping_neg());
    } else {
        write_u64(n as u64);
    }
}

/// `exit(status)` — never returns.  Used both for clean shutdown and
/// for error-path terminations above.  `noreturn` forbids asm outputs,
/// so `rcx`/`r11` (SYSCALL-clobbered) cannot be listed here; since we
/// don't return, their post-syscall state is moot.
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

/// Serialized RDTSC read.  `lfence; rdtsc` is the standard x86_64
/// idiom for ordering the read against prior instructions; good
/// enough for coarse per-cycle timing.  CR4.TSD is not set by the
/// vibix kernel so RDTSC is ring-3 accessible.
fn rdtsc_serialized() -> u64 {
    let lo: u32;
    let hi: u32;
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    // No unwinding, no allocator.  Shout a breadcrumb on stdout and
    // hang.  A real panic in this harness would only happen under
    // catastrophic conditions (ring-3 #PF, etc.); the kernel-side
    // panic handler fires long before we get here.
    write_line(b"repro: harness panic\n");
    loop {
        core::hint::spin_loop();
    }
}
