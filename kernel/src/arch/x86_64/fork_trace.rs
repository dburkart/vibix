//! Fork-path diagnostic instrumentation (issue #502, epic #501).
//!
//! The init `fork → execve → wait4` sequence hangs ~50% of boots on
//! HEAD. This module provides a `fork_trace!` macro that emits
//! `serial_println!`-style "ftrace:" lines at every major step of the
//! fork syscall handler, so the last surviving probe pinpoints the
//! stuck lock / wedged code path.
//!
//! ## Why a dedicated macro (instead of scattered `serial_println!`)
//!
//! - Every line carries the same `ftrace:` prefix so a grep on the
//!   captured serial log surfaces the whole trace in order without
//!   getting mixed into unrelated kernel chatter.
//! - A single compile-time gate (`debug_assertions` — always on for
//!   `cargo xtask build`/`test`/`smoke`, off for `--release`) turns
//!   every probe into a nop so release builds pay zero cost.
//! - Future regressions that re-introduce a fork hang will trip the
//!   same canary: the last `ftrace:` line is always the suspect.
//!
//! ## How this interacts with the COM1 lock
//!
//! `serial_println!` acquires `crate::serial::COM1` (a plain
//! `spin::Mutex`) via `without_interrupts`. The fork syscall handler
//! runs with IF=0 throughout (SFMASK clears IF on SYSCALL entry), so
//! no timer/serial IRQ can interleave. The only re-entry hazard would
//! be the kernel panic handler itself — which is acceptable since a
//! panic would already have terminated the boot. We therefore use the
//! existing `serial_println!` directly rather than a dedicated
//! IRQ-safe path.
//!
//! ## Emitting from asm (pre-Rust trampolines)
//!
//! `fork_child_sysret` runs before Rust-safe state is set up (no valid
//! kernel stack invariants yet for a `call` into Rust). To mark that
//! point we poke a single byte directly into the COM1 THR via `out`,
//! wrapped in `emit_raw_byte`.

/// Emit a single raw byte to the COM1 transmit-holding register.
///
/// Spins on the line-status register's THR-empty bit (bit 5 = 0x20)
/// before writing. Safe to call from contexts where the COM1 mutex is
/// inaccessible (pre-Rust trampolines, double-fault handlers, etc.)
/// at the cost of potentially interleaving a byte mid-`serial_println!`
/// line. The single-byte footprint keeps that cost bounded.
///
/// # Safety
/// - COM1 must have been initialised (`serial::init` has run).
/// - The caller must tolerate interleaving against any concurrent
///   `serial_println!` — use sparingly and only for diagnostic markers
///   that cannot use the normal print path.
#[cfg(debug_assertions)]
#[inline(always)]
pub unsafe fn emit_raw_byte(byte: u8) {
    use core::arch::asm;
    // Spin until THR-empty (LSR bit 5) is set, then write byte to THR (offset 0).
    loop {
        let lsr: u8;
        asm!(
            "in al, dx",
            in("dx") crate::serial::COM1_BASE + 5,
            out("al") lsr,
            options(nomem, nostack, preserves_flags),
        );
        if lsr & 0x20 != 0 {
            break;
        }
    }
    asm!(
        "out dx, al",
        in("dx") crate::serial::COM1_BASE,
        in("al") byte,
        options(nomem, nostack, preserves_flags),
    );
}

/// Release-build nop so callers compile cleanly with `--release`.
#[cfg(not(debug_assertions))]
#[inline(always)]
pub unsafe fn emit_raw_byte(_byte: u8) {}

/// Read the current RFLAGS value. Used by `fork_trace!` call sites
/// that want to record the IF-mask state on entry — the leading fork
/// hypothesis is that fork runs with IF=0 and spins on a lock whose
/// holder requires interrupts to release.
#[cfg(debug_assertions)]
#[inline(always)]
pub fn read_rflags() -> u64 {
    use core::arch::asm;
    let rflags: u64;
    // SAFETY: `pushfq; pop` has no side effects beyond reading RFLAGS.
    unsafe {
        asm!(
            "pushfq",
            "pop {0}",
            out(reg) rflags,
            options(nomem, preserves_flags),
        );
    }
    rflags
}

#[cfg(not(debug_assertions))]
#[inline(always)]
pub fn read_rflags() -> u64 {
    0
}

/// `fork_trace!("...", args...)` — bracketed probe point for the fork
/// syscall handler. Expands to `serial_println!("ftrace: ...")` in
/// debug builds (the default for `cargo xtask build|test|smoke`) and
/// to a nop under `--release`.
///
/// The `ftrace:` prefix lets a captured serial log be filtered with a
/// single `grep -E '^ftrace:'` to see the probe sequence cleanly.
#[macro_export]
macro_rules! fork_trace {
    ($($arg:tt)*) => {{
        #[cfg(debug_assertions)]
        {
            $crate::serial_println!("ftrace: {}", format_args!($($arg)*));
        }
    }};
}
