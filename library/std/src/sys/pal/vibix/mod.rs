//! Platform abstraction layer for vibix.
//!
//! This is the minimum viable PAL: init, cleanup, abort, and helpers.
//! All other subsystems use the `unsupported` fallback or vibix-specific
//! modules registered in `sys/`.

#![allow(missing_docs, nonstandard_style)]

use crate::io;

pub mod futex;

pub fn unsupported<T>() -> io::Result<T> {
    Err(unsupported_err())
}

pub fn unsupported_err() -> io::Error {
    io::const_error!(io::ErrorKind::Unsupported, "operation not supported on vibix yet")
}

pub fn abort_internal() -> ! {
    // exit_group(128 + 6) -- SIGABRT convention
    unsafe {
        vibix_abi::syscall::syscall1(231, 134);
    }
    // In case the syscall somehow returns:
    loop {
        core::hint::spin_loop();
    }
}

// SAFETY: must be called only once during runtime initialization.
pub unsafe fn init(argc: isize, argv: *const *const u8, _sigpipe: u8) {
    unsafe { crate::sys::args::init(argc, argv) };
}

// SAFETY: must be called only once during runtime cleanup.
pub unsafe fn cleanup() {}

/// Entry point for vibix userspace binaries.
///
/// The kernel loads ELF binaries with entry point set to `_start`.
/// Since vibix has no CRT, std provides the entry point directly.
/// `main` is the symbol rustc generates that calls `lang_start`.
///
/// The kernel writes the standard SysV AMD64 initial stack layout:
///   [rsp]       = argc
///   [rsp + 8]   = argv[0]
///   ...
///   [rsp + 8*argc] = argv[argc-1]
///   [rsp + 8*(argc+1)] = NULL (argv terminator)
///   followed by envp and auxv.
///
/// We use `global_asm!` to emit a raw entry stub that reads argc/argv
/// from the stack before any Rust prologue can disturb rsp, then calls
/// `_start_rust(argc, argv)`.
#[cfg(not(test))]
core::arch::global_asm!(
    ".global _start",
    "_start:",
    "    mov rdi, [rsp]",      // argc
    "    lea rsi, [rsp + 8]",  // argv
    "    call _start_rust",
    "    ud2",                  // unreachable
);

#[cfg(not(test))]
#[unsafe(no_mangle)]
unsafe extern "C" fn _start_rust(argc: isize, argv: *const *const u8) -> ! {
    unsafe extern "C" {
        fn main(argc: isize, argv: *const *const u8) -> isize;
    }

    let ret = unsafe { main(argc, argv) };

    // exit_group(ret)
    unsafe {
        vibix_abi::syscall::syscall1(231, ret as u64);
    }
    loop {
        core::hint::spin_loop();
    }
}

// --- cvt helpers (same as the unix PAL) ---

pub trait IsMinusOne {
    fn is_minus_one(&self) -> bool;
}

macro_rules! impl_is_minus_one {
    ($($t:ident)*) => ($(impl IsMinusOne for $t {
        fn is_minus_one(&self) -> bool {
            *self == -1
        }
    })*)
}

impl_is_minus_one! { i8 i16 i32 i64 isize }

pub fn cvt<T: IsMinusOne>(t: T) -> io::Result<T> {
    if t.is_minus_one() { Err(io::Error::last_os_error()) } else { Ok(t) }
}

pub fn cvt_r<T, F>(mut f: F) -> io::Result<T>
where
    T: IsMinusOne,
    F: FnMut() -> T,
{
    loop {
        match cvt(f()) {
            Err(ref e) if e.is_interrupted() => {}
            other => return other,
        }
    }
}

#[allow(dead_code)]
pub fn cvt_nz(error: libc::c_int) -> io::Result<()> {
    if error == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(error)) }
}
