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
pub unsafe fn init(_argc: isize, _argv: *const *const u8, _sigpipe: u8) {
}

// SAFETY: must be called only once during runtime cleanup.
pub unsafe fn cleanup() {}

/// Entry point for vibix userspace binaries.
///
/// The kernel loads ELF binaries with entry point set to `_start`.
/// Since vibix has no CRT, std provides the entry point directly.
/// `main` is the symbol rustc generates that calls `lang_start`.
#[cfg(not(test))]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _start() -> ! {
    unsafe extern "C" {
        fn main(argc: isize, argv: *const *const u8) -> isize;
    }

    // No args/env on vibix yet; pass zeros.
    let ret = unsafe { main(0, crate::ptr::null()) };

    // exit_group(ret)
    unsafe {
        vibix_abi::syscall::syscall1(231, ret as u64);
    }
    loop {
        core::hint::spin_loop();
    }
}
