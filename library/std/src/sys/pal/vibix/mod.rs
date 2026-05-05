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
    // Nothing to initialize yet. Args/env handling is deferred to later phases.
}

// SAFETY: must be called only once during runtime cleanup.
pub unsafe fn cleanup() {}
