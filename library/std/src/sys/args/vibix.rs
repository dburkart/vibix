//! Command line argument retrieval for vibix.
//!
//! The vibix kernel writes the standard SysV AMD64 initial stack layout
//! (argc, argv[], NULL, envp[], NULL, auxv[]) so we can read argc/argv
//! from the pointer the PAL passes through `init`.

#![allow(dead_code)]

pub use super::common::Args;
use crate::ffi::CStr;
use crate::os::unix::ffi::OsStringExt;
use crate::ptr;
use crate::sync::atomic::{AtomicIsize, AtomicPtr, Ordering};

/// Stored argc.
static ARGC: AtomicIsize = AtomicIsize::new(0);
/// Stored argv pointer.
static ARGV: AtomicPtr<*const u8> = AtomicPtr::new(ptr::null_mut());

/// One-time global initialization called from the vibix PAL.
pub unsafe fn init(argc: isize, argv: *const *const u8) {
    ARGC.store(argc, Ordering::Relaxed);
    ARGV.store(argv as *mut _, Ordering::Relaxed);
}

/// Returns the command line arguments.
pub fn args() -> Args {
    let argv = ARGV.load(Ordering::Relaxed);
    let argc = if argv.is_null() { 0 } else { ARGC.load(Ordering::Relaxed) };

    let mut vec = Vec::with_capacity(argc as usize);
    for i in 0..argc {
        let ptr = unsafe { argv.offset(i).read() };
        if ptr.is_null() {
            break;
        }
        let cstr = unsafe { CStr::from_ptr(ptr.cast()) };
        vec.push(OsStringExt::from_vec(cstr.to_bytes().to_vec()));
    }
    Args::new(vec)
}
