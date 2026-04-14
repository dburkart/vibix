//! Pinned Linux x86_64 syscall ABI surface.
//!
//! Submodules here declare the scalar widths and struct layouts that
//! cross the kernel/userspace boundary. They exist separately from the
//! kernel subsystems that use them so the ABI can be audited in one
//! place and so drift shows up as a change to `kernel/src/abi/` in
//! diff review.

#![allow(non_camel_case_types)] // POSIX type names intentionally mirror C.

pub mod posix_types;
