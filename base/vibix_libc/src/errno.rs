//! errno support -- re-exports vibix_abi's thread-local ERRNO and
//! __errno_location symbol.
//!
//! The actual `__errno_location` symbol is defined in `vibix_abi::errno`.
//! This module simply re-exports the ERRNO cell for internal use.

pub use vibix_abi::errno::ERRNO;
