//! One-shot expectation hooks for exception handlers, used by
//! integration tests that deliberately trigger CPU faults.
//!
//! An `extern "x86-interrupt"` handler can't return a value to the
//! faulting code, so tests can't write `assert_eq!` around the fault
//! itself. Instead a test calls `expect_page_fault(addr)`, triggers the
//! fault, and the handler consumes the expectation: a matching CR2
//! exits QEMU with Success; a mismatch (or a stray fault when nothing
//! is expected) takes the normal print-and-hang path and the test
//! times out or fails.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static PF_EXPECTED: AtomicBool = AtomicBool::new(false);
static PF_EXPECTED_ADDR: AtomicU64 = AtomicU64::new(0);

/// Arm a one-shot expectation that the next `#PF` will occur at
/// `addr`. Cleared by the handler when consumed.
pub fn expect_page_fault(addr: u64) {
    PF_EXPECTED_ADDR.store(addr, Ordering::SeqCst);
    PF_EXPECTED.store(true, Ordering::SeqCst);
}

/// Called from the `#PF` handler. Returns the expected address if one
/// was armed (and clears it), otherwise `None`.
pub fn take_page_fault_expectation() -> Option<u64> {
    if PF_EXPECTED.swap(false, Ordering::SeqCst) {
        Some(PF_EXPECTED_ADDR.load(Ordering::SeqCst))
    } else {
        None
    }
}
