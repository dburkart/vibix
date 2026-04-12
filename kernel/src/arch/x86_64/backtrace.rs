//! Frame-pointer-based stack unwinder.
//!
//! The kernel is built with `-Cforce-frame-pointers=yes`, so every
//! non-leaf function emits the canonical System V prologue
//! (`push rbp; mov rbp, rsp`). Each activation record then looks like:
//!
//! ```text
//!     [rbp + 0]   saved rbp of the caller
//!     [rbp + 8]   return address into the caller
//! ```
//!
//! Walking `rbp` by reading the saved `rbp` at offset 0 gives us the
//! entire chain of activations up to the first caller with no saved
//! frame (`rbp == 0`) or to whatever kernel entry point first set up a
//! stack. The return address at offset 8 identifies the call site.

use core::arch::asm;

/// Captured return address from one frame of the walk.
#[derive(Clone, Copy)]
pub struct Frame {
    pub return_addr: u64,
}

/// Hard ceiling on frames walked. Protects against a corrupt chain
/// pointing back at itself, and keeps panic output bounded.
pub const MAX_FRAMES: usize = 32;

/// Walk the caller's stack frames, invoking `f(Frame)` for each return
/// address found, oldest-to-newest suppressed — this prints
/// newest-to-oldest, i.e. the immediate caller first.
///
/// Skips the first `skip` frames (useful for hiding the walker +
/// panic-handler frames so the user sees their own code first).
#[inline(never)]
pub fn walk<F: FnMut(Frame)>(skip: usize, mut f: F) {
    let mut rbp: u64;
    unsafe {
        asm!("mov {}, rbp", out(reg) rbp, options(nomem, nostack, preserves_flags));
    }
    let mut emitted = 0usize;
    let mut skipped = 0usize;
    while emitted < MAX_FRAMES {
        if !is_valid_rbp(rbp) {
            break;
        }
        // SAFETY: is_valid_rbp checked canonicality + alignment.
        let saved_rbp = unsafe { core::ptr::read_volatile(rbp as *const u64) };
        let ret_addr = unsafe { core::ptr::read_volatile((rbp as *const u64).add(1)) };
        if ret_addr == 0 {
            break;
        }
        if skipped < skip {
            skipped += 1;
        } else {
            f(Frame {
                return_addr: ret_addr,
            });
            emitted += 1;
        }
        // A well-formed chain grows upward toward the stack base; if
        // the saved rbp isn't strictly greater, treat the chain as
        // corrupt and stop rather than loop forever.
        if saved_rbp <= rbp {
            break;
        }
        rbp = saved_rbp;
    }
}

/// Basic sanity gate: upper-half canonical address, 8-byte aligned.
/// A bad `rbp` (raw pointer from a clobbered stack) is the most likely
/// failure mode and this keeps us from dereferencing garbage.
fn is_valid_rbp(rbp: u64) -> bool {
    rbp != 0 && rbp & 0b111 == 0 && rbp >= 0xffff_8000_0000_0000
}

/// Dump the caller's backtrace to COM1, one frame per line, preceded
/// by a `backtrace:` marker so log scrapers can find it. Safe to call
/// from the panic handler.
///
/// `skip` hides the walker + caller frames — callers typically pass
/// 1 (skip the call to `dump_to_serial` itself).
#[inline(never)]
pub fn dump_to_serial(skip: usize) {
    use core::fmt::Write;
    crate::serial_println!("backtrace:");

    struct SerialSink;
    impl Write for SerialSink {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            crate::serial::_print(format_args!("{}", s));
            Ok(())
        }
    }

    let mut idx = 0usize;
    walk(skip + 1, |frame| {
        let _ = write!(SerialSink, "  #{idx:<2} ");
        let _ = crate::ksymtab::format_addr(&mut SerialSink, frame.return_addr);
        let _ = SerialSink.write_str("\n");
        idx += 1;
    });
    if idx == 0 {
        crate::serial_println!("  <no frames — frame pointers missing or stack corrupt>");
    }
}

/// Print a backtrace from the call site. Handy for ad-hoc debugging.
#[macro_export]
macro_rules! kbacktrace {
    () => {
        $crate::arch::backtrace::dump_to_serial(1)
    };
}
