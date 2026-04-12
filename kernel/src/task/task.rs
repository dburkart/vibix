//! Per-task state: a heap-allocated kernel stack and a saved stack
//! pointer. The stack is primed on construction so the first context
//! switch into a new task lands in `task_entry_trampoline`, which then
//! calls the entry function.

use alloc::alloc::{alloc_zeroed, handle_alloc_error, Layout};
use alloc::boxed::Box;

use super::switch::task_entry_trampoline;

/// 16 KiB per task — plenty for the handful of kernel frames
/// cooperative tasks build up between `yield_now()` calls. Aligned to
/// 16 so the primed `rsp` is ABI-legal at the trampoline's `call`.
const STACK_SIZE: usize = 16 * 1024;

#[repr(C, align(16))]
pub(super) struct Stack([u8; STACK_SIZE]);

pub(super) struct Task {
    /// Holder for the heap-allocated stack. `None` only for the
    /// bootstrap task, which inherits the boot-time kernel stack.
    _stack: Option<Box<Stack>>,
    /// Saved `rsp`. Updated on every `context_switch` out of the task.
    /// `0` is a sentinel meaning "not yet saved" — legal only for the
    /// bootstrap task before its first yield.
    pub rsp: usize,
}

impl Task {
    /// Bootstrap task for the currently-running thread of control. Its
    /// `rsp` is filled in by the first `context_switch` that yields
    /// away from this thread.
    pub fn bootstrap() -> Self {
        Self {
            _stack: None,
            rsp: 0,
        }
    }

    /// Allocate a fresh stack and prime it so the first switch into
    /// this task runs `entry` via the trampoline.
    ///
    /// Primed layout (low → high):
    /// ```text
    ///   r15=0  r14=0  r13=0  r12=entry  rbp=0  rbx=0  ret=trampoline  <top>
    ///   ^ saved rsp (initial)                          ^ rsp after 6 pops
    /// ```
    /// `ret` then consumes the last slot and lands rsp on `<top>`.
    pub fn new(entry: fn() -> !) -> Self {
        let layout = Layout::new::<Stack>();
        // SAFETY: Stack has non-zero size and align 16; alloc_zeroed
        // either returns a valid ptr of that layout or null (handled).
        let stack = unsafe {
            let ptr = alloc_zeroed(layout) as *mut Stack;
            if ptr.is_null() {
                handle_alloc_error(layout);
            }
            Box::from_raw(ptr)
        };

        let base = Box::as_ref(&stack) as *const Stack as *const u8 as usize;
        let top = base + STACK_SIZE;

        // Seven 8-byte slots: [r15, r14, r13, r12, rbp, rbx, ret].
        let rsp = top - 7 * 8;
        let slots = rsp as *mut usize;
        // SAFETY: the 56 bytes at `rsp` sit inside the freshly
        // allocated, zeroed Stack and are exclusively owned here.
        unsafe {
            slots.add(0).write(0); // r15
            slots.add(1).write(0); // r14
            slots.add(2).write(0); // r13
            slots.add(3).write(entry as *const () as usize); // r12 ← entry
            slots.add(4).write(0); // rbp
            slots.add(5).write(0); // rbx
            slots
                .add(6)
                .write(task_entry_trampoline as *const () as usize); // ret
        }

        Self {
            _stack: Some(stack),
            rsp,
        }
    }
}
