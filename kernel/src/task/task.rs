//! Per-task state: a guard-paged kernel stack and a saved stack pointer.
//!
//! Each spawned task owns a 20 KiB VA slot carved from the dedicated
//! `TASK_STACKS_VA_BASE` window:
//!
//! ```text
//!   [ guard page (4 KiB, unmapped) | stack pages (16 KiB, RW/NX) ]
//!   ^                               ^                             ^
//!   guard_base                   stack_base                     top
//! ```
//!
//! The guard page is never mapped. A stack overflow that walks past
//! `stack_base` takes a `#PF` whose fault address lands inside the guard,
//! which the `#PF` handler recognises and turns into a named diagnostic
//! instead of silent memory corruption.
//!
//! The stack is primed on construction so the first context switch into a
//! new task lands in `task_entry_trampoline`, which then calls the entry
//! function.

use core::sync::atomic::{AtomicUsize, Ordering};

use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

use crate::mem::paging;

use super::switch::task_entry_trampoline;
use super::DEFAULT_SLICE_MS;

/// Usable stack per task.
const STACK_SIZE: usize = 16 * 1024;
/// Guard page size (one 4 KiB page, never mapped).
const GUARD_SIZE: usize = 4096;
/// Total VA consumed per task slot: guard page + stack pages.
const TASK_SLOT_SIZE: usize = GUARD_SIZE + STACK_SIZE;

/// Base of the dedicated VA window for kernel task stacks. Chosen to sit
/// well above the heap cap (`HEAP_BASE` + 16 MiB = `0xFFFF_C000_1000_0000`)
/// and below the kernel image at `0xFFFF_FFFF_8000_0000`.
const TASK_STACKS_VA_BASE: usize = 0xFFFF_D000_0000_0000;

/// Bump allocator for task-stack VA slots. Monotonically increments;
/// task stacks are never freed (tasks don't exit yet).
static NEXT_STACK_VA: AtomicUsize = AtomicUsize::new(TASK_STACKS_VA_BASE);

/// Sequential task IDs. 0 is reserved for the bootstrap task.
static NEXT_TASK_ID: AtomicUsize = AtomicUsize::new(1);

pub(super) struct Task {
    /// Stable task identifier, used in diagnostic messages.
    pub id: usize,
    /// Base VA of the 4 KiB guard page. The range
    /// `[guard_base, guard_base + 4 KiB)` is permanently unmapped.
    /// Zero for the bootstrap task, which inherits the pre-existing boot
    /// stack (no separate guard page — that stack lives in reclaimable
    /// bootloader memory).
    pub guard_base: usize,
    /// Saved `rsp`. Updated on every `context_switch` out of the task.
    /// `0` is a sentinel meaning "not yet saved" — legal only for the
    /// bootstrap task before its first yield.
    pub rsp: usize,
    /// Milliseconds left in this task's current CPU slice. The PIT ISR
    /// decrements this by `TICK_MS`; when it hits zero the task rotates
    /// to the back of the ready queue and the counter is reloaded from
    /// `DEFAULT_SLICE_MS`.
    pub slice_remaining_ms: u32,
}

impl Task {
    /// Bootstrap task for the currently-running thread of control. Its
    /// `rsp` is filled in by the first `context_switch` that yields
    /// away from this thread.
    pub fn bootstrap() -> Self {
        Self {
            id: 0,
            guard_base: 0,
            rsp: 0,
            slice_remaining_ms: DEFAULT_SLICE_MS,
        }
    }

    /// Allocate a guard-paged stack and prime it so the first switch into
    /// this task runs `entry` via the trampoline.
    ///
    /// VA layout (low → high):
    /// ```text
    ///   [ guard page (unmapped) | stack pages (mapped RW/NX) ]
    ///                            ^                           ^
    ///                         stack_base                   top
    /// ```
    ///
    /// Primed register context (low → high inside the stack):
    /// ```text
    ///   r15=0  r14=0  r13=0  r12=entry  rbp=0  rbx=0  ret=trampoline  <top>
    ///   ^ saved rsp (initial)
    /// ```
    pub fn new(entry: fn() -> !) -> Self {
        // Bump-allocate a fresh VA slot.
        let slot_va = NEXT_STACK_VA.fetch_add(TASK_SLOT_SIZE, Ordering::Relaxed);
        let guard_base = slot_va;
        let stack_base = slot_va + GUARD_SIZE;

        // Map only the stack pages. The guard page at `guard_base` is left
        // unmapped intentionally — touching it raises a #PF.
        // `Page::from_start_address` (used internally by `map_range` via
        // `containing_address`) will catch misalignment loudly if the VA
        // calculation is ever wrong, matching the IST guard discipline.
        let stack_page_count = (STACK_SIZE / 4096) as u64;
        paging::map_range(
            VirtAddr::new(stack_base as u64),
            stack_page_count,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        )
        .expect("failed to map task stack");

        let top = stack_base + STACK_SIZE;

        // Seven 8-byte slots: [r15, r14, r13, r12, rbp, rbx, ret].
        let rsp = top - 7 * 8;
        let slots = rsp as *mut usize;
        // SAFETY: the 56 bytes at `rsp` were just mapped and are
        // exclusively owned by this Task. No other code references this
        // VA range until the first context switch delivers them to the CPU.
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

        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);

        Self {
            id,
            guard_base,
            rsp,
            slice_remaining_ms: DEFAULT_SLICE_MS,
        }
    }

    /// Returns `true` if `addr` falls within this task's guard page.
    ///
    /// Always returns `false` for the bootstrap task (`guard_base == 0`).
    pub fn is_guard_hit(&self, addr: usize) -> bool {
        self.guard_base != 0 && addr >= self.guard_base && addr < self.guard_base + GUARD_SIZE
    }
}
