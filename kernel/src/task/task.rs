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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use crate::mem::paging;
use crate::mem::vma::VmaList;

use super::priority::{AFFINITY_ALL, DEFAULT_PRIORITY};
use super::switch::task_entry_trampoline;
use super::DEFAULT_SLICE_MS;

/// Scheduling state of a [`Task`].
///
/// `Running` and `Ready` tasks live on `Scheduler::current` or in
/// `Scheduler::ready`; `Blocked` tasks are parked in `Scheduler::parked`
/// and invisible to the round-robin rotation until something calls
/// [`super::wake`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum TaskState {
    Running,
    Ready,
    Blocked,
}

/// Usable stack per task.
const STACK_SIZE: usize = 16 * 1024;
/// Guard page size (one 4 KiB page, never mapped).
pub(super) const GUARD_SIZE: usize = 4096;
/// Total VA consumed per task slot: guard page + stack pages.
pub(super) const TASK_SLOT_SIZE: usize = GUARD_SIZE + STACK_SIZE;

/// Base of the dedicated VA window for kernel task stacks. Chosen to sit
/// well above the heap cap (`HEAP_BASE` + 16 MiB = `0xFFFF_C000_1000_0000`)
/// and below the kernel image at `0xFFFF_FFFF_8000_0000`.
pub(super) const TASK_STACKS_VA_BASE: usize = 0xFFFF_D000_0000_0000;

/// Bump allocator for task-stack VA slots. Monotonically increments;
/// task stacks are never freed (tasks don't exit yet).
pub(super) static NEXT_STACK_VA: AtomicUsize = AtomicUsize::new(TASK_STACKS_VA_BASE);

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
    /// Current scheduling state — Running (is `Scheduler::current`),
    /// Ready (in `Scheduler::ready`), or Blocked (parked in
    /// `Scheduler::parked`).
    pub state: TaskState,
    /// Set by [`super::wake`] when the target task is Running or Ready
    /// at wake time. The task's next [`super::block_current`] call
    /// consumes the flag and returns without parking — this is what
    /// guards against the "wake before park" lost-wakeup race in
    /// [`crate::sync::WaitQueue::wait_while`].
    pub wake_pending: AtomicBool,
    /// Effective scheduling priority in `0..=MAX_PRIORITY`. Higher
    /// values preempt lower ones. See [`super::priority`] for the
    /// priority/nice mapping.
    pub priority: u8,
    /// Bitmask of CPUs this task is allowed to run on (bit `n` set =
    /// allowed on CPU `n`). Stored-but-unenforced on the single-CPU
    /// kernel; exists so affinity APIs keep a stable shape once SMP
    /// lands.
    pub affinity: u64,
    /// Physical frame holding this task's PML4. Loaded into CR3 on
    /// every `context_switch` into this task. The bootstrap task's
    /// PML4 is the kernel PML4 built by
    /// [`crate::mem::paging::build_and_switch_kernel_pml4`]; spawned
    /// tasks get a fresh PML4 from
    /// [`crate::mem::paging::new_task_pml4`] whose upper half shares
    /// kernel mappings and whose lower half is empty — groundwork for
    /// per-task userspace address spaces (#26).
    pub cr3: PhysFrame<Size4KiB>,
    /// Per-task virtual-memory areas resolved lazily by the `#PF`
    /// handler. Empty for the bootstrap task and for spawned tasks
    /// until something installs a VMA via
    /// [`super::install_vma_on_current`].
    pub vmas: VmaList,
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
            state: TaskState::Running,
            wake_pending: AtomicBool::new(false),
            priority: DEFAULT_PRIORITY,
            affinity: AFFINITY_ALL,
            // The bootstrap task runs on the kernel PML4 that
            // build_and_switch_kernel_pml4 installed — capture whatever
            // CR3 currently points at.
            cr3: Cr3::read().0,
            vmas: VmaList::new(),
        }
    }

    /// Allocate a guard-paged stack and prime it so the first switch
    /// into this task runs `entry` via the trampoline at the given
    /// scheduling priority. Affinity defaults to [`AFFINITY_ALL`];
    /// callers that care about pinning call [`super::set_affinity`]
    /// after spawning.
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
    pub fn new_with_priority(entry: fn() -> !, priority: u8) -> Self {
        // Bump-allocate a fresh VA slot.
        let slot_va = NEXT_STACK_VA.fetch_add(TASK_SLOT_SIZE, Ordering::Relaxed);
        let guard_base = slot_va;
        let stack_base = slot_va + GUARD_SIZE;

        // Map only the stack pages. The guard page at `guard_base` is left
        // unmapped intentionally — touching it raises a #PF.
        // Assert alignment explicitly: map_range uses containing_address
        // (which rounds down silently), so we validate here to catch any
        // future drift in the VA constants.
        Page::<Size4KiB>::from_start_address(VirtAddr::new(stack_base as u64))
            .expect("task stack base must be page aligned");
        let stack_page_count = (STACK_SIZE / 4096) as u64;
        paging::map_range(
            VirtAddr::new(stack_base as u64),
            stack_page_count,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        )
        .expect("failed to map task stack");

        // Build the per-task PML4 *after* mapping the stack — the new
        // PML4 snapshots the kernel PML4's upper half, and we want the
        // fresh stack's L4 entry to already be in place. Later tasks'
        // stacks fall under the same L4 entry and propagate by alias
        // through the shared L3 subtree.
        let cr3 = paging::new_task_pml4();

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
            state: TaskState::Ready,
            wake_pending: AtomicBool::new(false),
            priority: super::priority::clamp_priority(priority),
            affinity: AFFINITY_ALL,
            cr3,
            vmas: VmaList::new(),
        }
    }

    /// Base VA of the mapped stack pages (guard page excluded). Zero
    /// for the bootstrap task, which has no separate stack allocation.
    pub fn stack_base(&self) -> usize {
        if self.guard_base == 0 {
            0
        } else {
            self.guard_base + GUARD_SIZE
        }
    }

    /// Number of 4 KiB stack pages owned by this task.
    pub fn stack_page_count(&self) -> usize {
        STACK_SIZE / 4096
    }

    /// Returns `true` if `addr` falls within this task's guard page.
    ///
    /// Always returns `false` for the bootstrap task (`guard_base == 0`).
    pub fn is_guard_hit(&self, addr: usize) -> bool {
        self.guard_base != 0 && addr >= self.guard_base && addr < self.guard_base + GUARD_SIZE
    }
}
