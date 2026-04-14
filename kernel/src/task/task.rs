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

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::{Mutex, RwLock};
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::VirtAddr;

use crate::arch::x86_64::fpu::FpuArea;
use crate::fs::FileDescTable;
use crate::mem::addrspace::AddressSpace;
use crate::mem::paging;

use super::priority::{AFFINITY_ALL, DEFAULT_PRIORITY};
use super::switch::{fork_child_sysret, task_entry_trampoline};
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
    /// Per-task virtual address space — owns the PML4 (mirrored in
    /// [`Self::cr3`] as a switch-fast snapshot) and the lazily-resolved
    /// VMA map. Wrapped in `Arc<RwLock<_>>` so future thread groups
    /// (clone(2)-style) can share one address space across tasks; for
    /// today every task has its own.
    ///
    /// The `RwLock` is the raw `spin::RwLock`, not [`crate::mem::addrspace::AddressSpaceLock`],
    /// because the `#PF` handler must read this map with interrupts
    /// disabled — the wrapper's IRQ-safety assertion belongs on
    /// task-context syscall paths, not here.
    pub address_space: Arc<RwLock<AddressSpace>>,
    /// Per-task x87/SSE register image. Saved on every switch-out and
    /// restored on switch-in. A fresh area is seeded with the
    /// post-`fninit` canonical FPU state so a spawned task sees the
    /// same FPU starting conditions as the bootstrap thread.
    pub fpu: Box<FpuArea>,
    /// Per-process file-descriptor table. Wrapped in `Arc<Mutex>` so it
    /// can be shared across threads in the same process (clone(2)-style)
    /// and cloned cheaply for fork() and exec() paths.
    pub fd_table: Arc<Mutex<FileDescTable>>,

    /// Top of this task's dedicated SYSCALL kernel stack (set when this
    /// task runs in ring-3 and needs its own syscall entry point).
    ///
    /// `0` means "use the global `INIT_KERNEL_STACK`" — correct for
    /// purely-kernel tasks that never execute SYSCALL from ring-3, and
    /// for the init task before `init_ring3_entry` initialises it.
    ///
    /// Set to `guard_base + GUARD_SIZE + STACK_SIZE` for user-space
    /// tasks. The preempt / block paths update `SYSCALL_KERNEL_RSP` to
    /// this value whenever they switch into this task so that ring-3
    /// syscalls land on the right per-task stack.
    pub syscall_stack_top: u64,
}

impl Task {
    /// Bootstrap task for the currently-running thread of control. Its
    /// `rsp` is filled in by the first `context_switch` that yields
    /// away from this thread.
    pub fn bootstrap() -> Self {
        // The bootstrap task runs on the kernel PML4 that
        // build_and_switch_kernel_pml4 installed — capture whatever
        // CR3 currently points at and wrap it in an AddressSpace.
        let cr3 = Cr3::read().0;
        Self {
            id: 0,
            guard_base: 0,
            rsp: 0,
            slice_remaining_ms: DEFAULT_SLICE_MS,
            state: TaskState::Running,
            wake_pending: AtomicBool::new(false),
            priority: DEFAULT_PRIORITY,
            affinity: AFFINITY_ALL,
            cr3,
            address_space: Arc::new(RwLock::new(AddressSpace::for_bootstrap(cr3))),
            // The bootstrap task hasn't touched the FPU yet (kernel is
            // soft-float), so seeding with the canonical `fninit` image
            // is correct: the first switch-away from bootstrap will
            // overwrite this buffer with whatever live FPU state exists
            // at that moment.
            fpu: FpuArea::new_initialized(),
            fd_table: Arc::new(Mutex::new(FileDescTable::new_with_stdio())),
            syscall_stack_top: 0,
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
        let mut flusher = crate::mem::tlb::Flusher::new_active();
        paging::map_range(
            VirtAddr::new(stack_base as u64),
            stack_page_count,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            &mut flusher,
        )
        .expect("failed to map task stack");
        flusher.finish();

        // Build the per-task AddressSpace *after* mapping the stack —
        // its PML4 snapshots the kernel PML4's upper half, and we want
        // the fresh stack's L4 entry to already be in place. Later
        // tasks' stacks fall under the same L4 entry and propagate by
        // alias through the shared L3 subtree.
        let address_space = AddressSpace::new_empty();
        let cr3 = address_space.page_table_frame();

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
            address_space: Arc::new(RwLock::new(address_space)),
            fpu: FpuArea::new_initialized(),
            fd_table: Arc::new(Mutex::new(FileDescTable::new_with_stdio())),
            syscall_stack_top: 0, // kernel-only task — no ring-3 syscall stack needed yet
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

    /// Number of 4 KiB stack pages owned by this task. Zero for the
    /// bootstrap task (mirrors `stack_base() == 0`) so cleanup paths
    /// can loop `0..stack_page_count()` without a separate guard.
    pub fn stack_page_count(&self) -> usize {
        if self.guard_base == 0 {
            0
        } else {
            STACK_SIZE / 4096
        }
    }

    /// Returns `true` if `addr` falls within this task's guard page.
    ///
    /// Always returns `false` for the bootstrap task (`guard_base == 0`).
    pub fn is_guard_hit(&self, addr: usize) -> bool {
        self.guard_base != 0 && addr >= self.guard_base && addr < self.guard_base + GUARD_SIZE
    }

    /// Build a new task that is a fork child. On first scheduling the task
    /// returns to ring-3 via `fork_child_sysret` with rax=0 (the child's
    /// fork() return value).
    ///
    /// `user_rip`, `user_rflags`, and `user_rsp` are the saved ring-3
    /// register context from the parent's SYSCALL entry.
    /// `parent_fpu` is the parent's current FPU save area (copied verbatim
    /// so the child inherits the same floating-point state at fork time).
    /// `parent_priority` / `parent_affinity` are copied directly.
    ///
    /// # Safety
    /// `parent_fpu` must be a valid, aligned `FpuArea` that remains live
    /// for the duration of this call (the FPU copy happens before return).
    pub unsafe fn new_forked(
        user_rip: u64,
        user_rflags: u64,
        user_rsp: u64,
        parent_priority: u8,
        parent_affinity: u64,
        parent_fpu: *const crate::arch::x86_64::fpu::FpuArea,
        child_address_space: alloc::sync::Arc<spin::RwLock<AddressSpace>>,
        child_cr3: PhysFrame<Size4KiB>,
        child_fd_table: alloc::sync::Arc<Mutex<crate::fs::FileDescTable>>,
    ) -> Self {
        // Allocate a fresh guard+stack slot.
        let slot_va = NEXT_STACK_VA.fetch_add(TASK_SLOT_SIZE, Ordering::Relaxed);
        let guard_base = slot_va;
        let stack_base = slot_va + GUARD_SIZE;

        Page::<Size4KiB>::from_start_address(VirtAddr::new(stack_base as u64))
            .expect("forked task stack base must be page aligned");
        let stack_page_count = (STACK_SIZE / 4096) as u64;
        let mut flusher = crate::mem::tlb::Flusher::new_active();
        paging::map_range(
            VirtAddr::new(stack_base as u64),
            stack_page_count,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
            &mut flusher,
        )
        .expect("failed to map forked task stack");
        flusher.finish();

        let top = stack_base + STACK_SIZE;

        // Prime the stack so context_switch restores:
        //   r15=0, r14=0, r13=0,
        //   r12 = user_rip    → rcx for SYSRETQ
        //   rbp = user_rsp    → rsp before SYSRETQ
        //   rbx = user_rflags → r11 for SYSRETQ
        //   ret = fork_child_sysret
        let rsp = top - 7 * 8;
        let slots = rsp as *mut usize;
        unsafe {
            slots.add(0).write(0); // r15
            slots.add(1).write(0); // r14
            slots.add(2).write(0); // r13
            slots.add(3).write(user_rip as usize); // r12 → rcx
            slots.add(4).write(user_rsp as usize); // rbp → rsp
            slots.add(5).write(user_rflags as usize); // rbx → r11
            slots.add(6).write(fork_child_sysret as *const () as usize); // ret
        }

        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);

        // Copy the parent's FPU state into a fresh area.
        let mut fpu = FpuArea::new_initialized();
        unsafe {
            core::ptr::copy_nonoverlapping(parent_fpu, &mut *fpu as *mut _, 1);
        }

        Self {
            id,
            guard_base,
            rsp,
            slice_remaining_ms: DEFAULT_SLICE_MS,
            state: TaskState::Ready,
            wake_pending: AtomicBool::new(false),
            priority: parent_priority,
            affinity: parent_affinity,
            cr3: child_cr3,
            address_space: child_address_space,
            fpu,
            fd_table: child_fd_table,
            // The child task runs in ring-3; it needs its own SYSCALL stack
            // so it doesn't clobber the parent's saved SYSCALL context on the
            // shared INIT_KERNEL_STACK. Use the top of this task's kernel stack.
            syscall_stack_top: (stack_base + STACK_SIZE) as u64,
        }
    }
}
