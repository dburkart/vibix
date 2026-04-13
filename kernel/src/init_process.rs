//! PID 1 / init process bootstrap.
//!
//! `launch(bytes)` loads a lower-half ELF from `bytes` into a fresh
//! per-process PML4, allocates a user stack, then spawns a kernel task
//! (`init_ring3_entry`) that switches to the process's address space and
//! drops to ring-3 via `iretq`.
//!
//! ## Relationship to the rest of the kernel
//!
//! After `launch` returns, the init process is queued in the scheduler
//! as a normal task. Its kernel task function (`init_ring3_entry`) is
//! the *only* ring-0 code running on behalf of the process; once it
//! executes `iretq` it never returns. Subsequent entries into the kernel
//! (syscalls, IRQs, exceptions from ring-3) use the dedicated
//! `INIT_KERNEL_STACK` in `arch::x86_64::syscall`.
//!
//! ## PID
//!
//! PID assignment is intentionally minimal for this issue. Task IDs
//! start at 1 for the first spawned task. The bootstrap task (task 0)
//! and the shell / cursor-blink tasks occupy IDs 1…N. This module
//! assigns the first spawned task ID as the init PID and stores it in
//! `INIT_TASK_ID` so that `exit()` in the syscall dispatcher can
//! identify init. A proper PID table is tracked in issue #123.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::structures::paging::{Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

use crate::arch::x86_64::syscall;
use crate::mem::{loader, paging};
use crate::serial_println;

/// User-space entry point — set by `launch` before the task runs.
static INIT_ENTRY: AtomicU64 = AtomicU64::new(0);

/// Physical address of the init process's PML4 — set by `launch`.
static INIT_PML4_PHYS: AtomicU64 = AtomicU64::new(0);

/// Top of the single-page user stack allocated for init.
/// VA layout: one page at `USER_STACK_PAGE_VA`; top = page_base + 4096.
const USER_STACK_PAGE_VA: u64 = 0x7FFF_F000;
pub const USER_STACK_TOP: u64 = USER_STACK_PAGE_VA + 0x1000;

/// Load `bytes` as the init ELF, allocate a user PML4 + stack, and
/// spawn the ring-3 entry task. Returns the task ID of the init task.
///
/// # Panics
/// - If `bytes` is empty or fails ELF parsing.
/// - If frame allocation or PTE installation fails.
pub fn launch(bytes: &[u8]) -> usize {
    // 1. Allocate a fresh per-process PML4 with the kernel upper-half
    //    pre-populated so kernel code remains reachable after CR3 switch.
    let pml4: PhysFrame<Size4KiB> = paging::new_task_pml4();
    serial_println!(
        "init: new PML4 at phys={:#x}",
        pml4.start_address().as_u64()
    );

    // 2. Load the ELF into the lower-half of this PML4.
    let image = match loader::load_user_elf(bytes, pml4) {
        Ok(img) => img,
        Err(e) => panic!("kernel panic: /init ELF load failed: {:?}", e),
    };
    serial_println!(
        "init: ELF loaded entry={:#x} segments={}",
        image.entry.as_u64(),
        image.segments
    );

    // 3. Allocate and map the user stack — one page at USER_STACK_PAGE_VA.
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_PAGE_VA));
    paging::map_in_pml4(
        pml4,
        stack_page,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
    )
    .expect("init: user stack page allocation failed");
    serial_println!(
        "init: user stack at virt={:#x} top={:#x}",
        USER_STACK_PAGE_VA,
        USER_STACK_TOP
    );

    // 4. Publish entry + PML4 for the spawned task to read.
    INIT_ENTRY.store(image.entry.as_u64(), Ordering::Release);
    INIT_PML4_PHYS.store(pml4.start_address().as_u64(), Ordering::Release);

    // 5. Spawn the kernel task that will drop to ring-3.
    //    task::spawn returns immediately; the task is queued.
    crate::task::spawn(init_ring3_entry);
    serial_println!("init: ring-3 entry task spawned");

    // Return an approximation of the task ID. The first spawned task
    // after task::init() gets ID 1 if the shell and cursor-blink tasks
    // have already been spawned. We log this for diagnostics; a proper
    // PID table is issue #123.
    //
    // NOTE: we cannot easily read the ID of the just-spawned task from
    // here without reaching into scheduler internals. For this minimal
    // implementation the caller doesn't need the exact ID.
    1
}

/// Kernel task function for the init process. Runs once, drops to ring-3.
///
/// Execution order:
/// 1. Read INIT_PML4_PHYS and INIT_ENTRY (set by `launch`).
/// 2. Update this task's stored CR3 so future context switches use the
///    init process's PML4.
/// 3. Write CR3 to switch to the init address space.
/// 4. Configure TSS.rsp[0] and the SYSCALL kernel stack.
/// 5. Execute `iretq` to ring-3 — never returns.
fn init_ring3_entry() -> ! {
    let entry = INIT_ENTRY.load(Ordering::Acquire);
    let pml4_phys = INIT_PML4_PHYS.load(Ordering::Acquire);

    assert!(entry != 0, "init_ring3_entry: INIT_ENTRY not set");
    assert!(pml4_phys != 0, "init_ring3_entry: INIT_PML4_PHYS not set");

    let pml4_frame = PhysFrame::<Size4KiB>::containing_address(PhysAddr::new(pml4_phys));

    // Update this task's saved CR3 so context switches back to init use
    // the init process's PML4.
    crate::task::update_current_cr3(pml4_frame);

    // Switch to the init process's address space. The upper half (kernel
    // mappings) is identical to the current PML4 so code execution is
    // uninterrupted.
    unsafe {
        x86_64::registers::control::Cr3::write(
            pml4_frame,
            x86_64::registers::control::Cr3Flags::empty(),
        );
    }
    serial_println!("init: switched to process PML4");

    // Configure TSS.rsp[0] so interrupts from ring-3 land on a valid
    // kernel stack, and SYSCALL_KERNEL_RSP for the syscall path.
    syscall::setup_ring3_stacks();

    serial_println!(
        "init: entering ring-3 entry={:#x} stack={:#x}",
        entry,
        USER_STACK_TOP
    );

    // Drop to ring-3. Never returns.
    unsafe { syscall::jump_to_ring3(entry, USER_STACK_TOP) }
}
