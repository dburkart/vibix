//! PID 1 / init process bootstrap.
//!
//! `launch(bytes)` builds a complete `AddressSpace` for the init process —
//! fresh PML4 + ELF segments loaded with VMA tracking — then spawns a
//! kernel task (`init_ring3_entry`) that installs the address space and
//! drops to ring-3 via `sysretq`.
//!
//! Building the AddressSpace in `launch()` (not in `init_ring3_entry`) is
//! necessary so `fork_address_space` can walk the VMA tree when the init
//! process calls fork(). The ELF segments are registered as private VMAs
//! with pre-populated `AnonObject` caches so CoW fork semantics apply.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use spin::{Once, RwLock};
use x86_64::structures::paging::{Page, PageTableFlags, Size4KiB};
use x86_64::VirtAddr;

use crate::arch::x86_64::syscall;
use crate::mem::addrspace::AddressSpace;
use crate::mem::vmatree::{Share, Vma};
use crate::mem::vmobject::{AnonObject, VmObject};
use crate::mem::{loader, paging};
use crate::serial_println;

/// User-space entry point — set by `launch` before the task runs.
static INIT_ENTRY: AtomicU64 = AtomicU64::new(0);

/// Initial user RSP after the auxv/argv/argc layout has been written into
/// the stack frame. Set by `launch`; read by `init_ring3_entry`.
static INIT_STACK_PTR: AtomicU64 = AtomicU64::new(0);

/// Pre-built init AddressSpace (with ELF VMAs and stack VMA).
/// Consumed by `init_ring3_entry` on first and only use.
static INIT_ADDRESS_SPACE: Once<Arc<RwLock<AddressSpace>>> = Once::new();

/// Top of the single-page user stack allocated for init and exec children.
/// VA layout: one page at `USER_STACK_PAGE_VA`; top = page_base + 4096.
pub const USER_STACK_PAGE_VA: u64 = 0x7FFF_F000;
pub const USER_STACK_TOP: u64 = USER_STACK_PAGE_VA + 0x1000;

/// Load `bytes` as the init ELF, build a complete per-process
/// `AddressSpace` (PML4 + ELF VMAs + stack), and spawn the ring-3 entry
/// task. Returns the task ID of the init task.
///
/// # Panics
/// - If `bytes` is empty or fails ELF parsing.
/// - If frame allocation or PTE installation fails.
pub fn launch(bytes: &[u8]) -> usize {
    // 1. Build a fresh AddressSpace with a new PML4.
    let mut aspace = AddressSpace::new_empty();
    let pml4 = aspace.page_table_frame();
    serial_println!(
        "init: new PML4 at phys={:#x}",
        pml4.start_address().as_u64()
    );

    // 2. Load the ELF and populate VMA entries so fork can walk them.
    let image = match loader::load_user_elf_with_vmas(bytes, pml4, &mut aspace) {
        Ok(img) => img,
        Err(e) => panic!("kernel panic: /init ELF load failed: {:?}", e),
    };
    serial_println!(
        "init: ELF loaded entry={:#x} segments={}",
        image.entry.as_u64(),
        image.segments
    );

    // Set the heap base to immediately after the ELF image so sys_brk
    // starts the heap at the right address.
    aspace.set_brk_start(VirtAddr::new(image.image_end));

    // 3. Allocate and map the user stack, then add it as a VMA so fork
    //    copies it too.
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_STACK_PAGE_VA));
    let stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE;
    let stack_frame = paging::map_in_pml4(pml4, stack_page, stack_flags)
        .expect("init: user stack page allocation failed");

    // Register the pre-faulted stack frame in an AnonObject so fork
    // tracks it. The VMA is marked VMA_GROWSDOWN; the #PF resolver
    // inserts independent per-page VMAs below it as the stack grows.
    use crate::mem::vmatree::{VMA_GROWSDOWN, VMA_STACK_GUARD};
    let stack_obj = AnonObject::new(Some(1));
    let stack_phys = stack_frame.start_address().as_u64();
    stack_obj
        .insert_existing_frame(0, stack_phys)
        .expect("init: freshly-mapped user stack frame cannot be saturated");
    let stack_start = USER_STACK_PAGE_VA as usize;
    let mut stack_vma = Vma::new(
        stack_start,
        USER_STACK_TOP as usize,
        0x3, // PROT_READ|WRITE
        stack_flags.bits(),
        Share::Private,
        stack_obj as Arc<dyn VmObject>,
        0,
    );
    stack_vma.vma_flags = VMA_GROWSDOWN;
    aspace.insert(stack_vma);

    // Guard VMA: one page immediately below the maximum stack extent
    // (RLIMIT_STACK = 8 MiB below stack top). The guard must NOT be
    // adjacent to the initial stack page — that would block all growth.
    // Any fault past the RLIMIT boundary reaches the guard → SIGSEGV.
    use crate::mem::pf::DEFAULT_STACK_RLIMIT;
    let max_stack_bottom = (USER_STACK_TOP as u64)
        .saturating_sub(DEFAULT_STACK_RLIMIT)
        .saturating_sub(4096) as usize; // one guard page below the limit
    let guard_top = max_stack_bottom + 4096;
    let guard_obj = crate::mem::vmobject::AnonObject::new(Some(0));
    let mut guard_vma = Vma::new(
        max_stack_bottom,
        guard_top,
        0x0, // PROT_NONE
        0,   // prot_pte: no PTE flags
        Share::Private,
        guard_obj,
        0,
    );
    guard_vma.vma_flags = VMA_STACK_GUARD;
    aspace.insert(guard_vma);

    serial_println!(
        "init: user stack at virt={:#x} top={:#x}",
        USER_STACK_PAGE_VA,
        USER_STACK_TOP
    );

    // 3b. Write the System V AMD64 initial stack layout (argc/argv/envp/auxv)
    //     into the stack frame via the HHDM window before ring-3 entry.
    //     AT_RANDOM comes from RDRAND/RDSEED; if the CPU supports neither
    //     (e.g. QEMU without `-cpu max`), fall back to a documented-insecure
    //     XOR-splat with a boot-time warning.
    let random_bytes = match crate::arch::x86_64::csprng::rdrand16() {
        Some(b) => b,
        None => {
            serial_println!(
                "init: WARNING — RDRAND/RDSEED unavailable, AT_RANDOM is deterministic"
            );
            crate::arch::x86_64::csprng::deterministic_at_random_fallback(
                image.entry.as_u64() ^ stack_phys,
            )
        }
    };
    let auxv_params = crate::mem::auxv::AuxvParams {
        entry: image.entry.as_u64(),
        interp_base: image.interp_base.unwrap_or(0),
        phdr_vaddr: image.phdr_vaddr,
        phdr_count: image.phdr_count as u64,
        phdr_entsize: image.phdr_entsize as u64,
    };
    let initial_rsp = crate::mem::auxv::write_initial_stack(
        stack_phys,
        USER_STACK_PAGE_VA,
        &auxv_params,
        &random_bytes,
    );
    serial_println!("init: auxv written, initial rsp={:#x}", initial_rsp);

    // 4. Publish entry point and stash the address space.
    // If the binary has a dynamic interpreter (PT_INTERP), jump to the
    // interpreter's entry point — it will relocate itself and the main binary
    // before transferring control to the main binary's entry. The main binary's
    // original entry point is in the auxv AT_ENTRY vector.
    let effective_entry = image.interp_entry.unwrap_or(image.entry);
    if let Some(interp_base) = image.interp_base {
        serial_println!(
            "init: dynamic interpreter at base={:#x} entry={:#x} (main entry={:#x})",
            interp_base,
            effective_entry.as_u64(),
            image.entry.as_u64(),
        );
    }
    INIT_ENTRY.store(effective_entry.as_u64(), Ordering::Release);
    INIT_STACK_PTR.store(initial_rsp, Ordering::Release);
    INIT_ADDRESS_SPACE.call_once(|| Arc::new(RwLock::new(aspace)));

    // 5. Spawn the kernel task that will drop to ring-3 and register it
    //    as PID 1 in the process table so fork()/exit()/wait() can track it.
    let task_id = crate::task::spawn_and_get_id(init_ring3_entry);
    crate::process::register_init(task_id);
    serial_println!("init: ring-3 entry task spawned (task_id={task_id}, pid=1)");
    task_id
}

/// Kernel task function for the init process. Runs once, drops to ring-3.
///
/// Execution order:
/// 1. Take the pre-built `INIT_ADDRESS_SPACE` and install it on this task,
///    replacing the empty one created by `Task::new_with_priority`.
/// 2. Write CR3 to switch to the init address space.
/// 3. Configure TSS.rsp[0] and the SYSCALL kernel stack.
/// 4. Execute `sysretq` to ring-3 — never returns.
fn init_ring3_entry() -> ! {
    let entry = INIT_ENTRY.load(Ordering::Acquire);
    assert!(entry != 0, "init_ring3_entry: INIT_ENTRY not set");
    let initial_rsp = INIT_STACK_PTR.load(Ordering::Acquire);
    assert!(initial_rsp != 0, "init_ring3_entry: INIT_STACK_PTR not set");

    // Replace this task's (empty) address space with the pre-built one.
    let init_aspace = INIT_ADDRESS_SPACE
        .get()
        .expect("init_ring3_entry: INIT_ADDRESS_SPACE not set")
        .clone();

    let pml4_frame = init_aspace.read().page_table_frame();

    // Replace the task's address space, keeping the old Arc alive until after
    // the CR3 switch so the old PML4 frame stays valid for any IRQs that fire
    // in the gap between the assignment and the write to CR3.
    let _old_aspace = crate::task::replace_current_address_space(init_aspace, pml4_frame);

    // Switch to the init process's address space.
    unsafe {
        x86_64::registers::control::Cr3::write(
            pml4_frame,
            x86_64::registers::control::Cr3Flags::empty(),
        );
    }
    // _old_aspace is dropped here — after CR3 switch, safe to free the old PML4.
    drop(_old_aspace);
    serial_println!("init: switched to process PML4");

    // Configure TSS.rsp[0] and SYSCALL_KERNEL_RSP to use this task's OWN
    // kernel stack, not the shared INIT_KERNEL_STACK. This is required for
    // multi-process correctness: each user-space task needs its own SYSCALL
    // stack so concurrent/parallel syscalls don't clobber each other.
    crate::task::arm_ring3_syscall_stack();

    serial_println!(
        "init: entering ring-3 entry={:#x} rsp={:#x}",
        entry,
        initial_rsp
    );

    // Drop to ring-3. Never returns.
    unsafe { syscall::jump_to_ring3(entry, initial_rsp) }
}
