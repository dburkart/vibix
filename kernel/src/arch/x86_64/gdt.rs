//! GDT + TSS. A dedicated IST stack for #DF keeps double-faults from
//! triple-faulting when the current kernel stack is the thing on fire.
//!
//! The IST stack is page-aligned so that `ist_guard` can unmap the
//! lowest page as a guard: an overflow walks down past that boundary
//! and takes a #PF whose fault address pinpoints the overflow, rather
//! than silently scribbling through whatever `.bss` sits below.
//!
//! ## Segment layout (SYSCALL/SYSRET requires a specific order)
//!
//! ```text
//! index 0: null                  (selector 0x00)
//! index 1: kernel code           (selector 0x08)
//! index 2: kernel data           (selector 0x10)
//! index 3: user data             (selector 0x18, RPL=3 → 0x1b)
//! index 4: user code             (selector 0x20, RPL=3 → 0x23)
//! index 5+6: TSS (64-bit)        (selector 0x28)
//! ```
//!
//! STAR MSR encodes:
//! - bits[47:32] = 0x0008  (SYSCALL sets CS=0x08, SS=0x10)
//! - bits[63:48] = 0x0010  (SYSRETQ sets CS=0x10+16=0x20|3, SS=0x10+8=0x18|3)

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Lazy;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, FS, GS, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::registers::segmentation::SegmentSelector;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// 20 KiB total. The lowest 4 KiB becomes the guard page once paging
/// is up, leaving 16 KiB of usable stack — comfortable for the
/// handful of instructions a #DF handler needs to run.
const STACK_SIZE: usize = 4096 * 5;

#[repr(C, align(4096))]
struct PageAligned<const N: usize>([u8; N]);

static mut DOUBLE_FAULT_STACK: PageAligned<STACK_SIZE> = PageAligned([0; STACK_SIZE]);

/// User-mode code segment selector (RPL=3). Used by ring-3 entry and SYSRETQ.
pub const USER_CODE_SELECTOR: u16 = 0x20 | 3;
/// User-mode data/stack segment selector (RPL=3). Used by ring-3 entry and SYSRETQ.
pub const USER_DATA_SELECTOR: u16 = 0x18 | 3;

/// IA32_STAR SYSCALL field: kernel CS base (bits[47:32] of STAR MSR).
/// SYSCALL loads CS=0x08, SS=0x10.
pub const STAR_KERNEL_CS_BASE: u16 = 0x0008;
/// IA32_STAR SYSRET field: user base (bits[63:48] of STAR MSR).
/// SYSRETQ loads CS=0x10+16=0x20|3, SS=0x10+8=0x18|3.
pub const STAR_USER_CS_BASE: u16 = 0x0010;

/// RSP0 for the TSS — updated before ring-3 entry so exceptions from
/// user mode land on a valid kernel stack. Protected by caller: call
/// `set_tss_rsp0` while running at ring-0 with a known-good stack top
/// before executing `iretq` to user space.
static TSS_RSP0: AtomicU64 = AtomicU64::new(0);

/// Virtual address of the first byte of `DOUBLE_FAULT_STACK`. This is
/// the start of the 4 KiB page that `ist_guard` unmaps.
pub fn df_stack_guard_addr() -> VirtAddr {
    VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK)
}

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        df_stack_guard_addr() + STACK_SIZE as u64;
    // rsp[0] is used by the CPU to switch stacks when an exception or
    // IRQ fires from ring-3. We initialise it from TSS_RSP0 so that
    // callers who set it after GDT init (via set_tss_rsp0) get the right
    // value; it will be 0 until set_tss_rsp0 is called. The TSS lives in
    // a static, so in-place mutation after Lazy init is fine — the GDT
    // descriptor points to the struct, not to a copy.
    tss.privilege_stack_table[0] = VirtAddr::new(TSS_RSP0.load(Ordering::Relaxed));
    tss
});

struct Selectors {
    code: SegmentSelector,
    data: SegmentSelector,
    tss: SegmentSelector,
}

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let code = gdt.append(Descriptor::kernel_code_segment());
    let data = gdt.append(Descriptor::kernel_data_segment());
    // User segments must come before the TSS so SYSCALL/SYSRET selector
    // arithmetic lands at the indices the STAR MSR encodes.
    gdt.append(Descriptor::user_data_segment());
    gdt.append(Descriptor::user_code_segment());
    let tss = gdt.append(Descriptor::tss_segment(&TSS));
    (gdt, Selectors { code, data, tss })
});

pub fn init() {
    GDT.0.load();
    let sel = &GDT.1;
    unsafe {
        CS::set_reg(sel.code);
        DS::set_reg(sel.data);
        ES::set_reg(sel.data);
        FS::set_reg(sel.data);
        GS::set_reg(sel.data);
        SS::set_reg(sel.data);
        load_tss(sel.tss);
    }
}

/// Update `TSS.rsp[0]` to `stack_top` so that subsequent interrupts or
/// exceptions from ring-3 use `stack_top` as the kernel RSP.
///
/// The `TaskStateSegment` is a static — the CPU's TSS descriptor points
/// directly to it, so writing through a pointer is immediately visible
/// to the hardware on the next privilege-level change.
///
/// # Safety
/// Caller must ensure `stack_top` points to a valid, writable kernel
/// stack that will remain live for as long as ring-3 code may run on
/// this CPU.
pub fn set_tss_rsp0(stack_top: u64) {
    // Store in the atomic so the Lazy initializer could read it early,
    // then write directly into the live TSS struct in memory.
    TSS_RSP0.store(stack_top, Ordering::Relaxed);
    // SAFETY: `TSS` is a `Lazy<TaskStateSegment>` — after `init()` forces
    // the Lazy, the struct is live at a stable address. The CPU reads
    // rsp[0] only on privilege changes (ring-3 → ring-0), not continuously,
    // so writing here races with no hardware access.
    let tss_ptr: *mut TaskStateSegment = &*TSS as *const _ as *mut _;
    unsafe {
        (*tss_ptr).privilege_stack_table[0] = VirtAddr::new(stack_top);
    }
}
