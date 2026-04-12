//! GDT + TSS. A dedicated IST stack for #DF keeps double-faults from
//! triple-faulting when the current kernel stack is the thing on fire.
//!
//! The IST stack is page-aligned so that `ist_guard` can unmap the
//! lowest page as a guard: an overflow walks down past that boundary
//! and takes a #PF whose fault address pinpoints the overflow, rather
//! than silently scribbling through whatever `.bss` sits below.

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

/// Virtual address of the first byte of `DOUBLE_FAULT_STACK`. This is
/// the start of the 4 KiB page that `ist_guard` unmaps.
pub fn df_stack_guard_addr() -> VirtAddr {
    VirtAddr::from_ptr(&raw const DOUBLE_FAULT_STACK)
}

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] =
        df_stack_guard_addr() + STACK_SIZE as u64;
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
