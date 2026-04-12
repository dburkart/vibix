//! Guard page at the low end of the #DF IST stack.
//!
//! The double-fault handler runs on a dedicated 20 KiB stack carved
//! out of `.bss` (see `gdt.rs`). If the handler overflows that stack,
//! there is no next-level fault to catch us — we'd silently corrupt
//! whatever came before it in `.bss`. We fix that by unmapping the
//! lowest 4 KiB of the stack once paging is up: an overflow past that
//! boundary now takes a #PF with a fault address that pinpoints the
//! overflow, instead of turning into memory corruption.
//!
//! The TSS still points at the *high* end of the stack. Usable stack
//! shrinks from 20 KiB to 16 KiB — plenty for the handler.

use x86_64::structures::paging::{Page, Size4KiB};

use super::gdt;
use crate::mem::paging;
use crate::serial_println;

pub fn install() {
    let guard = gdt::df_stack_guard_addr();
    // `from_start_address` instead of `containing_address`: the guard VA
    // must be exactly page-aligned — otherwise we'd silently round down
    // and unmap something that isn't the guard.
    let page: Page<Size4KiB> =
        Page::from_start_address(guard).expect("IST guard address must be page-aligned");
    paging::unmap(page).expect("failed to unmap IST guard page");
    serial_println!("paging: IST guard installed @ {:#x}", guard.as_u64());
}
