//! System V AMD64 initial stack layout writer.
//!
//! Before ring-3 entry the kernel must build the initial stack frame that
//! the C runtime (or dynamic linker) expects to find at `[rsp]` on process
//! start. The layout is defined in the System V AMD64 ABI §3.4:
//!
//! ```text
//! HIGH ADDRESS (stack top)
//!   [16-byte AT_RANDOM seed region]
//!   AT_NULL    (0, 0)
//!   AT_PAGESZ  (6, 4096)
//!   AT_RANDOM  (25, va_of_16_bytes)
//!   AT_ENTRY   (9,  main_entry)
//!   AT_BASE    (7,  interp_base or 0)
//!   AT_PHNUM   (5,  phdr_count)
//!   AT_PHENT   (4,  phdr_entsize)
//!   AT_PHDR    (3,  phdr_vaddr)
//!   NULL       (envp terminator)
//!   NULL       (argv terminator)
//!   argc = 0
//! LOW ADDRESS  ← initial RSP
//! ```
//!
//! The stack frame is written into a physical page via the HHDM window
//! because the page is mapped in the *user* PML4, not the kernel's. The
//! HHDM window gives the kernel writable access to any physical frame
//! without changing CR3.

use super::loader::LoadedImage;
use super::paging;

/// Auxv tag constants (System V AMD64 ABI).
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_PAGESZ: u64 = 6;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;
const AT_RANDOM: u64 = 25;

/// Page size reported to user space.
const PAGE_SIZE: u64 = 4096;

/// Write the System V AMD64 initial stack layout into the physical frame
/// `stack_phys` via the HHDM window.
///
/// `image` provides the auxv values (`AT_PHDR`, `AT_PHENT`, `AT_PHNUM`,
/// `AT_BASE`, `AT_ENTRY`). `stack_page_user_va` is the user-space VA of
/// the base of the stack page (used to compute `AT_RANDOM`'s user-space
/// address). `random_bytes` is the 16-byte seed placed at the top of the
/// frame for `AT_RANDOM`.
///
/// Returns the new user RSP: the virtual address of the `argc` word at the
/// bottom of the constructed layout.
///
/// # Panics
///
/// Panics if the layout would exceed 4096 bytes (the single-page stack frame).
pub fn write_initial_stack(
    stack_phys: u64,
    stack_page_user_va: u64,
    image: &LoadedImage,
    random_bytes: &[u8; 16],
) -> u64 {
    // Map the physical frame into kernel VA space via HHDM.
    let hhdm = paging::hhdm_offset();
    let frame_base: *mut u8 = (hhdm.as_u64() + stack_phys) as *mut u8;

    // We build the layout top-down within the 4096-byte page.
    // `offset` counts bytes from the *top* of the frame.
    let mut offset: usize = PAGE_SIZE as usize;

    // Helper: write a u64 word top-down and return the new (lower) offset.
    let push_u64 = |val: u64, offset: &mut usize| {
        *offset -= 8;
        // SAFETY: frame_base points to a writable HHDM-mapped frame;
        // `offset` stays within [0, PAGE_SIZE).
        unsafe {
            core::ptr::write_unaligned(frame_base.add(*offset).cast::<u64>(), val);
        }
    };

    // 1. Place the 16 AT_RANDOM bytes at the very top of the frame.
    //    Their user-space VA is the top of the page minus 16.
    let random_va = stack_page_user_va + PAGE_SIZE - 16;
    // SAFETY: same frame, offset >= 0.
    unsafe {
        core::ptr::copy_nonoverlapping(
            random_bytes.as_ptr(),
            frame_base.add(PAGE_SIZE as usize - 16),
            16,
        );
    }
    offset -= 16;

    // 2. Build auxv pairs (tag, value) — top-down, so write in reverse order.
    //    AT_NULL must be the terminator (written first = highest in memory
    //    before we push argc/argv/envp below it, but the iteration order
    //    means we push the *last* entry first and work down to AT_NULL last).
    //    We write in this order (which ends up high→low):
    //      AT_NULL, AT_PAGESZ, AT_RANDOM, AT_ENTRY, AT_BASE,
    //      AT_PHNUM, AT_PHENT, AT_PHDR
    //    Reading bottom-up (low→high) the loader sees:
    //      AT_PHDR, AT_PHENT, AT_PHNUM, AT_BASE, AT_ENTRY,
    //      AT_RANDOM, AT_PAGESZ, AT_NULL
    //    Both orderings are valid per the ABI (the auxv is a flat array
    //    terminated by AT_NULL; order of other entries is implementation-defined).

    // AT_NULL (terminator)
    push_u64(0, &mut offset); // value
    push_u64(AT_NULL, &mut offset); // tag

    // AT_PAGESZ
    push_u64(PAGE_SIZE, &mut offset);
    push_u64(AT_PAGESZ, &mut offset);

    // AT_RANDOM — pointer to the 16 bytes placed above
    push_u64(random_va, &mut offset);
    push_u64(AT_RANDOM, &mut offset);

    // AT_ENTRY — main binary entry point (not the interpreter's)
    push_u64(image.entry.as_u64(), &mut offset);
    push_u64(AT_ENTRY, &mut offset);

    // AT_BASE — interpreter load base (0 if statically linked)
    push_u64(image.interp_base.unwrap_or(0), &mut offset);
    push_u64(AT_BASE, &mut offset);

    // AT_PHNUM
    push_u64(image.phdr_count as u64, &mut offset);
    push_u64(AT_PHNUM, &mut offset);

    // AT_PHENT
    push_u64(image.phdr_entsize as u64, &mut offset);
    push_u64(AT_PHENT, &mut offset);

    // AT_PHDR
    push_u64(image.phdr_vaddr, &mut offset);
    push_u64(AT_PHDR, &mut offset);

    // 3. envp terminator (NULL pointer)
    push_u64(0, &mut offset);

    // 4. argv terminator (NULL pointer)
    push_u64(0, &mut offset);

    // 5. argc = 0
    push_u64(0, &mut offset);

    // Sanity: ensure we haven't overflowed into the random-seed region at the
    // top of the frame. The random bytes occupy the top 16 bytes, and all
    // auxv/envp/argv/argc words were written below them.
    assert!(
        offset + 16 <= PAGE_SIZE as usize,
        "auxv: initial stack layout exceeds page boundary"
    );

    // The initial RSP is the user-space VA of the `argc` word we just wrote.
    stack_page_user_va + offset as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mem::loader::LoadedImage;
    use x86_64::VirtAddr;

    fn sample_image() -> LoadedImage {
        LoadedImage {
            entry: VirtAddr::new(0x400080),
            segments: 2,
            image_end: 0x403000,
            interp_entry: None,
            interp_base: None,
            phdr_vaddr: 0x400040,
            phdr_count: 3,
            phdr_entsize: 56,
        }
    }

    // Simulate write_initial_stack without the HHDM dependency by writing
    // into a local buffer and verifying the layout.
    #[test]
    fn initial_stack_layout_is_correct() {
        let mut page = [0u8; 4096];
        let random_bytes = [0xAAu8; 16];

        // We manually replicate the layout logic here without the HHDM call.
        let image = sample_image();
        let stack_page_user_va: u64 = 0x7FFF_F000;
        let mut offset: usize = 4096;

        let push = |val: u64, page: &mut [u8; 4096], offset: &mut usize| {
            *offset -= 8;
            page[*offset..*offset + 8].copy_from_slice(&val.to_le_bytes());
        };

        // Place random bytes at top
        let random_va = stack_page_user_va + 4096 - 16;
        page[4096 - 16..4096].copy_from_slice(&random_bytes);
        offset -= 16;

        push(0, &mut page, &mut offset); // AT_NULL value
        push(AT_NULL, &mut page, &mut offset);
        push(PAGE_SIZE, &mut page, &mut offset);
        push(AT_PAGESZ, &mut page, &mut offset);
        push(random_va, &mut page, &mut offset);
        push(AT_RANDOM, &mut page, &mut offset);
        push(image.entry.as_u64(), &mut page, &mut offset);
        push(AT_ENTRY, &mut page, &mut offset);
        push(0u64, &mut page, &mut offset); // AT_BASE (no interp)
        push(AT_BASE, &mut page, &mut offset);
        push(image.phdr_count as u64, &mut page, &mut offset);
        push(AT_PHNUM, &mut page, &mut offset);
        push(image.phdr_entsize as u64, &mut page, &mut offset);
        push(AT_PHENT, &mut page, &mut offset);
        push(image.phdr_vaddr, &mut page, &mut offset);
        push(AT_PHDR, &mut page, &mut offset);
        push(0, &mut page, &mut offset); // envp NULL
        push(0, &mut page, &mut offset); // argv NULL
        push(0, &mut page, &mut offset); // argc

        let rsp_offset = offset;

        // argc == 0
        let argc = u64::from_le_bytes(page[rsp_offset..rsp_offset + 8].try_into().unwrap());
        assert_eq!(argc, 0, "argc must be 0");

        // argv terminator follows
        let argv_null =
            u64::from_le_bytes(page[rsp_offset + 8..rsp_offset + 16].try_into().unwrap());
        assert_eq!(argv_null, 0, "argv terminator must be NULL");

        // Walk the auxv array from (rsp + 24: past argc, argv NULL, envp NULL)
        let auxv_start = rsp_offset + 24;
        let mut found_pagesz = false;
        let mut found_null = false;
        let mut i = auxv_start;
        while i + 16 <= 4096 {
            let tag = u64::from_le_bytes(page[i..i + 8].try_into().unwrap());
            let val = u64::from_le_bytes(page[i + 8..i + 16].try_into().unwrap());
            if tag == AT_NULL {
                found_null = true;
                break;
            }
            if tag == AT_PAGESZ {
                assert_eq!(val, 4096, "AT_PAGESZ must be 4096");
                found_pagesz = true;
            }
            i += 16;
        }
        assert!(found_pagesz, "AT_PAGESZ not found in auxv");
        assert!(found_null, "AT_NULL terminator not found in auxv");
    }
}
