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

/// Auxv tag constants (System V AMD64 ABI).
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_ENTRY: u64 = 9;
pub const AT_RANDOM: u64 = 25;

/// Page size reported to user space.
pub const STACK_PAGE_SIZE: u64 = 4096;

/// Parameters for the System V AMD64 initial stack layout.
///
/// Passed to [`write_initial_stack`] so the layout logic is decoupled from
/// the `LoadedImage` type (which lives in `loader`, a kernel-only module).
pub struct AuxvParams {
    /// Main binary entry point (AT_ENTRY).
    pub entry: u64,
    /// Interpreter load base, or 0 if statically linked (AT_BASE).
    pub interp_base: u64,
    /// Virtual address of the main binary's program-header table (AT_PHDR).
    pub phdr_vaddr: u64,
    /// Number of program-header entries (AT_PHNUM).
    pub phdr_count: u64,
    /// Size of each program-header entry in bytes (AT_PHENT).
    pub phdr_entsize: u64,
}

/// Write the System V AMD64 initial stack layout into the physical frame
/// `stack_phys` via the HHDM window.
///
/// `params` provides the auxv values. `stack_page_user_va` is the user-space
/// VA of the base of the stack page (used to compute `AT_RANDOM`'s
/// user-space address). `random_bytes` is the 16-byte seed placed at the top
/// of the frame for `AT_RANDOM`.
///
/// Returns the new user RSP: the virtual address of the `argc` word at the
/// bottom of the constructed layout.
///
/// # Panics
///
/// Panics if the layout would exceed 4096 bytes (the single-page stack frame).
#[cfg(target_os = "none")]
pub fn write_initial_stack(
    stack_phys: u64,
    stack_page_user_va: u64,
    params: &AuxvParams,
    random_bytes: &[u8; 16],
) -> u64 {
    use super::paging;

    // Map the physical frame into kernel VA space via HHDM.
    let hhdm = paging::hhdm_offset();
    let frame_base: *mut u8 = (hhdm.as_u64() + stack_phys) as *mut u8;

    // We build the layout top-down within the 4096-byte page.
    // `offset` counts bytes from the *top* of the frame.
    let mut offset: usize = STACK_PAGE_SIZE as usize;

    // Helper: write a u64 word top-down.
    let push_u64 = |val: u64, offset: &mut usize| {
        *offset -= 8;
        // SAFETY: frame_base points to a writable HHDM-mapped frame;
        // `offset` stays within [0, STACK_PAGE_SIZE).
        unsafe {
            core::ptr::write_unaligned(frame_base.add(*offset).cast::<u64>(), val);
        }
    };

    // 1. Place the 16 AT_RANDOM bytes at the very top of the frame.
    //    Their user-space VA is the top of the page minus 16.
    let random_va = stack_page_user_va + STACK_PAGE_SIZE - 16;
    // SAFETY: frame_base + (PAGE_SIZE - 16) is within the same 4KiB frame.
    unsafe {
        core::ptr::copy_nonoverlapping(
            random_bytes.as_ptr(),
            frame_base.add(STACK_PAGE_SIZE as usize - 16),
            16,
        );
    }
    offset -= 16;

    // 2. Build auxv pairs (tag, value) top-down.
    //    Written high→low: AT_NULL first (highest), then AT_PAGESZ, ..., AT_PHDR last.
    //    The loader reads low→high: AT_PHDR, AT_PHENT, ..., AT_PAGESZ, AT_NULL.
    //    Both orderings are valid per the ABI (auxv is an unordered array
    //    terminated by AT_NULL).

    push_u64(0, &mut offset); // AT_NULL value
    push_u64(AT_NULL, &mut offset);

    push_u64(STACK_PAGE_SIZE, &mut offset);
    push_u64(AT_PAGESZ, &mut offset);

    push_u64(random_va, &mut offset);
    push_u64(AT_RANDOM, &mut offset);

    push_u64(params.entry, &mut offset);
    push_u64(AT_ENTRY, &mut offset);

    push_u64(params.interp_base, &mut offset);
    push_u64(AT_BASE, &mut offset);

    push_u64(params.phdr_count, &mut offset);
    push_u64(AT_PHNUM, &mut offset);

    push_u64(params.phdr_entsize, &mut offset);
    push_u64(AT_PHENT, &mut offset);

    push_u64(params.phdr_vaddr, &mut offset);
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
        offset + 16 <= STACK_PAGE_SIZE as usize,
        "auxv: initial stack layout exceeds page boundary"
    );

    // The initial RSP is the user-space VA of the `argc` word we just wrote.
    stack_page_user_va + offset as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    // Build the SysV AMD64 initial stack layout into a caller-supplied buffer
    // without any HHDM / kernel-paging dependency. Used by tests to verify
    // the layout without booting a kernel.
    fn build_layout_into_buf(
        buf: &mut [u8; 4096],
        stack_page_user_va: u64,
        params: &AuxvParams,
        random_bytes: &[u8; 16],
    ) -> usize {
        let mut offset: usize = 4096;

        let push = |val: u64, buf: &mut [u8; 4096], offset: &mut usize| {
            *offset -= 8;
            buf[*offset..*offset + 8].copy_from_slice(&val.to_le_bytes());
        };

        // Random bytes at the top
        let random_va = stack_page_user_va + STACK_PAGE_SIZE - 16;
        buf[4096 - 16..4096].copy_from_slice(random_bytes);
        offset -= 16;

        push(0, buf, &mut offset); // AT_NULL value
        push(AT_NULL, buf, &mut offset);
        push(STACK_PAGE_SIZE, buf, &mut offset);
        push(AT_PAGESZ, buf, &mut offset);
        push(random_va, buf, &mut offset);
        push(AT_RANDOM, buf, &mut offset);
        push(params.entry, buf, &mut offset);
        push(AT_ENTRY, buf, &mut offset);
        push(params.interp_base, buf, &mut offset);
        push(AT_BASE, buf, &mut offset);
        push(params.phdr_count, buf, &mut offset);
        push(AT_PHNUM, buf, &mut offset);
        push(params.phdr_entsize, buf, &mut offset);
        push(AT_PHENT, buf, &mut offset);
        push(params.phdr_vaddr, buf, &mut offset);
        push(AT_PHDR, buf, &mut offset);
        push(0, buf, &mut offset); // envp NULL
        push(0, buf, &mut offset); // argv NULL
        push(0, buf, &mut offset); // argc

        offset
    }

    #[test]
    fn initial_stack_layout_is_correct() {
        let mut page = [0u8; 4096];
        let random_bytes = [0xAAu8; 16];
        let stack_page_user_va: u64 = 0x7FFF_F000;
        let params = AuxvParams {
            entry: 0x400080,
            interp_base: 0,
            phdr_vaddr: 0x400040,
            phdr_count: 3,
            phdr_entsize: 56,
        };

        let rsp_offset =
            build_layout_into_buf(&mut page, stack_page_user_va, &params, &random_bytes);

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
