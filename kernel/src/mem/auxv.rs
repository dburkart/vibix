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
    write_initial_stack_with_args(
        stack_phys,
        stack_page_user_va,
        params,
        random_bytes,
        &[],
        &[],
    )
}

/// Write the System V AMD64 initial stack layout with argv and envp.
///
/// `argv` and `envp` are slices of NUL-terminated byte strings. Their
/// contents are placed at the top of the stack page (below the AT_RANDOM
/// seed), and pointer arrays are built pointing into those copies.
///
/// Layout (high to low):
/// ```text
/// [16-byte AT_RANDOM seed]
/// [envp string data, NUL-terminated each]
/// [argv string data, NUL-terminated each]
/// [padding to 8-byte alignment]
/// auxv pairs (AT_NULL ... AT_PHDR)
/// envp[n] = NULL
/// envp[n-1] ... envp[0]
/// argv[argc] = NULL
/// argv[argc-1] ... argv[0]
/// argc
/// <- initial RSP
/// ```
#[cfg(target_os = "none")]
pub fn write_initial_stack_with_args(
    stack_phys: u64,
    stack_page_user_va: u64,
    params: &AuxvParams,
    random_bytes: &[u8; 16],
    argv: &[&[u8]],
    envp: &[&[u8]],
) -> u64 {
    use super::paging;

    // Map the physical frame into kernel VA space via HHDM.
    let hhdm = paging::hhdm_offset();
    let frame_base: *mut u8 = (hhdm.as_u64() + stack_phys) as *mut u8;

    // We build the layout top-down within the 4096-byte page.
    // `offset` counts bytes from the *start* of the frame (i.e. `offset`
    // is in [0, STACK_PAGE_SIZE]; we write downward from STACK_PAGE_SIZE).
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

    // 2. Place argv and envp string data at the top (below AT_RANDOM).
    //    Each string is NUL-terminated in the caller's data; we copy
    //    including the NUL. Record user-VA of each string start.
    //
    //    We use a fixed-size array to avoid heap allocation. The limit
    //    of 64 args + 64 env vars is generous for early vibix userspace.
    const MAX_STRINGS: usize = 64;
    let mut argv_vas = [0u64; MAX_STRINGS];
    let mut envp_vas = [0u64; MAX_STRINGS];

    // Copy envp strings first (higher addresses), then argv.
    for (i, env) in envp.iter().enumerate().take(MAX_STRINGS) {
        let len = env.len();
        offset -= len;
        // SAFETY: `offset` is within the frame and `len` fits.
        unsafe {
            core::ptr::copy_nonoverlapping(env.as_ptr(), frame_base.add(offset), len);
        }
        envp_vas[i] = stack_page_user_va + offset as u64;
    }

    for (i, arg) in argv.iter().enumerate().take(MAX_STRINGS) {
        let len = arg.len();
        offset -= len;
        // SAFETY: same as above.
        unsafe {
            core::ptr::copy_nonoverlapping(arg.as_ptr(), frame_base.add(offset), len);
        }
        argv_vas[i] = stack_page_user_va + offset as u64;
    }

    // SysV AMD64 ABI: rsp must be 16-byte aligned at process entry.
    // We push a known number of 8-byte words below this point (auxv pairs,
    // envp/argv pointer arrays + NULLs, and argc).  If that total is odd
    // the final rsp would land on 8-mod-16, so we start at 8-mod-16 here
    // to compensate.
    let argc = argv.len().min(MAX_STRINGS);
    let envp_count = envp.len().min(MAX_STRINGS);
    let total_words = 16 /* auxv pairs */ + 1 /* envp NULL */ + envp_count
        + 1 /* argv NULL */ + argc + 1 /* argc */;
    offset &= !15; // 16-byte align
    if total_words % 2 != 0 {
        offset -= 8;
    }

    // 3. Build auxv pairs (tag, value) top-down.
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

    // 4. envp pointer array (NULL-terminated).
    push_u64(0, &mut offset);
    for i in (0..envp_count).rev() {
        push_u64(envp_vas[i], &mut offset);
    }

    // 5. argv pointer array (NULL-terminated).
    push_u64(0, &mut offset);
    for i in (0..argc).rev() {
        push_u64(argv_vas[i], &mut offset);
    }

    // 6. argc
    push_u64(argc as u64, &mut offset);

    // Sanity: ensure we haven't overflowed into the random-seed region at the
    // top of the frame.
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

        // 16-byte align (19 words = odd, so start at 8-mod-16)
        offset &= !15;
        offset -= 8;

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

        let rsp = stack_page_user_va + rsp_offset as u64;
        assert_eq!(rsp % 16, 0, "initial rsp must be 16-byte aligned (SysV ABI)");

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

    /// Build the SysV AMD64 initial stack layout with argv/envp into a
    /// caller-supplied buffer. Mirrors `write_initial_stack_with_args`
    /// but without HHDM / kernel-paging dependency.
    fn build_layout_with_args_into_buf(
        buf: &mut [u8; 4096],
        stack_page_user_va: u64,
        params: &AuxvParams,
        random_bytes: &[u8; 16],
        argv: &[&[u8]],
        envp: &[&[u8]],
    ) -> usize {
        let mut offset: usize = 4096;

        let push = |val: u64, buf: &mut [u8; 4096], offset: &mut usize| {
            *offset -= 8;
            buf[*offset..*offset + 8].copy_from_slice(&val.to_le_bytes());
        };

        // Random bytes at the top.
        let random_va = stack_page_user_va + STACK_PAGE_SIZE - 16;
        buf[4096 - 16..4096].copy_from_slice(random_bytes);
        offset -= 16;

        // String data (envp first, then argv — higher to lower).
        const MAX_STRINGS: usize = 64;
        let mut argv_vas = [0u64; MAX_STRINGS];
        let mut envp_vas = [0u64; MAX_STRINGS];

        for (i, env) in envp.iter().enumerate().take(MAX_STRINGS) {
            offset -= env.len();
            buf[offset..offset + env.len()].copy_from_slice(env);
            envp_vas[i] = stack_page_user_va + offset as u64;
        }
        for (i, arg) in argv.iter().enumerate().take(MAX_STRINGS) {
            offset -= arg.len();
            buf[offset..offset + arg.len()].copy_from_slice(arg);
            argv_vas[i] = stack_page_user_va + offset as u64;
        }

        // 16-byte align for SysV ABI.
        let argc = argv.len().min(MAX_STRINGS);
        let envp_count = envp.len().min(MAX_STRINGS);
        let total_words = 16 + 1 + envp_count + 1 + argc + 1;
        offset &= !15;
        if total_words % 2 != 0 {
            offset -= 8;
        }

        // Auxv.
        push(0, buf, &mut offset);
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

        // envp pointers.
        push(0, buf, &mut offset);
        for i in (0..envp_count).rev() {
            push(envp_vas[i], buf, &mut offset);
        }

        // argv pointers.
        push(0, buf, &mut offset);
        for i in (0..argc).rev() {
            push(argv_vas[i], buf, &mut offset);
        }

        // argc.
        push(argc as u64, buf, &mut offset);

        offset
    }

    #[test]
    fn initial_stack_layout_with_args_is_correct() {
        let mut page = [0u8; 4096];
        let random_bytes = [0xBBu8; 16];
        let stack_page_user_va: u64 = 0x7FFF_F000;
        let params = AuxvParams {
            entry: 0x400080,
            interp_base: 0,
            phdr_vaddr: 0x400040,
            phdr_count: 2,
            phdr_entsize: 56,
        };

        // argv: ["/bin/hello\0", "world\0"]
        // envp: ["HOME=/\0"]
        let argv: &[&[u8]] = &[b"/bin/hello\0", b"world\0"];
        let envp: &[&[u8]] = &[b"HOME=/\0"];

        let rsp_offset = build_layout_with_args_into_buf(
            &mut page,
            stack_page_user_va,
            &params,
            &random_bytes,
            argv,
            envp,
        );

        let rsp = stack_page_user_va + rsp_offset as u64;
        assert_eq!(rsp % 16, 0, "initial rsp must be 16-byte aligned (SysV ABI)");

        // argc == 2
        let argc = u64::from_le_bytes(page[rsp_offset..rsp_offset + 8].try_into().unwrap());
        assert_eq!(argc, 2, "argc must be 2");

        // argv[0] pointer — must be non-null.
        let argv0_ptr =
            u64::from_le_bytes(page[rsp_offset + 8..rsp_offset + 16].try_into().unwrap());
        assert_ne!(argv0_ptr, 0, "argv[0] must be non-null");

        // argv[1] pointer — must be non-null.
        let argv1_ptr =
            u64::from_le_bytes(page[rsp_offset + 16..rsp_offset + 24].try_into().unwrap());
        assert_ne!(argv1_ptr, 0, "argv[1] must be non-null");

        // argv[2] (terminator) — must be NULL.
        let argv_null =
            u64::from_le_bytes(page[rsp_offset + 24..rsp_offset + 32].try_into().unwrap());
        assert_eq!(argv_null, 0, "argv terminator must be NULL");

        // envp[0] pointer — must be non-null.
        let envp0_ptr =
            u64::from_le_bytes(page[rsp_offset + 32..rsp_offset + 40].try_into().unwrap());
        assert_ne!(envp0_ptr, 0, "envp[0] must be non-null");

        // envp[1] (terminator) — must be NULL.
        let envp_null =
            u64::from_le_bytes(page[rsp_offset + 40..rsp_offset + 48].try_into().unwrap());
        assert_eq!(envp_null, 0, "envp terminator must be NULL");

        // Verify argv[0] string content by reading from the string data area.
        let argv0_page_offset = (argv0_ptr - stack_page_user_va) as usize;
        assert_eq!(
            &page[argv0_page_offset..argv0_page_offset + 11],
            b"/bin/hello\0",
            "argv[0] string must be '/bin/hello\\0'"
        );

        // Verify envp[0] string content.
        let envp0_page_offset = (envp0_ptr - stack_page_user_va) as usize;
        assert_eq!(
            &page[envp0_page_offset..envp0_page_offset + 7],
            b"HOME=/\0",
            "envp[0] string must be 'HOME=/\\0'"
        );

        // Walk auxv to find AT_PAGESZ (from envp_null + 8 onward).
        let auxv_start = rsp_offset + 48;
        let mut found_pagesz = false;
        let mut found_entry = false;
        let mut i = auxv_start;
        while i + 16 <= 4096 {
            let tag = u64::from_le_bytes(page[i..i + 8].try_into().unwrap());
            let val = u64::from_le_bytes(page[i + 8..i + 16].try_into().unwrap());
            if tag == AT_NULL {
                break;
            }
            if tag == AT_PAGESZ {
                assert_eq!(val, 4096);
                found_pagesz = true;
            }
            if tag == AT_ENTRY {
                assert_eq!(val, 0x400080);
                found_entry = true;
            }
            i += 16;
        }
        assert!(found_pagesz, "AT_PAGESZ not found");
        assert!(found_entry, "AT_ENTRY not found");
    }

    #[test]
    fn initial_stack_with_no_args_matches_legacy() {
        // write_initial_stack (no args) should produce the same layout as
        // write_initial_stack_with_args with empty argv/envp.
        let mut page_legacy = [0u8; 4096];
        let mut page_new = [0u8; 4096];
        let random_bytes = [0xCCu8; 16];
        let stack_page_user_va: u64 = 0x7FFF_F000;
        let params = AuxvParams {
            entry: 0x400080,
            interp_base: 0,
            phdr_vaddr: 0x400040,
            phdr_count: 3,
            phdr_entsize: 56,
        };

        let off_legacy =
            build_layout_into_buf(&mut page_legacy, stack_page_user_va, &params, &random_bytes);
        let off_new = build_layout_with_args_into_buf(
            &mut page_new,
            stack_page_user_va,
            &params,
            &random_bytes,
            &[],
            &[],
        );

        assert_eq!(off_legacy, off_new, "RSP offset must match");
        assert_eq!(page_legacy, page_new, "page content must match");
    }
}
