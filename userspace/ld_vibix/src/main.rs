//! `ld-vibix.so` — minimal Rust-based dynamic linker for vibix.
//!
//! This linker performs eager binding (all relocations resolved at load
//! time, no lazy PLT). It is loaded by the kernel at `INTERP_LOAD_BASE`
//! (0x4000_0000) and receives control before the main executable.
//!
//! Responsibilities:
//!   1. Self-relocate via own `.rela.dyn`
//!   2. Parse the main executable's PT_DYNAMIC and PT_LOAD segments
//!   3. Load DT_NEEDED shared libraries (walk PT_LOAD segments)
//!   4. Resolve relocations in the main binary and all loaded libraries
//!   5. Set up TLS (allocate block, set FS base via arch_prctl)
//!   6. Transfer control to the main executable's e_entry

#![no_std]
#![no_main]
#![allow(dead_code)]

use core::panic::PanicInfo;
use core::ptr;
use core::slice;

mod elf;
mod reloc;
mod serial;

/// The kernel loads us at this fixed base address.
const INTERP_LOAD_BASE: u64 = 0x4000_0000;

/// Maximum number of loaded shared objects (including the main binary).
const MAX_LOADED: usize = 8;

/// Shared library load base — libraries are placed starting here,
/// each page-aligned after the previous.
const LIB_LOAD_BASE: u64 = 0x5000_0000;

// Syscall numbers (Linux x86_64 ABI).
const SYS_WRITE: u64 = 1;
const SYS_MMAP: u64 = 9;
const SYS_MPROTECT: u64 = 10;
const SYS_EXIT: u64 = 60;
const SYS_ARCH_PRCTL: u64 = 158;
const SYS_OPEN: u64 = 2;
const SYS_READ: u64 = 0;
const SYS_CLOSE: u64 = 3;
const SYS_FSTAT: u64 = 5;

// mmap constants.
const PROT_READ: u64 = 1;
const PROT_WRITE: u64 = 2;
const PROT_EXEC: u64 = 4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;
const MAP_FIXED: u64 = 0x10;

// open flags.
const O_RDONLY: u64 = 0;

// arch_prctl subcommands.
const ARCH_SET_FS: u64 = 0x1002;

/// A loaded ELF object (main binary or shared library).
#[derive(Clone, Copy)]
struct LoadedObject {
    /// Base address where PT_LOAD segment 0 was mapped.
    base: u64,
    /// Pointer to the ELF's .dynamic section (relocated).
    dynamic: u64,
    /// Symbol table (.dynsym) pointer.
    symtab: u64,
    /// String table (.dynstr) pointer.
    strtab: u64,
    /// .rela.dyn pointer and size.
    rela: u64,
    rela_size: u64,
    /// .rela.plt (DT_JMPREL) pointer and size.
    jmprel: u64,
    jmprel_size: u64,
    /// DT_NEEDED strtab offsets (up to 4 deps).
    needed: [u64; 4],
    needed_count: usize,
    /// SONAME strtab offset (0 if none).
    soname_offset: u64,
}

impl LoadedObject {
    const fn zeroed() -> Self {
        Self {
            base: 0,
            dynamic: 0,
            symtab: 0,
            strtab: 0,
            rela: 0,
            rela_size: 0,
            jmprel: 0,
            jmprel_size: 0,
            needed: [0; 4],
            needed_count: 0,
            soname_offset: 0,
        }
    }

    /// Get the SONAME as a byte slice (or empty if none).
    unsafe fn soname(&self) -> &[u8] {
        if self.strtab == 0 || self.soname_offset == 0 {
            return b"";
        }
        let ptr = (self.strtab + self.soname_offset) as *const u8;
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        slice::from_raw_parts(ptr, len)
    }
}

/// Global table of loaded objects.
static mut LOADED: [LoadedObject; MAX_LOADED] = [LoadedObject::zeroed(); MAX_LOADED];
static mut LOADED_COUNT: usize = 0;

// ─── Entry point ───��───────────────────────────────────────────────────────

/// Naked entry point. The kernel jumps here with the stack set up per
/// the System V x86_64 ABI initial process stack:
///   [rsp]     = argc
///   [rsp+8]   = argv[0] ... argv[argc-1]
///   [rsp+8*(argc+1)] = NULL
///   ... envp ...
///   NULL
///   auxv pairs
///
/// We pass rsp to `_dl_start` which does all the work.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!(
        "mov rdi, rsp",  // pass stack pointer as arg
        "call _dl_start",
        // _dl_start should not return, but if it does:
        "ud2",
    )
}

/// Main linker logic. `stack` points to the initial process stack
/// (argc, argv, envp, auxv).
#[no_mangle]
unsafe extern "C" fn _dl_start(stack: *const u64) -> ! {
    // Step 0: Self-relocate. We know our own base is INTERP_LOAD_BASE.
    self_relocate();

    // Step 1: Parse auxv to find the main executable's program headers.
    let auxv = parse_auxv(stack);

    serial::puts(b"ld-vibix: starting dynamic linker\n");

    // Step 2: Parse the main binary's program headers to find PT_DYNAMIC.
    let main_obj = parse_main_binary(&auxv);
    LOADED[0] = main_obj;
    LOADED_COUNT = 1;

    // Step 3: Load DT_NEEDED libraries.
    load_needed_libraries();

    // Step 4: Perform relocations on all loaded objects.
    relocate_all();

    // Step 5: Set up TLS if needed (simple: just set FS base to a zeroed page).
    setup_tls(&auxv);

    serial::puts(b"ld-vibix: transferring control to main binary\n");

    // Step 6: Jump to the main binary's entry point.
    let entry = auxv.entry;
    jump_to_entry(entry, stack);
}

// ─── Auxiliary vector parsing ──────────────────────────────────────────────

/// Relevant auxv entries.
struct Auxv {
    phdr: u64,
    phnum: u64,
    phent: u64,
    entry: u64,
    base: u64, // AT_BASE = interpreter load base
}

// auxv type constants.
const AT_NULL: u64 = 0;
const AT_PHDR: u64 = 3;
const AT_PHENT: u64 = 4;
const AT_PHNUM: u64 = 5;
const AT_BASE: u64 = 7;
const AT_ENTRY: u64 = 9;

unsafe fn parse_auxv(stack: *const u64) -> Auxv {
    let argc = *stack as usize;
    // Skip: argc, argv[0..argc], NULL, envp..., NULL
    let mut ptr = stack.add(1 + argc + 1); // past argv + NULL
    // Skip envp
    while *ptr != 0 {
        ptr = ptr.add(1);
    }
    ptr = ptr.add(1); // past envp NULL

    let mut auxv = Auxv {
        phdr: 0,
        phnum: 0,
        phent: 0,
        entry: 0,
        base: 0,
    };

    loop {
        let a_type = *ptr;
        let a_val = *ptr.add(1);
        ptr = ptr.add(2);
        match a_type {
            AT_NULL => break,
            AT_PHDR => auxv.phdr = a_val,
            AT_PHENT => auxv.phent = a_val,
            AT_PHNUM => auxv.phnum = a_val,
            AT_ENTRY => auxv.entry = a_val,
            AT_BASE => auxv.base = a_val,
            _ => {}
        }
    }

    auxv
}

// ─── Self-relocation ───────────────────────────────────────────────────────

/// Self-relocate using our own .rela.dyn. At this point no global data
/// is usable, so we operate purely on the raw addresses.
unsafe fn self_relocate() {
    // We find our own .rela.dyn by scanning our own ELF headers.
    // Our base is INTERP_LOAD_BASE. Parse the ELF header at that address.
    let base = INTERP_LOAD_BASE;
    let ehdr = base as *const elf::Elf64Ehdr;

    // Find PT_DYNAMIC in our own program headers.
    let phoff = (*ehdr).e_phoff;
    let phnum = (*ehdr).e_phnum as u64;
    let phent = (*ehdr).e_phentsize as u64;

    let mut dyn_ptr: u64 = 0;
    for i in 0..phnum {
        let ph = (base + phoff + i * phent) as *const elf::Elf64Phdr;
        if (*ph).p_type == elf::PT_DYNAMIC {
            dyn_ptr = base + (*ph).p_vaddr;
            break;
        }
    }

    if dyn_ptr == 0 {
        // No PT_DYNAMIC — nothing to relocate.
        return;
    }

    // Walk .dynamic to find DT_RELA, DT_RELASZ.
    let mut rela_off: u64 = 0;
    let mut rela_sz: u64 = 0;
    let mut d = dyn_ptr as *const elf::Elf64Dyn;
    loop {
        let tag = (*d).d_tag;
        if tag == 0 {
            break; // DT_NULL
        }
        match tag {
            7 => rela_off = (*d).d_val, // DT_RELA
            8 => rela_sz = (*d).d_val,  // DT_RELASZ
            _ => {}
        }
        d = d.add(1);
    }

    if rela_off == 0 || rela_sz == 0 {
        return;
    }

    let rela_ptr = (base + rela_off) as *const elf::Elf64Rela;
    let count = rela_sz / core::mem::size_of::<elf::Elf64Rela>() as u64;

    for i in 0..count {
        let r = &*rela_ptr.add(i as usize);
        let r_type = (r.r_info & 0xFFFF_FFFF) as u32;

        match r_type {
            elf::R_X86_64_RELATIVE => {
                // *target = base + addend
                let target = (base + r.r_offset) as *mut u64;
                *target = base.wrapping_add(r.r_addend as u64);
            }
            _ => {}
        }
    }
}

// ─── Main binary parsing ───────────────────────��───────────────────────────

/// Parse the main binary's program headers (from auxv) and extract its
/// PT_DYNAMIC section.
unsafe fn parse_main_binary(auxv: &Auxv) -> LoadedObject {
    let mut obj = LoadedObject::zeroed();

    // The main binary is loaded at its linked address (typically 0x400000).
    // We derive its base from AT_PHDR - phdr_file_offset. For simplicity,
    // since userspace binaries link at 0x400000 with phdr at a known offset,
    // we compute base = AT_PHDR & ~0xFFF (page containing the ELF header).
    // Actually, more precisely: walk the PHDR entries to find PT_PHDR or
    // just use AT_PHDR - ehdr.e_phoff. But we don't have the ehdr easily.
    // For vibix, the main binary is always loaded at its linked vaddr, so
    // base offset = 0 (no ASLR, static base).
    obj.base = 0;

    // Find PT_DYNAMIC.
    let phdr_base = auxv.phdr as *const u8;
    for i in 0..auxv.phnum {
        let ph = phdr_base.add((i * auxv.phent) as usize) as *const elf::Elf64Phdr;
        if (*ph).p_type == elf::PT_DYNAMIC {
            obj.dynamic = (*ph).p_vaddr + obj.base;
            break;
        }
    }

    if obj.dynamic != 0 {
        parse_dynamic(&mut obj);
    }

    obj
}

/// Parse a .dynamic section and fill in the LoadedObject fields.
unsafe fn parse_dynamic(obj: &mut LoadedObject) {
    let mut d = obj.dynamic as *const elf::Elf64Dyn;
    loop {
        let tag = (*d).d_tag;
        if tag == 0 {
            break;
        }
        match tag {
            elf::DT_STRTAB => obj.strtab = (*d).d_val + obj.base,
            elf::DT_SYMTAB => obj.symtab = (*d).d_val + obj.base,
            elf::DT_RELA => obj.rela = (*d).d_val + obj.base,
            elf::DT_RELASZ => obj.rela_size = (*d).d_val,
            elf::DT_JMPREL => obj.jmprel = (*d).d_val + obj.base,
            elf::DT_PLTRELSZ => obj.jmprel_size = (*d).d_val,
            elf::DT_NEEDED => {
                if obj.needed_count < 4 {
                    obj.needed[obj.needed_count] = (*d).d_val;
                    obj.needed_count += 1;
                }
            }
            elf::DT_SONAME => obj.soname_offset = (*d).d_val,
            _ => {}
        }
        d = d.add(1);
    }
}

// ─── Library loading ─────��─────────────────────────────────────────────────

/// Load all DT_NEEDED libraries referenced by loaded objects.
/// Breadth-first: process each object's DT_NEEDED list in order.
unsafe fn load_needed_libraries() {
    let mut idx = 0;
    while idx < LOADED_COUNT {
        let obj = LOADED[idx];
        for i in 0..obj.needed_count {
            let name_offset = obj.needed[i];
            if obj.strtab == 0 {
                continue;
            }
            let name_ptr = (obj.strtab + name_offset) as *const u8;
            let name = cstr_slice(name_ptr);

            // Check if already loaded (by SONAME match).
            if find_loaded_by_name(name).is_some() {
                continue;
            }

            // Try to load from /lib/<name>.
            if let Some(lib_obj) = load_library(name) {
                if LOADED_COUNT < MAX_LOADED {
                    LOADED[LOADED_COUNT] = lib_obj;
                    LOADED_COUNT += 1;
                }
            } else {
                serial::puts(b"ld-vibix: warning: could not load ");
                serial::puts(name);
                serial::puts(b"\n");
            }
        }
        idx += 1;
    }
}

/// Check if a library with the given name is already loaded.
unsafe fn find_loaded_by_name(name: &[u8]) -> Option<usize> {
    for i in 0..LOADED_COUNT {
        let soname = LOADED[i].soname();
        if !soname.is_empty() && bytes_eq(soname, name) {
            return Some(i);
        }
    }
    None
}

/// Load a shared library from `/lib/<name>`.
unsafe fn load_library(name: &[u8]) -> Option<LoadedObject> {
    // Build path: /lib/<name>\0
    let mut path_buf = [0u8; 256];
    let prefix = b"/lib/";
    if prefix.len() + name.len() + 1 > path_buf.len() {
        return None;
    }
    ptr::copy_nonoverlapping(prefix.as_ptr(), path_buf.as_mut_ptr(), prefix.len());
    ptr::copy_nonoverlapping(name.as_ptr(), path_buf.as_mut_ptr().add(prefix.len()), name.len());
    path_buf[prefix.len() + name.len()] = 0;

    // Open the file.
    let fd = syscall3(SYS_OPEN, path_buf.as_ptr() as u64, O_RDONLY, 0);
    if fd < 0 {
        return None;
    }

    // Stat to get file size.
    let mut stat_buf = [0u8; 144]; // struct stat is 144 bytes on x86_64
    let ret = syscall2(SYS_FSTAT, fd as u64, stat_buf.as_mut_ptr() as u64);
    if ret < 0 {
        syscall1(SYS_CLOSE, fd as u64);
        return None;
    }
    // st_size is at offset 48 in struct stat (Linux x86_64).
    let file_size = *(stat_buf.as_ptr().add(48) as *const i64) as u64;

    // mmap the entire file into memory for parsing.
    let map_addr = syscall6(
        SYS_MMAP,
        0,
        file_size,
        PROT_READ,
        MAP_PRIVATE,
        fd as u64,
        0,
    );
    syscall1(SYS_CLOSE, fd as u64);

    if map_addr < 0 || (map_addr as u64) > 0x7FFF_FFFF_FFFF {
        return None;
    }

    let elf_bytes = map_addr as *const u8;

    // Verify ELF magic.
    if *elf_bytes != 0x7f
        || *elf_bytes.add(1) != b'E'
        || *elf_bytes.add(2) != b'L'
        || *elf_bytes.add(3) != b'F'
    {
        return None;
    }

    let ehdr = elf_bytes as *const elf::Elf64Ehdr;

    // Determine the total virtual memory span needed.
    let phoff = (*ehdr).e_phoff;
    let phnum = (*ehdr).e_phnum as u64;
    let phent = (*ehdr).e_phentsize as u64;

    let mut vaddr_min: u64 = u64::MAX;
    let mut vaddr_max: u64 = 0;
    for i in 0..phnum {
        let ph = elf_bytes.add((phoff + i * phent) as usize) as *const elf::Elf64Phdr;
        if (*ph).p_type == elf::PT_LOAD {
            let start = (*ph).p_vaddr;
            let end = start + (*ph).p_memsz;
            if start < vaddr_min {
                vaddr_min = start;
            }
            if end > vaddr_max {
                vaddr_max = end;
            }
        }
    }

    if vaddr_min == u64::MAX {
        return None;
    }

    // Align to page boundaries.
    vaddr_min &= !0xFFF;
    vaddr_max = (vaddr_max + 0xFFF) & !0xFFF;
    let total_size = vaddr_max - vaddr_min;

    // Choose a load base for this library.
    let load_base = next_lib_base(total_size);

    // Map each PT_LOAD segment.
    for i in 0..phnum {
        let ph = elf_bytes.add((phoff + i * phent) as usize) as *const elf::Elf64Phdr;
        if (*ph).p_type != elf::PT_LOAD {
            continue;
        }

        let seg_vaddr = ((*ph).p_vaddr & !0xFFF) + load_base - vaddr_min;
        let seg_offset = (*ph).p_offset & !0xFFF;
        let seg_filesz = (*ph).p_filesz + ((*ph).p_offset & 0xFFF);
        let seg_memsz = (*ph).p_memsz + ((*ph).p_vaddr & 0xFFF);
        let map_len = (seg_memsz + 0xFFF) & !0xFFF;

        // Compute protection flags.
        let mut prot = PROT_READ;
        if (*ph).p_flags & elf::PF_W != 0 {
            prot |= PROT_WRITE;
        }
        if (*ph).p_flags & elf::PF_X != 0 {
            prot |= PROT_EXEC;
        }

        // Map anonymous first (to get the address range), then copy data.
        let mapped = syscall6(
            SYS_MMAP,
            seg_vaddr,
            map_len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            u64::MAX, // fd = -1
            0,
        );
        if mapped < 0 {
            serial::puts(b"ld-vibix: mmap failed for library segment\n");
            return None;
        }

        // Copy file content.
        let copy_len = if seg_filesz < map_len {
            seg_filesz
        } else {
            map_len
        };
        ptr::copy_nonoverlapping(
            elf_bytes.add(seg_offset as usize),
            mapped as *mut u8,
            copy_len as usize,
        );

        // Set final protection (remove write if not needed).
        if prot != (PROT_READ | PROT_WRITE) {
            syscall3(SYS_MPROTECT, seg_vaddr, map_len, prot);
        }
    }

    // Build the LoadedObject.
    let base_offset = load_base - vaddr_min;
    let mut obj = LoadedObject::zeroed();
    obj.base = base_offset;

    // Find PT_DYNAMIC.
    for i in 0..phnum {
        let ph = elf_bytes.add((phoff + i * phent) as usize) as *const elf::Elf64Phdr;
        if (*ph).p_type == elf::PT_DYNAMIC {
            obj.dynamic = (*ph).p_vaddr + base_offset;
            break;
        }
    }

    if obj.dynamic != 0 {
        parse_dynamic(&mut obj);
    }

    serial::puts(b"ld-vibix: loaded ");
    serial::puts(name);
    serial::puts(b"\n");

    Some(obj)
}

/// Track the next available library load address.
static mut NEXT_LIB_ADDR: u64 = LIB_LOAD_BASE;

unsafe fn next_lib_base(size: u64) -> u64 {
    let base = NEXT_LIB_ADDR;
    NEXT_LIB_ADDR = (base + size + 0xFFF) & !0xFFF;
    base
}

// ─── Relocation ─���─────────────────────────��────────────────────────────────

/// Perform relocations on all loaded objects.
unsafe fn relocate_all() {
    for i in 0..LOADED_COUNT {
        let obj = LOADED[i];
        reloc::relocate_object(&obj, &LOADED[..LOADED_COUNT]);
    }
}

// ─── TLS setup ──────────────────────���─────────────────────���────────────────

/// Minimal TLS setup: allocate a zeroed page and set FS base.
/// The main binary's PT_TLS will have been set up by the kernel
/// before invoking us, so we only need to handle the case where
/// the kernel didn't set it up (e.g., the binary has no PT_TLS
/// but a library does).
unsafe fn setup_tls(_auxv: &Auxv) {
    // For now, if FS base is already set (kernel allocated TLS for
    // the main binary), do nothing. The kernel handles TLS for static
    // executables. Dynamic TLS for libraries is a future enhancement.
    //
    // If no TLS was set up at all, allocate a minimal TCB so
    // thread_local access doesn't fault.

    // Read current FS base.
    let mut fs_base: u64 = 0;
    let ret = syscall2(
        SYS_ARCH_PRCTL,
        0x1003, // ARCH_GET_FS
        &mut fs_base as *mut u64 as u64,
    );

    if ret == 0 && fs_base != 0 {
        // Kernel already set up TLS. Nothing to do.
        return;
    }

    // Allocate a minimal TLS block (one page).
    let page = syscall6(
        SYS_MMAP,
        0,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        u64::MAX,
        0,
    );
    if page < 0 {
        serial::puts(b"ld-vibix: TLS allocation failed\n");
        exit(1);
    }

    // x86_64 variant II: TCB is at the end of the block. The TCB's
    // first word is a self-pointer.
    let tcb = page as u64 + 4096 - 8;
    *(tcb as *mut u64) = tcb;

    // Set FS base to TCB.
    let ret = syscall2(SYS_ARCH_PRCTL, ARCH_SET_FS, tcb);
    if ret < 0 {
        serial::puts(b"ld-vibix: arch_prctl(SET_FS) failed\n");
        exit(1);
    }
}

// ─── Control transfer ──────────────────────��───────────────────────────────

/// Jump to the main binary's entry point with the original stack.
#[inline(never)]
unsafe fn jump_to_entry(entry: u64, stack: *const u64) -> ! {
    core::arch::asm!(
        "mov rsp, {stack}",
        "xor rbp, rbp",
        "jmp {entry}",
        stack = in(reg) stack,
        entry = in(reg) entry,
        options(noreturn),
    )
}

// ─── Utilities ────────────────────────────────────────────��────────────────

unsafe fn exit(code: u64) -> ! {
    syscall1(SYS_EXIT, code);
    loop {
        core::hint::spin_loop();
    }
}

#[inline(always)]
unsafe fn syscall1(nr: u64, a0: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rdx") _,
        lateout("rsi") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
unsafe fn syscall2(nr: u64, a0: u64, a1: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("rdx") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        lateout("rcx") _,
        lateout("r11") _,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r10") _,
        options(nostack, preserves_flags),
    );
    ret
}

#[inline(always)]
unsafe fn syscall6(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") nr as i64 => ret,
        inlateout("rdi") a0 => _,
        inlateout("rsi") a1 => _,
        inlateout("rdx") a2 => _,
        inlateout("r10") a3 => _,
        inlateout("r8") a4 => _,
        inlateout("r9") a5 => _,
        lateout("rcx") _,
        lateout("r11") _,
        options(nostack, preserves_flags),
    );
    ret
}

/// Get the length of a null-terminated byte string and return a slice.
unsafe fn cstr_slice(ptr: *const u8) -> &'static [u8] {
    let mut len = 0;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    slice::from_raw_parts(ptr, len)
}

/// Compare two byte slices for equality.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    serial::puts(b"ld-vibix: PANIC\n");
    unsafe { exit(127) }
}
