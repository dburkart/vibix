//! Relocation processing for the dynamic linker.
//!
//! Handles:
//! - R_X86_64_RELATIVE (base + addend) — ~90% of relocations
//! - R_X86_64_GLOB_DAT (symbol lookup in loaded libraries)
//! - R_X86_64_JUMP_SLOT (eager binding — resolve at load time)
//! - R_X86_64_64 (absolute symbol reference)

use crate::elf;
use crate::serial;
use crate::LoadedObject;

/// Process all relocations for a single loaded object.
pub unsafe fn relocate_object(obj: &LoadedObject, all_objects: &[LoadedObject]) {
    // Process .rela.dyn
    if obj.rela != 0 && obj.rela_size != 0 {
        process_rela_table(obj, all_objects, obj.rela, obj.rela_size);
    }

    // Process .rela.plt (DT_JMPREL) — eager binding.
    if obj.jmprel != 0 && obj.jmprel_size != 0 {
        process_rela_table(obj, all_objects, obj.jmprel, obj.jmprel_size);
    }
}

/// Process a single relocation table (.rela.dyn or .rela.plt).
unsafe fn process_rela_table(
    obj: &LoadedObject,
    all_objects: &[LoadedObject],
    rela_addr: u64,
    rela_size: u64,
) {
    let entry_size = core::mem::size_of::<elf::Elf64Rela>() as u64;
    let count = rela_size / entry_size;
    let rela_ptr = rela_addr as *const elf::Elf64Rela;

    for i in 0..count {
        let r = &*rela_ptr.add(i as usize);
        let r_type = (r.r_info & 0xFFFF_FFFF) as u32;
        let r_sym = (r.r_info >> 32) as u32;
        let target = (obj.base + r.r_offset) as *mut u64;

        match r_type {
            elf::R_X86_64_NONE => {}

            elf::R_X86_64_RELATIVE => {
                // S + A where S = base
                *target = (obj.base as i64 + r.r_addend) as u64;
            }

            elf::R_X86_64_GLOB_DAT | elf::R_X86_64_JUMP_SLOT => {
                // Symbol lookup: find the symbol in all loaded objects.
                if let Some(value) = lookup_symbol(r_sym, obj, all_objects) {
                    *target = value;
                } else {
                    let name = symbol_name(r_sym, obj);
                    serial::puts(b"ld-vibix: unresolved symbol: ");
                    serial::puts(name);
                    serial::puts(b"\n");
                    // Write 0 — will fault if called. Better than leaving
                    // stale data.
                    *target = 0;
                }
            }

            elf::R_X86_64_64 => {
                // S + A where S = symbol value
                if let Some(value) = lookup_symbol(r_sym, obj, all_objects) {
                    *target = (value as i64 + r.r_addend) as u64;
                } else {
                    let name = symbol_name(r_sym, obj);
                    serial::puts(b"ld-vibix: unresolved R_X86_64_64: ");
                    serial::puts(name);
                    serial::puts(b"\n");
                    *target = 0;
                }
            }

            _ => {
                // Unknown relocation type — skip.
            }
        }
    }
}

/// Look up a symbol by index in the referencing object's symtab,
/// then search all loaded objects for a definition.
unsafe fn lookup_symbol(
    sym_idx: u32,
    referencing: &LoadedObject,
    all_objects: &[LoadedObject],
) -> Option<u64> {
    if referencing.symtab == 0 || referencing.strtab == 0 {
        return None;
    }

    let sym = get_symbol(referencing, sym_idx);
    if sym.is_null() {
        return None;
    }

    let name_ptr = (referencing.strtab + (*sym).st_name as u64) as *const u8;

    // If the symbol is defined in the referencing object itself, use it.
    if (*sym).is_defined() {
        return Some((*sym).st_value + referencing.base);
    }

    // Search all loaded objects for the symbol.
    for obj in all_objects.iter() {
        if obj.symtab == 0 || obj.strtab == 0 {
            continue;
        }
        if let Some(value) = find_symbol_in_object(obj, name_ptr) {
            return Some(value);
        }
    }

    None
}

/// Find a symbol by name in a single object's symbol table.
/// Linear search (no hash table yet — acceptable for small dep counts).
unsafe fn find_symbol_in_object(obj: &LoadedObject, name: *const u8) -> Option<u64> {
    // We need to walk the symbol table. The number of entries isn't
    // directly stored in .dynamic (it's implied by .hash or .gnu.hash).
    // For simplicity, walk until we hit a zero entry or a reasonable limit.
    // The symbol table is terminated by DT_SYMENT-aligned entries.
    // A practical limit: 4096 symbols.
    let sym_entry_size = core::mem::size_of::<elf::Elf64Sym>() as u64;

    for i in 1..4096u32 {
        let sym = (obj.symtab + i as u64 * sym_entry_size) as *const elf::Elf64Sym;

        // Stop if we hit unmapped memory (rough heuristic: st_name
        // would be garbage). We rely on the symbol table being
        // well-formed.
        if (*sym).st_name == 0 && (*sym).st_info == 0 && (*sym).st_value == 0 {
            break;
        }

        if !(*sym).is_defined() {
            continue;
        }

        // Only consider global/weak symbols.
        let binding = (*sym).binding();
        if binding != elf::STB_GLOBAL && binding != elf::STB_WEAK {
            continue;
        }

        // Compare names.
        let sym_name = (obj.strtab + (*sym).st_name as u64) as *const u8;
        if cstr_eq(sym_name, name) {
            return Some((*sym).st_value + obj.base);
        }
    }

    None
}

/// Get a pointer to the symbol at index `idx` in `obj`'s symtab.
unsafe fn get_symbol(obj: &LoadedObject, idx: u32) -> *const elf::Elf64Sym {
    if obj.symtab == 0 {
        return core::ptr::null();
    }
    let entry_size = core::mem::size_of::<elf::Elf64Sym>() as u64;
    (obj.symtab + idx as u64 * entry_size) as *const elf::Elf64Sym
}

/// Get the name of a symbol by its index.
unsafe fn symbol_name(sym_idx: u32, obj: &LoadedObject) -> &'static [u8] {
    if obj.symtab == 0 || obj.strtab == 0 {
        return b"<unknown>";
    }
    let sym = get_symbol(obj, sym_idx);
    if sym.is_null() {
        return b"<unknown>";
    }
    let name_ptr = (obj.strtab + (*sym).st_name as u64) as *const u8;
    crate::cstr_slice(name_ptr)
}

/// Compare two null-terminated strings.
unsafe fn cstr_eq(a: *const u8, b: *const u8) -> bool {
    let mut i = 0;
    loop {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb {
            return false;
        }
        if ca == 0 {
            return true;
        }
        i += 1;
    }
}
