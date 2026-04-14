//! Integration test for #267: a partial-failure ELF load must not leak
//! leaf frames into the staged PML4. `Drop for AddressSpace` walks
//! `self.vmas` only, so any frame `load_user_elf` maps before bailing
//! out would escape reclamation if the loader itself didn't clean up
//! on its error path.
//!
//! We craft a two-segment ELF where segment 0 is a valid lower-half
//! mapping (so `load_user_elf` maps one leaf frame into the fresh
//! PML4) and segment 1 ends at `USER_VA_END`, tripping the
//! `SegmentEndsAtUserVaEnd` check *after* segment 0 has already
//! installed its frame. A correct loader frees that frame before
//! returning `Err`; a leaky one leaves it stranded.
//!
//! The test then reclaims the PML4 and its intermediate page tables
//! so the only remaining delta between baseline and post-load is any
//! frame that escaped the loader's cleanup. That delta must be zero.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

use vibix::mem::frame;
use vibix::mem::loader::{load_user_elf, LoadError};
use vibix::mem::paging;
use vibix::{
    exit_qemu, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[(
        "partial_load_failure_does_not_leak_frames",
        &(partial_load_failure_does_not_leak_frames as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// Minimal ELF64 layout: one Ehdr then N Phdrs, no sections, no data.
// Segment 0's single page lives entirely inside the HHDM-mapped image
// bytes — the loader zero-fills via `map_in_pml4` and only copies
// `filesz` bytes, which we leave at 0 so no source data is needed.
const EHDR: usize = 64;
const PHDR: usize = 56;
const HEADER_SIZE: usize = EHDR + 2 * PHDR;

/// Build an ELF64 with two PT_LOAD segments:
///   - seg 0: lower-half, one page, filesz=0 (pure .bss). Maps cleanly.
///   - seg 1: `p_vaddr = USER_VA_END - 0x1000`, `p_memsz = 0x1000`, so
///     page-aligned end equals `USER_VA_END` → triggers
///     `SegmentEndsAtUserVaEnd` in the loader.
fn build_partial_fail_elf() -> [u8; HEADER_SIZE] {
    let mut bytes = [0u8; HEADER_SIZE];

    // Ehdr
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // ELF version
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
                                                        // e_entry: inside segment 0.
    bytes[24..32].copy_from_slice(&0x0000_0000_0040_0000u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
    bytes[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
    bytes[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum = 2

    // Phdr 0: PT_LOAD at 0x0040_0000, one page, R+X, filesz=0.
    let p0 = EHDR;
    bytes[p0..p0 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[p0 + 4..p0 + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
    bytes[p0 + 16..p0 + 24].copy_from_slice(&0x0000_0000_0040_0000u64.to_le_bytes()); // p_vaddr
    bytes[p0 + 40..p0 + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz
                                                                      // p_offset/p_filesz/p_paddr default to 0 — a zero-filesz PT_LOAD is
                                                                      // a valid .bss-only segment.

    // Phdr 1: PT_LOAD whose page-aligned end lands on USER_VA_END.
    let p1 = EHDR + PHDR;
    bytes[p1..p1 + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[p1 + 4..p1 + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
    bytes[p1 + 16..p1 + 24].copy_from_slice(&0x0000_7fff_ffff_f000u64.to_le_bytes()); // p_vaddr
    bytes[p1 + 40..p1 + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // p_memsz

    bytes
}

fn partial_load_failure_does_not_leak_frames() {
    let bytes = build_partial_fail_elf();

    // Baseline taken *before* the PML4 alloc so the allocation and
    // later `free_pml4_frame` cancel out in the arithmetic — the only
    // surviving delta would be leaked leaf frames from the failed load.
    let before = frame::free_frames();
    let pml4 = paging::new_task_pml4();

    let result = load_user_elf(&bytes, pml4);
    match result {
        Err(LoadError::SegmentEndsAtUserVaEnd) => {}
        other => panic!(
            "expected SegmentEndsAtUserVaEnd, got {:?} — the crafted ELF \
             may have been rejected earlier than the intended failure \
             point, invalidating the leak check",
            other
        ),
    }

    let after_load = frame::free_frames();

    // Tear down the intermediate page tables the loader installed while
    // mapping segment 0 (L3/L2/L1 under 0x0040_0000) plus the PML4
    // frame itself. With a correct loader, segment 0's leaf data frame
    // was already reclaimed on the error path, so after this teardown
    // the frame count must return to `before` exactly. A leaky loader
    // leaves that frame stranded, surfacing as a one-frame deficit.
    unsafe {
        paging::free_user_page_tables(pml4);
        paging::free_pml4_frame(pml4);
    }
    let after_teardown = frame::free_frames();

    serial_println!(
        "frame counts: before={before} after_load={after_load} after_teardown={after_teardown}"
    );

    assert_eq!(
        after_teardown, before,
        "frame accounting mismatch after failed load+teardown: \
         before={before}, after_teardown={after_teardown}, \
         delta={} — a leaf frame leaked on the loader error path",
        before as isize - after_teardown as isize,
    );
}
