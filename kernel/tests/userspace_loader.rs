//! Integration test: the ELF loader maps the userspace_hello image
//! into the active upper-half of the kernel PML4 and the mapped pages
//! hold the expected ELF contents.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
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
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "loader_maps_upper_half_segments",
            &(loader_maps_upper_half_segments as fn()),
        ),
        (
            "loader_entry_page_matches_file_image",
            &(loader_entry_page_matches_file_image as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn loader_maps_upper_half_segments() {
    let bytes = vibix::mem::userspace_module_elf_bytes().expect("hello module bytes missing");
    let image = vibix::mem::loader::load(bytes).expect("loader failed to map segments");
    assert!(
        image.entry.as_u64() >> 63 == 1,
        "entry {:#x} must be upper-half",
        image.entry.as_u64()
    );
    assert!(image.segments > 0, "at least one PT_LOAD must map");
    serial_println!(
        "loader mapped entry={:#x} segments={}",
        image.entry.as_u64(),
        image.segments
    );
}

fn loader_entry_page_matches_file_image() {
    // The loader runs once during `vibix::init()`; the first four bytes
    // at the entry point should be whatever the file image holds at the
    // corresponding file offset. Use the ELF Ehdr-reported entry plus
    // the first PT_LOAD's (offset, vaddr) to locate the right file
    // bytes, then memcmp against the live mapping.
    let bytes = vibix::mem::userspace_module_elf_bytes().unwrap();
    let (entry, _) = vibix::mem::userspace_module_elf_summary().unwrap();

    // Minimal hand-rolled re-parse: first PT_LOAD's p_offset / p_vaddr
    // give us the mapping from virtual address to file offset.
    let phoff = u64::from_le_bytes(bytes[32..40].try_into().unwrap()) as usize;
    let phentsize = u16::from_le_bytes(bytes[54..56].try_into().unwrap()) as usize;
    let phnum = u16::from_le_bytes(bytes[56..58].try_into().unwrap()) as usize;

    let mut located = None;
    for i in 0..phnum {
        let off = phoff + i * phentsize;
        let p_type = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if p_type != 1 {
            continue;
        }
        let p_offset = u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap());
        let p_vaddr = u64::from_le_bytes(bytes[off + 16..off + 24].try_into().unwrap());
        let p_filesz = u64::from_le_bytes(bytes[off + 32..off + 40].try_into().unwrap());
        if entry.as_u64() >= p_vaddr && entry.as_u64() < p_vaddr + p_filesz {
            located = Some((p_offset, p_vaddr));
            break;
        }
    }
    let (p_offset, p_vaddr) = located.expect("entry not inside a PT_LOAD filesz range");
    let file_off = (entry.as_u64() - p_vaddr + p_offset) as usize;
    let expected = &bytes[file_off..file_off + 16];
    // SAFETY: the loader mapped this virtual address PRESENT during
    // `vibix::init()`; reading 16 bytes stays within the first page of
    // the text segment.
    let live: &[u8] = unsafe { core::slice::from_raw_parts(entry.as_u64() as *const u8, 16) };
    assert_eq!(live, expected, "mapped entry bytes differ from file image");
    serial_println!(
        "loader entry page matches file image ({} bytes)",
        live.len()
    );
}
