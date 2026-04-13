//! Integration test: the user-space ELF loader maps the init image
//! into a fresh per-process PML4 with a lower-half entry point.

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
            "load_user_elf_maps_lower_half_segments",
            &(load_user_elf_maps_lower_half_segments as fn()),
        ),
        (
            "load_user_elf_rejects_upper_half",
            &(load_user_elf_rejects_upper_half as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn load_user_elf_maps_lower_half_segments() {
    let bytes =
        vibix::mem::userspace_module_elf_bytes().expect("init module bytes missing");
    // Allocate a fresh per-process PML4 for the test.
    let pml4 = vibix::mem::paging::new_task_pml4();
    let image = vibix::mem::loader::load_user_elf(bytes, pml4)
        .expect("load_user_elf failed for init image");
    // Entry must be in the lower half (canonical lower-half: bit 47..=63 = 0).
    assert!(
        image.entry.as_u64() < 0x0000_8000_0000_0000,
        "entry {:#x} must be lower-half",
        image.entry.as_u64()
    );
    assert!(image.segments > 0, "at least one PT_LOAD must map");
    serial_println!(
        "load_user_elf: entry={:#x} segments={}",
        image.entry.as_u64(),
        image.segments
    );
}

fn load_user_elf_rejects_upper_half() {
    // Build a minimal fake ELF with an upper-half PT_LOAD + entry.
    const EHDR: usize = 64;
    const PHDR: usize = 56;
    let mut bytes = [0u8; EHDR + PHDR];

    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // ELF version
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes()); // EM_X86_64
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    // Upper-half entry (bit 63 set, canonical kernel address).
    bytes[24..32].copy_from_slice(&0xffff_ffff_c000_0080u64.to_le_bytes());
    bytes[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes()); // e_phoff
    bytes[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes()); // e_ehsize
    bytes[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes()); // e_phentsize
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum = 1

    let p = EHDR;
    bytes[p..p + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    bytes[p + 4..p + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
    bytes[p + 16..p + 24].copy_from_slice(&0xffff_ffff_c000_0000u64.to_le_bytes()); // p_vaddr
    bytes[p + 40..p + 48].copy_from_slice(&0x2000u64.to_le_bytes()); // p_memsz

    let pml4 = vibix::mem::paging::new_task_pml4();
    let result = vibix::mem::loader::load_user_elf(&bytes, pml4);
    assert!(
        matches!(result, Err(vibix::mem::loader::LoadError::SegmentNotLowerHalf)),
        "expected SegmentNotLowerHalf, got {:?}",
        result
    );
    serial_println!("load_user_elf correctly rejected upper-half ELF");
}
