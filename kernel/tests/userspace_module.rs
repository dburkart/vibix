//! Integration test: module request delivers the init ELF and parser
//! exposes entry point + load segments.

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
    let tests: &[(&str, &dyn Testable)] = &[(
        "userspace_module_elf_present_and_parsed",
        &(userspace_module_elf_present_and_parsed as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn userspace_module_elf_present_and_parsed() {
    let (entry, segs) =
        vibix::mem::userspace_module_elf_summary().expect("userspace init module missing");
    assert!(entry.as_u64() > 0, "module entry must be non-zero");
    assert!(segs > 0, "module must contain at least one PT_LOAD segment");
    serial_println!(
        "userspace module parsed: entry={:#x} segments={}",
        entry.as_u64(),
        segs
    );
}
