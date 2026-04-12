//! Integration test: ACPI + APIC bring-up on the BSP.
//!
//! After `vibix::init()` the MADT should have been parsed, the BSP
//! LAPIC enabled, and at least one IOAPIC set up. This test does not
//! re-verify IRQ delivery (timer_tick covers that); it just confirms
//! the discovered topology is sane.

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
        ("madt_parsed", &(madt_parsed as fn())),
        ("ioapic_present", &(ioapic_present as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn madt_parsed() {
    let info = vibix::acpi::info().expect("ACPI info missing after init");
    assert!(info.cpu_count >= 1, "MADT reported {} CPUs", info.cpu_count);
    assert_ne!(info.lapic_phys, 0, "LAPIC base is zero");
}

fn ioapic_present() {
    let info = vibix::acpi::info().expect("ACPI info missing after init");
    let count = info.ioapics().count();
    assert!(count >= 1, "no IOAPICs discovered");
}
