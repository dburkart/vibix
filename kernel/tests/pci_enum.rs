//! Integration test: legacy PCI bus-0 enumeration finds the devices
//! QEMU's `q35`/`pc-i440fx` machines always expose.
//!
//! The test is tolerant to QEMU's machine-type variations (q35 in
//! `xtask test`) — it only asserts devices that are guaranteed by
//! *both* machine types: the host bridge, the ISA bridge, an IDE/AHCI
//! storage controller, and a VGA class device.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::{
    exit_qemu, pci, serial_println,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    pci::scan();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("scan_finds_devices", &(scan_finds_devices as fn())),
        ("host_bridge_present", &(host_bridge_present as fn())),
        ("isa_bridge_present", &(isa_bridge_present as fn())),
        ("ide_controller_present", &(ide_controller_present as fn())),
        ("vga_class_present", &(vga_class_present as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn scan_finds_devices() {
    let n = pci::device_count();
    assert!(n >= 4, "expected at least 4 PCI devices, saw {}", n);
}

fn host_bridge_present() {
    // i440FX: 8086:1237 or Q35 MCH: 8086:29C0 — both class 06:00.
    let mut found = false;
    for d in pci::devices() {
        if d.class == 0x06 && d.subclass == 0x00 {
            found = true;
            serial_println!(
                "  host bridge: {:04x}:{:04x} at {:02x}:{:02x}.{:x}",
                d.vendor_id,
                d.device_id,
                d.addr.bus,
                d.addr.device,
                d.addr.function,
            );
            break;
        }
    }
    assert!(found, "no class 06:00 host bridge enumerated");
}

fn isa_bridge_present() {
    let mut found = false;
    for d in pci::devices() {
        if d.class == 0x06 && d.subclass == 0x01 {
            found = true;
            break;
        }
    }
    assert!(found, "no class 06:01 ISA bridge enumerated");
}

fn ide_controller_present() {
    // IDE controller: class 01, subclass 01. Present in pc-i440fx.
    // Q35 ships AHCI (01:06) instead — accept either, but one of them
    // must be there.
    let mut found = false;
    for d in pci::devices() {
        if d.class == 0x01 && (d.subclass == 0x01 || d.subclass == 0x06) {
            found = true;
            break;
        }
    }
    assert!(found, "no IDE or AHCI storage controller enumerated");
}

fn vga_class_present() {
    let mut found = false;
    for d in pci::devices() {
        if d.class == 0x03 {
            found = true;
            break;
        }
    }
    assert!(found, "no class 03 display controller enumerated");
}
