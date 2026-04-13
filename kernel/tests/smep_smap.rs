//! Integration test for #116: SMEP/SMAP enforcement is live on the CPU
//! and `copy_from_user` / `copy_to_user` gate ring-0 access to user
//! pages behind STAC/CLAC.
//!
//! Verifies:
//! 1. CR4.SMEP / CR4.SMAP are set after `vibix::init()`.
//! 2. `copy_from_user` / `copy_to_user` reject kernel-half and wrapping
//!    pointers with `Efault`.
//! 3. A round-trip through a real user VMA copies the expected bytes
//!    (implicitly exercising the STAC/CLAC bracket — without it the
//!    access would take a `#PF` with the SMAP bit set).

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::arch::x86_64::uaccess::{self, USER_VA_END};
use vibix::mem::vma::{Vma, VmaKind};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::registers::control::{Cr4, Cr4Flags};
use x86_64::structures::paging::PageTableFlags;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    x86_64::instructions::interrupts::enable();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("cr4_smep_smap_bits_set", &(cr4_smep_smap_bits_set as fn())),
        (
            "copy_rejects_kernel_half",
            &(copy_rejects_kernel_half as fn()),
        ),
        ("copy_rejects_wrap", &(copy_rejects_wrap as fn())),
        ("copy_roundtrip_user", &(copy_roundtrip_user as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn cr4_smep_smap_bits_set() {
    let flags = Cr4::read();
    assert!(
        flags.contains(Cr4Flags::SUPERVISOR_MODE_EXECUTION_PROTECTION),
        "CR4.SMEP not set — SMEP enforcement is off"
    );
    assert!(
        flags.contains(Cr4Flags::SUPERVISOR_MODE_ACCESS_PREVENTION),
        "CR4.SMAP not set — SMAP enforcement is off"
    );
}

fn copy_rejects_kernel_half() {
    let mut buf = [0u8; 8];
    let kernel_va = USER_VA_END as usize;
    unsafe {
        assert!(uaccess::copy_from_user(&mut buf, kernel_va).is_err());
        assert!(uaccess::copy_to_user(kernel_va, &buf).is_err());
    }
}

fn copy_rejects_wrap() {
    let mut buf = [0u8; 8];
    unsafe {
        // A near-max usize pointer + non-trivial length overflows — must
        // be rejected, not silently wrap past 0 into the low user VA.
        assert!(uaccess::copy_from_user(&mut buf, usize::MAX - 3).is_err());
    }
}

/// Install an AnonZero VMA on the current task, fault the pages in by
/// touching them, then exercise `copy_to_user` / `copy_from_user` through
/// that real user mapping. On an SMAP-on CPU, missing STAC/CLAC brackets
/// inside the helpers would `#PF` here.
fn copy_roundtrip_user() {
    const BASE: usize = 0x0000_3000_0010_0000;
    const PAGES: usize = 2;

    task::install_vma_on_current(Vma::new(
        BASE,
        BASE + PAGES * 4096,
        VmaKind::AnonZero,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
    ));

    // Fault each page in by touching it. We're still running in ring-0
    // and this task's PML4 — this is a demand-paging trigger, not a
    // user-pointer-from-kernel access.
    for i in 0..PAGES {
        unsafe { core::ptr::write_volatile((BASE + i * 4096) as *mut u8, 0) };
    }

    let payload: [u8; 16] = *b"smep_smap_rtrip!";
    let mut readback = [0u8; 16];
    unsafe {
        uaccess::copy_to_user(BASE + 32, &payload).expect("copy_to_user ok");
        uaccess::copy_from_user(&mut readback, BASE + 32).expect("copy_from_user ok");
    }
    assert_eq!(readback, payload);
}
