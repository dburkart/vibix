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
use vibix::mem::vmobject::AnonObject;
use vibix::mem::vmatree::{Share, Vma};
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

    // USER_ACCESSIBLE is load-bearing here: without it the pages are
    // mapped supervisor-only (U/S=0), SMAP wouldn't block ring-0 access,
    // and the copy_*_user helpers would appear to work even if their
    // STAC/CLAC bracket were broken. With U/S=1 the round-trip only
    // succeeds when SMAP is actually toggled inside the helpers.
    let pte_flags = (PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE)
        .bits();
    task::install_vma_on_current(Vma::new(
        BASE,
        BASE + PAGES * 4096,
        0x3, // PROT_READ | PROT_WRITE
        pte_flags,
        Share::Private,
        AnonObject::new(Some(PAGES)),
        0,
    ));

    // No explicit warm-up touch: with USER_ACCESSIBLE mappings a ring-0
    // write without `stac` would itself trip SMAP. Let `copy_to_user`
    // drive demand paging under its own STAC bracket — the fault
    // handler's CLAC keeps the resolver running with SMAP live, and the
    // IRET retry completes inside the bracket.
    let payload: [u8; 16] = *b"smep_smap_rtrip!";
    let mut readback = [0u8; 16];
    unsafe {
        uaccess::copy_to_user(BASE + 32, &payload).expect("copy_to_user ok");
        uaccess::copy_from_user(&mut readback, BASE + 32).expect("copy_from_user ok");
    }
    assert_eq!(readback, payload);
}
