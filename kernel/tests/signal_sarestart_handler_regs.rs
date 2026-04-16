//! Integration test: user syscall arg regs survive the SA_RESTART+handler
//! sigreturn path (#499).
//!
//! Before #499, `push_signal_frame` dropped `(rax, rdi, rsi, rdx, r10, r8,
//! r9)` on the floor — so after an SA_RESTART-style restart that routed
//! through a user handler, sigreturn would land on the rewound SYSCALL
//! instruction with clobbered arg regs and the syscall would re-execute
//! with garbage. This test pins the roundtrip: push → restore → verify the
//! recovered `SyscallArgRegs` match, and that fault-pushed frames set no
//! flag (`syscall_args == None`) so fault-delivered signals don't force a
//! spurious zero-fill of user GPRs on sigreturn.
//!
//! End-to-end verification of an SA_RESTART handler actually replaying a
//! real syscall with the original args requires ring-3 job-control testing
//! and lives in the shell-level smoke suite.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;

use vibix::mem::vmatree::{Share, Vma};
use vibix::mem::vmobject::AnonObject;
use vibix::signal::frame::{
    push_fault_signal_frame, push_signal_frame, restore_signal_frame, SyscallArgRegs,
};
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};
use x86_64::structures::paging::PageTableFlags;

#[no_mangle]
pub extern "C" fn _start() -> ! {
    vibix::init();
    task::init();
    x86_64::instructions::interrupts::enable();
    serial_println!("signal_sarestart_handler_regs: init ok");
    install_user_stack();
    run_tests();
    exit_qemu(QemuExitCode::Success);
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    test_panic_handler(info)
}

// A 2-page user-accessible VMA used as a fake user stack. Both
// `push_signal_frame` and `restore_signal_frame` round-trip through
// `copy_to_user` / `copy_from_user`, so we need a real user mapping.
const STACK_BASE: usize = 0x0000_3000_0020_0000;
const STACK_PAGES: usize = 2;
const STACK_TOP: u64 = (STACK_BASE + STACK_PAGES * 4096) as u64;

fn install_user_stack() {
    let pte_flags = (PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::NO_EXECUTE)
        .bits();
    task::install_vma_on_current(Vma::new(
        STACK_BASE,
        STACK_BASE + STACK_PAGES * 4096,
        0x3, // PROT_READ | PROT_WRITE
        pte_flags,
        Share::Private,
        AnonObject::new(Some(STACK_PAGES)),
        0,
    ));
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "push_then_restore_preserves_syscall_args",
            &(push_then_restore_preserves_syscall_args as fn()),
        ),
        (
            "push_preserves_rip_rflags_rsp_alongside_args",
            &(push_preserves_rip_rflags_rsp_alongside_args as fn()),
        ),
        (
            "fault_frame_yields_no_syscall_args",
            &(fault_frame_yields_no_syscall_args as fn()),
        ),
        (
            "non_restart_handler_frame_yields_no_syscall_args",
            &(non_restart_handler_frame_yields_no_syscall_args as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

fn push_then_restore_preserves_syscall_args() {
    // Plausible `write(fd=7, buf=0x…, count=42)` interrupted by SIGTTOU.
    // Syscall nr `write = 1` on Linux x86_64.
    let args = SyscallArgRegs {
        rax: 1,                     // write
        rdi: 7,                     // fd
        rsi: 0x0000_2000_0000_0080, // buf
        rdx: 42,                    // count
        r10: 0xdead,                // a3 (unused by write, but must round-trip)
        r8: 0xbeef,
        r9: 0xcafe,
    };
    let user_rsp = STACK_TOP - 16;
    let saved_rip = 0x0000_4000_0010_0100;
    let saved_rflags = 0x202;
    let saved_mask = 0;

    let frame_addr = unsafe {
        push_signal_frame(
            user_rsp,
            22,
            saved_rip,
            saved_rflags,
            saved_mask,
            Some(args),
        )
        .expect("push_signal_frame ok")
    };
    let restored = unsafe { restore_signal_frame(frame_addr).expect("restore ok") };
    let got = restored
        .syscall_args
        .expect("syscall-path frame must carry UC_VIBIX_SYSCALL_REGS");
    assert_eq!(got, args, "syscall arg regs must round-trip verbatim");
}

fn non_restart_handler_frame_yields_no_syscall_args() {
    // Non-restart handler delivery (no SA_RESTART+handler on ERESTARTSYS)
    // must NOT flag the frame with UC_VIBIX_SYSCALL_REGS, because rip in
    // that frame points past SYSCALL and gregs[REG_RAX] holds the syscall
    // nr rather than the rv. Restoring rax from gregs on sigreturn would
    // clobber the syscall's return value that userspace is about to read.
    let user_rsp = STACK_TOP - 64;
    let saved_rip = 0x0000_4000_0040_0400;
    let saved_rflags = 0x202;
    let saved_mask = 0;

    let frame_addr = unsafe {
        push_signal_frame(user_rsp, 22, saved_rip, saved_rflags, saved_mask, None)
            .expect("push_signal_frame(None) ok")
    };
    let restored = unsafe { restore_signal_frame(frame_addr).expect("restore ok") };
    assert!(
        restored.syscall_args.is_none(),
        "non-restart handler frames must not carry syscall arg regs"
    );
    assert_eq!(restored.rip, saved_rip);
}

fn push_preserves_rip_rflags_rsp_alongside_args() {
    // Adding syscall-arg round-trip must not regress the existing rip /
    // rflags / rsp / saved_mask path that sigreturn has always restored.
    let args = SyscallArgRegs {
        rax: 0x11,
        rdi: 0x22,
        rsi: 0x33,
        rdx: 0x44,
        r10: 0x55,
        r8: 0x66,
        r9: 0x77,
    };
    let user_rsp = STACK_TOP - 32;
    let saved_rip = 0x0000_4000_0020_0200;
    let saved_rflags = 0x246;
    let saved_mask = 0xabcd_ef01_2345_6789;

    let frame_addr = unsafe {
        push_signal_frame(
            user_rsp,
            15,
            saved_rip,
            saved_rflags,
            saved_mask,
            Some(args),
        )
        .expect("push ok")
    };
    let restored = unsafe { restore_signal_frame(frame_addr).expect("restore ok") };
    assert_eq!(restored.rip, saved_rip);
    assert_eq!(restored.rflags, saved_rflags);
    assert_eq!(restored.rsp, user_rsp);
    assert_eq!(restored.saved_mask, saved_mask);
}

fn fault_frame_yields_no_syscall_args() {
    // Fault-delivered signals (`#PF` → SIGSEGV) push through
    // `push_fault_signal_frame`, which has no `SyscallReturnContext` with
    // arg regs. `restore_signal_frame` must report `syscall_args = None`
    // so the sigreturn path leaves user GPRs alone — zero-filling them
    // from an all-zero `gregs` array would regress caller state for
    // userspace running a SIGSEGV handler over a fault at a non-SYSCALL
    // instruction.
    let user_rsp = STACK_TOP - 48;
    let saved_rip = 0x0000_4000_0030_0300;
    let saved_rflags = 0x202;
    let fault_addr = 0xdead_beef;

    let frame_addr = unsafe {
        push_fault_signal_frame(user_rsp, 11, saved_rip, saved_rflags, 0, fault_addr)
            .expect("push_fault_signal_frame ok")
    };
    let restored = unsafe { restore_signal_frame(frame_addr).expect("restore ok") };
    assert!(
        restored.syscall_args.is_none(),
        "fault frames must not carry syscall arg regs"
    );
    assert_eq!(restored.rip, saved_rip);
    assert_eq!(restored.rsp, user_rsp);
}
