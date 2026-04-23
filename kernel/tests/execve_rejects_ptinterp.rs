//! Integration test for #578: `execve` must refuse dynamically-linked
//! binaries with `ENOEXEC` until a userspace `ld.so` lands.
//!
//! Synthesizes a minimal but otherwise well-formed ELF64 image that
//! carries a `PT_INTERP` program header naming `/lib/ld-linux.so.2` and
//! feeds it to the public `arch::x86_64::syscall::exec_atomic` hook.
//! Asserts that the call returns `Err(-8)` (ENOEXEC) and that the
//! caller's address-space `Arc` pointer is unchanged — the gate must
//! refuse the binary *before* any staged PML4 could be committed.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use vibix::arch::x86_64::syscall::exec_atomic;
use vibix::{
    exit_qemu, serial_println, task,
    test_harness::{test_panic_handler, Testable},
    QemuExitCode,
};

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
    let tests: &[(&str, &dyn Testable)] = &[(
        "execve_refuses_ptinterp_with_enoexec",
        &(execve_refuses_ptinterp_with_enoexec as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- ELF64 synthesis helpers --------------------------------------------
//
// Just enough machinery to emit a well-formed ELF64 with one PT_INTERP
// segment and two PT_LOAD segments. Fields we don't care about are left
// zero — the loader (and the execve gate) only look at the ELF magic,
// e_phoff/e_phnum, and the phdr entries themselves.

const EHDR_SIZE: usize = 0x40;
const PHDR_SIZE: usize = 0x38;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn sample_elf_with_interp(path: &[u8]) -> Vec<u8> {
    // Layout: EHDR | PHDR[0]=PT_INTERP | PHDR[1]=PT_LOAD(rx) | PHDR[2]=PT_LOAD(rw) | path bytes
    let phdr_count = 3;
    let phdr_table_size = phdr_count * PHDR_SIZE;
    let path_offset = EHDR_SIZE + phdr_table_size;
    // path bytes include null terminator
    let total = path_offset + path.len() + 1;

    let mut bytes = vec![0u8; total];
    // ELF magic + class/data/version
    bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // ELF v1
    put16(&mut bytes, 16, 2); // ET_EXEC
    put16(&mut bytes, 18, 0x3e); // x86_64
    put32(&mut bytes, 20, 1); // EV_CURRENT
    put64(&mut bytes, 24, 0x400080); // entry (within PT_LOAD[0])
    put64(&mut bytes, 32, EHDR_SIZE as u64); // e_phoff
    put16(&mut bytes, 52, EHDR_SIZE as u16); // e_ehsize
    put16(&mut bytes, 54, PHDR_SIZE as u16); // e_phentsize
    put16(&mut bytes, 56, phdr_count as u16); // e_phnum

    // phdr 0: PT_INTERP
    let p0 = EHDR_SIZE;
    put32(&mut bytes, p0, 3); // PT_INTERP
    put64(&mut bytes, p0 + 8, path_offset as u64); // p_offset → appended path
    put64(&mut bytes, p0 + 32, (path.len() + 1) as u64); // p_filesz (with nul)
    put64(&mut bytes, p0 + 40, (path.len() + 1) as u64); // p_memsz

    // phdr 1: PT_LOAD RX (covers entry 0x400080)
    let p1 = EHDR_SIZE + PHDR_SIZE;
    put32(&mut bytes, p1, 1); // PT_LOAD
    put32(&mut bytes, p1 + 4, 1); // PF_X
    put64(&mut bytes, p1 + 16, 0x400000); // p_vaddr
    put64(&mut bytes, p1 + 40, 0x2000); // p_memsz

    // phdr 2: PT_LOAD RW
    let p2 = EHDR_SIZE + 2 * PHDR_SIZE;
    put32(&mut bytes, p2, 1); // PT_LOAD
    put32(&mut bytes, p2 + 4, 2); // PF_W
    put64(&mut bytes, p2 + 16, 0x402000); // p_vaddr
    put64(&mut bytes, p2 + 40, 0x1000); // p_memsz

    // Write the path bytes (with null terminator) at `path_offset`.
    bytes[path_offset..path_offset + path.len()].copy_from_slice(path);
    bytes[path_offset + path.len()] = 0; // null terminator

    bytes
}

static WORKER_OBSERVED_ENOEXEC: AtomicUsize = AtomicUsize::new(0);
static WORKER_ASPACE_PRESERVED: AtomicUsize = AtomicUsize::new(0);
static WORKER_DONE: AtomicUsize = AtomicUsize::new(0);

fn exec_worker() -> ! {
    let before = task::current_address_space();
    let before_ptr = Arc::as_ptr(&before) as usize;
    drop(before);

    // Synthesize a dynamically-linked ELF: well-formed phdr table with
    // one PT_INTERP. If the gate is missing, the loader would attempt
    // to resolve `/lib/ld-linux.so.2` as a Limine module and return a
    // different errno (InterpNotFound → -ENOEXEC too, but via a path
    // we explicitly do not want to exercise here).
    let bytes = sample_elf_with_interp(b"/lib/ld-linux.so.2");
    match exec_atomic(&bytes) {
        Ok(_never) => {
            unreachable!("exec_atomic returned Ok with a dynamically-linked ELF");
        }
        Err(code) => {
            if code == -8 {
                WORKER_OBSERVED_ENOEXEC.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // Gate must refuse before any staged PML4 commit — address-space
    // identity must be preserved.
    let after = task::current_address_space();
    let after_ptr = Arc::as_ptr(&after) as usize;
    drop(after);
    if after_ptr == before_ptr {
        WORKER_ASPACE_PRESERVED.fetch_add(1, Ordering::SeqCst);
    }

    WORKER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn execve_refuses_ptinterp_with_enoexec() {
    WORKER_OBSERVED_ENOEXEC.store(0, Ordering::SeqCst);
    WORKER_ASPACE_PRESERVED.store(0, Ordering::SeqCst);
    WORKER_DONE.store(0, Ordering::SeqCst);

    task::spawn(exec_worker);

    for _ in 0..200 {
        if WORKER_DONE.load(Ordering::SeqCst) == 1 {
            for _ in 0..4 {
                x86_64::instructions::hlt();
            }
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        WORKER_DONE.load(Ordering::SeqCst),
        1,
        "exec_worker never finished"
    );
    assert_eq!(
        WORKER_OBSERVED_ENOEXEC.load(Ordering::SeqCst),
        1,
        "exec_atomic with PT_INTERP did not return -ENOEXEC"
    );
    assert_eq!(
        WORKER_ASPACE_PRESERVED.load(Ordering::SeqCst),
        1,
        "address-space Arc swapped despite refused exec — gate ran too late"
    );
}
