//! Integration test for #763: the PT_INTERP ENOEXEC gate from RFC 0004
//! Workstream F has been removed. `execve` of a dynamically-linked ELF
//! now proceeds past the old gate and fails only because the named
//! interpreter module is not present among the Limine modules
//! (`InterpNotFound` → still `-8`/ENOEXEC from the LoadError mapping,
//! but via the loader, not the gate).
//!
//! The test synthesizes a minimal ELF64 with a `PT_INTERP` naming a
//! non-existent interpreter and verifies that:
//!
//! 1. `exec_atomic` returns `Err(-8)` (ENOEXEC) — the interpreter
//!    module is absent, so the loader returns `InterpNotFound`.
//! 2. The caller's address-space `Arc` pointer is unchanged (the staged
//!    PML4 is never committed on failure).
//!
//! Prior to #763 the gate refused the binary *before* even attempting
//! the load; now the binary passes through and the loader's
//! `InterpNotFound` is the observable failure mode.

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
        "execve_ptinterp_passes_gate_fails_interp_not_found",
        &(execve_ptinterp_passes_gate_fails_interp_not_found as fn()),
    )];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- ELF64 synthesis helpers --------------------------------------------

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

static WORKER_OBSERVED_ERR: AtomicUsize = AtomicUsize::new(0);
static WORKER_ASPACE_PRESERVED: AtomicUsize = AtomicUsize::new(0);
static WORKER_DONE: AtomicUsize = AtomicUsize::new(0);

fn exec_worker() -> ! {
    let before = task::current_address_space();
    let before_ptr = Arc::as_ptr(&before) as usize;
    drop(before);

    // Synthesize a dynamically-linked ELF with a PT_INTERP naming a
    // non-existent interpreter. The old gate would have returned
    // ENOEXEC before reaching the loader; now the loader proceeds
    // and returns InterpNotFound (still mapped to -8 by exec_atomic).
    let bytes = sample_elf_with_interp(b"/lib/ld-linux.so.2");
    // Leak the Vec so the slice is 'static — exec_atomic now requires
    // &'static [u8] for the demand-paged loader.
    let leaked: &'static [u8] = bytes.leak();
    match exec_atomic(leaked) {
        Ok(_never) => {
            unreachable!("exec_atomic returned Ok with a dynamically-linked ELF");
        }
        Err(code) => {
            // -8 = ENOEXEC, which is the mapping of LoadError (either
            // InterpNotFound or InterpLoadFailed).
            if code == -8 {
                WORKER_OBSERVED_ERR.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    // Address-space identity must be preserved on failure.
    let after = task::current_address_space();
    let after_ptr = Arc::as_ptr(&after) as usize;
    drop(after);
    if after_ptr == before_ptr {
        WORKER_ASPACE_PRESERVED.fetch_add(1, Ordering::SeqCst);
    }

    WORKER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn execve_ptinterp_passes_gate_fails_interp_not_found() {
    WORKER_OBSERVED_ERR.store(0, Ordering::SeqCst);
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
        WORKER_OBSERVED_ERR.load(Ordering::SeqCst),
        1,
        "exec_atomic with PT_INTERP did not return -8 (InterpNotFound)"
    );
    assert_eq!(
        WORKER_ASPACE_PRESERVED.load(Ordering::SeqCst),
        1,
        "address-space Arc swapped despite failed exec — staged PML4 leaked"
    );
}
