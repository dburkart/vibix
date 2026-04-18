//! Integration test: the context-switch paths all route through
//! [`task::set_active_syscall_stack`], and after every switch the live
//! TSS.rsp[0] / `SYSCALL_KERNEL_RSP` agree with the incoming task's
//! `syscall_stack_top`.
//!
//! Regression guard for issue #505 (epic #501): before consolidation
//! the preempt / block / exit paths each carried their own inlined
//! pair of writes to `SYSCALL_KERNEL_RSP` and `TSS.rsp[0]`. A future
//! switch path that forgot the pair would silently land the incoming
//! ring-3 task's SYSCALL on some other task's kernel stack. The single
//! helper eliminates that drift risk, and this test is the teeth:
//! spawn two workers, arm each with a distinct `syscall_stack_top`,
//! force switches between them, and confirm the live TSS matches the
//! current task's stack top after each switch.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use vibix::arch::x86_64::gdt;
use vibix::arch::x86_64::syscall::SYSCALL_KERNEL_RSP;
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
    let tests: &[(&str, &dyn Testable)] = &[
        (
            "tss_tracks_current_task_after_switch",
            &(tss_tracks_current_task_after_switch as fn()),
        ),
        (
            "kernel_only_task_leaves_prior_stack_in_place",
            &(kernel_only_task_leaves_prior_stack_in_place as fn()),
        ),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// -------------------------------------------------------------------
// Test 1: two armed workers rotate, and the live TSS / SYSCALL_KERNEL_RSP
// always match the current task's syscall_stack_top.

static A_STACK: AtomicU64 = AtomicU64::new(0);
static B_STACK: AtomicU64 = AtomicU64::new(0);
static A_MISMATCHES: AtomicUsize = AtomicUsize::new(0);
static B_MISMATCHES: AtomicUsize = AtomicUsize::new(0);
static A_SAMPLES: AtomicUsize = AtomicUsize::new(0);
static B_SAMPLES: AtomicUsize = AtomicUsize::new(0);
static WORKERS_DONE: AtomicUsize = AtomicUsize::new(0);

const SAMPLES_PER_WORKER: usize = 200;

fn worker_a() -> ! {
    // Arm this task's dedicated SYSCALL kernel stack exactly as the
    // init path does before `jump_to_ring3`. That populates
    // `syscall_stack_top` in the Task struct and flows through the
    // helper under test.
    task::arm_ring3_syscall_stack();
    let my_stack = task::current_syscall_stack_top();
    A_STACK.store(my_stack, Ordering::SeqCst);
    assert_ne!(my_stack, 0, "worker_a: arm_ring3_syscall_stack left 0");

    // Hammer the scheduler: each iteration parks briefly on `hlt` so
    // the PIT rotates us out, then on wake we confirm the live TSS
    // and SYSCALL_KERNEL_RSP were updated to OUR stack top by the
    // set_active_syscall_stack call in the preempt/block return path.
    for _ in 0..SAMPLES_PER_WORKER {
        x86_64::instructions::hlt();
        let live = gdt::tss_rsp0();
        let shadow = gdt::tss_rsp0_shadow();
        let syscall_rsp = SYSCALL_KERNEL_RSP.load(Ordering::Relaxed);
        A_SAMPLES.fetch_add(1, Ordering::SeqCst);
        if live != my_stack || shadow != my_stack || syscall_rsp != my_stack {
            A_MISMATCHES.fetch_add(1, Ordering::SeqCst);
        }
    }
    WORKERS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn worker_b() -> ! {
    task::arm_ring3_syscall_stack();
    let my_stack = task::current_syscall_stack_top();
    B_STACK.store(my_stack, Ordering::SeqCst);
    assert_ne!(my_stack, 0, "worker_b: arm_ring3_syscall_stack left 0");

    for _ in 0..SAMPLES_PER_WORKER {
        x86_64::instructions::hlt();
        let live = gdt::tss_rsp0();
        let shadow = gdt::tss_rsp0_shadow();
        let syscall_rsp = SYSCALL_KERNEL_RSP.load(Ordering::Relaxed);
        B_SAMPLES.fetch_add(1, Ordering::SeqCst);
        if live != my_stack || shadow != my_stack || syscall_rsp != my_stack {
            B_MISMATCHES.fetch_add(1, Ordering::SeqCst);
        }
    }
    WORKERS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn tss_tracks_current_task_after_switch() {
    A_STACK.store(0, Ordering::SeqCst);
    B_STACK.store(0, Ordering::SeqCst);
    A_MISMATCHES.store(0, Ordering::SeqCst);
    B_MISMATCHES.store(0, Ordering::SeqCst);
    A_SAMPLES.store(0, Ordering::SeqCst);
    B_SAMPLES.store(0, Ordering::SeqCst);
    WORKERS_DONE.store(0, Ordering::SeqCst);

    task::spawn(worker_a);
    task::spawn(worker_b);

    // Park the driver until both workers have sampled to completion
    // or the deadline passes. Generous slack: at 100 Hz PIT and
    // SAMPLES_PER_WORKER=200 per task plus rotation overhead, a few
    // seconds' worth of ticks is the right order of magnitude.
    for _ in 0..2_000 {
        if WORKERS_DONE.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }

    let a_stack = A_STACK.load(Ordering::SeqCst);
    let b_stack = B_STACK.load(Ordering::SeqCst);
    let a_samples = A_SAMPLES.load(Ordering::SeqCst);
    let b_samples = B_SAMPLES.load(Ordering::SeqCst);
    let a_mismatches = A_MISMATCHES.load(Ordering::SeqCst);
    let b_mismatches = B_MISMATCHES.load(Ordering::SeqCst);
    let done = WORKERS_DONE.load(Ordering::SeqCst);

    assert_eq!(done, 2, "workers did not finish sampling (done={done})");
    assert_ne!(a_stack, 0, "worker_a never published its stack top");
    assert_ne!(b_stack, 0, "worker_b never published its stack top");
    assert_ne!(
        a_stack, b_stack,
        "workers ended up with the same syscall_stack_top ({a_stack:#x})"
    );
    assert_eq!(
        a_samples, SAMPLES_PER_WORKER,
        "worker_a sampled {a_samples} times, expected {SAMPLES_PER_WORKER}"
    );
    assert_eq!(
        b_samples, SAMPLES_PER_WORKER,
        "worker_b sampled {b_samples} times, expected {SAMPLES_PER_WORKER}"
    );
    assert_eq!(
        a_mismatches, 0,
        "worker_a saw {a_mismatches}/{a_samples} post-switch TSS/SYSCALL_KERNEL_RSP mismatches against its own stack ({a_stack:#x})"
    );
    assert_eq!(
        b_mismatches, 0,
        "worker_b saw {b_mismatches}/{b_samples} post-switch TSS/SYSCALL_KERNEL_RSP mismatches against its own stack ({b_stack:#x})"
    );
}

// -------------------------------------------------------------------
// Test 2: a kernel-only task (syscall_stack_top == 0) must NOT clobber
// the TSS / SYSCALL_KERNEL_RSP with zero when switched in — the helper
// treats `syscall_stack_top == 0` as "don't touch", keeping the prior
// ring-3 task's stack pointers live.

static ARMER_STACK: AtomicU64 = AtomicU64::new(0);
static ARMER_READY: AtomicBool = AtomicBool::new(false);
static KERNEL_ONLY_RAN: AtomicBool = AtomicBool::new(false);
static TSS_DURING_KERNEL_ONLY: AtomicU64 = AtomicU64::new(0);
static SYSCALL_RSP_DURING_KERNEL_ONLY: AtomicU64 = AtomicU64::new(0);

fn armer_task() -> ! {
    task::arm_ring3_syscall_stack();
    ARMER_STACK.store(task::current_syscall_stack_top(), Ordering::SeqCst);
    ARMER_READY.store(true, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn kernel_only_task() -> ! {
    // This task NEVER calls arm_ring3_syscall_stack — its
    // syscall_stack_top stays at 0 (kernel-only task). When the
    // scheduler rotates us in, the helper should skip the write,
    // leaving whatever the prior ring-3 armer stored.
    KERNEL_ONLY_RAN.store(true, Ordering::SeqCst);
    TSS_DURING_KERNEL_ONLY.store(gdt::tss_rsp0(), Ordering::SeqCst);
    SYSCALL_RSP_DURING_KERNEL_ONLY
        .store(SYSCALL_KERNEL_RSP.load(Ordering::Relaxed), Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn kernel_only_task_leaves_prior_stack_in_place() {
    ARMER_STACK.store(0, Ordering::SeqCst);
    ARMER_READY.store(false, Ordering::SeqCst);
    KERNEL_ONLY_RAN.store(false, Ordering::SeqCst);
    TSS_DURING_KERNEL_ONLY.store(0, Ordering::SeqCst);
    SYSCALL_RSP_DURING_KERNEL_ONLY.store(0, Ordering::SeqCst);

    // Spawn the armer first and wait for it to publish its stack top
    // (and therefore install it on the TSS). Only then spawn the
    // kernel-only follower, so we know the TSS held a non-zero
    // armer-specific value at the moment of the kernel-only switch-in.
    task::spawn(armer_task);
    for _ in 0..200 {
        if ARMER_READY.load(Ordering::SeqCst) {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert!(
        ARMER_READY.load(Ordering::SeqCst),
        "armer task never ran / published its stack"
    );
    let armer_stack = ARMER_STACK.load(Ordering::SeqCst);
    assert_ne!(armer_stack, 0, "armer stack top was still 0");

    task::spawn(kernel_only_task);
    for _ in 0..200 {
        if KERNEL_ONLY_RAN.load(Ordering::SeqCst) {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert!(
        KERNEL_ONLY_RAN.load(Ordering::SeqCst),
        "kernel-only task never got the CPU"
    );

    // The kernel-only task observed live TSS/SYSCALL_KERNEL_RSP while
    // running — both should still be whatever the armer installed,
    // not zero.
    let tss = TSS_DURING_KERNEL_ONLY.load(Ordering::SeqCst);
    let syscall_rsp = SYSCALL_RSP_DURING_KERNEL_ONLY.load(Ordering::SeqCst);
    assert_ne!(
        tss, 0,
        "kernel-only task observed TSS.rsp[0] == 0 after switch-in (armer stack was {armer_stack:#x})"
    );
    assert_ne!(
        syscall_rsp, 0,
        "kernel-only task observed SYSCALL_KERNEL_RSP == 0 after switch-in (armer stack was {armer_stack:#x})"
    );
}
