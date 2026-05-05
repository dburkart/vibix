//! Thread implementation for vibix.
//!
//! Uses the `clone` syscall with CLONE_VM|CLONE_THREAD|... to create threads,
//! and futex-based join via CLONE_CHILD_CLEARTID.

use crate::ffi::CStr;
use crate::io;
use crate::num::NonZero;
use crate::sync::atomic::{Atomic, Ordering};
use crate::thread::ThreadInit;
use crate::time::Duration;

/// Minimum stack size for a vibix thread (1 MiB).
pub const DEFAULT_MIN_STACK_SIZE: usize = 1 << 20;

/// Clone flags for pthreads-style threading.
const CLONE_VM: u64 = 0x0000_0100;
const CLONE_FS: u64 = 0x0000_0200;
const CLONE_FILES: u64 = 0x0000_0400;
const CLONE_SIGHAND: u64 = 0x0000_0800;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;
const CLONE_SETTLS: u64 = 0x0008_0000;
const CLONE_PARENT_SETTID: u64 = 0x0010_0000;
const CLONE_CHILD_CLEARTID: u64 = 0x0020_0000;

const CLONE_THREAD_FLAGS: u64 = CLONE_VM
    | CLONE_FS
    | CLONE_FILES
    | CLONE_SIGHAND
    | CLONE_THREAD
    | CLONE_SETTLS
    | CLONE_PARENT_SETTID
    | CLONE_CHILD_CLEARTID
    | CLONE_SYSVSEM;

/// Syscall numbers.
const SYS_CLONE: u64 = 56;
const SYS_MMAP: u64 = 9;
const SYS_MUNMAP: u64 = 11;
const SYS_SCHED_YIELD: u64 = 24;
const SYS_NANOSLEEP: u64 = 35;
const SYS_GETTID: u64 = 186;
const SYS_EXIT: u64 = 60;

/// mmap constants.
const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

/// Timespec structure matching Linux's `struct timespec`.
#[repr(C)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

pub struct Thread {
    /// Pointer to the `ThreadData` allocation (used for join and cleanup).
    data: *mut ThreadData,
}

/// Per-thread data allocated on the heap and shared between parent and child.
/// The `child_tid` field is set by the kernel (CLONE_PARENT_SETTID) and
/// cleared atomically + futex-woken on thread exit (CLONE_CHILD_CLEARTID).
#[repr(C)]
struct ThreadData {
    /// The child's TID -- set by clone, cleared on exit.
    child_tid: Atomic<u32>,
    /// Base of the mmap'd stack allocation.
    stack_base: *mut u8,
    /// Size of the stack allocation.
    stack_size: usize,
    /// The thread init data (consumed by the child on first run).
    init: Option<Box<ThreadInit>>,
}

unsafe impl Send for Thread {}
unsafe impl Sync for Thread {}

impl Thread {
    /// Spawn a new thread.
    ///
    /// # Safety
    /// See `thread::Builder::spawn_unchecked` for safety requirements.
    pub unsafe fn new(stack: usize, init: Box<ThreadInit>) -> io::Result<Thread> {
        // Round stack up to page size (4 KiB).
        let stack_size = (stack + 4095) & !4095;

        // Allocate stack via mmap (grows downward on x86_64).
        let stack_base = unsafe {
            vibix_abi::syscall::syscall6(
                SYS_MMAP,
                0,                             // addr: kernel chooses
                stack_size as u64,             // length
                PROT_READ | PROT_WRITE,        // prot
                MAP_PRIVATE | MAP_ANONYMOUS,   // flags
                u64::MAX,                      // fd: -1 (no file)
                0,                             // offset
            )
        };

        if stack_base < 0 {
            return Err(io::Error::from_raw_os_error(-stack_base as i32));
        }
        let stack_base = stack_base as *mut u8;

        // Allocate ThreadData on the heap.
        let data = Box::into_raw(Box::new(ThreadData {
            child_tid: Atomic::<u32>::new(0),
            stack_base,
            stack_size,
            init: Some(init),
        }));

        // Stack grows downward: top = base + size.
        // We place the ThreadData pointer at the top of the stack so the
        // trampoline can retrieve it.
        let stack_top = unsafe { stack_base.add(stack_size) };

        // Subtract 8 bytes from stack_top to store the data pointer, ensuring
        // 16-byte alignment for the entry point (stack_top - 8 is 8-byte aligned,
        // and after the implicit "call" alignment, the function entry sees 16-byte
        // aligned RSP).
        let stack_top = unsafe { stack_top.sub(16) };
        unsafe {
            *(stack_top as *mut *mut ThreadData) = data;
        }

        // Clone the thread.
        // The child starts at `thread_trampoline` with RSP = stack_top.
        // We use inline asm to call clone because we need to set up the child
        // to jump to our trampoline with the correct stack.
        let child_tid_ptr = &(*data).child_tid as *const Atomic<u32> as *mut u32;
        let ret: i64;
        unsafe {
            core::arch::asm!(
                // syscall: clone(flags, stack, parent_tid, child_tid, tls)
                // rax = 56 (SYS_clone)
                // rdi = flags
                // rsi = stack_top
                // rdx = &parent_tid (same as child_tid for us)
                // r10 = &child_tid
                // r8  = tls (0, we inherit parent TLS for now -- kernel allocates new TLS)
                "syscall",
                // In parent: rax = child TID (> 0)
                // In child:  rax = 0
                "test rax, rax",
                "jnz 2f",
                // --- Child path ---
                // RSP is already set to stack_top by the kernel.
                // Load the ThreadData pointer from [rsp].
                "mov rdi, [rsp]",
                "call {trampoline}",
                // trampoline should not return, but just in case:
                "mov rdi, 0",
                "mov rax, 60",
                "syscall",
                "2:",
                trampoline = sym thread_trampoline,
                inlateout("rax") SYS_CLONE as i64 => ret,
                in("rdi") CLONE_THREAD_FLAGS,
                in("rsi") stack_top,
                in("rdx") child_tid_ptr,
                inlateout("r10") child_tid_ptr => _,
                inlateout("r8") 0u64 => _,
                lateout("rcx") _,
                lateout("r11") _,
                lateout("r9") _,
                options(nostack),
            );
        }

        if ret < 0 {
            // Clone failed -- clean up.
            unsafe {
                vibix_abi::syscall::syscall2(SYS_MUNMAP, stack_base as u64, stack_size as u64);
                drop(Box::from_raw(data));
            }
            return Err(io::Error::from_raw_os_error(-ret as i32));
        }

        Ok(Thread { data })
    }

    /// Wait for the thread to exit.
    pub fn join(self) {
        let data = unsafe { &*self.data };

        // Futex-wait on child_tid until the kernel clears it to 0.
        loop {
            let tid = data.child_tid.load(Ordering::Acquire);
            if tid == 0 {
                break;
            }
            // FUTEX_WAIT on the child_tid address.
            crate::sys::futex::futex_wait(&data.child_tid, tid, None);
        }

        // Thread has exited. Clean up.
        let data = unsafe { Box::from_raw(self.data) };
        unsafe {
            vibix_abi::syscall::syscall2(
                SYS_MUNMAP,
                data.stack_base as u64,
                data.stack_size as u64,
            );
        }
    }
}

/// Trampoline function called by the child thread.
///
/// # Safety
/// `data_ptr` must be a valid pointer to a `ThreadData` whose `init` field
/// is `Some`.
unsafe extern "C" fn thread_trampoline(data_ptr: *mut ThreadData) -> ! {
    let data = unsafe { &mut *data_ptr };

    // Take the init data.
    let init = data.init.take().unwrap();
    let rust_start = init.init();
    rust_start();

    // Run TLS destructors.
    unsafe {
        crate::sys::thread_local::destructors::run();
    }
    crate::rt::thread_cleanup();

    // Exit just this thread (not the whole process).
    unsafe {
        vibix_abi::syscall::syscall1(SYS_EXIT, 0);
    }
    // Unreachable, but the compiler needs a diverging type.
    loop {
        core::hint::spin_loop();
    }
}

/// Return the number of available CPUs.
/// vibix currently supports only 1 CPU.
pub fn available_parallelism() -> io::Result<NonZero<usize>> {
    Ok(unsafe { NonZero::new_unchecked(1) })
}

/// Get the current thread's OS-level ID (TID).
pub fn current_os_id() -> Option<u64> {
    let tid = unsafe { vibix_abi::syscall::syscall0(SYS_GETTID as u64) };
    Some(tid as u64)
}

/// Yield the current thread's timeslice.
#[inline]
pub fn yield_now() {
    unsafe {
        vibix_abi::syscall::syscall0(SYS_SCHED_YIELD);
    }
}

/// Set the current thread's name (stub -- not yet supported).
pub fn set_name(_name: &CStr) {
    // No-op: vibix does not yet support thread naming.
}

/// Sleep for the specified duration.
pub fn sleep(dur: Duration) {
    let mut req = Timespec {
        tv_sec: dur.as_secs() as i64,
        tv_nsec: dur.subsec_nanos() as i64,
    };

    // Loop in case of EINTR.
    loop {
        let ret = unsafe {
            vibix_abi::syscall::syscall2(
                SYS_NANOSLEEP,
                &req as *const Timespec as u64,
                &mut req as *mut Timespec as u64,
            )
        };
        if ret == 0 || ret != -4 {
            // 0 = success, anything other than -EINTR = done
            break;
        }
        // -EINTR: remaining time is in req, loop again.
    }
}
