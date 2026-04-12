//! Integration test: blocking primitives (BlockingMutex, WaitQueue,
//! bounded SPSC channel) park and wake tasks correctly under the
//! round-robin scheduler.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex as SpinMutex;
use vibix::sync::spsc;
use vibix::sync::{BlockingMutex, WaitQueue};
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
        ("channel_ping_pong", &(channel_ping_pong as fn())),
        ("mutex_contention", &(mutex_contention as fn())),
        ("waitqueue_notify_all", &(waitqueue_notify_all as fn())),
    ];
    serial_println!("running {} tests", tests.len());
    for (name, t) in tests {
        serial_println!("test {name}");
        t.run();
    }
}

// --- channel_ping_pong ----------------------------------------------
//
// A producer sends 0..N through a small bounded channel. A consumer
// receives and checksums. The capacity is 4 so the producer must
// block at least (N - 4) times, proving the "full" path actually
// parks.

static CH_PROD_DONE: AtomicUsize = AtomicUsize::new(0);
static CH_CONS_DONE: AtomicUsize = AtomicUsize::new(0);
static CH_SUM: AtomicUsize = AtomicUsize::new(0);

// Hand-off globals: driver deposits the endpoints, each worker takes
// its own on first run. `SpinMutex<Option<_>>` is the no-runtime-cost
// way to avoid `static_mut_refs` (the endpoints can't be reconstructed
// in a const context, so this has to be runtime).
static CH_TX: SpinMutex<Option<spsc::Sender<u32>>> = SpinMutex::new(None);
static CH_RX: SpinMutex<Option<spsc::Receiver<u32>>> = SpinMutex::new(None);

const CH_N: u32 = 60;

fn ch_producer() -> ! {
    let tx = CH_TX.lock().take().expect("producer: CH_TX not set");
    for i in 0..CH_N {
        tx.send(i);
    }
    CH_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        task::yield_now();
    }
}

fn ch_consumer() -> ! {
    let rx = CH_RX.lock().take().expect("consumer: CH_RX not set");
    for _ in 0..CH_N {
        let v = rx.recv();
        CH_SUM.fetch_add(v as usize, Ordering::SeqCst);
    }
    CH_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        task::yield_now();
    }
}

fn channel_ping_pong() {
    let (tx, rx) = spsc::channel::<u32>(4);
    *CH_TX.lock() = Some(tx);
    *CH_RX.lock() = Some(rx);
    CH_PROD_DONE.store(0, Ordering::SeqCst);
    CH_CONS_DONE.store(0, Ordering::SeqCst);
    CH_SUM.store(0, Ordering::SeqCst);

    task::spawn(ch_producer);
    task::spawn(ch_consumer);

    // Drive the scheduler until both workers finish or we time out.
    // 100_000 yields is comfortably enough for 60 messages through a
    // capacity-4 channel; failure fails fast instead of hanging CI.
    for _ in 0..100_000 {
        if CH_PROD_DONE.load(Ordering::SeqCst) == 1 && CH_CONS_DONE.load(Ordering::SeqCst) == 1 {
            break;
        }
        task::yield_now();
    }

    assert_eq!(
        CH_PROD_DONE.load(Ordering::SeqCst),
        1,
        "producer didn't finish — send() likely wedged on a lost wakeup"
    );
    assert_eq!(
        CH_CONS_DONE.load(Ordering::SeqCst),
        1,
        "consumer didn't finish — recv() likely wedged on a lost wakeup"
    );
    let expected: usize = (0..CH_N).map(|i| i as usize).sum();
    assert_eq!(
        CH_SUM.load(Ordering::SeqCst),
        expected,
        "checksum mismatch — channel reordered or dropped items"
    );
}

// --- mutex_contention -----------------------------------------------
//
// Three worker tasks each increment a shared counter N times under a
// blocking mutex. The final value proves the mutex actually serialised
// the accesses (no lost updates) and that each worker made progress
// (no forever-parked tasks).

static MU: BlockingMutex<u64> = BlockingMutex::new(0);
static MU_DONE: AtomicUsize = AtomicUsize::new(0);

const MU_ROUNDS: u64 = 200;

fn mu_worker() -> ! {
    for _ in 0..MU_ROUNDS {
        {
            let mut g = MU.lock();
            *g += 1;
        }
        // Yield between iterations so the workers actually interleave
        // — without a yield the 10 ms preempt slice will let each
        // worker burn through all its rounds while holding nothing
        // contended, and we wouldn't exercise the blocking path.
        task::yield_now();
    }
    MU_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        task::yield_now();
    }
}

fn mutex_contention() {
    // Reset shared state. BlockingMutex doesn't expose a const reset;
    // locking is how we zero it.
    *MU.lock() = 0;
    MU_DONE.store(0, Ordering::SeqCst);

    task::spawn(mu_worker);
    task::spawn(mu_worker);
    task::spawn(mu_worker);

    for _ in 0..100_000 {
        if MU_DONE.load(Ordering::SeqCst) == 3 {
            break;
        }
        task::yield_now();
    }

    assert_eq!(
        MU_DONE.load(Ordering::SeqCst),
        3,
        "not all mutex workers finished"
    );
    assert_eq!(
        *MU.lock(),
        3 * MU_ROUNDS,
        "lost updates — mutex didn't serialise the increments"
    );
}

// --- waitqueue_notify_all -------------------------------------------
//
// Two waiters park on a waitqueue until a condition flips. The driver
// flips the condition then calls `notify_all`; both waiters must wake
// and make forward progress.

static WQ: WaitQueue = WaitQueue::new();
static WQ_FLAG: AtomicUsize = AtomicUsize::new(0);
static WQ_WOKEN: AtomicUsize = AtomicUsize::new(0);

fn wq_waiter() -> ! {
    WQ.wait_while(|| WQ_FLAG.load(Ordering::SeqCst) == 0);
    WQ_WOKEN.fetch_add(1, Ordering::SeqCst);
    loop {
        task::yield_now();
    }
}

fn waitqueue_notify_all() {
    WQ_FLAG.store(0, Ordering::SeqCst);
    WQ_WOKEN.store(0, Ordering::SeqCst);

    task::spawn(wq_waiter);
    task::spawn(wq_waiter);

    // Let both waiters reach their park. A handful of yields is
    // enough — round-robin will rotate through them immediately.
    for _ in 0..200 {
        task::yield_now();
    }
    // Nobody should be "woken" yet: flag is still 0.
    assert_eq!(
        WQ_WOKEN.load(Ordering::SeqCst),
        0,
        "waiters woke before the flag flipped"
    );

    // Publish the state change, then notify.
    WQ_FLAG.store(1, Ordering::SeqCst);
    WQ.notify_all();

    for _ in 0..10_000 {
        if WQ_WOKEN.load(Ordering::SeqCst) == 2 {
            break;
        }
        task::yield_now();
    }
    assert_eq!(
        WQ_WOKEN.load(Ordering::SeqCst),
        2,
        "notify_all didn't wake both waiters"
    );
}
