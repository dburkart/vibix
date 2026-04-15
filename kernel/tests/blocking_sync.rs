//! Integration test: blocking primitives (BlockingMutex, WaitQueue,
//! bounded SPSC channel) park and wake tasks correctly under the
//! round-robin scheduler.

#![no_std]
#![no_main]

extern crate alloc;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicUsize, Ordering};

use spin::Mutex as SpinMutex;
use vibix::sync::{mpmc, spsc};
use vibix::sync::{BlockingMutex, BlockingRwLock, Semaphore, WaitQueue};
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

/// Park the driver on `hlt` until `parked()` reports that `expected`
/// waiters have actually enqueued themselves on the primitive under
/// test. Queried directly against the primitive (`WaitQueue`, channel
/// endpoint), so the driver observes the real parked state instead of
/// a pre-call readiness flag — this closes the race where a worker
/// bumps a readiness counter, gets preempted before the blocking call,
/// and the driver's wake hits `wake_pending` instead of the parked-wake
/// branch the test exists to exercise.
///
/// Panics if the waiters haven't all parked within `deadline_ticks`
/// hlt cycles — a real bug (worker wedged or scheduler not advancing).
fn wait_for_parked<F: Fn() -> usize>(parked: F, expected: usize, deadline_ticks: usize) {
    for _ in 0..deadline_ticks {
        if parked() >= expected {
            return;
        }
        x86_64::instructions::hlt();
    }
    if parked() >= expected {
        return;
    }
    panic!(
        "waiters didn't park in time: parked={}/{}",
        parked(),
        expected
    );
}

fn run_tests() {
    let tests: &[(&str, &dyn Testable)] = &[
        ("channel_ping_pong", &(channel_ping_pong as fn())),
        ("mutex_contention", &(mutex_contention as fn())),
        ("waitqueue_notify_all", &(waitqueue_notify_all as fn())),
        (
            "spsc_close_wakes_receiver",
            &(spsc_close_wakes_receiver as fn()),
        ),
        (
            "spsc_close_wakes_sender",
            &(spsc_close_wakes_sender as fn()),
        ),
        ("mpmc_many_to_one", &(mpmc_many_to_one as fn())),
        ("mpmc_many_to_many", &(mpmc_many_to_many as fn())),
        (
            "mpmc_close_wakes_receivers",
            &(mpmc_close_wakes_receivers as fn()),
        ),
        (
            "mpmc_close_wakes_senders",
            &(mpmc_close_wakes_senders as fn()),
        ),
        (
            "rwlock_concurrent_readers",
            &(rwlock_concurrent_readers as fn()),
        ),
        (
            "rwlock_writer_exclusion",
            &(rwlock_writer_exclusion as fn()),
        ),
        (
            "rwlock_writer_not_starved",
            &(rwlock_writer_not_starved as fn()),
        ),
        (
            "semaphore_permits_block",
            &(semaphore_permits_block as fn()),
        ),
        (
            "semaphore_release_wakes_one",
            &(semaphore_release_wakes_one as fn()),
        ),
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
        tx.send(i).expect("producer: send returned Err");
    }
    CH_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn ch_consumer() -> ! {
    let rx = CH_RX.lock().take().expect("consumer: CH_RX not set");
    for _ in 0..CH_N {
        let v = rx.recv().expect("consumer: recv returned None");
        CH_SUM.fetch_add(v as usize, Ordering::SeqCst);
    }
    CH_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
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

    // Park the driver on `hlt` until both workers finish or the
    // deadline passes. `hlt` wakes on the next PIT tick (~10 ms),
    // handing the CPU to producer/consumer in between.
    for _ in 0..2_000 {
        if CH_PROD_DONE.load(Ordering::SeqCst) == 1 && CH_CONS_DONE.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
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

const MU_ROUNDS: u64 = 10;
/// Busy-work inside the critical section, sized so each lock holder
/// spans at least one preempt tick (~10 ms). Without this, three
/// workers each complete their rounds in <1 ms — the mutex is never
/// actually contended because one worker releases before the next
/// even tries to acquire, and the `wait_while` / `notify_one` park
/// path goes untested. ~200k `pause` ≈ 1–2 ms on typical QEMU; the
/// preempt tick falls inside it and the other workers run headlong
/// into a lock that's still held.
const MU_CRIT_SPINS: usize = 200_000;

fn mu_worker() -> ! {
    for _ in 0..MU_ROUNDS {
        let mut g = MU.lock();
        for _ in 0..MU_CRIT_SPINS {
            core::hint::spin_loop();
        }
        *g += 1;
        // Guard dropped at end of scope -> notify_one wakes a waiter.
    }
    MU_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mutex_contention() {
    // Reset shared state. BlockingMutex doesn't expose a const reset;
    // locking is how we zero it.
    *MU.lock() = 0;
    MU_DONE.store(0, Ordering::SeqCst);

    task::spawn(mu_worker);
    task::spawn(mu_worker);
    task::spawn(mu_worker);

    for _ in 0..2_000 {
        if MU_DONE.load(Ordering::SeqCst) == 3 {
            break;
        }
        x86_64::instructions::hlt();
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
    task::exit();
}

fn waitqueue_notify_all() {
    WQ_FLAG.store(0, Ordering::SeqCst);
    WQ_WOKEN.store(0, Ordering::SeqCst);

    task::spawn(wq_waiter);
    task::spawn(wq_waiter);

    // Wait until both waiters have actually enqueued themselves on WQ.
    // Deadline is generous (~2 s) — hitting it means a worker
    // wedged, not just "slower than expected".
    wait_for_parked(|| WQ.waiter_count(), 2, 200);
    // Nobody should be "woken" yet: flag is still 0.
    assert_eq!(
        WQ_WOKEN.load(Ordering::SeqCst),
        0,
        "waiters woke before the flag flipped"
    );

    // Publish the state change, then notify.
    WQ_FLAG.store(1, Ordering::SeqCst);
    WQ.notify_all();

    for _ in 0..1_000 {
        if WQ_WOKEN.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        WQ_WOKEN.load(Ordering::SeqCst),
        2,
        "notify_all didn't wake both waiters"
    );
}

// --- spsc_close_wakes_receiver --------------------------------------
//
// A receiver parks on an empty SPSC channel. The driver drops the
// sender; the receiver must wake and observe `None` from `recv`.

static SPSC_CLOSE_RX: SpinMutex<Option<spsc::Receiver<u32>>> = SpinMutex::new(None);
static SPSC_CLOSE_RX_SAW_NONE: AtomicUsize = AtomicUsize::new(0);

fn spsc_close_rx_worker() -> ! {
    let rx = SPSC_CLOSE_RX
        .lock()
        .take()
        .expect("spsc_close_rx_worker: receiver not set");
    if rx.recv().is_none() {
        SPSC_CLOSE_RX_SAW_NONE.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn spsc_close_wakes_receiver() {
    let (tx, rx) = spsc::channel::<u32>(4);
    *SPSC_CLOSE_RX.lock() = Some(rx);
    SPSC_CLOSE_RX_SAW_NONE.store(0, Ordering::SeqCst);

    task::spawn(spsc_close_rx_worker);

    // Wait until the worker has actually parked inside `recv`.
    wait_for_parked(|| tx.receivers_parked(), 1, 200);

    // Drop the sender. This must wake the parked receiver.
    drop(tx);

    for _ in 0..1_000 {
        if SPSC_CLOSE_RX_SAW_NONE.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SPSC_CLOSE_RX_SAW_NONE.load(Ordering::SeqCst),
        1,
        "receiver didn't observe None after sender dropped"
    );
}

// --- spsc_close_wakes_sender ----------------------------------------
//
// A sender fills a capacity-1 channel and then parks on `send`. The
// driver drops the receiver; the sender must wake and observe `Err`.

static SPSC_CLOSE_TX: SpinMutex<Option<spsc::Sender<u32>>> = SpinMutex::new(None);
static SPSC_CLOSE_TX_SAW_ERR: AtomicUsize = AtomicUsize::new(0);

fn spsc_close_tx_worker() -> ! {
    let tx = SPSC_CLOSE_TX
        .lock()
        .take()
        .expect("spsc_close_tx_worker: sender not set");
    // Channel already has one item buffered; this send parks.
    if tx.send(2).is_err() {
        SPSC_CLOSE_TX_SAW_ERR.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn spsc_close_wakes_sender() {
    let (tx, rx) = spsc::channel::<u32>(1);
    tx.send(1).expect("prefill send");
    *SPSC_CLOSE_TX.lock() = Some(tx);
    SPSC_CLOSE_TX_SAW_ERR.store(0, Ordering::SeqCst);

    task::spawn(spsc_close_tx_worker);

    wait_for_parked(|| rx.senders_parked(), 1, 200);

    drop(rx);

    for _ in 0..1_000 {
        if SPSC_CLOSE_TX_SAW_ERR.load(Ordering::SeqCst) == 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SPSC_CLOSE_TX_SAW_ERR.load(Ordering::SeqCst),
        1,
        "sender didn't observe Err after receiver dropped"
    );
}

// --- mpmc_many_to_one -----------------------------------------------
//
// Three producer tasks each push a disjoint range; one consumer
// drains all 3*M items and checksums. Exercises `Sender: Clone` and
// the Mutex-protected queue under fan-in contention.

static MPMC_M2O_RX: SpinMutex<Option<mpmc::Receiver<u32>>> = SpinMutex::new(None);
static MPMC_M2O_SUM: AtomicUsize = AtomicUsize::new(0);
static MPMC_M2O_PROD_DONE: AtomicUsize = AtomicUsize::new(0);
static MPMC_M2O_CONS_DONE: AtomicUsize = AtomicUsize::new(0);

const MPMC_M2O_PRODUCERS: u32 = 3;
const MPMC_M2O_PER_PROD: u32 = 20;

// One of three static slots each producer claims on entry. Mirrors
// the CH_TX pattern but with per-producer handoff to avoid racing on
// a single mutex for the take.
static MPMC_M2O_TX_A: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_M2O_TX_B: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_M2O_TX_C: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);

fn mpmc_m2o_prod_a() -> ! {
    {
        let tx = MPMC_M2O_TX_A.lock().take().expect("m2o prod A: tx not set");
        for i in 0..MPMC_M2O_PER_PROD {
            tx.send(i).expect("m2o prod A: send failed");
        }
        // tx drops here at end of the inner scope; releases this
        // producer's sender count. The `-> !` function never
        // returns, so the drop would never run if tx were a
        // top-level local.
    }
    MPMC_M2O_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_m2o_prod_b() -> ! {
    {
        let tx = MPMC_M2O_TX_B.lock().take().expect("m2o prod B: tx not set");
        for i in 0..MPMC_M2O_PER_PROD {
            tx.send(100 + i).expect("m2o prod B: send failed");
        }
    }
    MPMC_M2O_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_m2o_prod_c() -> ! {
    {
        let tx = MPMC_M2O_TX_C.lock().take().expect("m2o prod C: tx not set");
        for i in 0..MPMC_M2O_PER_PROD {
            tx.send(1000 + i).expect("m2o prod C: send failed");
        }
    }
    MPMC_M2O_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_m2o_cons() -> ! {
    let rx = MPMC_M2O_RX.lock().take().expect("m2o cons: rx not set");
    let total = MPMC_M2O_PRODUCERS * MPMC_M2O_PER_PROD;
    for _ in 0..total {
        let v = rx.recv().expect("m2o cons: recv returned None");
        MPMC_M2O_SUM.fetch_add(v as usize, Ordering::SeqCst);
    }
    MPMC_M2O_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_many_to_one() {
    let (tx, rx) = mpmc::channel::<u32>(4);
    *MPMC_M2O_TX_A.lock() = Some(tx.clone());
    *MPMC_M2O_TX_B.lock() = Some(tx.clone());
    *MPMC_M2O_TX_C.lock() = Some(tx.clone());
    // Drop the driver's original tx; only the three cloned handles
    // in TX_A/_B/_C keep the channel open until the workers finish.
    drop(tx);

    *MPMC_M2O_RX.lock() = Some(rx);
    MPMC_M2O_SUM.store(0, Ordering::SeqCst);
    MPMC_M2O_PROD_DONE.store(0, Ordering::SeqCst);
    MPMC_M2O_CONS_DONE.store(0, Ordering::SeqCst);

    task::spawn(mpmc_m2o_prod_a);
    task::spawn(mpmc_m2o_prod_b);
    task::spawn(mpmc_m2o_prod_c);
    task::spawn(mpmc_m2o_cons);

    for _ in 0..2_000 {
        if MPMC_M2O_PROD_DONE.load(Ordering::SeqCst) == MPMC_M2O_PRODUCERS as usize
            && MPMC_M2O_CONS_DONE.load(Ordering::SeqCst) == 1
        {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        MPMC_M2O_PROD_DONE.load(Ordering::SeqCst),
        MPMC_M2O_PRODUCERS as usize,
        "not all producers finished"
    );
    assert_eq!(
        MPMC_M2O_CONS_DONE.load(Ordering::SeqCst),
        1,
        "consumer didn't finish"
    );
    let expected: usize = (0..MPMC_M2O_PER_PROD).map(|i| i as usize).sum::<usize>()
        + (0..MPMC_M2O_PER_PROD)
            .map(|i| (100 + i) as usize)
            .sum::<usize>()
        + (0..MPMC_M2O_PER_PROD)
            .map(|i| (1000 + i) as usize)
            .sum::<usize>();
    assert_eq!(
        MPMC_M2O_SUM.load(Ordering::SeqCst),
        expected,
        "checksum mismatch — fan-in dropped or duplicated items"
    );
}

// --- mpmc_many_to_many ----------------------------------------------
//
// Two producers and two consumers share a channel. The aggregate sum
// across both consumers must equal the expected total.

static MPMC_M2M_TX_A: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_M2M_TX_B: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_M2M_RX_A: SpinMutex<Option<mpmc::Receiver<u32>>> = SpinMutex::new(None);
static MPMC_M2M_RX_B: SpinMutex<Option<mpmc::Receiver<u32>>> = SpinMutex::new(None);
static MPMC_M2M_SUM: AtomicUsize = AtomicUsize::new(0);
static MPMC_M2M_RECEIVED: AtomicUsize = AtomicUsize::new(0);
static MPMC_M2M_PROD_DONE: AtomicUsize = AtomicUsize::new(0);
static MPMC_M2M_CONS_DONE: AtomicUsize = AtomicUsize::new(0);

const MPMC_M2M_PER_PROD: u32 = 20;
const MPMC_M2M_TOTAL: usize = 2 * MPMC_M2M_PER_PROD as usize;

fn mpmc_m2m_prod_a() -> ! {
    {
        let tx = MPMC_M2M_TX_A.lock().take().expect("m2m prod A: tx");
        for i in 0..MPMC_M2M_PER_PROD {
            tx.send(i).expect("m2m prod A: send");
        }
        // tx drops here — critical for consumers' `while let Some`
        // loop to terminate once both producers finish. `-> !` means
        // we'd otherwise hold tx forever in the hlt loop.
    }
    MPMC_M2M_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_m2m_prod_b() -> ! {
    {
        let tx = MPMC_M2M_TX_B.lock().take().expect("m2m prod B: tx");
        for i in 0..MPMC_M2M_PER_PROD {
            tx.send(500 + i).expect("m2m prod B: send");
        }
    }
    MPMC_M2M_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

// Each consumer drains until `recv` returns None (channel closed
// after both senders drop). They cooperatively share the total.
fn mpmc_m2m_cons_a() -> ! {
    let rx = MPMC_M2M_RX_A.lock().take().expect("m2m cons A: rx");
    while let Some(v) = rx.recv() {
        MPMC_M2M_SUM.fetch_add(v as usize, Ordering::SeqCst);
        MPMC_M2M_RECEIVED.fetch_add(1, Ordering::SeqCst);
    }
    MPMC_M2M_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_m2m_cons_b() -> ! {
    let rx = MPMC_M2M_RX_B.lock().take().expect("m2m cons B: rx");
    while let Some(v) = rx.recv() {
        MPMC_M2M_SUM.fetch_add(v as usize, Ordering::SeqCst);
        MPMC_M2M_RECEIVED.fetch_add(1, Ordering::SeqCst);
    }
    MPMC_M2M_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn mpmc_many_to_many() {
    let (tx, rx) = mpmc::channel::<u32>(4);
    *MPMC_M2M_TX_A.lock() = Some(tx.clone());
    *MPMC_M2M_TX_B.lock() = Some(tx.clone());
    // The driver's original `tx` drops at end of scope (immediately
    // below) — only the two cloned handles held by the producer
    // tasks keep the channel open.
    drop(tx);
    *MPMC_M2M_RX_A.lock() = Some(rx.clone());
    *MPMC_M2M_RX_B.lock() = Some(rx);
    MPMC_M2M_SUM.store(0, Ordering::SeqCst);
    MPMC_M2M_RECEIVED.store(0, Ordering::SeqCst);
    MPMC_M2M_PROD_DONE.store(0, Ordering::SeqCst);
    MPMC_M2M_CONS_DONE.store(0, Ordering::SeqCst);

    task::spawn(mpmc_m2m_prod_a);
    task::spawn(mpmc_m2m_prod_b);
    task::spawn(mpmc_m2m_cons_a);
    task::spawn(mpmc_m2m_cons_b);

    for _ in 0..2_000 {
        if MPMC_M2M_PROD_DONE.load(Ordering::SeqCst) == 2
            && MPMC_M2M_CONS_DONE.load(Ordering::SeqCst) == 2
        {
            break;
        }
        x86_64::instructions::hlt();
    }

    assert_eq!(
        MPMC_M2M_PROD_DONE.load(Ordering::SeqCst),
        2,
        "not all producers finished"
    );
    assert_eq!(
        MPMC_M2M_CONS_DONE.load(Ordering::SeqCst),
        2,
        "consumers didn't observe channel close"
    );
    assert_eq!(
        MPMC_M2M_RECEIVED.load(Ordering::SeqCst),
        MPMC_M2M_TOTAL,
        "total item count mismatch across consumers"
    );
    let expected: usize = (0..MPMC_M2M_PER_PROD).map(|i| i as usize).sum::<usize>()
        + (0..MPMC_M2M_PER_PROD)
            .map(|i| (500 + i) as usize)
            .sum::<usize>();
    assert_eq!(
        MPMC_M2M_SUM.load(Ordering::SeqCst),
        expected,
        "checksum mismatch — m2m dropped or duplicated items"
    );
}

// --- mpmc_close_wakes_receivers -------------------------------------
//
// Two receivers park on an empty channel. The driver drops the
// sender; both receivers must wake and observe `None`.

static MPMC_CLOSE_RX_A: SpinMutex<Option<mpmc::Receiver<u32>>> = SpinMutex::new(None);
static MPMC_CLOSE_RX_B: SpinMutex<Option<mpmc::Receiver<u32>>> = SpinMutex::new(None);
static MPMC_CLOSE_RX_WOKEN: AtomicUsize = AtomicUsize::new(0);

fn mpmc_close_rx_a() -> ! {
    let rx = MPMC_CLOSE_RX_A.lock().take().expect("close rx A");
    if rx.recv().is_none() {
        MPMC_CLOSE_RX_WOKEN.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn mpmc_close_rx_b() -> ! {
    let rx = MPMC_CLOSE_RX_B.lock().take().expect("close rx B");
    if rx.recv().is_none() {
        MPMC_CLOSE_RX_WOKEN.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn mpmc_close_wakes_receivers() {
    let (tx, rx) = mpmc::channel::<u32>(4);
    *MPMC_CLOSE_RX_A.lock() = Some(rx.clone());
    *MPMC_CLOSE_RX_B.lock() = Some(rx);
    MPMC_CLOSE_RX_WOKEN.store(0, Ordering::SeqCst);

    task::spawn(mpmc_close_rx_a);
    task::spawn(mpmc_close_rx_b);

    wait_for_parked(|| tx.receivers_parked(), 2, 200);

    // Drop the sole sender; both parked receivers must wake.
    drop(tx);

    for _ in 0..1_000 {
        if MPMC_CLOSE_RX_WOKEN.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        MPMC_CLOSE_RX_WOKEN.load(Ordering::SeqCst),
        2,
        "receivers didn't both wake on last-sender drop"
    );
}

// --- mpmc_close_wakes_senders ---------------------------------------
//
// Channel of capacity 1 is prefilled; two senders each park on
// `send`. The driver drops the sole receiver; both senders must
// wake and observe `Err`.

static MPMC_CLOSE_TX_A: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_CLOSE_TX_B: SpinMutex<Option<mpmc::Sender<u32>>> = SpinMutex::new(None);
static MPMC_CLOSE_TX_ERRS: AtomicUsize = AtomicUsize::new(0);

fn mpmc_close_tx_a() -> ! {
    let tx = MPMC_CLOSE_TX_A.lock().take().expect("close tx A");
    if tx.send(2).is_err() {
        MPMC_CLOSE_TX_ERRS.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn mpmc_close_tx_b() -> ! {
    let tx = MPMC_CLOSE_TX_B.lock().take().expect("close tx B");
    if tx.send(3).is_err() {
        MPMC_CLOSE_TX_ERRS.fetch_add(1, Ordering::SeqCst);
    }
    task::exit();
}

fn mpmc_close_wakes_senders() {
    let (tx, rx) = mpmc::channel::<u32>(1);
    tx.send(1).expect("prefill send");
    *MPMC_CLOSE_TX_A.lock() = Some(tx.clone());
    *MPMC_CLOSE_TX_B.lock() = Some(tx);
    MPMC_CLOSE_TX_ERRS.store(0, Ordering::SeqCst);

    task::spawn(mpmc_close_tx_a);
    task::spawn(mpmc_close_tx_b);

    wait_for_parked(|| rx.senders_parked(), 2, 200);

    // Drop the sole receiver; both parked senders must wake.
    drop(rx);

    for _ in 0..1_000 {
        if MPMC_CLOSE_TX_ERRS.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        MPMC_CLOSE_TX_ERRS.load(Ordering::SeqCst),
        2,
        "senders didn't both wake with Err on last-receiver drop"
    );
}

// --- rwlock_concurrent_readers --------------------------------------
//
// Three reader tasks hold a read guard simultaneously. The test asserts
// that the observed peak reader count reaches 3 — proving the rwlock
// actually allows multiple readers rather than silently serialising them.

static RW_READERS: BlockingRwLock<u64> = BlockingRwLock::new(0);
static RW_READ_LIVE: AtomicUsize = AtomicUsize::new(0);
static RW_READ_PEAK: AtomicUsize = AtomicUsize::new(0);
static RW_READ_DONE: AtomicUsize = AtomicUsize::new(0);

const RW_READ_HOLD_SPINS: usize = 100_000;

fn rw_reader_worker() -> ! {
    let _g = RW_READERS.read();
    let live = RW_READ_LIVE.fetch_add(1, Ordering::SeqCst) + 1;
    // Publish a new peak if we raised it. Racy by design — peak is a
    // high-water mark, not a synchronisation point.
    let mut peak = RW_READ_PEAK.load(Ordering::SeqCst);
    while live > peak {
        match RW_READ_PEAK.compare_exchange(peak, live, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
    for _ in 0..RW_READ_HOLD_SPINS {
        core::hint::spin_loop();
    }
    RW_READ_LIVE.fetch_sub(1, Ordering::SeqCst);
    RW_READ_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn rwlock_concurrent_readers() {
    RW_READ_LIVE.store(0, Ordering::SeqCst);
    RW_READ_PEAK.store(0, Ordering::SeqCst);
    RW_READ_DONE.store(0, Ordering::SeqCst);

    task::spawn(rw_reader_worker);
    task::spawn(rw_reader_worker);
    task::spawn(rw_reader_worker);

    for _ in 0..2_000 {
        if RW_READ_DONE.load(Ordering::SeqCst) == 3 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        RW_READ_DONE.load(Ordering::SeqCst),
        3,
        "readers didn't all finish — park/wake wedged"
    );
    assert_eq!(
        RW_READ_PEAK.load(Ordering::SeqCst),
        3,
        "readers serialised — rwlock didn't grant shared access"
    );
}

// --- rwlock_writer_exclusion ----------------------------------------
//
// Three writer tasks each increment a shared counter N times under the
// write lock. Final value proves writes were serialised (no lost
// updates) and every worker made forward progress.

static RW_WRITERS: BlockingRwLock<u64> = BlockingRwLock::new(0);
static RW_WRITE_DONE: AtomicUsize = AtomicUsize::new(0);

const RW_WRITE_ROUNDS: u64 = 5;
const RW_WRITE_CRIT_SPINS: usize = 50_000;

fn rw_writer_worker() -> ! {
    for _ in 0..RW_WRITE_ROUNDS {
        let mut g = RW_WRITERS.write();
        for _ in 0..RW_WRITE_CRIT_SPINS {
            core::hint::spin_loop();
        }
        *g += 1;
    }
    RW_WRITE_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn rwlock_writer_exclusion() {
    *RW_WRITERS.write() = 0;
    RW_WRITE_DONE.store(0, Ordering::SeqCst);

    task::spawn(rw_writer_worker);
    task::spawn(rw_writer_worker);
    task::spawn(rw_writer_worker);

    for _ in 0..2_000 {
        if RW_WRITE_DONE.load(Ordering::SeqCst) == 3 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        RW_WRITE_DONE.load(Ordering::SeqCst),
        3,
        "not all writer workers finished"
    );
    assert_eq!(
        *RW_WRITERS.read(),
        3 * RW_WRITE_ROUNDS,
        "lost updates — rwlock didn't serialise writers"
    );
}

// --- rwlock_writer_not_starved --------------------------------------
//
// One task holds the write lock and parks. A second task parks on
// `write()` behind it. A stream of reader tasks then tries to acquire;
// they must queue behind the pending writer (the rwlock's
// writer-priority invariant). The test asserts the second writer
// eventually gets through despite continuous reader churn.

static RW_STARVE: BlockingRwLock<u64> = BlockingRwLock::new(0);
static RW_STARVE_WRITER_DONE: AtomicUsize = AtomicUsize::new(0);
static RW_STARVE_READERS_DONE: AtomicUsize = AtomicUsize::new(0);
static RW_STARVE_GO: AtomicUsize = AtomicUsize::new(0);

const RW_STARVE_READERS: u32 = 4;

fn rw_starve_writer() -> ! {
    // Wait until the driver signals us to go, then contend against
    // the first writer (held by the driver).
    while RW_STARVE_GO.load(Ordering::SeqCst) == 0 {
        x86_64::instructions::hlt();
    }
    let mut g = RW_STARVE.write();
    *g += 1;
    drop(g);
    RW_STARVE_WRITER_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn rw_starve_reader() -> ! {
    while RW_STARVE_GO.load(Ordering::SeqCst) == 0 {
        x86_64::instructions::hlt();
    }
    let _g = RW_STARVE.read();
    RW_STARVE_READERS_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn rwlock_writer_not_starved() {
    *RW_STARVE.write() = 0;
    RW_STARVE_WRITER_DONE.store(0, Ordering::SeqCst);
    RW_STARVE_READERS_DONE.store(0, Ordering::SeqCst);
    RW_STARVE_GO.store(0, Ordering::SeqCst);

    // Driver grabs the write lock first.
    let g = RW_STARVE.write();

    // Spawn the second writer and a flood of readers. All of them
    // spin on RW_STARVE_GO so they queue up before any contention
    // begins; when we release RW_STARVE_GO they race to acquire.
    task::spawn(rw_starve_writer);
    for _ in 0..RW_STARVE_READERS {
        task::spawn(rw_starve_reader);
    }

    // Release the go-flag, then drop the driver's guard. The second
    // writer should win the lock next (readers queue behind it due to
    // writer_waiting), complete, then readers drain.
    RW_STARVE_GO.store(1, Ordering::SeqCst);
    // Wait until every worker has actually parked on the rwlock
    // (1 writer + RW_STARVE_READERS). A fixed-hlt grace period was
    // flaky under heavy CI load — workers sometimes hadn't reached
    // `block_current` yet when the driver dropped its guard, so a
    // notify_all found an empty waitqueue and the workers lost the
    // wake. Polling `waiter_count` closes that window deterministically.
    wait_for_parked(
        || RW_STARVE.waiter_count(),
        1 + RW_STARVE_READERS as usize,
        4_000,
    );
    drop(g);

    for _ in 0..4_000 {
        if RW_STARVE_WRITER_DONE.load(Ordering::SeqCst) == 1
            && RW_STARVE_READERS_DONE.load(Ordering::SeqCst) == RW_STARVE_READERS as usize
        {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        RW_STARVE_WRITER_DONE.load(Ordering::SeqCst),
        1,
        "second writer didn't make progress — starved by reader flood"
    );
    assert_eq!(
        RW_STARVE_READERS_DONE.load(Ordering::SeqCst),
        RW_STARVE_READERS as usize,
        "not all readers finished"
    );
}

// --- semaphore_permits_block ----------------------------------------
//
// Semaphore starts with 2 permits; three worker tasks each `acquire`,
// hold briefly, then `release`. Only two can be inside the critical
// region at once — the third must park until one of the first two
// releases. Live-worker peak of exactly 2 proves the permit count is
// honoured.

static SEM_GATE: Semaphore = Semaphore::new(2);
static SEM_LIVE: AtomicUsize = AtomicUsize::new(0);
static SEM_PEAK: AtomicUsize = AtomicUsize::new(0);
static SEM_DONE: AtomicUsize = AtomicUsize::new(0);

const SEM_HOLD_SPINS: usize = 100_000;

fn sem_worker() -> ! {
    SEM_GATE.acquire();
    let live = SEM_LIVE.fetch_add(1, Ordering::SeqCst) + 1;
    let mut peak = SEM_PEAK.load(Ordering::SeqCst);
    while live > peak {
        match SEM_PEAK.compare_exchange(peak, live, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
    for _ in 0..SEM_HOLD_SPINS {
        core::hint::spin_loop();
    }
    SEM_LIVE.fetch_sub(1, Ordering::SeqCst);
    SEM_GATE.release();
    SEM_DONE.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn semaphore_permits_block() {
    // Reset the semaphore by draining any leftover permits and
    // re-releasing to the starting count of 2.
    while SEM_GATE.try_acquire() {}
    SEM_GATE.release();
    SEM_GATE.release();
    SEM_LIVE.store(0, Ordering::SeqCst);
    SEM_PEAK.store(0, Ordering::SeqCst);
    SEM_DONE.store(0, Ordering::SeqCst);

    task::spawn(sem_worker);
    task::spawn(sem_worker);
    task::spawn(sem_worker);

    for _ in 0..4_000 {
        if SEM_DONE.load(Ordering::SeqCst) == 3 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SEM_DONE.load(Ordering::SeqCst),
        3,
        "semaphore workers didn't all finish — park/wake wedged"
    );
    assert_eq!(
        SEM_PEAK.load(Ordering::SeqCst),
        2,
        "permit budget exceeded — semaphore let more than 2 in concurrently"
    );
}

// --- semaphore_release_wakes_one ------------------------------------
//
// Two workers park on a 0-permit semaphore. The driver calls
// `release()` once; exactly one worker must unpark and record its
// wake. A second `release()` frees the other. This mirrors
// `ChildState::Loading`'s "one waiter wins, the rest stay parked until
// their permit arrives" contract.

static SEM_WAKE: Semaphore = Semaphore::new(0);
static SEM_WAKE_COUNT: AtomicUsize = AtomicUsize::new(0);

fn sem_wake_worker() -> ! {
    SEM_WAKE.acquire();
    SEM_WAKE_COUNT.fetch_add(1, Ordering::SeqCst);
    task::exit();
}

fn semaphore_release_wakes_one() {
    while SEM_WAKE.try_acquire() {}
    SEM_WAKE_COUNT.store(0, Ordering::SeqCst);

    task::spawn(sem_wake_worker);
    task::spawn(sem_wake_worker);

    // Wait for both workers to actually park inside `acquire`. We check
    // the waitqueue directly rather than relying on a timing-only grace
    // period — on a CI scheduler with many accumulated background tasks
    // from earlier tests, a hlt-count grace can expire before both
    // workers have run far enough to enqueue.
    for _ in 0..500 {
        if SEM_WAKE.waiter_count() >= 2 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SEM_WAKE.waiter_count(),
        2,
        "both workers did not park on the semaphore in time"
    );
    assert_eq!(
        SEM_WAKE_COUNT.load(Ordering::SeqCst),
        0,
        "workers acquired before any permit was released"
    );

    // One release — exactly one worker should wake.
    SEM_WAKE.release();
    for _ in 0..500 {
        if SEM_WAKE_COUNT.load(Ordering::SeqCst) >= 1 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SEM_WAKE_COUNT.load(Ordering::SeqCst),
        1,
        "first release didn't wake exactly one waiter"
    );

    // Second release frees the other worker.
    SEM_WAKE.release();
    for _ in 0..500 {
        if SEM_WAKE_COUNT.load(Ordering::SeqCst) == 2 {
            break;
        }
        x86_64::instructions::hlt();
    }
    assert_eq!(
        SEM_WAKE_COUNT.load(Ordering::SeqCst),
        2,
        "second release didn't wake the remaining waiter"
    );
}
