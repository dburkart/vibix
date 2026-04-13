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

/// Park the driver on `hlt` until `counter` reaches `expected`, so wake-side
/// tests fire their wake only after every worker has reached its blocking
/// call. Each worker bumps its own slot in `counter` immediately before the
/// blocking op (`recv`, `send`, `wait_while`); without this, the driver's
/// wake can race the worker into the fast-path `wake_pending` bail and never
/// actually exercise the parked-wake branch.
///
/// Panics if the workers don't all arrive within `deadline_ticks` hlt cycles
/// — a real bug (worker wedged or scheduler not advancing), not the
/// previous "probably long enough" heuristic.
fn wait_for_ready(counter: &AtomicUsize, expected: usize, deadline_ticks: usize) {
    for _ in 0..deadline_ticks {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        x86_64::instructions::hlt();
    }
    panic!(
        "workers didn't reach the park point in time: ready={}/{}",
        counter.load(Ordering::SeqCst),
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
    loop {
        x86_64::instructions::hlt();
    }
}

fn ch_consumer() -> ! {
    let rx = CH_RX.lock().take().expect("consumer: CH_RX not set");
    for _ in 0..CH_N {
        let v = rx.recv().expect("consumer: recv returned None");
        CH_SUM.fetch_add(v as usize, Ordering::SeqCst);
    }
    CH_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
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
    loop {
        x86_64::instructions::hlt();
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
static WQ_READY: AtomicUsize = AtomicUsize::new(0);

fn wq_waiter() -> ! {
    WQ_READY.fetch_add(1, Ordering::SeqCst);
    WQ.wait_while(|| WQ_FLAG.load(Ordering::SeqCst) == 0);
    WQ_WOKEN.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn waitqueue_notify_all() {
    WQ_FLAG.store(0, Ordering::SeqCst);
    WQ_WOKEN.store(0, Ordering::SeqCst);
    WQ_READY.store(0, Ordering::SeqCst);

    task::spawn(wq_waiter);
    task::spawn(wq_waiter);

    // Wait until both waiters have run up to their wait_while call.
    // Deadline is generous (~2 s) — hitting it means a worker
    // wedged, not just "slower than expected".
    wait_for_ready(&WQ_READY, 2, 200);
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
static SPSC_CLOSE_RX_READY: AtomicUsize = AtomicUsize::new(0);

fn spsc_close_rx_worker() -> ! {
    let rx = SPSC_CLOSE_RX
        .lock()
        .take()
        .expect("spsc_close_rx_worker: receiver not set");
    SPSC_CLOSE_RX_READY.fetch_add(1, Ordering::SeqCst);
    if rx.recv().is_none() {
        SPSC_CLOSE_RX_SAW_NONE.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn spsc_close_wakes_receiver() {
    let (tx, rx) = spsc::channel::<u32>(4);
    *SPSC_CLOSE_RX.lock() = Some(rx);
    SPSC_CLOSE_RX_SAW_NONE.store(0, Ordering::SeqCst);
    SPSC_CLOSE_RX_READY.store(0, Ordering::SeqCst);

    task::spawn(spsc_close_rx_worker);

    // Wait until the worker has reached its recv call.
    wait_for_ready(&SPSC_CLOSE_RX_READY, 1, 200);

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
static SPSC_CLOSE_TX_READY: AtomicUsize = AtomicUsize::new(0);

fn spsc_close_tx_worker() -> ! {
    let tx = SPSC_CLOSE_TX
        .lock()
        .take()
        .expect("spsc_close_tx_worker: sender not set");
    // Channel already has one item buffered; this send parks.
    SPSC_CLOSE_TX_READY.fetch_add(1, Ordering::SeqCst);
    if tx.send(2).is_err() {
        SPSC_CLOSE_TX_SAW_ERR.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn spsc_close_wakes_sender() {
    let (tx, rx) = spsc::channel::<u32>(1);
    tx.send(1).expect("prefill send");
    *SPSC_CLOSE_TX.lock() = Some(tx);
    SPSC_CLOSE_TX_SAW_ERR.store(0, Ordering::SeqCst);
    SPSC_CLOSE_TX_READY.store(0, Ordering::SeqCst);

    task::spawn(spsc_close_tx_worker);

    wait_for_ready(&SPSC_CLOSE_TX_READY, 1, 200);

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
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_m2o_prod_b() -> ! {
    {
        let tx = MPMC_M2O_TX_B.lock().take().expect("m2o prod B: tx not set");
        for i in 0..MPMC_M2O_PER_PROD {
            tx.send(100 + i).expect("m2o prod B: send failed");
        }
    }
    MPMC_M2O_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_m2o_prod_c() -> ! {
    {
        let tx = MPMC_M2O_TX_C.lock().take().expect("m2o prod C: tx not set");
        for i in 0..MPMC_M2O_PER_PROD {
            tx.send(1000 + i).expect("m2o prod C: send failed");
        }
    }
    MPMC_M2O_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_m2o_cons() -> ! {
    let rx = MPMC_M2O_RX.lock().take().expect("m2o cons: rx not set");
    let total = MPMC_M2O_PRODUCERS * MPMC_M2O_PER_PROD;
    for _ in 0..total {
        let v = rx.recv().expect("m2o cons: recv returned None");
        MPMC_M2O_SUM.fetch_add(v as usize, Ordering::SeqCst);
    }
    MPMC_M2O_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
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
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_m2m_prod_b() -> ! {
    {
        let tx = MPMC_M2M_TX_B.lock().take().expect("m2m prod B: tx");
        for i in 0..MPMC_M2M_PER_PROD {
            tx.send(500 + i).expect("m2m prod B: send");
        }
    }
    MPMC_M2M_PROD_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
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
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_m2m_cons_b() -> ! {
    let rx = MPMC_M2M_RX_B.lock().take().expect("m2m cons B: rx");
    while let Some(v) = rx.recv() {
        MPMC_M2M_SUM.fetch_add(v as usize, Ordering::SeqCst);
        MPMC_M2M_RECEIVED.fetch_add(1, Ordering::SeqCst);
    }
    MPMC_M2M_CONS_DONE.fetch_add(1, Ordering::SeqCst);
    loop {
        x86_64::instructions::hlt();
    }
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
static MPMC_CLOSE_RX_READY: AtomicUsize = AtomicUsize::new(0);

fn mpmc_close_rx_a() -> ! {
    let rx = MPMC_CLOSE_RX_A.lock().take().expect("close rx A");
    MPMC_CLOSE_RX_READY.fetch_add(1, Ordering::SeqCst);
    if rx.recv().is_none() {
        MPMC_CLOSE_RX_WOKEN.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_close_rx_b() -> ! {
    let rx = MPMC_CLOSE_RX_B.lock().take().expect("close rx B");
    MPMC_CLOSE_RX_READY.fetch_add(1, Ordering::SeqCst);
    if rx.recv().is_none() {
        MPMC_CLOSE_RX_WOKEN.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_close_wakes_receivers() {
    let (tx, rx) = mpmc::channel::<u32>(4);
    *MPMC_CLOSE_RX_A.lock() = Some(rx.clone());
    *MPMC_CLOSE_RX_B.lock() = Some(rx);
    MPMC_CLOSE_RX_WOKEN.store(0, Ordering::SeqCst);
    MPMC_CLOSE_RX_READY.store(0, Ordering::SeqCst);

    task::spawn(mpmc_close_rx_a);
    task::spawn(mpmc_close_rx_b);

    wait_for_ready(&MPMC_CLOSE_RX_READY, 2, 200);

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
static MPMC_CLOSE_TX_READY: AtomicUsize = AtomicUsize::new(0);

fn mpmc_close_tx_a() -> ! {
    let tx = MPMC_CLOSE_TX_A.lock().take().expect("close tx A");
    MPMC_CLOSE_TX_READY.fetch_add(1, Ordering::SeqCst);
    if tx.send(2).is_err() {
        MPMC_CLOSE_TX_ERRS.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_close_tx_b() -> ! {
    let tx = MPMC_CLOSE_TX_B.lock().take().expect("close tx B");
    MPMC_CLOSE_TX_READY.fetch_add(1, Ordering::SeqCst);
    if tx.send(3).is_err() {
        MPMC_CLOSE_TX_ERRS.fetch_add(1, Ordering::SeqCst);
    }
    loop {
        x86_64::instructions::hlt();
    }
}

fn mpmc_close_wakes_senders() {
    let (tx, rx) = mpmc::channel::<u32>(1);
    tx.send(1).expect("prefill send");
    *MPMC_CLOSE_TX_A.lock() = Some(tx.clone());
    *MPMC_CLOSE_TX_B.lock() = Some(tx);
    MPMC_CLOSE_TX_ERRS.store(0, Ordering::SeqCst);
    MPMC_CLOSE_TX_READY.store(0, Ordering::SeqCst);

    task::spawn(mpmc_close_tx_a);
    task::spawn(mpmc_close_tx_b);

    wait_for_ready(&MPMC_CLOSE_TX_READY, 2, 200);

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
