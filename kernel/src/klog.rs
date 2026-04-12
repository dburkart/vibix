//! Kernel log ring buffer + leveled logger (`dmesg`-style retention).
//!
//! A fixed-size byte ring holds the most recent log records. Each record
//! is `[level:u8][len_lo:u8][len_hi:u8][utf8 payload: len bytes]`. When
//! the ring is full, the oldest record is evicted to make room. The
//! writer lock disables interrupts on the kernel target so that a log
//! call from an ISR can't deadlock against the cooperative kernel.
//!
//! Records that pass the current level threshold are both stored in the
//! ring *and* forwarded to the live serial + framebuffer sinks, so the
//! ring coexists with existing `println!` / `serial_println!` flow.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU8, Ordering};

use spin::Mutex;

/// Total ring capacity in bytes, headers included.
pub const RING_BYTES: usize = 64 * 1024;
/// Header is `level` + two length bytes (little-endian u16).
const HEADER: usize = 3;
/// Max payload bytes per record; longer formats are truncated.
const RECORD_MAX: usize = 512;

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
    Trace = 4,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }

    fn from_u8(v: u8) -> Option<Level> {
        match v {
            0 => Some(Level::Error),
            1 => Some(Level::Warn),
            2 => Some(Level::Info),
            3 => Some(Level::Debug),
            4 => Some(Level::Trace),
            _ => None,
        }
    }
}

static THRESHOLD: AtomicU8 = AtomicU8::new(Level::Info as u8);

pub fn set_threshold(level: Level) {
    THRESHOLD.store(level as u8, Ordering::Relaxed);
}

pub fn threshold() -> Level {
    Level::from_u8(THRESHOLD.load(Ordering::Relaxed)).unwrap_or(Level::Info)
}

pub fn enabled(level: Level) -> bool {
    (level as u8) <= THRESHOLD.load(Ordering::Relaxed)
}

pub struct Ring {
    buf: [u8; RING_BYTES],
    head: usize,
    filled: usize,
}

impl Ring {
    const fn new() -> Self {
        Self {
            buf: [0; RING_BYTES],
            head: 0,
            filled: 0,
        }
    }

    fn tail(&self) -> usize {
        (self.head + self.filled) % RING_BYTES
    }

    fn evict_one(&mut self) {
        if self.filled < HEADER {
            self.head = 0;
            self.filled = 0;
            return;
        }
        let len_lo = self.buf[(self.head + 1) % RING_BYTES] as usize;
        let len_hi = self.buf[(self.head + 2) % RING_BYTES] as usize;
        let len = len_lo | (len_hi << 8);
        let total = HEADER + len;
        let skip = total.min(self.filled);
        self.head = (self.head + skip) % RING_BYTES;
        self.filled -= skip;
    }

    fn push(&mut self, level: Level, bytes: &[u8]) {
        let len = bytes.len().min(RECORD_MAX);
        let total = HEADER + len;
        if total > RING_BYTES {
            return;
        }
        while RING_BYTES - self.filled < total {
            self.evict_one();
        }
        let mut p = self.tail();
        self.buf[p] = level as u8;
        p = (p + 1) % RING_BYTES;
        self.buf[p] = (len & 0xFF) as u8;
        p = (p + 1) % RING_BYTES;
        self.buf[p] = ((len >> 8) & 0xFF) as u8;
        p = (p + 1) % RING_BYTES;
        for &b in &bytes[..len] {
            self.buf[p] = b;
            p = (p + 1) % RING_BYTES;
        }
        self.filled += total;
    }

    /// Walk records oldest-first. `f` receives level + payload, with the
    /// payload unwrapped into a contiguous slice via a scratch buffer.
    fn for_each<F: FnMut(Level, &[u8])>(&self, mut f: F) {
        let mut p = self.head;
        let mut remaining = self.filled;
        let mut tmp = [0u8; RECORD_MAX];
        while remaining >= HEADER {
            let lvl_b = self.buf[p % RING_BYTES];
            let len_lo = self.buf[(p + 1) % RING_BYTES] as usize;
            let len_hi = self.buf[(p + 2) % RING_BYTES] as usize;
            let len = len_lo | (len_hi << 8);
            let total = HEADER + len;
            if total > remaining || len > tmp.len() {
                break;
            }
            let lvl = Level::from_u8(lvl_b).unwrap_or(Level::Info);
            let start = (p + HEADER) % RING_BYTES;
            if start + len <= RING_BYTES {
                tmp[..len].copy_from_slice(&self.buf[start..start + len]);
            } else {
                let first = RING_BYTES - start;
                tmp[..first].copy_from_slice(&self.buf[start..]);
                tmp[first..len].copy_from_slice(&self.buf[..len - first]);
            }
            f(lvl, &tmp[..len]);
            p = (p + total) % RING_BYTES;
            remaining -= total;
        }
    }

    fn record_count(&self) -> usize {
        let mut c = 0;
        self.for_each(|_, _| c += 1);
        c
    }
}

static RING: Mutex<Ring> = Mutex::new(Ring::new());

#[cfg(target_os = "none")]
fn with_ring<R>(f: impl FnOnce(&mut Ring) -> R) -> R {
    x86_64::instructions::interrupts::without_interrupts(|| f(&mut RING.lock()))
}

#[cfg(not(target_os = "none"))]
fn with_ring<R>(f: impl FnOnce(&mut Ring) -> R) -> R {
    f(&mut RING.lock())
}

/// One-shot formatting buffer — truncates cleanly on overflow and
/// refuses to split a UTF-8 code point mid-character.
struct FixedBuf {
    buf: [u8; RECORD_MAX],
    len: usize,
}

impl FixedBuf {
    fn new() -> Self {
        Self {
            buf: [0; RECORD_MAX],
            len: 0,
        }
    }
    fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }
}

impl Write for FixedBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let room = self.buf.len() - self.len;
        let mut take = s.len().min(room);
        while take > 0 && !s.is_char_boundary(take) {
            take -= 1;
        }
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

#[doc(hidden)]
pub fn _log(level: Level, args: fmt::Arguments) {
    if !enabled(level) {
        return;
    }
    let mut fb = FixedBuf::new();
    let _ = fb.write_fmt(args);
    with_ring(|r| r.push(level, fb.as_bytes()));

    #[cfg(target_os = "none")]
    {
        crate::serial::_print(format_args!("[{}] {}\n", level.as_str(), fb.as_str()));
        crate::framebuffer::_print(format_args!("[{}] {}\n", level.as_str(), fb.as_str()));
    }
}

/// Drain all records in the ring to `w`, oldest first, formatted as
/// `[LEVEL] payload\n`. Intended for a future `dmesg` shell builtin.
pub fn drain_to<W: Write>(w: &mut W) -> fmt::Result {
    let mut err: fmt::Result = Ok(());
    with_ring(|r| {
        r.for_each(|lvl, payload| {
            if err.is_err() {
                return;
            }
            let s = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
            if let Err(e) = writeln!(w, "[{}] {}", lvl.as_str(), s) {
                err = Err(e);
            }
        });
    });
    err
}

/// Dump the last `n` records to `w`. Use from the panic handler.
pub fn tail_to<W: Write>(w: &mut W, n: usize) -> fmt::Result {
    let mut err: fmt::Result = Ok(());
    with_ring(|r| {
        // Count + iterate under the same lock: a split across two
        // `with_ring` calls would let an ISR push + evict between them,
        // making `skip` larger than the post-eviction record count and
        // producing an empty tail right when we need it most (panic).
        let total = r.record_count();
        let skip = total.saturating_sub(n);
        let mut i = 0usize;
        r.for_each(|lvl, payload| {
            if err.is_err() {
                return;
            }
            if i >= skip {
                let s = core::str::from_utf8(payload).unwrap_or("<non-utf8>");
                if let Err(e) = writeln!(w, "[{}] {}", lvl.as_str(), s) {
                    err = Err(e);
                }
            }
            i += 1;
        });
    });
    err
}

/// Dump the last `n` records straight to COM1. Safe to call from the
/// panic handler before halting.
#[cfg(target_os = "none")]
pub fn dump_tail_to_serial(n: usize) {
    struct SerialSink;
    impl Write for SerialSink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            crate::serial::_print(format_args!("{}", s));
            Ok(())
        }
    }
    let _ = tail_to(&mut SerialSink, n);
}

#[macro_export]
macro_rules! klog {
    ($level:expr, $($arg:tt)*) => {
        $crate::klog::_log($level, format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! kerror { ($($arg:tt)*) => { $crate::klog!($crate::klog::Level::Error, $($arg)*) }; }
#[macro_export]
macro_rules! kwarn  { ($($arg:tt)*) => { $crate::klog!($crate::klog::Level::Warn,  $($arg)*) }; }
#[macro_export]
macro_rules! kinfo  { ($($arg:tt)*) => { $crate::klog!($crate::klog::Level::Info,  $($arg)*) }; }
#[macro_export]
macro_rules! kdebug { ($($arg:tt)*) => { $crate::klog!($crate::klog::Level::Debug, $($arg)*) }; }
#[macro_export]
macro_rules! ktrace { ($($arg:tt)*) => { $crate::klog!($crate::klog::Level::Trace, $($arg)*) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    // Serialize tests that touch the global ring.
    static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn reset() {
        set_threshold(Level::Info);
        with_ring(|r| {
            r.head = 0;
            r.filled = 0;
        });
    }

    #[test]
    fn wrap_around_evicts_oldest() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        // Each record ≈ 80 bytes; 1000 records ≫ 64 KiB → wrap many times.
        for i in 0..1000 {
            _log(
                Level::Info,
                format_args!(
                    "record {i:04} padding padding padding padding padding padding padding"
                ),
            );
        }
        let mut out = String::new();
        drain_to(&mut out).unwrap();
        assert!(out.contains("record 0999"), "most recent record missing");
        assert!(
            !out.contains("record 0000"),
            "oldest record should be evicted"
        );
        // Ring must still hold < capacity bytes of records.
        let filled = with_ring(|r| r.filled);
        assert!(filled <= RING_BYTES);
    }

    #[test]
    fn level_filtering() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        set_threshold(Level::Warn);
        _log(Level::Error, format_args!("boom"));
        _log(Level::Warn, format_args!("yikes"));
        _log(Level::Info, format_args!("hi"));
        _log(Level::Debug, format_args!("dbg"));
        let mut out = String::new();
        drain_to(&mut out).unwrap();
        assert!(out.contains("boom"));
        assert!(out.contains("yikes"));
        assert!(!out.contains("hi"));
        assert!(!out.contains("dbg"));
    }

    #[test]
    fn tail_returns_only_last_n() {
        let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        reset();
        for i in 0..10 {
            _log(Level::Info, format_args!("line {i}"));
        }
        let mut out = String::new();
        tail_to(&mut out, 3).unwrap();
        assert!(out.contains("line 7"));
        assert!(out.contains("line 8"));
        assert!(out.contains("line 9"));
        assert!(!out.contains("line 6"));
    }
}
