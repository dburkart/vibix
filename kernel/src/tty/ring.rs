//! `DeferredByteRing` — a fixed-capacity, allocation-free byte ring used as
//! the ISR→soft-IRQ handoff buffer for TTY drivers.
//!
//! The producer side is an ISR (serial UART rx, PS/2 keyboard) that has
//! exclusive access through the hardware vectoring — there is at most one
//! concurrent pusher per ring. The consumer is the registered soft-IRQ
//! drain handler that runs in process context. Per RFC 0003 §Soft-IRQ we
//! therefore implement a lock-free SPSC ring where the "S" producer is
//! assumed-exclusive by callsite discipline.
//!
//! The storage is a `[AtomicU8; CAPACITY]` so that compilers never
//! reorder the data store past the `tail` release, and so the Miri/UB
//! rules for concurrent aliased access are the atomic ones even though
//! only one thread writes a given slot at a time. `head` and `tail` sit
//! on separate cache lines to avoid false sharing between producer and
//! consumer.

use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

/// Ring capacity in bytes. Power of two so `(idx & MASK)` replaces
/// modulo, and small enough to stay cheap on the ISR side.
pub const CAPACITY: usize = 128;

/// High-watermark threshold (bytes). When `len() >= WATERMARK_HIGH` a
/// driver may deassert RTS to backpressure the peer. 96/128 = 75%.
pub const WATERMARK_HIGH: usize = 96;

const MASK: usize = CAPACITY - 1;
const _: () = assert!(CAPACITY.is_power_of_two());

/// Cache-line-sized wrapper. x86-64's L1 cache line is 64 bytes, so two
/// counters in separate `CachePadded` slots won't false-share.
#[repr(C, align(64))]
struct CachePadded<T>(T);

/// Fixed-capacity SPSC byte ring.
///
/// Capacity is [`CAPACITY`] bytes. Push returns `false` when full;
/// `pop` returns `None` when empty. Both operations are lock-free and
/// safe to call with IRQs disabled — there is no spinning and no
/// allocation.
pub struct DeferredByteRing {
    buf: [AtomicU8; CAPACITY],
    head: CachePadded<AtomicUsize>,
    tail: CachePadded<AtomicUsize>,
}

impl DeferredByteRing {
    /// Construct an empty ring. `const fn` so it can live in a `static`.
    pub const fn new() -> Self {
        // `AtomicU8::new` is `const`; build the array by repeated initialiser.
        const INIT: AtomicU8 = AtomicU8::new(0);
        Self {
            buf: [INIT; CAPACITY],
            head: CachePadded(AtomicUsize::new(0)),
            tail: CachePadded(AtomicUsize::new(0)),
        }
    }

    /// Bytes currently queued. Lock-free snapshot; may race with a
    /// concurrent `push` or `pop` but is monotone-sound for watermark
    /// checks.
    #[inline]
    pub fn len(&self) -> usize {
        let tail = self.tail.0.load(Ordering::Acquire);
        let head = self.head.0.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.len() >= CAPACITY
    }

    /// True once the ring has crossed the 75% fill line. Drivers use this
    /// to deassert flow control before the ring overruns.
    #[inline]
    pub fn watermark_high(&self) -> bool {
        self.len() >= WATERMARK_HIGH
    }

    /// Producer side: append `byte` and return `true`, or `false` if
    /// full. Caller must ensure single-producer discipline (the ISR
    /// exclusivity guarantee).
    pub fn push(&self, byte: u8) -> bool {
        let tail = self.tail.0.load(Ordering::Relaxed);
        let head = self.head.0.load(Ordering::Acquire);
        if tail.wrapping_sub(head) >= CAPACITY {
            return false;
        }
        self.buf[tail & MASK].store(byte, Ordering::Relaxed);
        self.tail.0.store(tail.wrapping_add(1), Ordering::Release);
        true
    }

    /// Consumer side: remove and return the oldest byte, or `None` if
    /// empty. Caller must ensure single-consumer discipline (the
    /// registered soft-IRQ drain handler).
    pub fn pop(&self) -> Option<u8> {
        let head = self.head.0.load(Ordering::Relaxed);
        let tail = self.tail.0.load(Ordering::Acquire);
        if head == tail {
            return None;
        }
        let b = self.buf[head & MASK].load(Ordering::Relaxed);
        self.head.0.store(head.wrapping_add(1), Ordering::Release);
        Some(b)
    }
}

impl Default for DeferredByteRing {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_pop_returns_none() {
        let r = DeferredByteRing::new();
        assert!(r.is_empty());
        assert_eq!(r.pop(), None);
        assert_eq!(r.len(), 0);
    }

    #[test]
    fn push_pop_roundtrip() {
        let r = DeferredByteRing::new();
        assert!(r.push(0x41));
        assert!(r.push(0x42));
        assert_eq!(r.len(), 2);
        assert_eq!(r.pop(), Some(0x41));
        assert_eq!(r.pop(), Some(0x42));
        assert_eq!(r.pop(), None);
    }

    #[test]
    fn fills_to_capacity_then_fails() {
        let r = DeferredByteRing::new();
        for i in 0..CAPACITY {
            assert!(r.push((i & 0xff) as u8), "push {i} must succeed");
        }
        assert!(r.is_full());
        assert!(!r.push(0xff), "push past capacity must fail");
        assert_eq!(r.len(), CAPACITY);
    }

    #[test]
    fn drain_and_refill_wraps() {
        let r = DeferredByteRing::new();
        // Fill, drain, fill again past the physical wrap point.
        for i in 0..CAPACITY {
            assert!(r.push(i as u8));
        }
        for i in 0..CAPACITY {
            assert_eq!(r.pop(), Some(i as u8));
        }
        assert!(r.is_empty());
        // Second round pushes indices CAPACITY..2*CAPACITY; head/tail
        // wrap modulo CAPACITY but the indices themselves are raw.
        for i in 0..CAPACITY {
            assert!(r.push(((i + 7) & 0xff) as u8));
        }
        for i in 0..CAPACITY {
            assert_eq!(r.pop(), Some(((i + 7) & 0xff) as u8));
        }
    }

    #[test]
    fn watermark_trips_at_96() {
        let r = DeferredByteRing::new();
        for _ in 0..WATERMARK_HIGH - 1 {
            r.push(0);
        }
        assert!(
            !r.watermark_high(),
            "watermark must stay low below threshold"
        );
        r.push(0);
        assert!(
            r.watermark_high(),
            "watermark must flip at {WATERMARK_HIGH}"
        );
    }
}
