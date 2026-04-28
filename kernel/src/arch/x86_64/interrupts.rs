//! Hardware-IRQ vector numbers and ISRs for the devices we care about.
//!
//! ISRs are kept deliberately tiny: update shared state, EOI, return.
//! Any decoding or IO (serial logging, pc-keyboard state machine) is
//! deferred to the consumer side — a keyboard burst of ~10 scancodes
//! at boot should never block inside an interrupt handler.

use x86_64::instructions::port::Port;
use x86_64::structures::idt::InterruptStackFrame;

use crate::arch::x86_64::pic::{notify_eoi, PIC_1_OFFSET};

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum InterruptIndex {
    Timer = PIC_1_OFFSET,
    Keyboard = PIC_1_OFFSET + 1,
    Serial = PIC_1_OFFSET + 4,
}

impl InterruptIndex {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

pub extern "x86-interrupt" fn timer_interrupt(_frame: InterruptStackFrame) {
    #[cfg(feature = "bench")]
    crate::bench::irq::record_entry();
    crate::time::on_tick();
    // EOI before any attempt to preempt. If we switched to another
    // task first and *that* task ever re-entered this ISR, the PIC
    // would be carrying an un-acked IRQ and subsequent ticks would
    // stall.
    //
    // Routed through the scheduler/IRQ seam (RFC 0005) so the
    // simulator and mock test wiring can substitute the EOI; in
    // production this resolves to `notify_eoi(Timer)` →
    // `apic::lapic_eoi()`. The ordering (EOI before `preempt_tick`)
    // is preserved deliberately — see equivalence note in PR body.
    let (_clock, irq) = crate::task::env::env();
    irq.ack_timer();
    #[cfg(feature = "bench")]
    crate::bench::irq::record_exit();
    crate::task::preempt_tick();
}

pub extern "x86-interrupt" fn keyboard_interrupt(_frame: InterruptStackFrame) {
    let code: u8 = unsafe { Port::new(0x60).read() };
    crate::input::push_scancode_from_isr(code);
    crate::tty::ps2::push_scancode_from_isr(code);
    notify_eoi(InterruptIndex::Keyboard.as_u8());
}

pub extern "x86-interrupt" fn serial_interrupt(_frame: InterruptStackFrame) {
    // Draining RBR until LSR.DR clears acks the Received-Data-Available
    // condition in IIR, so no separate register read is needed to
    // dismiss the IRQ.
    crate::serial::drain_rx_hardware();
    notify_eoi(InterruptIndex::Serial.as_u8());
}
