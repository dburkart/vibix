#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::backtrace;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{init, init_apic};

/// Acknowledge the timer IRQ that drove the current scheduler tick.
///
/// Arch-level shim so that scheduler/seam adapters (`task::env::HwIrq`)
/// don't reach into x86-specific modules. Today: forwards to the LAPIC
/// EOI write; on a future legacy-PIC fallback or non-x86 port the
/// PIC/IOAPIC policy stays centralized here.
#[cfg(target_arch = "x86_64")]
pub fn ack_timer_irq() {
    x86_64::apic::lapic_eoi();
}
