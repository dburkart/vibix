pub mod apic;
pub mod backtrace;
pub mod csprng;
pub mod fpu;
pub mod gdb_trampoline;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ist_guard;
pub mod pic;
pub mod syscall;
pub mod syscalls;
pub mod uaccess;

use core::sync::atomic::{AtomicBool, Ordering};

/// `true` after [`enable_fsgsbase`] has set `CR4.FSGSBASE` on this CPU.
/// Checked by the context-switch fast path in `sched_core.rs` to choose
/// between `rdfsbase`/`wrfsbase` (fast, user-visible) and
/// `rdmsr`/`wrmsr` (slow, always-available fallback).
static FSGSBASE_ON: AtomicBool = AtomicBool::new(false);

/// Return `true` if `CR4.FSGSBASE` was successfully enabled at boot.
///
/// Lock-free: reads a `Relaxed` `AtomicBool` populated once by
/// [`enable_fsgsbase`] during `arch::init()`.
#[inline]
pub fn fsgsbase_enabled() -> bool {
    FSGSBASE_ON.load(Ordering::Relaxed)
}

/// Enable the FSGSBASE CPU feature (CR4 bit 16) so that userspace can
/// use `wrfsbase`/`rdfsbase` directly and the kernel context-switch
/// path can use the faster non-serialising instructions instead of
/// `rdmsr`/`wrmsr`.
///
/// Checks CPUID leaf 7 sub-leaf 0 EBX bit 0 (already cached by
/// `cpu::init()`). If the CPU does not advertise FSGSBASE the function
/// is a no-op and the fallback MSR path remains in effect.
fn enable_fsgsbase() {
    use crate::cpu::{self, Feature};
    use x86_64::registers::control::{Cr4, Cr4Flags};

    if !cpu::has(Feature::Fsgsbase) {
        crate::serial_println!("fsgsbase: unavailable");
        return;
    }

    // SAFETY: We only set CR4.FSGSBASE after confirming the CPU
    // supports it via CPUID. No other CR4 bits are touched.
    unsafe {
        Cr4::update(|f| {
            f.insert(Cr4Flags::FSGSBASE);
        });
    }

    FSGSBASE_ON.store(true, Ordering::Relaxed);
    crate::serial_println!("fsgsbase: CR4.FSGSBASE enabled");
}

/// Bring up arch-specific interrupt plumbing that doesn't depend on
/// the kernel mapper. Interrupts stay disabled throughout.
pub fn init() {
    // Feature detection first — everything below may query cpu::has().
    crate::cpu::init();
    // SMEP/SMAP enforcement: blocks ring-0 fetch/access of user pages
    // outside a `stac`/`clac` bracket. Must precede `syscall::init` so
    // the first SYSCALL fires with enforcement already live.
    uaccess::enable_smep_smap();
    // Enable CR4.FSGSBASE so userspace can use wrfsbase/rdfsbase for
    // fast TLS access, and the kernel context switch can use the
    // faster non-serialising instructions (#836).
    enable_fsgsbase();
    // FPU init needs CR0/CR4 writes but no heap, so it fits here —
    // ahead of task::init() which spawns the first saving task.
    fpu::init();
    gdt::init();
    idt::init();
    // SYSCALL/SYSRET MSR setup. Runs after GDT (segment selectors must
    // be live) and before any ring-3 entry.
    syscall::init();
    // Remap + mask the 8259 before touching ACPI/APIC. Leaving it in
    // its reset state would fire legacy IRQs into CPU exception
    // vectors as soon as we `sti`.
    pic::init_and_disable();
}

/// Bring up ACPI + APIC. Must run after `mem::init` — the ACPI
/// parser and APIC drivers lean on the kernel mapper to map ACPI
/// tables (in BIOS/ACPI-reclaimable memory) and LAPIC/IOAPIC MMIO
/// regions into the HHDM window.
pub fn init_apic(rsdp_phys: usize, hhdm_offset: u64) {
    crate::acpi::init(rsdp_phys, hhdm_offset);
    apic::init_bsp(hhdm_offset);
    apic::ioapic_init(hhdm_offset);
    apic::route_legacy_irq(0, interrupts::InterruptIndex::Timer.as_u8());
    apic::route_legacy_irq(1, interrupts::InterruptIndex::Keyboard.as_u8());
    apic::route_legacy_irq(4, interrupts::InterruptIndex::Serial.as_u8());
    // Enable RX IER only after the IOAPIC redirection for IRQ4 is in
    // place — otherwise the first byte raises against a masked vector.
    crate::serial::enable_rx_interrupts();
}
