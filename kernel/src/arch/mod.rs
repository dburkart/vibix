#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "x86_64")]
pub use x86_64::backtrace;
#[cfg(target_arch = "x86_64")]
pub use x86_64::{init, init_apic};
