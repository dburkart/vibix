pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod ist_guard;
pub mod pic;

pub fn init() {
    gdt::init();
    idt::init();
    pic::init();
}
