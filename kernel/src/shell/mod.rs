//! Tiny kernel shell, spawned as its own preemptively-scheduled task.
//!
//! Reads a line from the PS/2 keyboard, dispatches it against a small
//! table of builtins, and loops. When no input is pending the task
//! `hlt`s — the keyboard ISR wakes the CPU on the next keypress, and
//! the PIT preempt tick rotates other tasks in meanwhile.
//!
//! The input path is PS/2-only for now. Serial RX is orthogonal (needs
//! IOAPIC IRQ4 routing) and deliberately out of scope for this module.

use alloc::string::String;
use core::sync::atomic::{AtomicBool, Ordering};

use pc_keyboard::DecodedKey;

use crate::mem::{frame, heap, FRAME_SIZE};
use crate::task::TaskStateView;
use crate::{input, serial_print, serial_println, task, time};

/// Flipped to `true` the first time the shell's `run` enters its main
/// loop. Integration tests poll this to confirm the shell actually
/// started; `main` doesn't care.
pub static SHELL_ONLINE: AtomicBool = AtomicBool::new(false);

const PROMPT: &str = "vibix> ";
/// Maximum line length in bytes. Additional keystrokes past this cap
/// are silently dropped so a stuck key or keyboard auto-repeat can't
/// grow the input buffer unchecked against the 16 MiB heap ceiling.
const MAX_LINE_LEN: usize = 256;

/// Task entry point. Spawn as `task::spawn(shell::run)`.
pub fn run() -> ! {
    serial_println!("shell: prompt online");
    SHELL_ONLINE.store(true, Ordering::SeqCst);
    prompt();

    let mut line = String::new();
    loop {
        match input::try_read_key() {
            Some(DecodedKey::Unicode('\r')) | Some(DecodedKey::Unicode('\n')) => {
                serial_print!("\r\n");
                // Only strip leading whitespace so `echo` can round-trip
                // user-entered trailing spaces.
                dispatch(line.trim_start());
                line.clear();
                prompt();
            }
            // Backspace (0x08) or DEL (0x7f) — both map to "erase one char".
            Some(DecodedKey::Unicode('\x08')) | Some(DecodedKey::Unicode('\x7f')) => {
                if line.pop().is_some() {
                    serial_print!("\x08 \x08");
                }
            }
            Some(DecodedKey::Unicode(c)) if !c.is_control() => {
                if line.len() + c.len_utf8() <= MAX_LINE_LEN {
                    line.push(c);
                    serial_print!("{}", c);
                }
            }
            Some(_) => {}
            // Nothing in the scancode ring. Halt until the next IRQ
            // (keyboard press wakes us; PIT rotates us out on slice
            // expiry).
            None => x86_64::instructions::hlt(),
        }
    }
}

fn prompt() {
    serial_print!("{}", PROMPT);
}

fn dispatch(line: &str) {
    if line.is_empty() {
        return;
    }
    let (cmd, rest) = match line.split_once(' ') {
        Some((c, r)) => (c, r),
        None => (line, ""),
    };
    match cmd {
        "help" => cmd_help(),
        "uptime" => cmd_uptime(),
        "mem" => cmd_mem(),
        "tasks" => cmd_tasks(),
        "echo" => serial_println!("{}", rest),
        "panic" => panic!("shell: panic builtin invoked"),
        _ => serial_println!("unknown command: {} (try `help`)", cmd),
    }
}

fn cmd_help() {
    serial_println!("builtins:");
    serial_println!("  help            show this list");
    serial_println!("  uptime          milliseconds since boot");
    serial_println!("  mem             heap + free-frame counters");
    serial_println!("  tasks           live task ids and remaining slices");
    serial_println!("  echo <args>     echo the rest of the line");
    serial_println!("  panic           trigger a kernel panic (test aid)");
}

fn cmd_uptime() {
    let ms = time::uptime_ms();
    serial_println!("uptime: {} ms ({}.{:03} s)", ms, ms / 1000, ms % 1000);
}

fn cmd_mem() {
    let h = heap::stats();
    serial_println!(
        "heap:   used {} B, free {} B, mapped {} KiB",
        h.used,
        h.free,
        h.mapped / 1024,
    );
    let free = frame::free_frames();
    serial_println!(
        "frames: {} free ({} KiB)",
        free,
        (free as u64 * FRAME_SIZE) / 1024,
    );
}

fn cmd_tasks() {
    task::for_each_task(|t| {
        let tag = match t.state {
            TaskStateView::Running => "[run]",
            TaskStateView::Ready => "[rdy]",
            TaskStateView::Blocked => "[blk]",
        };
        serial_println!(
            "  task {:>3} {} slice={} ms",
            t.id,
            tag,
            t.slice_remaining_ms,
        );
    });
}
