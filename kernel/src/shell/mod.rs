//! Tiny kernel shell, spawned as its own preemptively-scheduled task.
//!
//! Reads a line from either the PS/2 keyboard or COM1 serial input,
//! dispatches it against a small table of builtins, and loops. When no
//! input is pending the task `hlt`s — the keyboard or UART ISR wakes
//! the CPU on the next byte, and the PIT preempt tick rotates other
//! tasks in meanwhile.
//!
//! Line-editing state (history ring, current line) lives in the
//! [`line_editor`] submodule as pure logic so it's host-unit-testable.

pub mod line_editor;

#[cfg(target_os = "none")]
mod kernel_side {
    use core::sync::atomic::{AtomicBool, Ordering};

    use pc_keyboard::{DecodedKey, KeyCode};

    use super::line_editor::{Effect, Input, LineEditor};
    use crate::mem::{frame, heap, FRAME_SIZE};
    use crate::task::TaskStateView;
    use crate::{input, pci, serial, serial_print, serial_println, task, time};

    /// Flipped to `true` the first time the shell's `run` enters its main
    /// loop. Integration tests poll this to confirm the shell actually
    /// started; `main` doesn't care.
    pub static SHELL_ONLINE: AtomicBool = AtomicBool::new(false);

    const PROMPT: &str = "vibix> ";

    /// Serial-side ANSI CSI state. Serial arrow keys arrive as three
    /// bytes `ESC [ A..D`; xterm sometimes prefixes with `O` instead of
    /// `[`, so we accept both.
    #[derive(Clone, Copy, Eq, PartialEq)]
    enum Ansi {
        Ground,
        Esc,
        Csi,
    }

    /// Task entry point. Spawn as `task::spawn(shell::run)`.
    pub fn run() -> ! {
        serial_println!("shell: prompt online");
        SHELL_ONLINE.store(true, Ordering::SeqCst);
        prompt();

        let mut editor = LineEditor::new();
        let mut ansi = Ansi::Ground;
        loop {
            if let Some(ev) = next_input(&mut ansi) {
                for eff in editor.on_input(ev) {
                    emit(eff);
                }
            } else {
                // Nothing in either input ring. Halt until the next IRQ
                // (keyboard or UART byte wakes us; PIT rotates us out on
                // slice expiry).
                x86_64::instructions::hlt();
            }
        }
    }

    /// Pull the next editor event from whichever input source has one
    /// ready. Serial is polled first so headless operation feels
    /// responsive even when both rings accumulate simultaneously. The
    /// `ansi` state machine is threaded across calls so multi-byte
    /// escape sequences on serial survive across `hlt` gaps.
    fn next_input(ansi: &mut Ansi) -> Option<Input> {
        if let Some(b) = serial::try_read_byte() {
            return serial_byte(b, ansi);
        }
        let key = input::try_read_key()?;
        match key {
            DecodedKey::Unicode(c) => char_to_input(c),
            DecodedKey::RawKey(KeyCode::ArrowUp) => Some(Input::HistoryPrev),
            DecodedKey::RawKey(KeyCode::ArrowDown) => Some(Input::HistoryNext),
            DecodedKey::RawKey(_) => None,
        }
    }

    /// Translate a serial byte through the CSI state machine. On
    /// completion of an arrow escape, return the corresponding `Input`.
    /// Unrecognised finals drop the sequence silently.
    fn serial_byte(b: u8, ansi: &mut Ansi) -> Option<Input> {
        match (*ansi, b) {
            (Ansi::Ground, 0x1b) => {
                *ansi = Ansi::Esc;
                None
            }
            (Ansi::Esc, b'[') | (Ansi::Esc, b'O') => {
                *ansi = Ansi::Csi;
                None
            }
            (Ansi::Esc, _) => {
                // Bare ESC followed by non-CSI: drop, reset.
                *ansi = Ansi::Ground;
                None
            }
            (Ansi::Csi, b'A') => {
                *ansi = Ansi::Ground;
                Some(Input::HistoryPrev)
            }
            (Ansi::Csi, b'B') => {
                *ansi = Ansi::Ground;
                Some(Input::HistoryNext)
            }
            (Ansi::Csi, b'C') | (Ansi::Csi, b'D') => {
                // Left/right — deferred per issue #112.
                *ansi = Ansi::Ground;
                None
            }
            (Ansi::Csi, _) => {
                // Unrecognised CSI final — drop and resync.
                *ansi = Ansi::Ground;
                None
            }
            (Ansi::Ground, _) => char_to_input(b as char),
        }
    }

    /// Map a single decoded character to an editor event. Ctrl+C/L
    /// arrive as U+0003/U+000C because the keyboard layer is configured
    /// with `HandleControl::MapLettersToUnicode`.
    fn char_to_input(c: char) -> Option<Input> {
        match c {
            '\r' | '\n' => Some(Input::Enter),
            '\x08' | '\x7f' => Some(Input::Backspace),
            '\x03' => Some(Input::Interrupt),
            '\x0c' => Some(Input::ClearScreen),
            c if !c.is_control() => Some(Input::Char(c)),
            _ => None,
        }
    }

    fn emit(eff: Effect) {
        match eff {
            Effect::Put(c) => serial_print!("{}", c),
            Effect::EraseChar => serial_print!("\x08 \x08"),
            Effect::Newline => {
                serial_print!("\r\n");
                prompt();
            }
            Effect::Dispatch(line) => {
                serial_print!("\r\n");
                dispatch(line.trim_start());
                prompt();
            }
            Effect::ClearScreen { line } => {
                // VT100: clear whole screen, home cursor, redraw prompt
                // and whatever the user had typed so far.
                serial_print!("\x1b[2J\x1b[H");
                prompt();
                serial_print!("{}", line);
            }
            Effect::Replace { old_len, new } => {
                for _ in 0..old_len {
                    serial_print!("\x08 \x08");
                }
                serial_print!("{}", new);
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
            "time" => cmd_time(),
            "mem" => cmd_mem(),
            "tasks" => cmd_tasks(),
            "pci" => cmd_pci(),
            "echo" => serial_println!("{}", rest),
            "panic" => panic!("shell: panic builtin invoked"),
            _ => serial_println!("unknown command: {} (try `help`)", cmd),
        }
    }

    fn cmd_help() {
        serial_println!("builtins:");
        serial_println!("  help            show this list");
        serial_println!("  uptime          milliseconds since boot");
        serial_println!("  time            seconds since boot, ms precision");
        serial_println!("  mem             heap + free-frame counters");
        serial_println!("  tasks           live task ids and remaining slices");
        serial_println!("  pci             enumerated PCI devices on bus 0");
        serial_println!("  echo <args>     echo the rest of the line");
        serial_println!("  panic           trigger a kernel panic (test aid)");
    }

    fn cmd_uptime() {
        let ms = time::uptime_ms();
        serial_println!("uptime: {} ms ({}.{:03} s)", ms, ms / 1000, ms % 1000);
    }

    fn cmd_time() {
        let ns = time::uptime_ns();
        let secs = ns / 1_000_000_000;
        let ms = (ns % 1_000_000_000) / 1_000_000;
        serial_println!("time: {}.{:03} s", secs, ms);
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

    fn cmd_pci() {
        let n = pci::device_count();
        if n == 0 {
            serial_println!("pci: no devices enumerated (scan not yet run?)");
            return;
        }
        serial_println!("pci: {} device(s) on bus 0", n);
        for d in pci::devices() {
            serial_println!(
                "  {:02x}:{:02x}.{:x}  {:04x}:{:04x}  class {:02x}:{:02x} pi={:02x}  {}",
                d.addr.bus,
                d.addr.device,
                d.addr.function,
                d.vendor_id,
                d.device_id,
                d.class,
                d.subclass,
                d.prog_if,
                d.class_name(),
            );
            // Walk BARs skipping the high-dword slot that follows a 64-bit
            // memory BAR — that slot holds raw upper address bits, not a
            // self-describing BAR, and calling is_io/is_64bit/addr on it
            // produces nonsense (e.g. a set low bit would mislabel it as io).
            let mut i = 0;
            while i < d.bars.len() {
                let bar = d.bars[i];
                if bar.is_empty() {
                    i += 1;
                    continue;
                }
                if bar.is_io() {
                    serial_println!("     bar{}: {:#010x} (io)", i, bar.addr());
                    i += 1;
                } else if bar.is_64bit() && i + 1 < d.bars.len() {
                    let full = bar.addr64(d.bars[i + 1]);
                    serial_println!("     bar{}: {:#018x} (mem64)", i, full);
                    i += 2;
                } else {
                    serial_println!("     bar{}: {:#010x} (mem32)", i, bar.addr());
                    i += 1;
                }
            }
        }
    }

    fn cmd_tasks() {
        task::for_each_task(|t| {
            let tag = match t.state {
                TaskStateView::Running => "[run]",
                TaskStateView::Ready => "[rdy]",
                TaskStateView::Blocked => "[blk]",
            };
            serial_println!(
                "  task {:>3} {} slice={} ms prio={} nice={}",
                t.id,
                tag,
                t.slice_remaining_ms,
                t.priority,
                t.nice,
            );
        });
    }
}

#[cfg(target_os = "none")]
pub use kernel_side::{run, SHELL_ONLINE};
