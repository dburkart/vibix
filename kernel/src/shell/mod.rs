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

pub mod ansi;
pub mod line_editor;

#[cfg(target_os = "none")]
mod kernel_side {
    use core::sync::atomic::{AtomicBool, Ordering};

    use pc_keyboard::{DecodedKey, KeyCode};

    use super::ansi::{self, CsiFinal, Event};
    use super::line_editor::{Effect, Input, LineEditor};
    use crate::build_info;
    use crate::mem::{frame, heap, FRAME_SIZE};
    use crate::task::TaskStateView;
    use crate::{input, pci, serial, serial_print, serial_println, task, time};

    /// Flipped to `true` the first time the shell's `run` enters its main
    /// loop. Integration tests poll this to confirm the shell actually
    /// started; `main` doesn't care.
    pub static SHELL_ONLINE: AtomicBool = AtomicBool::new(false);

    const PROMPT: &str = "vibix> ";

    /// Task entry point. Spawn as `task::spawn(shell::run)`.
    pub fn run() -> ! {
        serial_println!("shell: prompt online");
        SHELL_ONLINE.store(true, Ordering::SeqCst);
        prompt();

        let mut editor = LineEditor::new();
        let mut ansi = ansi::State::default();
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
    fn next_input(state: &mut ansi::State) -> Option<Input> {
        if let Some(b) = serial::try_read_byte() {
            return serial_byte(b, state);
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
    /// Unrecognised finals and parameterised sequences with non-arrow
    /// finals drop silently.
    fn serial_byte(b: u8, state: &mut ansi::State) -> Option<Input> {
        match ansi::step(state, b)? {
            Event::Byte(b) => byte_to_input(b),
            Event::Csi(CsiFinal::Up) => Some(Input::HistoryPrev),
            Event::Csi(CsiFinal::Down) => Some(Input::HistoryNext),
            // Left/right and other finals: deferred per issue #112.
            Event::Csi(_) => None,
        }
    }

    /// Ground-state byte from the ANSI state machine. Bytes above
    /// 0x7F (UTF-8 continuation bytes, 8-bit terminals) are ignored
    /// rather than cast blindly to `char`, which would coerce them
    /// into unrelated Latin-1 code points.
    fn byte_to_input(b: u8) -> Option<Input> {
        if b > 0x7F {
            return None;
        }
        char_to_input(b as char)
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
            "uname" => cmd_uname(rest),
            "version" => cmd_version(),
            "whoami" => cmd_whoami(),
            "clear" => cmd_clear(),
            "date" => cmd_date(),
            "echo" => serial_println!("{}", rest),
            "panic" => panic!("shell: panic builtin invoked"),
            _ => serial_println!("unknown command: {} (try `help`)", cmd),
        }
    }

    /// Test-only entry point: run one line through the dispatch table
    /// without touching the line editor or input rings. Integration
    /// tests capture the serial output directly via UART loopback.
    pub fn dispatch_for_test(line: &str) {
        dispatch(line);
    }

    fn cmd_help() {
        serial_println!("builtins:");
        serial_println!("  help            show this list");
        serial_println!("  uptime          milliseconds since boot");
        serial_println!("  time            seconds since boot, ms precision");
        serial_println!("  mem             heap + free-frame counters");
        serial_println!("  tasks           live task ids and remaining slices");
        serial_println!("  pci             enumerated PCI devices on bus 0");
        serial_println!("  uname [-asrvm]  print kernel name / release / arch");
        serial_println!("  version         kernel version + build metadata");
        serial_println!("  whoami          print effective user name");
        serial_println!("  clear           clear the screen (Ctrl+L with no key)");
        serial_println!("  date            wall-clock time from the RTC (UTC)");
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

    fn cmd_uname(args: &str) {
        // Flag parsing: glued (`-am`) or split (`-a -m`) tokens are
        // both accepted; bare `uname` → `-s`. `-a` wins over any other
        // letters in the same invocation (Linux behavior).
        let mut show_name = false;
        let mut show_release = false;
        let mut show_version = false;
        let mut show_machine = false;
        let mut show_all = false;
        let mut any_flag = false;
        let mut bad: Option<char> = None;

        for tok in args.split_whitespace() {
            if let Some(rest) = tok.strip_prefix('-') {
                if rest.is_empty() {
                    bad = Some('-');
                    break;
                }
                for c in rest.chars() {
                    any_flag = true;
                    match c {
                        'a' => show_all = true,
                        's' => show_name = true,
                        'r' => show_release = true,
                        'v' => show_version = true,
                        'm' => show_machine = true,
                        other => {
                            bad = Some(other);
                            break;
                        }
                    }
                }
                if bad.is_some() {
                    break;
                }
            } else {
                bad = Some(tok.chars().next().unwrap_or('?'));
                break;
            }
        }

        if let Some(c) = bad {
            serial_println!("uname: invalid option -- '{}'", c);
            return;
        }

        if !any_flag {
            show_name = true;
        }

        if show_all {
            serial_println!(
                "{} {} {} {}",
                build_info::KERNEL_NAME,
                build_info::RELEASE,
                build_info::BUILD_TIMESTAMP,
                build_info::ARCH,
            );
            return;
        }

        let mut first = true;
        for (flag, value) in [
            (show_name, build_info::KERNEL_NAME),
            (show_release, build_info::RELEASE),
            (show_version, build_info::BUILD_TIMESTAMP),
            (show_machine, build_info::ARCH),
        ] {
            if flag {
                if !first {
                    serial_print!(" ");
                }
                serial_print!("{}", value);
                first = false;
            }
        }
        serial_println!();
    }

    fn cmd_version() {
        serial_println!(
            "{} {} {} {}",
            build_info::KERNEL_NAME,
            build_info::RELEASE,
            build_info::BUILD_TIMESTAMP,
            build_info::ARCH,
        );
        serial_println!(
            "build: {} (git {})",
            build_info::PROFILE,
            build_info::GIT_SHA,
        );
    }

    fn cmd_whoami() {
        serial_println!("root");
    }

    fn cmd_clear() {
        // Same VT100 sequence the line editor emits on Ctrl+L.
        serial_print!("\x1b[2J\x1b[H");
    }

    fn cmd_date() {
        match time::wall_clock() {
            Some(now) => serial_println!("{} UTC", now),
            None => serial_println!("date: unavailable (no RTC)"),
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
pub use kernel_side::{dispatch_for_test, run, SHELL_ONLINE};
