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
    use crate::{framebuffer, input, pci, serial, serial_print, serial_println, task, time};

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
        // Shift+PgUp/PgDn pages the framebuffer scrollback. We capture the
        // shift state immediately after decode (before any other scancode
        // can advance the modifier state) and consume the key without
        // forwarding it to the line editor.
        if let DecodedKey::RawKey(kc @ (KeyCode::PageUp | KeyCode::PageDown)) = key {
            if input::shift_held() {
                match kc {
                    KeyCode::PageUp => framebuffer::scroll_view_up_page(),
                    KeyCode::PageDown => framebuffer::scroll_view_down_page(),
                    _ => {}
                }
                return None;
            }
        }
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

    /// Per-builtin help text. `summary` feeds the global `help` listing;
    /// `usage` and `examples` are shown by `help <cmd>`.
    pub struct BuiltinHelp {
        pub summary: &'static str,
        pub usage: &'static str,
        pub examples: &'static [&'static str],
    }

    /// One row of the dispatch table. Pairing the runner and the help
    /// text in one struct means new builtins can't be added without
    /// supplying both.
    struct Builtin {
        name: &'static str,
        run: fn(&str),
        help: BuiltinHelp,
    }

    /// Source-of-truth dispatch table. Order is alphabetical so the
    /// `help` listing reads naturally — hand-maintained, since the table
    /// only compiles under `target_os = "none"` and can't be checked by
    /// a host-side unit test.
    const BUILTINS: &[Builtin] = &[
        Builtin {
            name: "clear",
            run: cmd_clear_wrap,
            help: BuiltinHelp {
                summary: "clear the screen (VT100)",
                usage: "clear",
                examples: &["clear"],
            },
        },
        Builtin {
            name: "date",
            run: cmd_date_wrap,
            help: BuiltinHelp {
                summary: "wall-clock time from the RTC (UTC)",
                usage: "date",
                examples: &["date"],
            },
        },
        Builtin {
            name: "echo",
            run: cmd_echo,
            help: BuiltinHelp {
                summary: "echo the rest of the line",
                usage: "echo <args...>",
                examples: &["echo hello world"],
            },
        },
        Builtin {
            name: "help",
            run: cmd_help,
            help: BuiltinHelp {
                summary: "list builtins, or describe one",
                usage: "help [cmd]",
                examples: &["help", "help tasks"],
            },
        },
        Builtin {
            name: "mem",
            run: cmd_mem_wrap,
            help: BuiltinHelp {
                summary: "heap + free-frame counters",
                usage: "mem",
                examples: &["mem"],
            },
        },
        Builtin {
            name: "panic",
            run: cmd_panic,
            help: BuiltinHelp {
                summary: "trigger a kernel panic (test aid)",
                usage: "panic",
                examples: &["panic"],
            },
        },
        Builtin {
            name: "pci",
            run: cmd_pci_wrap,
            help: BuiltinHelp {
                summary: "enumerated PCI devices on bus 0",
                usage: "pci",
                examples: &["pci"],
            },
        },
        Builtin {
            name: "tasks",
            run: cmd_tasks_wrap,
            help: BuiltinHelp {
                summary: "live task ids, states, and remaining slices",
                usage: "tasks",
                examples: &["tasks"],
            },
        },
        Builtin {
            name: "time",
            run: cmd_time_wrap,
            help: BuiltinHelp {
                summary: "seconds since boot, ms precision",
                usage: "time",
                examples: &["time"],
            },
        },
        Builtin {
            name: "uname",
            run: cmd_uname,
            help: BuiltinHelp {
                summary: "print kernel name / release / arch",
                usage: "uname [-asrvm]",
                examples: &["uname", "uname -a", "uname -srm"],
            },
        },
        Builtin {
            name: "uptime",
            run: cmd_uptime_wrap,
            help: BuiltinHelp {
                summary: "milliseconds since boot",
                usage: "uptime",
                examples: &["uptime"],
            },
        },
        Builtin {
            name: "version",
            run: cmd_version_wrap,
            help: BuiltinHelp {
                summary: "kernel version + build metadata",
                usage: "version",
                examples: &["version"],
            },
        },
        Builtin {
            name: "whoami",
            run: cmd_whoami_wrap,
            help: BuiltinHelp {
                summary: "print effective user name",
                usage: "whoami",
                examples: &["whoami"],
            },
        },
    ];

    fn dispatch(line: &str) {
        if line.is_empty() {
            return;
        }
        let (cmd, rest) = match line.split_once(' ') {
            Some((c, r)) => (c, r),
            None => (line, ""),
        };
        match BUILTINS.iter().find(|b| b.name == cmd) {
            Some(b) => (b.run)(rest),
            None => serial_println!("unknown command: {} (try `help`)", cmd),
        }
    }

    /// Test-only entry point: run one line through the dispatch table
    /// without touching the line editor or input rings. Integration
    /// tests capture the serial output directly via UART loopback.
    pub fn dispatch_for_test(line: &str) {
        dispatch(line);
    }

    fn cmd_help(args: &str) {
        let arg = args.trim();
        if arg.is_empty() {
            serial_println!("builtins:");
            for b in BUILTINS {
                serial_println!("  {:<8}  {}", b.name, b.help.summary);
            }
            return;
        }
        match BUILTINS.iter().find(|b| b.name == arg) {
            Some(b) => {
                serial_println!("{}", b.help.summary);
                serial_println!("usage: {}", b.help.usage);
                if !b.help.examples.is_empty() {
                    serial_println!("examples:");
                    for ex in b.help.examples {
                        serial_println!("  $ {}", ex);
                    }
                }
            }
            None => serial_println!("help: no help for `{}`", arg),
        }
    }

    fn cmd_echo(rest: &str) {
        serial_println!("{}", rest);
    }

    fn cmd_panic(_: &str) {
        panic!("shell: panic builtin invoked");
    }

    fn cmd_uptime_wrap(_: &str) {
        cmd_uptime();
    }

    fn cmd_time_wrap(_: &str) {
        cmd_time();
    }

    fn cmd_pci_wrap(_: &str) {
        cmd_pci();
    }

    fn cmd_tasks_wrap(_: &str) {
        cmd_tasks();
    }

    fn cmd_version_wrap(_: &str) {
        cmd_version();
    }

    fn cmd_whoami_wrap(_: &str) {
        cmd_whoami();
    }

    fn cmd_clear_wrap(_: &str) {
        cmd_clear();
    }

    fn cmd_date_wrap(_: &str) {
        cmd_date();
    }

    fn cmd_mem_wrap(_: &str) {
        cmd_mem();
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
