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
pub mod banner;
pub mod line_editor;
#[cfg(target_os = "none")]
pub mod vfs_helpers;

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
        super::banner::print_banner();
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
    ///
    /// The modifier flags (per #336) are decoded but the line editor
    /// doesn't yet have bindings for Ctrl/Shift/Alt + arrow, so the
    /// initial routing keeps Up/Down → history regardless of modifier
    /// state (preserving the #310 fix where Ctrl+Up didn't strand) and
    /// drops Left/Right. Future PRs can add `Input` variants and route
    /// modified arrows here without re-touching the state machine.
    fn serial_byte(b: u8, state: &mut ansi::State) -> Option<Input> {
        match ansi::step(state, b)? {
            Event::Byte(b) => byte_to_input(b),
            Event::Csi(CsiFinal::Up, _mods) => Some(Input::HistoryPrev),
            Event::Csi(CsiFinal::Down, _mods) => Some(Input::HistoryNext),
            // Left/right and other finals: deferred per issue #112.
            Event::Csi(_, _) => None,
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
            name: "cat",
            run: cmd_cat,
            help: BuiltinHelp {
                summary: "concatenate file contents to stdout",
                usage: "cat <path>...",
                examples: &["cat /etc/motd", "cat /dev/zero"],
            },
        },
        Builtin {
            name: "cd",
            run: cmd_cd,
            help: BuiltinHelp {
                summary: "change the shell's working directory",
                usage: "cd <path>",
                examples: &["cd /tmp", "cd ..", "cd /"],
            },
        },
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
            name: "cp",
            run: cmd_cp,
            help: BuiltinHelp {
                summary: "copy a file (naive read-loop, no flags)",
                usage: "cp <src> <dst>",
                examples: &["cp /etc/motd /tmp/motd.bak"],
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
            name: "ls",
            run: cmd_ls,
            help: BuiltinHelp {
                summary: "list directory entries (one per line)",
                usage: "ls [path]",
                examples: &["ls", "ls /dev"],
            },
        },
        Builtin {
            name: "mkdir",
            run: cmd_mkdir,
            help: BuiltinHelp {
                summary: "create a directory (single-level only, no -p)",
                usage: "mkdir <path>",
                examples: &["mkdir /tmp/work"],
            },
        },
        Builtin {
            name: "mv",
            run: cmd_mv,
            help: BuiltinHelp {
                summary: "rename or move a file (rename, falls back to link+unlink)",
                usage: "mv <src> <dst>",
                examples: &["mv /tmp/a /tmp/b"],
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
            name: "pwd",
            run: cmd_pwd,
            help: BuiltinHelp {
                summary: "print the shell's working directory",
                usage: "pwd",
                examples: &["pwd"],
            },
        },
        Builtin {
            name: "rm",
            run: cmd_rm,
            help: BuiltinHelp {
                summary: "remove a file (no -r in v1)",
                usage: "rm <path>",
                examples: &["rm /tmp/a"],
            },
        },
        Builtin {
            name: "rmdir",
            run: cmd_rmdir,
            help: BuiltinHelp {
                summary: "remove an empty directory",
                usage: "rmdir <path>",
                examples: &["rmdir /tmp/work"],
            },
        },
        Builtin {
            name: "stat",
            run: cmd_stat,
            help: BuiltinHelp {
                summary: "print stat(2) fields for a path",
                usage: "stat <path>",
                examples: &["stat /dev", "stat /tmp"],
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
            name: "touch",
            run: cmd_touch,
            help: BuiltinHelp {
                summary: "create an empty file if missing (no mtime update)",
                usage: "touch <path>",
                examples: &["touch /tmp/marker"],
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

    // -- file-touching builtins (#395) ----------------------------------
    //
    // These builtins call straight into the in-kernel VFS via the
    // `vfs_helpers` module. Errors come back as small negative `i64`
    // errnos; `errno_msg` renders the common ones into a printable
    // string. Anything unrecognised is shown as the raw number so the
    // user can still triage.

    use super::vfs_helpers;
    use crate::fs::vfs::InodeKind;
    use crate::fs::{
        EACCES, EBUSY, EEXIST, EINVAL, EISDIR, ENAMETOOLONG, ENOENT, ENOSPC, ENOTDIR, ENOTEMPTY,
        EPERM, EROFS, EXDEV,
    };

    fn errno_msg(e: i64) -> alloc::string::String {
        use alloc::format;
        use alloc::string::ToString;
        let s: &'static str = match e {
            ENOENT => "no such file or directory",
            ENOTDIR => "not a directory",
            EISDIR => "is a directory",
            EEXIST => "file exists",
            EPERM => "operation not permitted",
            EACCES => "permission denied",
            EBUSY => "device or resource busy",
            EINVAL => "invalid argument",
            ENAMETOOLONG => "file name too long",
            ENOTEMPTY => "directory not empty",
            ENOSPC => "no space left on device",
            EROFS => "read-only filesystem",
            EXDEV => "cross-device link",
            // Unknown / unmapped errno: keep the raw number visible so a
            // VFS code path that returns something we don't have a string
            // for is still debuggable.
            _ => return format!("errno {}", e),
        };
        s.to_string()
    }

    /// Trim leading whitespace and split off the first whitespace-delimited
    /// token. Returns `(token, rest_unparsed)`.
    fn first_arg(args: &str) -> (&str, &str) {
        let trimmed = args.trim_start();
        match trimmed.find(char::is_whitespace) {
            Some(i) => (&trimmed[..i], trimmed[i..].trim_start()),
            None => (trimmed, ""),
        }
    }

    fn cmd_pwd(args: &str) {
        if !args.trim().is_empty() {
            serial_println!("pwd: too many arguments");
            return;
        }
        let cwd_dentry = task::current_cwd();
        let path = match cwd_dentry {
            Some(d) => vfs_helpers::dentry_path(&d),
            None => alloc::string::String::from("/"),
        };
        serial_println!("{}", path);
    }

    fn cmd_cd(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("cd: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("cd: too many arguments");
            return;
        }
        // Lexically normalize the input so `..` always means "drop the
        // last component" — the kernel's `path_walk::step_dotdot` only
        // crosses one mount edge per `..` and stops at the parent FS's
        // mountpoint dentry without taking its parent, which would make
        // `cd ..` from `/tmp` land back at `/tmp`. Resolving against an
        // absolute, lexically-normalized path side-steps that.
        let normalized = normalize_cd_path(path);
        match vfs_helpers::resolve(normalized.as_bytes(), /* follow */ true) {
            Ok(r) => {
                if r.inode.kind != InodeKind::Dir {
                    serial_println!("cd: {}: not a directory", path);
                    return;
                }
                task::set_current_cwd(r.dentry.clone());
            }
            Err(e) => serial_println!("cd: {}: {}", path, errno_msg(e)),
        }
    }

    /// Lexically resolve `path` to an absolute, normalized form using the
    /// shell's CWD as the relative anchor. Strips `.` segments and pops
    /// `..` segments at the string level. Always returns a path beginning
    /// with `/`. Empty result collapses to `/`.
    fn normalize_cd_path(path: &str) -> alloc::string::String {
        use alloc::string::String;
        use alloc::vec::Vec;
        let mut buf: String = if path.starts_with('/') {
            String::from(path)
        } else {
            let cwd_str = match task::current_cwd() {
                Some(d) => vfs_helpers::dentry_path(&d),
                None => String::from("/"),
            };
            let mut s = cwd_str;
            if !s.ends_with('/') {
                s.push('/');
            }
            s.push_str(path);
            s
        };
        // Split, normalize, rejoin. Collect owned strings so we can
        // safely clear and rebuild `buf`.
        let mut stack: Vec<String> = Vec::new();
        for comp in buf.split('/') {
            match comp {
                "" | "." => {}
                ".." => {
                    let _ = stack.pop();
                }
                other => stack.push(String::from(other)),
            }
        }
        buf.clear();
        if stack.is_empty() {
            buf.push('/');
        } else {
            for c in &stack {
                buf.push('/');
                buf.push_str(c);
            }
        }
        buf
    }

    fn cmd_ls(args: &str) {
        let trimmed = args.trim();
        let path: &str = if trimmed.is_empty() { "." } else { trimmed };
        let r = match vfs_helpers::resolve(path.as_bytes(), /* follow */ true) {
            Ok(r) => r,
            Err(e) => {
                serial_println!("ls: {}: {}", path, errno_msg(e));
                return;
            }
        };
        if r.inode.kind != InodeKind::Dir {
            // For a non-dir path, `ls` of a single file just prints the
            // basename — same as GNU coreutils minus the formatting.
            serial_println!("{}", path);
            return;
        }
        let mut had_err: Option<i64> = None;
        let result = vfs_helpers::for_each_dirent(&r.inode, &r.dentry, |name, _kind| {
            // Skip "." / ".." for a flag-free v1 to match GNU `ls`
            // default behaviour.
            if name == b"." || name == b".." {
                return true;
            }
            match core::str::from_utf8(name) {
                Ok(s) => serial_println!("{}", s),
                Err(_) => serial_println!("?<non-utf8>"),
            }
            true
        });
        if let Err(e) = result {
            had_err = Some(e);
        }
        if let Some(e) = had_err {
            serial_println!("ls: {}: {}", path, errno_msg(e));
        }
    }

    fn cmd_cat(args: &str) {
        let trimmed = args.trim();
        if trimmed.is_empty() {
            serial_println!("cat: missing path argument");
            return;
        }
        for tok in trimmed.split_whitespace() {
            // Defensively cap at 64 KiB per `cat` invocation. The shell
            // task runs in kernel context and a runaway read against
            // /dev/zero would otherwise OOM the kernel heap.
            const CAT_LIMIT: usize = 64 * 1024;
            let r = match vfs_helpers::resolve(tok.as_bytes(), /* follow */ true) {
                Ok(r) => r,
                Err(e) => {
                    serial_println!("cat: {}: {}", tok, errno_msg(e));
                    continue;
                }
            };
            if r.inode.kind == InodeKind::Dir {
                serial_println!("cat: {}: {}", tok, errno_msg(EISDIR));
                continue;
            }
            let of = match vfs_helpers::open_inode(&r.inode, &r.dentry) {
                Ok(of) => of,
                Err(e) => {
                    serial_println!("cat: {}: {}", tok, errno_msg(e));
                    continue;
                }
            };
            let mut chunk = [0u8; 256];
            let mut off: u64 = 0;
            let mut total: usize = 0;
            loop {
                if total >= CAT_LIMIT {
                    serial_println!("\ncat: {}: output truncated at {} bytes", tok, CAT_LIMIT);
                    break;
                }
                let n = match r.inode.file_ops.read(&of, &mut chunk, off) {
                    Ok(n) => n,
                    Err(e) => {
                        serial_println!("\ncat: {}: {}", tok, errno_msg(e));
                        break;
                    }
                };
                if n == 0 {
                    break;
                }
                // Best-effort UTF-8 print; non-utf8 bytes get a `?`
                // placeholder so the serial console doesn't choke.
                match core::str::from_utf8(&chunk[..n]) {
                    Ok(s) => serial_print!("{}", s),
                    Err(_) => {
                        for &b in &chunk[..n] {
                            if b.is_ascii() && (b == b'\n' || !b.is_ascii_control()) {
                                serial_print!("{}", b as char);
                            } else {
                                serial_print!("?");
                            }
                        }
                    }
                }
                off += n as u64;
                total += n;
            }
        }
    }

    fn cmd_mkdir(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("mkdir: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("mkdir: too many arguments");
            return;
        }
        if let Err(e) = vfs_helpers::mkdir(path.as_bytes(), 0o755) {
            serial_println!("mkdir: {}: {}", path, errno_msg(e));
        }
    }

    fn cmd_rmdir(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("rmdir: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("rmdir: too many arguments");
            return;
        }
        if let Err(e) = vfs_helpers::rmdir(path.as_bytes()) {
            serial_println!("rmdir: {}: {}", path, errno_msg(e));
        }
    }

    fn cmd_rm(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("rm: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("rm: too many arguments (no -r in v1)");
            return;
        }
        if let Err(e) = vfs_helpers::unlink(path.as_bytes()) {
            serial_println!("rm: {}: {}", path, errno_msg(e));
        }
    }

    fn cmd_touch(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("touch: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("touch: too many arguments");
            return;
        }
        // If the path resolves, touch is a no-op (no mtime bump in v1).
        // Otherwise create an empty regular file.
        match vfs_helpers::resolve(path.as_bytes(), /* follow */ true) {
            Ok(_) => {}
            Err(e) if e == ENOENT => {
                if let Err(e2) = vfs_helpers::create_file(path.as_bytes(), 0o644) {
                    serial_println!("touch: {}: {}", path, errno_msg(e2));
                }
            }
            Err(e) => serial_println!("touch: {}: {}", path, errno_msg(e)),
        }
    }

    fn cmd_mv(args: &str) {
        let (src, rest) = first_arg(args);
        let (dst, extra) = first_arg(rest);
        if src.is_empty() || dst.is_empty() {
            serial_println!("mv: usage: mv <src> <dst>");
            return;
        }
        if !extra.is_empty() {
            serial_println!("mv: too many arguments");
            return;
        }
        // Try a real rename first. Most in-kernel filesystems implement
        // `InodeOps::rename`; the default trait body returns EPERM, which
        // we use as the signal to fall back to link+unlink. The fallback
        // is best-effort and only valid for non-directory inputs.
        match vfs_helpers::rename(src.as_bytes(), dst.as_bytes()) {
            Ok(()) => return,
            Err(e) if e == EPERM => {
                // Fall through to link+unlink below.
                serial_println!("mv: rename unsupported by FS, falling back to link+unlink");
            }
            Err(e) => {
                serial_println!("mv: {} -> {}: {}", src, dst, errno_msg(e));
                return;
            }
        }
        if let Err(e) = vfs_helpers::link(src.as_bytes(), dst.as_bytes()) {
            serial_println!("mv: link {} -> {}: {}", src, dst, errno_msg(e));
            return;
        }
        if let Err(e) = vfs_helpers::unlink(src.as_bytes()) {
            serial_println!("mv: unlink {}: {}", src, errno_msg(e));
        }
    }

    fn cmd_cp(args: &str) {
        let (src, rest) = first_arg(args);
        let (dst, extra) = first_arg(rest);
        if src.is_empty() || dst.is_empty() {
            serial_println!("cp: usage: cp <src> <dst>");
            return;
        }
        if !extra.is_empty() {
            serial_println!("cp: too many arguments");
            return;
        }
        // Stream the copy in fixed-size chunks rather than slurping
        // the whole source into the kernel heap. The 64 MiB cap keeps
        // pathological inputs (e.g. `cp /dev/zero ...`) from wedging
        // the box; a real coreutils-style `cp` would just keep going,
        // but this is a kernel-resident debug shell.
        const CP_LIMIT: u64 = 64 * 1024 * 1024;
        if let Err(e) = vfs_helpers::stream_copy(src.as_bytes(), dst.as_bytes(), CP_LIMIT) {
            serial_println!("cp: {} -> {}: {}", src, dst, errno_msg(e));
        }
    }

    fn cmd_stat(args: &str) {
        let (path, rest) = first_arg(args);
        if path.is_empty() {
            serial_println!("stat: missing path argument");
            return;
        }
        if !rest.is_empty() {
            serial_println!("stat: too many arguments");
            return;
        }
        let (st, kind) = match vfs_helpers::stat(path.as_bytes()) {
            Ok(v) => v,
            Err(e) => {
                serial_println!("stat: {}: {}", path, errno_msg(e));
                return;
            }
        };
        let kind_str = match kind {
            InodeKind::Reg => "regular file",
            InodeKind::Dir => "directory",
            InodeKind::Link => "symbolic link",
            InodeKind::Chr => "character device",
            InodeKind::Blk => "block device",
            InodeKind::Fifo => "fifo",
            InodeKind::Sock => "socket",
        };
        serial_println!("  File: {}", path);
        serial_println!(
            "  Size: {:<12} Blocks: {:<10} IO Block: {:<6} {}",
            st.st_size,
            st.st_blocks,
            st.st_blksize,
            kind_str,
        );
        serial_println!(
            "Device: {:#x}      Inode: {:<10} Links: {}",
            st.st_dev,
            st.st_ino,
            st.st_nlink,
        );
        serial_println!(
            "Access: ({:04o})  Uid: {:<5}  Gid: {}",
            st.st_mode & 0o7777,
            st.st_uid,
            st.st_gid,
        );
    }
}

#[cfg(target_os = "none")]
pub use kernel_side::{dispatch_for_test, run, SHELL_ONLINE};
