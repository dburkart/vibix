//! Boot banner shown at shell startup.
//!
//! Emits a single multi-line block: kernel identity + build metadata,
//! CPU brand + count, memory totals, elapsed boot time, and any active
//! mounts, followed by the contents of `/etc/motd` (best-effort).
//!
//! The formatter is a pure function over an `Inputs` struct so host
//! unit tests can exercise it without any kernel state. `print_banner()`
//! is the live caller; it gathers `Inputs` from the running kernel and
//! writes the result to serial (and the framebuffer when one is up).

use core::fmt::{self, Write};

/// Byte prefix of the banner's first line. Smoke tests assert this
/// marker, so keep it stable.
pub const BANNER_PREFIX: &str = "banner: ";

/// Kernel state fed into the formatter. Broken out so host unit tests
/// can construct fixture values without touching ACPI, mm, time, etc.
pub struct Inputs<'a> {
    pub kernel_name: &'a str,
    pub release: &'a str,
    pub git_sha: &'a str,
    pub build_timestamp: &'a str,
    pub profile: &'a str,
    pub arch: &'a str,
    pub cpu_brand: &'a str,
    pub cpu_count: u32,
    pub mem_total_bytes: u64,
    pub mem_free_bytes: u64,
    pub uptime_ms: u64,
    /// `(mount_point, fs_type)` pairs. Order is preserved in the output.
    pub mounts: &'a [(&'a str, &'a str)],
    /// Raw `/etc/motd` bytes. When `None`, the motd section is omitted.
    pub motd: Option<&'a [u8]>,
}

/// Pure formatter. Writes the banner to `out`. Never fails for any
/// reason other than `out` itself returning `Err`, which propagates.
pub fn format_banner(out: &mut dyn Write, inp: &Inputs<'_>) -> fmt::Result {
    writeln!(
        out,
        "{}{} {} ({}, built {}, {}) {}",
        BANNER_PREFIX,
        inp.kernel_name,
        inp.release,
        inp.git_sha,
        inp.build_timestamp,
        inp.profile,
        inp.arch,
    )?;
    writeln!(out, "cpu: {} x{}", inp.cpu_brand, inp.cpu_count)?;
    writeln!(
        out,
        "mem: {} MiB total, {} MiB free",
        inp.mem_total_bytes / (1024 * 1024),
        inp.mem_free_bytes / (1024 * 1024),
    )?;
    writeln!(out, "boot: {} ms", inp.uptime_ms)?;
    if !inp.mounts.is_empty() {
        writeln!(out, "mounts:")?;
        for (path, fs_type) in inp.mounts {
            writeln!(out, "  {}  {}", path, fs_type)?;
        }
    }
    if let Some(bytes) = inp.motd {
        for line in split_lines(bytes) {
            // Motd is user-configurable; emit as bytes via a best-effort
            // utf-8 view. Non-utf8 lines are written with replacement.
            match core::str::from_utf8(line) {
                Ok(s) => writeln!(out, "{}", s)?,
                Err(_) => writeln!(out, "{}", Lossy(line))?,
            }
        }
    }
    Ok(())
}

/// Split a motd byte buffer on `\n`, stripping a trailing `\r` if present
/// and dropping a final empty line so a motd that ends with `\n` doesn't
/// print a blank line at the end.
fn split_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = bytes;
    core::iter::from_fn(move || {
        if rest.is_empty() {
            return None;
        }
        let (line, next) = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let line = &rest[..i];
                let line = if line.last() == Some(&b'\r') {
                    &line[..line.len() - 1]
                } else {
                    line
                };
                (line, &rest[i + 1..])
            }
            None => (rest, &rest[rest.len()..]),
        };
        rest = next;
        Some(line)
    })
}

/// Writer adapter that emits `?` for any non-utf8 byte — cheap and keeps
/// the formatter total over arbitrary motd payloads.
struct Lossy<'a>(&'a [u8]);

impl fmt::Display for Lossy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in self.0 {
            let c = if (0x20..0x7f).contains(&b) || b == b'\t' {
                b as char
            } else {
                '?'
            };
            f.write_char(c)?;
        }
        Ok(())
    }
}

#[cfg(target_os = "none")]
pub use kernel_side::print_banner;

#[cfg(target_os = "none")]
mod kernel_side {
    use alloc::string::String;
    use alloc::vec::Vec;

    use super::{format_banner, Inputs};
    use crate::build_info;
    use crate::mem::{frame, FRAME_SIZE};
    use crate::{acpi, cpu, mem, serial_print, time};

    /// Collect live kernel state and emit the banner.
    ///
    /// Writes to serial unconditionally; a future framebuffer mirror
    /// can tap the same `format_banner` with a different sink.
    pub fn print_banner() {
        let cpu_brand = cpu::brand();
        let cpu_count = acpi::info().map_or(1, |i| i.cpu_count);
        let mem_total = mem::total_usable_bytes();
        let mem_free = frame::free_frames() as u64 * FRAME_SIZE;
        let uptime_ms = time::uptime_ms();

        let mounts_vec = collect_mounts();
        let mounts: Vec<(&str, &str)> = mounts_vec
            .iter()
            .map(|(p, f)| (p.as_str(), *f))
            .collect();

        let motd = find_motd();

        let inputs = Inputs {
            kernel_name: build_info::KERNEL_NAME,
            release: build_info::RELEASE,
            git_sha: build_info::GIT_SHA,
            build_timestamp: build_info::BUILD_TIMESTAMP,
            profile: build_info::PROFILE,
            arch: build_info::ARCH,
            cpu_brand,
            cpu_count,
            mem_total_bytes: mem_total,
            mem_free_bytes: mem_free,
            uptime_ms,
            mounts: &mounts,
            motd: motd.as_deref(),
        };

        let mut buf = String::new();
        // String's Write impl cannot fail; the unwrap is total.
        let _ = format_banner(&mut buf, &inputs);
        serial_print!("{}", buf);
    }

    /// Collect `(path, fs_type)` pairs for every mount in `MOUNT_TABLE`.
    /// The mountpoint path is reconstructed by walking the dentry's
    /// `parent` chain until a root is reached. Root mounts (where
    /// `mountpoint` is weakly held by the mount graph itself and may
    /// not upgrade) are reported as `/`.
    fn collect_mounts() -> Vec<(String, &'static str)> {
        use crate::fs::vfs::mount_table::MOUNT_TABLE;
        let guard = MOUNT_TABLE.read();
        let mut out: Vec<(String, &'static str)> = Vec::with_capacity(guard.len());
        for edge in guard.iter() {
            let fs_type = edge.super_block.fs_type;
            let path = mountpoint_path(edge);
            out.push((path, fs_type));
        }
        out
    }

    fn mountpoint_path(edge: &crate::fs::vfs::dentry::MountEdge) -> String {
        use crate::fs::vfs::dentry::{DFlags, Dentry};
        use alloc::sync::Arc;

        let Some(mp) = edge.mountpoint.upgrade() else {
            return String::from("/");
        };
        // Walk up to (but not including) the root, prefixing each
        // component. Guard against cycles with a generous cap.
        let mut parts: Vec<Arc<Dentry>> = Vec::new();
        let mut cur = mp;
        for _ in 0..64 {
            if cur.flags.contains(DFlags::IS_ROOT) {
                break;
            }
            let parent = match cur.parent.upgrade() {
                Some(p) => p,
                None => break,
            };
            parts.push(cur.clone());
            if Arc::ptr_eq(&parent, &cur) {
                break;
            }
            cur = parent;
        }
        if parts.is_empty() {
            return String::from("/");
        }
        let mut s = String::new();
        for d in parts.iter().rev() {
            s.push('/');
            // DString bytes are always valid UTF-8 subset (path components
            // reject `/` and NUL); fall back to `?` on surprise.
            match core::str::from_utf8(d.name.as_bytes()) {
                Ok(name) => s.push_str(name),
                Err(_) => s.push('?'),
            }
        }
        s
    }

    /// Locate `/etc/motd` in the Limine rootfs tarball module. Returns a
    /// heap copy of the payload so the formatter can treat it uniformly
    /// with other strings. `None` when the module is absent or no motd
    /// entry is present — both expected on host builds and on ISOs that
    /// haven't shipped one yet.
    fn find_motd() -> Option<alloc::vec::Vec<u8>> {
        let module = find_rootfs_module()?;
        let bytes = read_ustar_file(module, b"etc/motd")?;
        Some(bytes.to_vec())
    }

    fn find_rootfs_module() -> Option<&'static [u8]> {
        let resp = crate::boot::MODULE_REQUEST.get_response()?;
        let file = resp
            .modules()
            .iter()
            .find(|f| f.path().to_bytes().ends_with(b"/boot/rootfs.tar"))?;
        // SAFETY: Limine places module payloads in EXECUTABLE_AND_MODULES
        // memory, preserved across reclaim_bootloader_memory(). Mirrors
        // `vfs::init::find_rootfs_module` — kept local so banner.rs has
        // no lock-ordering dependency on the VFS.
        Some(unsafe { core::slice::from_raw_parts(file.addr(), file.size() as usize) })
    }

    /// Minimal USTAR walker: return the payload of the first regular
    /// file whose name equals `target`. Supports the `ustar\0` and
    /// `ustar ` variants. Standalone to keep the banner independent of
    /// any mounted filesystem.
    pub(super) fn read_ustar_file<'a>(tar: &'a [u8], target: &[u8]) -> Option<&'a [u8]> {
        const BLOCK: usize = 512;
        let mut off = 0;
        while off + BLOCK <= tar.len() {
            let hdr = &tar[off..off + BLOCK];
            // Two consecutive zero blocks (or just "all zero") terminate.
            if hdr.iter().all(|&b| b == 0) {
                return None;
            }
            let has_ustar =
                &hdr[257..263] == b"ustar\0" || &hdr[257..263] == b"ustar ";
            let name_end = hdr[..100]
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(100);
            let base_name = &hdr[..name_end];
            let size = parse_octal(&hdr[124..135]).unwrap_or(0) as usize;
            let typeflag = hdr[156];
            let data_off = off + BLOCK;
            let data_end = data_off.saturating_add(size);
            // Honor ustar prefix (bytes 345..500) when present.
            let matches = if has_ustar {
                let prefix_end = hdr[345..500]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(155);
                let prefix = &hdr[345..345 + prefix_end];
                if prefix.is_empty() {
                    base_name == target
                } else {
                    let mut full = [0u8; 256];
                    let plen = prefix.len().min(full.len());
                    full[..plen].copy_from_slice(&prefix[..plen]);
                    let rem = full.len() - plen;
                    let nlen = base_name.len().min(rem.saturating_sub(1));
                    if nlen + plen + 1 <= full.len() {
                        full[plen] = b'/';
                        full[plen + 1..plen + 1 + nlen]
                            .copy_from_slice(&base_name[..nlen]);
                        &full[..plen + 1 + nlen] == target
                    } else {
                        false
                    }
                }
            } else {
                base_name == target
            };
            // typeflag '0' or b'\0' = regular file.
            let is_regular = typeflag == b'0' || typeflag == 0;
            if matches && is_regular && data_end <= tar.len() {
                return Some(&tar[data_off..data_end]);
            }
            let padded = (size + BLOCK - 1) / BLOCK * BLOCK;
            off = data_off.saturating_add(padded);
        }
        None
    }

    fn parse_octal(field: &[u8]) -> Option<u64> {
        let mut v: u64 = 0;
        let mut seen = false;
        for &b in field {
            match b {
                b'0'..=b'7' => {
                    v = v.checked_mul(8)?.checked_add((b - b'0') as u64)?;
                    seen = true;
                }
                b' ' | 0 => {
                    if seen {
                        return Some(v);
                    }
                }
                _ => return None,
            }
        }
        if seen {
            Some(v)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::String;

    fn inputs() -> Inputs<'static> {
        Inputs {
            kernel_name: "vibix",
            release: "0.1.2",
            git_sha: "abc123",
            build_timestamp: "2026-04-16T00:00:00Z",
            profile: "debug",
            arch: "x86_64",
            cpu_brand: "Test CPU",
            cpu_count: 4,
            mem_total_bytes: 256 * 1024 * 1024,
            mem_free_bytes: 128 * 1024 * 1024,
            uptime_ms: 1234,
            mounts: &[("/", "tarfs"), ("/dev", "devfs")],
            motd: Some(b"hello\nworld\n"),
        }
    }

    #[test]
    fn contains_kernel_version() {
        let mut s = String::new();
        format_banner(&mut s, &inputs()).unwrap();
        assert!(s.contains("0.1.2"), "missing release: {}", s);
        assert!(s.starts_with(BANNER_PREFIX));
    }

    #[test]
    fn reports_cpu_mem_boot() {
        let mut s = String::new();
        format_banner(&mut s, &inputs()).unwrap();
        assert!(s.contains("cpu: Test CPU x4"));
        assert!(s.contains("mem: 256 MiB total, 128 MiB free"));
        assert!(s.contains("boot: 1234 ms"));
    }

    #[test]
    fn lists_mounts_in_order() {
        let mut s = String::new();
        format_banner(&mut s, &inputs()).unwrap();
        let slash = s.find("/  tarfs").expect("slash mount");
        let dev = s.find("/dev  devfs").expect("dev mount");
        assert!(slash < dev, "expected / before /dev:\n{}", s);
    }

    #[test]
    fn motd_lines_appear_verbatim() {
        let mut s = String::new();
        format_banner(&mut s, &inputs()).unwrap();
        assert!(s.contains("\nhello\n"));
        assert!(s.contains("\nworld\n"));
    }

    #[test]
    fn missing_motd_is_silent() {
        let mut inp = inputs();
        inp.motd = None;
        let mut s = String::new();
        format_banner(&mut s, &inp).unwrap();
        assert!(!s.contains("hello"));
        assert!(!s.contains("world"));
    }

    #[test]
    fn empty_mounts_section_is_omitted() {
        let mut inp = inputs();
        inp.mounts = &[];
        let mut s = String::new();
        format_banner(&mut s, &inp).unwrap();
        assert!(!s.contains("mounts:"));
    }

    #[test]
    fn split_lines_trims_trailing_newline_and_cr() {
        let lines: alloc::vec::Vec<&[u8]> = split_lines(b"a\r\nb\n").collect();
        assert_eq!(lines, vec![&b"a"[..], &b"b"[..]]);
    }

    #[test]
    fn split_lines_handles_no_trailing_newline() {
        let lines: alloc::vec::Vec<&[u8]> = split_lines(b"only").collect();
        assert_eq!(lines, vec![&b"only"[..]]);
    }

    #[test]
    fn lossy_replaces_non_ascii() {
        let mut s = String::new();
        write!(&mut s, "{}", Lossy(&[0xff, b'A', 0x00, b'z'])).unwrap();
        assert_eq!(s, "?A?z");
    }

}
