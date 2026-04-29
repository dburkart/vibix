//! xtask-side line-number table embedder.
//!
//! Parses the freshly-linked kernel ELF's `.debug_line` sections via
//! `gimli`, collects one `(pc, file, line, col)` row per distinct source
//! location, and patches the result into the kernel's `LNTAB_RESERVATION`
//! section. See `kernel/src/lntab.rs` for the on-wire format.

// xtask is host build tooling — its output is a build artefact, not a
// kernel trace. The DST-simulator determinism lint (RFC 0006 / issue
// #714) targets kernel `sched-mock` paths and the `simulator/` crate;
// the file-offset cache below is a pure lookup table whose iteration
// order does not feed any seeded run.
#![allow(clippy::disallowed_types)]

use std::collections::HashMap;
use std::fs;
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use gimli::Reader;
use object::{Object, ObjectSection, ObjectSymbol};

use crate::R;

// Layout constants — must stay in sync with kernel/src/lntab.rs. That
// file pins matching `size_of::<Header>() == 20` and
// `size_of::<Entry>() == 24` asserts so drift breaks the kernel build
// before a bad blob can ship.
const MAGIC: &[u8; 4] = b"LNTB";
const VERSION: u8 = 1;
const HEADER_SIZE: usize = 20;
const ENTRY_SIZE: usize = 24;

/// One collected line-table row, pre-dedup/sort.
#[derive(Debug, Clone)]
struct LnRow {
    pc: u64,
    file: String,
    line: u32,
    col: u32,
}

/// Parse `.debug_line` across all compilation units, returning one row
/// per (pc, file, line) triple. The caller sorts and deduplicates.
fn collect_rows(obj: &object::File<'_>) -> R<Vec<LnRow>> {
    let endian = gimli::RunTimeEndian::Little;

    let load_section = |id: gimli::SectionId| -> R<gimli::EndianRcSlice<gimli::RunTimeEndian>> {
        let name = id.name();
        let data: std::rc::Rc<[u8]> = match obj.section_by_name(name) {
            Some(section) => section.uncompressed_data()?.into_owned().into(),
            None => std::rc::Rc::new([]),
        };
        Ok(gimli::EndianRcSlice::new(data, endian))
    };

    let dwarf_sections = gimli::DwarfSections::load(load_section)?;
    let dwarf = dwarf_sections.borrow(|section| section.clone());

    let mut rows: Vec<LnRow> = Vec::new();
    let mut units = dwarf.units();
    while let Some(header) = units.next()? {
        let unit = dwarf.unit(header)?;
        let unit_ref = unit.unit_ref(&dwarf);

        let Some(program) = unit_ref.line_program.clone() else {
            continue;
        };

        let comp_dir: String = match unit_ref.comp_dir.as_ref() {
            Some(d) => d
                .to_string_lossy()
                .ok()
                .map(|s| s.into_owned())
                .unwrap_or_default(),
            None => String::new(),
        };

        // Cache filenames per `file_index` within this unit so we don't
        // re-resolve the same DW_AT_decl_file on every row.
        let mut file_cache: HashMap<u64, String> = HashMap::new();

        let mut state_machine = program.rows();
        while let Some((header, row)) = state_machine.next_row()? {
            if row.end_sequence() {
                continue;
            }
            let pc = row.address();
            if pc == 0 {
                continue;
            }
            let line = row.line().map(|l| l.get()).unwrap_or(0);
            let col = match row.column() {
                gimli::ColumnType::Column(c) => c.get(),
                gimli::ColumnType::LeftEdge => 0,
            };

            let file_idx = row.file_index();
            let file = if let Some(f) = file_cache.get(&file_idx) {
                f.clone()
            } else {
                let Some(file) = resolve_file_path(&unit_ref, header, file_idx, &comp_dir) else {
                    // Cache the negative result so we don't re-resolve every
                    // row, but skip emitting the row — `at :<line>` output
                    // is worse than just an unannotated frame.
                    file_cache.insert(file_idx, String::new());
                    continue;
                };
                file_cache.insert(file_idx, file.clone());
                file
            };
            if file.is_empty() {
                continue;
            }

            // Clamp line to u32; rustc never emits anything near this.
            let line_u32 = u32::try_from(line).unwrap_or(u32::MAX);
            rows.push(LnRow {
                pc,
                file,
                line: line_u32,
                col: col.min(u32::MAX as u64) as u32,
            });
        }
    }

    Ok(rows)
}

fn resolve_file_path(
    unit: &gimli::UnitRef<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    header: &gimli::LineProgramHeader<gimli::EndianRcSlice<gimli::RunTimeEndian>>,
    file_idx: u64,
    comp_dir: &str,
) -> Option<String> {
    let file = header.file(file_idx)?;

    // Filename.
    let name_attr = file.path_name();
    let name = unit
        .attr_string(name_attr)
        .ok()?
        .to_string_lossy()
        .ok()?
        .into_owned();

    // Directory.
    let dir = if let Some(dir_attr) = file.directory(header) {
        unit.attr_string(dir_attr)
            .ok()
            .and_then(|s| s.to_string_lossy().ok().map(|c| c.into_owned()))
            .unwrap_or_default()
    } else {
        String::new()
    };

    let path: PathBuf = if dir.is_empty() {
        PathBuf::from(&name)
    } else if Path::new(&dir).is_absolute() {
        Path::new(&dir).join(&name)
    } else if !comp_dir.is_empty() {
        Path::new(comp_dir).join(&dir).join(&name)
    } else {
        Path::new(&dir).join(&name)
    };

    Some(path.to_string_lossy().into_owned())
}

/// Normalize a file path relative to the workspace root when possible.
/// For paths outside the workspace (sysroot, cargo-registry, etc.), keeps
/// only the last two path components so the strtab stays compact and
/// machine-independent (e.g. `.../spin/src/mutex.rs` → `src/mutex.rs`).
fn normalize(path: &str, workspace_root: &Path) -> String {
    let p = Path::new(path);
    if let Ok(stripped) = p.strip_prefix(workspace_root) {
        stripped.to_string_lossy().into_owned()
    } else {
        // Keep only the last two normal components so the blob doesn't
        // embed machine-specific absolute sysroot or registry paths.
        // Root/prefix components are skipped so the result is always
        // a relative fragment (e.g. `/etc/passwd` → `etc/passwd`,
        // `/libc.so` → `libc.so`).
        let components: Vec<_> = p
            .components()
            .filter(|c| matches!(c, std::path::Component::Normal(_)))
            .rev()
            .take(2)
            .collect();
        let short: PathBuf = components.into_iter().rev().collect();
        short.to_string_lossy().into_owned()
    }
}

/// Sort rows by pc and collapse duplicates / runs of (file, line, col)
/// with the same source location to their first pc.
fn sort_and_dedup(rows: &mut Vec<LnRow>) {
    rows.sort_by_key(|a| a.pc);
    // For equal-PC rows, keep the LAST entry: DWARF iteration order is
    // implementation-defined, but for inlined functions the innermost
    // (callee) source location tends to appear last and is more useful
    // for backtraces than the call-site row that comes first.
    // `dedup_by` removes `a` (the later slot) when the closure returns
    // true, so we copy `a`'s fields into `b` before returning true.
    rows.dedup_by(|a, b| {
        if a.pc == b.pc {
            b.file = a.file.clone();
            b.line = a.line;
            b.col = a.col;
            true
        } else {
            false
        }
    });
    // Collapse adjacent rows with identical source triples, keeping the
    // lowest pc. Iterate in a single pass.
    let mut write = 0usize;
    for read in 0..rows.len() {
        if write > 0 {
            let prev = &rows[write - 1];
            let cur = &rows[read];
            if prev.file == cur.file && prev.line == cur.line && prev.col == cur.col {
                continue;
            }
        }
        if read != write {
            rows.swap(read, write);
        }
        write += 1;
    }
    rows.truncate(write);
}

/// Serialize collected rows into the on-wire blob the kernel decodes.
fn build_blob(rows: &[LnRow], workspace_root: &Path) -> Vec<u8> {
    let mut strtab: Vec<u8> = Vec::new();
    let mut file_offsets: HashMap<String, (u32, u32)> = HashMap::new();
    let mut entries: Vec<u8> = Vec::with_capacity(rows.len() * ENTRY_SIZE);

    for r in rows {
        let normalized = normalize(&r.file, workspace_root);
        let (off, len) = match file_offsets.get(&normalized) {
            Some(&v) => v,
            None => {
                let off = strtab.len() as u32;
                let len = normalized.len() as u32;
                strtab.extend_from_slice(normalized.as_bytes());
                file_offsets.insert(normalized.clone(), (off, len));
                (off, len)
            }
        };
        let col = r.col.min(u16::MAX as u32) as u16;

        entries.extend_from_slice(&r.pc.to_le_bytes());
        entries.extend_from_slice(&off.to_le_bytes());
        entries.extend_from_slice(&len.to_le_bytes());
        entries.extend_from_slice(&r.line.to_le_bytes());
        entries.extend_from_slice(&col.to_le_bytes());
        entries.extend_from_slice(&0u16.to_le_bytes());
    }

    let count = rows.len() as u32;
    let str_off = (HEADER_SIZE + entries.len()) as u32;
    let str_len = strtab.len() as u32;

    let mut blob = Vec::with_capacity(HEADER_SIZE + entries.len() + strtab.len());
    blob.extend_from_slice(MAGIC);
    blob.push(VERSION);
    blob.extend_from_slice(&[0u8; 3]);
    blob.extend_from_slice(&count.to_le_bytes());
    blob.extend_from_slice(&str_off.to_le_bytes());
    blob.extend_from_slice(&str_len.to_le_bytes());
    blob.extend_from_slice(&entries);
    blob.extend_from_slice(&strtab);
    blob
}

/// Locate the `LNTAB_RESERVATION` symbol and return `(file_offset, size)`
/// for the bytes to overwrite.
fn find_reservation(obj: &object::File<'_>) -> R<(u64, usize)> {
    let rsv = obj
        .symbols()
        .find(|s| s.name().map(|n| n == "LNTAB_RESERVATION").unwrap_or(false))
        .ok_or("LNTAB_RESERVATION symbol not found in kernel ELF")?;
    let rsv_vma = rsv.address();
    let rsv_size = rsv.size() as usize;
    if rsv_size == 0 {
        return Err("LNTAB_RESERVATION has zero size".into());
    }
    let section = obj
        .sections()
        .find(|s| {
            let (addr, size) = (s.address(), s.size());
            rsv_vma >= addr && rsv_vma + rsv_size as u64 <= addr + size
        })
        .ok_or("no section contains LNTAB_RESERVATION")?;
    let (sec_file_off, _) = section
        .file_range()
        .ok_or("section containing LNTAB_RESERVATION has no file bytes")?;
    let off = sec_file_off + (rsv_vma - section.address());
    Ok((off, rsv_size))
}

/// Embed the line table into `kernel`. Idempotent: safe to re-run.
/// `workspace_root` is used to relativize file paths so the strtab
/// ships `kernel/src/foo.rs` instead of `/home/agent/work/kernel/...`.
pub fn embed(kernel: &Path, workspace_root: &Path) -> R<()> {
    let bytes = fs::read(kernel)?;
    let obj = object::File::parse(&*bytes)?;

    // Without .debug_line present, there's nothing to embed — leave the
    // reservation as-is (the kernel decoder tolerates an unpopulated
    // table by returning None). This can happen if someone flipped the
    // profile back to `debug = 0`.
    if obj.section_by_name(".debug_line").is_none() {
        println!("→ lntab: .debug_line absent, skipping");
        return Ok(());
    }

    let mut rows = collect_rows(&obj)?;
    if rows.is_empty() {
        println!("→ lntab: 0 rows extracted");
        return Ok(());
    }
    sort_and_dedup(&mut rows);

    let (sec_off, sec_size) = find_reservation(&obj)?;
    let blob = build_blob(&rows, workspace_root);

    if blob.len() > sec_size {
        return Err(format!(
            "lntab blob {} bytes exceeds reservation {}; bump LNTAB_BYTES",
            blob.len(),
            sec_size
        )
        .into());
    }

    let count = rows.len();
    drop(obj);

    let mut padded = vec![0u8; sec_size];
    padded[..blob.len()].copy_from_slice(&blob);

    let mut f = fs::OpenOptions::new().write(true).open(kernel)?;
    f.seek(SeekFrom::Start(sec_off))?;
    f.write_all(&padded)?;

    println!("→ lntab: {count} rows, {}/{sec_size} bytes", blob.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pc: u64, file: &str, line: u32, col: u32) -> LnRow {
        LnRow {
            pc,
            file: file.to_string(),
            line,
            col,
        }
    }

    #[test]
    fn sort_and_dedup_orders_by_pc() {
        let mut rows = vec![
            row(0x3000, "c.rs", 3, 0),
            row(0x1000, "a.rs", 1, 0),
            row(0x2000, "b.rs", 2, 0),
        ];
        sort_and_dedup(&mut rows);
        assert_eq!(rows[0].pc, 0x1000);
        assert_eq!(rows[1].pc, 0x2000);
        assert_eq!(rows[2].pc, 0x3000);
    }

    #[test]
    fn sort_and_dedup_drops_equal_pc() {
        let mut rows = vec![row(0x1000, "a.rs", 1, 0), row(0x1000, "a.rs", 2, 0)];
        sort_and_dedup(&mut rows);
        assert_eq!(rows.len(), 1);
        // The LAST row for a given PC is kept (line 2, not line 1).
        assert_eq!(rows[0].line, 2);
    }

    #[test]
    fn sort_and_dedup_collapses_adjacent_same_source() {
        let mut rows = vec![
            row(0x1000, "a.rs", 1, 0),
            row(0x1004, "a.rs", 1, 0),
            row(0x1008, "a.rs", 1, 0),
            row(0x100c, "a.rs", 2, 0),
        ];
        sort_and_dedup(&mut rows);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pc, 0x1000);
        assert_eq!(rows[0].line, 1);
        assert_eq!(rows[1].pc, 0x100c);
        assert_eq!(rows[1].line, 2);
    }

    #[test]
    fn build_blob_roundtrip() {
        let ws = Path::new("/ws");
        let rows = vec![
            row(0x1000, "a.rs", 1, 4),
            row(0x2000, "b.rs", 2, 8),
            row(0x3000, "a.rs", 3, 12),
        ];
        let blob = build_blob(&rows, ws);

        assert_eq!(&blob[0..4], MAGIC);
        assert_eq!(blob[4], VERSION);
        let count = u32::from_le_bytes(blob[8..12].try_into().unwrap());
        assert_eq!(count, 3);

        // First entry.
        let pc = u64::from_le_bytes(blob[HEADER_SIZE..HEADER_SIZE + 8].try_into().unwrap());
        assert_eq!(pc, 0x1000);

        // Verify strtab contents exist and contain both filenames.
        let str_off = u32::from_le_bytes(blob[12..16].try_into().unwrap()) as usize;
        let str_len = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
        let strs = &blob[str_off..str_off + str_len];
        let s = std::str::from_utf8(strs).unwrap();
        assert!(s.contains("a.rs"));
        assert!(s.contains("b.rs"));
    }

    #[test]
    fn build_blob_dedups_filenames_in_strtab() {
        // Three rows referencing the same file should result in a
        // single strtab entry (verified via expected strtab length).
        let ws = Path::new("/ws");
        let rows = vec![
            row(0x1000, "same.rs", 1, 0),
            row(0x2000, "same.rs", 2, 0),
            row(0x3000, "same.rs", 3, 0),
        ];
        let blob = build_blob(&rows, ws);
        let str_len = u32::from_le_bytes(blob[16..20].try_into().unwrap()) as usize;
        assert_eq!(str_len, "same.rs".len());
    }

    #[test]
    fn build_blob_saturates_col_to_u16() {
        let ws = Path::new("/ws");
        let rows = vec![row(0x1000, "a.rs", 1, 100_000)];
        let blob = build_blob(&rows, ws);
        // Entry layout: pc(8) file_off(4) file_len(4) line(4) col(2) pad(2)
        // col sits at HEADER_SIZE + 20 ..+ 22.
        let col_start = HEADER_SIZE + 8 + 4 + 4 + 4;
        let col = u16::from_le_bytes(blob[col_start..col_start + 2].try_into().unwrap());
        assert_eq!(col, u16::MAX);
    }

    #[test]
    fn normalize_strips_workspace_prefix() {
        let ws = Path::new("/ws");
        assert_eq!(normalize("/ws/kernel/src/foo.rs", ws), "kernel/src/foo.rs");
        // Non-workspace paths are shortened to the last two normal components.
        assert_eq!(normalize("/etc/passwd", ws), "etc/passwd");
    }

    #[test]
    fn normalize_shortens_non_workspace_path() {
        let ws = Path::new("/ws");
        // Cargo registry paths get truncated to the last two components.
        assert_eq!(
            normalize("/home/user/.cargo/registry/src/spin/src/mutex.rs", ws),
            "src/mutex.rs"
        );
    }

    #[test]
    fn normalize_shortens_single_component_path() {
        let ws = Path::new("/ws");
        // Paths with fewer than two components return what's available.
        assert_eq!(normalize("/libc.so", ws), "libc.so");
    }
}
