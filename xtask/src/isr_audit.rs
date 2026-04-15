//! Regression guard for issue #306: no `BlockingMutex` / `BlockingRwLock`
//! may appear on an ISR-reachable source path.
//!
//! Kept deliberately simple — a line-oriented string scan, no syn parsing.
//! The goal is to catch new acquisitions added to files we already know
//! the ISR handlers reach. Refreshing the file list is the maintainer's
//! job when the reachable surface grows; `docs/isr-paging-audit.md`
//! documents the procedure.

use std::path::{Path, PathBuf};

type R<T> = Result<T, Box<dyn std::error::Error>>;

/// Files reachable from any ISR / exception handler. Paths are relative
/// to the workspace root. See `docs/isr-paging-audit.md` for the
/// per-file call-chain justification.
const ISR_REACHABLE_FILES: &[&str] = &[
    "kernel/src/arch/x86_64/idt.rs",
    "kernel/src/arch/x86_64/interrupts.rs",
    "kernel/src/mem/paging.rs",
    "kernel/src/mem/frame.rs",
    "kernel/src/mem/refcount.rs",
    "kernel/src/mem/pf.rs",
    "kernel/src/mem/addrspace.rs",
    "kernel/src/mem/vmatree.rs",
    "kernel/src/mem/vmobject.rs",
    "kernel/src/time.rs",
    "kernel/src/task/mod.rs",
    "kernel/src/input.rs",
    "kernel/src/serial.rs",
    "kernel/src/signal/mod.rs",
    "kernel/src/process/mod.rs",
];

/// Patterns that, if present on a line, indicate a blocking-primitive
/// acquisition or construction reachable from an ISR. We look for type
/// mentions (`BlockingMutex<`, `BlockingRwLock<`) and constructors
/// (`BlockingMutex::new`, `BlockingRwLock::new`) — any of the four on
/// an ISR-reachable file fails the lint.
const FORBIDDEN_PATTERNS: &[&str] = &[
    "BlockingMutex<",
    "BlockingMutex::new",
    "BlockingRwLock<",
    "BlockingRwLock::new",
];

/// A single violation the lint found.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub file: String,
    pub line_no: usize,
    pub line: String,
    pub pattern: &'static str,
}

/// Scan one file's contents for any forbidden pattern. Lines containing
/// `// isr-audit: ok` are skipped (escape hatch for cases reviewed by
/// hand — annotate the line with a rationale when using it).
fn scan_contents(file: &str, contents: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if line.contains("// isr-audit: ok") {
            continue;
        }
        for pat in FORBIDDEN_PATTERNS {
            if line.contains(pat) {
                out.push(Finding {
                    file: file.to_string(),
                    line_no: idx + 1,
                    line: line.trim_end().to_string(),
                    pattern: pat,
                });
            }
        }
    }
    out
}

fn scan_file(root: &Path, rel: &str) -> R<Vec<Finding>> {
    let path: PathBuf = root.join(rel);
    let contents = std::fs::read_to_string(&path)
        .map_err(|e| format!("isr-audit: cannot read {}: {e}", path.display()))?;
    Ok(scan_contents(rel, &contents))
}

/// Entry point used by `cargo xtask isr-audit` and by `cargo xtask lint`.
pub fn run(workspace_root: &Path) -> R<()> {
    let mut findings = Vec::new();
    for rel in ISR_REACHABLE_FILES {
        findings.extend(scan_file(workspace_root, rel)?);
    }
    if findings.is_empty() {
        println!(
            "→ isr-audit: OK ({} files scanned, no blocking-primitive acquisitions)",
            ISR_REACHABLE_FILES.len()
        );
        return Ok(());
    }
    eprintln!(
        "isr-audit: {} forbidden pattern(s) on ISR-reachable path(s):",
        findings.len()
    );
    for f in &findings {
        eprintln!("  {}:{}: [{}] {}", f.file, f.line_no, f.pattern, f.line);
    }
    eprintln!(
        "See docs/isr-paging-audit.md. If the acquisition is provably safe, \
         annotate the line with `// isr-audit: ok` and explain why."
    );
    Err(format!("isr-audit: {} finding(s)", findings.len()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_file_produces_no_findings() {
        let src = "use spin::Mutex;\nstatic M: Mutex<u32> = Mutex::new(0);\n";
        assert!(scan_contents("fake.rs", src).is_empty());
    }

    #[test]
    fn blocking_mutex_type_flagged() {
        let src = "use crate::sync::BlockingMutex;\n\
                   static M: BlockingMutex<u32> = BlockingMutex::new(0);\n";
        let findings = scan_contents("fake.rs", src);
        // First line: `BlockingMutex;` — no `<` or `::new`, so no match.
        // Second line: matches both `BlockingMutex<` and `BlockingMutex::new`.
        assert_eq!(findings.len(), 2, "got: {findings:?}");
        assert_eq!(findings[0].line_no, 2);
        assert!(findings[0].pattern == "BlockingMutex<" || findings[0].pattern == "BlockingMutex::new");
    }

    #[test]
    fn blocking_rwlock_constructor_flagged() {
        let src = "let x = BlockingRwLock::new(0);\n";
        let findings = scan_contents("fake.rs", src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].pattern, "BlockingRwLock::new");
    }

    #[test]
    fn escape_hatch_suppresses_finding() {
        let src =
            "let x = BlockingMutex::new(0); // isr-audit: ok — routed via reaper\n";
        assert!(scan_contents("fake.rs", src).is_empty());
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let src = "\n\nBlockingMutex::new(0)\n";
        let findings = scan_contents("fake.rs", src);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line_no, 3);
    }

    #[test]
    fn allowlisted_files_exist_on_disk() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        for rel in ISR_REACHABLE_FILES {
            let p = root.join(rel);
            assert!(
                p.is_file(),
                "isr-audit allowlist references missing file: {}",
                p.display()
            );
        }
    }
}
