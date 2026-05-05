//! POSIX shell globbing / pathname expansion.
//!
//! Implements pattern matching and pathname expansion per POSIX.1-2024
//! §2.6.6 (Pathname Expansion) and §2.13.1 (Patterns Matching a Single
//! Character) / §2.13.3 (Patterns Used for Filename Expansion).
//!
//! ## Pattern syntax
//!
//! - `?` — matches any single character.
//! - `*` — matches any string, including the empty string.
//! - `[...]` — character class; matches any single character listed.
//! - `[!...]` or `[^...]` — negated character class.
//! - `\c` — literal character `c` (backslash escaping).
//!
//! ## Pathname expansion
//!
//! For each word containing unquoted glob metacharacters, the shell
//! walks the directory tree and collects matching entries, sorted
//! alphabetically. If no matches are found, the original word is
//! returned unchanged (POSIX default behaviour).
//!
//! Leading `.` in filenames is only matched by an explicit `.` in the
//! pattern (POSIX rule: `*` does not match dot-files unless the pattern
//! starts with `.`).

use std::path::{Path, PathBuf};

// ── Pattern element representation ───────────────────────────────

/// A single element in a compiled glob pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PatElem {
    /// Match a literal character.
    Literal(char),
    /// `?` — match any single character.
    AnyChar,
    /// `*` — match any string (including empty).
    AnyStar,
    /// `[...]` — match a character in the class.
    Class { negated: bool, ranges: Vec<ClassRange> },
}

/// A range within a character class: either a single character or an
/// inclusive range `lo-hi`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ClassRange {
    Single(char),
    Range(char, char),
}

// ── Pattern compilation ──────────────────────────────────────────

/// Compile a pattern string into a sequence of [`PatElem`]s.
///
/// Backslash-escaped characters become `Literal`s.  Returns `None`
/// if the pattern is malformed (e.g. unterminated `[`).
fn compile_pattern(pat: &str) -> Option<Vec<PatElem>> {
    let chars: Vec<char> = pat.chars().collect();
    let mut elems = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            '\\' => {
                i += 1;
                if i < chars.len() {
                    elems.push(PatElem::Literal(chars[i]));
                    i += 1;
                } else {
                    // Trailing backslash — treat as literal.
                    elems.push(PatElem::Literal('\\'));
                }
            }
            '?' => {
                elems.push(PatElem::AnyChar);
                i += 1;
            }
            '*' => {
                // Collapse consecutive stars.
                while i < chars.len() && chars[i] == '*' {
                    i += 1;
                }
                elems.push(PatElem::AnyStar);
            }
            '[' => {
                i += 1;
                let (class, new_i) = parse_class(&chars, i)?;
                elems.push(class);
                i = new_i;
            }
            c => {
                elems.push(PatElem::Literal(c));
                i += 1;
            }
        }
    }

    Some(elems)
}

/// Parse a character class starting right after the opening `[`.
/// Returns the `PatElem::Class` and the index right after the closing `]`.
fn parse_class(chars: &[char], start: usize) -> Option<(PatElem, usize)> {
    let mut i = start;
    let negated = if i < chars.len() && (chars[i] == '!' || chars[i] == '^') {
        i += 1;
        true
    } else {
        false
    };

    let mut ranges = Vec::new();

    // A `]` immediately after `[` or `[!` is literal per POSIX.
    if i < chars.len() && chars[i] == ']' {
        ranges.push(ClassRange::Single(']'));
        i += 1;
    }

    while i < chars.len() && chars[i] != ']' {
        let c = chars[i];
        if c == '\\' && i + 1 < chars.len() {
            i += 1;
            let esc = chars[i];
            i += 1;
            // Check for range: \c-d
            if i + 1 < chars.len() && chars[i] == '-' && chars[i + 1] != ']' {
                i += 1; // skip '-'
                let hi = if chars[i] == '\\' && i + 1 < chars.len() {
                    i += 1;
                    let h = chars[i];
                    i += 1;
                    h
                } else {
                    let h = chars[i];
                    i += 1;
                    h
                };
                ranges.push(ClassRange::Range(esc, hi));
            } else {
                ranges.push(ClassRange::Single(esc));
            }
        } else if i + 2 < chars.len() && chars[i + 1] == '-' && chars[i + 2] != ']' {
            let lo = c;
            i += 2; // skip char and '-'
            let hi = if chars[i] == '\\' && i + 1 < chars.len() {
                i += 1;
                let h = chars[i];
                i += 1;
                h
            } else {
                let h = chars[i];
                i += 1;
                h
            };
            ranges.push(ClassRange::Range(lo, hi));
        } else {
            ranges.push(ClassRange::Single(c));
            i += 1;
        }
    }

    if i >= chars.len() {
        // No closing `]` found — malformed.
        return None;
    }

    i += 1; // skip closing ']'
    Some((PatElem::Class { negated, ranges }, i))
}

// ── Pattern matching ─────────────────────────────────────────────

/// Test whether `text` matches the compiled pattern `elems`.
fn match_pattern(elems: &[PatElem], text: &str) -> bool {
    let text_chars: Vec<char> = text.chars().collect();
    match_recursive(elems, 0, &text_chars, 0)
}

fn match_recursive(elems: &[PatElem], ei: usize, text: &[char], ti: usize) -> bool {
    if ei == elems.len() {
        return ti == text.len();
    }

    match &elems[ei] {
        PatElem::Literal(c) => {
            if ti < text.len() && text[ti] == *c {
                match_recursive(elems, ei + 1, text, ti + 1)
            } else {
                false
            }
        }
        PatElem::AnyChar => {
            if ti < text.len() {
                match_recursive(elems, ei + 1, text, ti + 1)
            } else {
                false
            }
        }
        PatElem::AnyStar => {
            // Try matching 0, 1, 2, ... characters.
            for skip in 0..=(text.len() - ti) {
                if match_recursive(elems, ei + 1, text, ti + skip) {
                    return true;
                }
            }
            false
        }
        PatElem::Class { negated, ranges } => {
            if ti >= text.len() {
                return false;
            }
            let c = text[ti];
            let in_class = ranges.iter().any(|r| match r {
                ClassRange::Single(s) => c == *s,
                ClassRange::Range(lo, hi) => c >= *lo && c <= *hi,
            });
            if in_class != *negated {
                match_recursive(elems, ei + 1, text, ti + 1)
            } else {
                false
            }
        }
    }
}

// ── Public API ───────────────────────────────────────────────────

/// Returns `true` if the word contains unquoted glob metacharacters
/// (`*`, `?`, or `[`).
///
/// This operates on the *raw* word as produced by the lexer — quoting
/// has already been stripped, so any remaining `*`, `?`, or `[` was
/// unquoted.
pub fn has_glob_chars(word: &str) -> bool {
    let bytes = word.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => {
                // Skip escaped character.
                i += 2;
            }
            b'*' | b'?' | b'[' => return true,
            _ => i += 1,
        }
    }
    false
}

/// Match a pattern string against a single filename.
///
/// Returns `true` if `filename` matches `pattern`.  The pattern is
/// compiled on the fly; returns `false` for malformed patterns.
pub fn fnmatch(pattern: &str, filename: &str) -> bool {
    let elems = match compile_pattern(pattern) {
        Some(e) => e,
        None => return false,
    };
    match_pattern(&elems, filename)
}

/// Perform pathname expansion on a single word.
///
/// If the word contains glob metacharacters, it is expanded against the
/// filesystem rooted at the process's working directory. Results are
/// sorted alphabetically per POSIX.
///
/// If no matches are found (or the word has no metacharacters), the
/// original word is returned unchanged.
pub fn glob_expand(word: &str) -> Vec<String> {
    if !has_glob_chars(word) {
        return vec![word.to_string()];
    }

    let results = expand_path(word);

    if results.is_empty() {
        // No matches — return the literal pattern per POSIX.
        vec![word.to_string()]
    } else {
        let mut sorted: Vec<String> = results;
        sorted.sort();
        sorted
    }
}

/// Expand a glob pattern that may contain path separators.
///
/// Splits the pattern on `/` and walks the directory tree one component
/// at a time, matching each component against its sub-pattern.
fn expand_path(pattern: &str) -> Vec<String> {
    let components: Vec<&str> = split_pattern_components(pattern);

    if components.is_empty() {
        return vec![];
    }

    // Determine the starting point.
    let (start, comp_start) = if pattern.starts_with('/') {
        (PathBuf::from("/"), 0)
    } else {
        (PathBuf::from("."), 0)
    };

    let mut candidates: Vec<PathBuf> = vec![start];

    for (ci, comp) in components.iter().enumerate().skip(comp_start) {
        // Skip empty components from leading/trailing/doubled slashes,
        // except the very first one on an absolute path.
        if comp.is_empty() {
            continue;
        }

        let mut next_candidates = Vec::new();

        for base in &candidates {
            if has_glob_chars(comp) {
                // Match this component against directory entries.
                if let Ok(entries) = std::fs::read_dir(base) {
                    let compiled = match compile_pattern(comp) {
                        Some(e) => e,
                        None => continue,
                    };
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();

                        // POSIX: leading dot must be matched explicitly.
                        if name_str.starts_with('.') && !comp.starts_with('.') {
                            continue;
                        }

                        if match_pattern(&compiled, &name_str) {
                            let mut path = base.clone();
                            path.push(&*name_str);
                            // If there are more components, only
                            // directories can match.
                            if ci + 1 < components.len() {
                                if path.is_dir() {
                                    next_candidates.push(path);
                                }
                            } else {
                                next_candidates.push(path);
                            }
                        }
                    }
                }
            } else {
                // Literal component — just append it.
                let mut path = base.clone();
                path.push(comp);
                // For intermediate components, verify the directory exists.
                if ci + 1 < components.len() {
                    if path.is_dir() {
                        next_candidates.push(path);
                    }
                } else {
                    // Final component: include it if it exists on disk.
                    if path.exists() {
                        next_candidates.push(path);
                    }
                }
            }
        }

        candidates = next_candidates;
    }

    // Convert PathBuf results back to strings.
    candidates
        .into_iter()
        .filter_map(|p| {
            let s = p.to_string_lossy().into_owned();
            // Strip leading "./" that we added for relative patterns.
            if pattern.starts_with('/') {
                Some(s)
            } else {
                Some(strip_dot_slash(&s))
            }
        })
        .collect()
}

/// Split a pattern into path components, preserving the ability to
/// detect absolute paths (leading `/` produces an empty first component).
fn split_pattern_components(pattern: &str) -> Vec<&str> {
    pattern.split('/').collect()
}

/// Strip a leading "./" prefix from a path string.
fn strip_dot_slash(s: &str) -> String {
    if s.starts_with("./") {
        s[2..].to_string()
    } else {
        s.to_string()
    }
}

/// Expand glob patterns in a list of words.
///
/// Each word that contains glob metacharacters is expanded; words
/// without metacharacters pass through unchanged. This is the entry
/// point the shell executor should call after variable expansion and
/// field splitting.
pub fn glob_expand_words(words: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    for word in words {
        result.extend(glob_expand(word));
    }
    result
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // ── has_glob_chars ───────────────────────────────────────────

    #[test]
    fn detect_star() {
        assert!(has_glob_chars("*.rs"));
    }

    #[test]
    fn detect_question() {
        assert!(has_glob_chars("file?.txt"));
    }

    #[test]
    fn detect_bracket() {
        assert!(has_glob_chars("[abc]"));
    }

    #[test]
    fn no_glob_plain_word() {
        assert!(!has_glob_chars("hello"));
    }

    #[test]
    fn escaped_star_not_glob() {
        assert!(!has_glob_chars("\\*"));
    }

    #[test]
    fn escaped_question_not_glob() {
        assert!(!has_glob_chars("\\?"));
    }

    // ── fnmatch — basic patterns ─────────────────────────────────

    #[test]
    fn literal_match() {
        assert!(fnmatch("hello", "hello"));
    }

    #[test]
    fn literal_mismatch() {
        assert!(!fnmatch("hello", "world"));
    }

    #[test]
    fn star_matches_everything() {
        assert!(fnmatch("*", "anything"));
    }

    #[test]
    fn star_matches_empty() {
        assert!(fnmatch("*", ""));
    }

    #[test]
    fn star_prefix() {
        assert!(fnmatch("*.rs", "main.rs"));
        assert!(fnmatch("*.rs", ".rs"));
        assert!(!fnmatch("*.rs", "main.txt"));
    }

    #[test]
    fn star_suffix() {
        assert!(fnmatch("src*", "src"));
        assert!(fnmatch("src*", "src/main.rs"));
    }

    #[test]
    fn star_middle() {
        assert!(fnmatch("a*z", "az"));
        assert!(fnmatch("a*z", "abcz"));
        assert!(!fnmatch("a*z", "abcx"));
    }

    #[test]
    fn double_star_collapses() {
        assert!(fnmatch("a**b", "ab"));
        assert!(fnmatch("a**b", "axb"));
    }

    #[test]
    fn question_mark() {
        assert!(fnmatch("?", "a"));
        assert!(!fnmatch("?", ""));
        assert!(!fnmatch("?", "ab"));
    }

    #[test]
    fn question_in_pattern() {
        assert!(fnmatch("file?.txt", "file1.txt"));
        assert!(fnmatch("file?.txt", "fileA.txt"));
        assert!(!fnmatch("file?.txt", "file12.txt"));
    }

    #[test]
    fn mixed_star_question() {
        assert!(fnmatch("*?.rs", "x.rs"));
        assert!(fnmatch("*?.rs", "main.rs"));
        assert!(!fnmatch("*?.rs", ".rs"));
    }

    // ── fnmatch — character classes ──────────────────────────────

    #[test]
    fn class_simple() {
        assert!(fnmatch("[abc]", "a"));
        assert!(fnmatch("[abc]", "b"));
        assert!(fnmatch("[abc]", "c"));
        assert!(!fnmatch("[abc]", "d"));
    }

    #[test]
    fn class_range() {
        assert!(fnmatch("[a-z]", "m"));
        assert!(!fnmatch("[a-z]", "M"));
        assert!(fnmatch("[0-9]", "5"));
        assert!(!fnmatch("[0-9]", "a"));
    }

    #[test]
    fn class_negated_bang() {
        assert!(!fnmatch("[!abc]", "a"));
        assert!(fnmatch("[!abc]", "d"));
    }

    #[test]
    fn class_negated_caret() {
        assert!(!fnmatch("[^abc]", "a"));
        assert!(fnmatch("[^abc]", "d"));
    }

    #[test]
    fn class_literal_close_bracket() {
        // `]` immediately after `[` is literal per POSIX.
        assert!(fnmatch("[]abc]", "]"));
        assert!(fnmatch("[]abc]", "a"));
    }

    #[test]
    fn class_in_pattern() {
        assert!(fnmatch("file[0-9].txt", "file3.txt"));
        assert!(!fnmatch("file[0-9].txt", "fileA.txt"));
    }

    #[test]
    fn class_combined_with_star() {
        assert!(fnmatch("*.[ch]", "main.c"));
        assert!(fnmatch("*.[ch]", "main.h"));
        assert!(!fnmatch("*.[ch]", "main.o"));
    }

    // ── fnmatch — backslash escaping ─────────────────────────────

    #[test]
    fn backslash_escapes_star() {
        assert!(fnmatch("\\*", "*"));
        assert!(!fnmatch("\\*", "x"));
    }

    #[test]
    fn backslash_escapes_question() {
        assert!(fnmatch("\\?", "?"));
        assert!(!fnmatch("\\?", "x"));
    }

    #[test]
    fn backslash_escapes_bracket() {
        assert!(fnmatch("\\[abc]", "[abc]"));
    }

    // ── fnmatch — malformed patterns ─────────────────────────────

    #[test]
    fn unterminated_bracket_returns_false() {
        assert!(!fnmatch("[abc", "a"));
    }

    // ── fnmatch — edge cases ─────────────────────────────────────

    #[test]
    fn empty_pattern_matches_empty_string() {
        assert!(fnmatch("", ""));
    }

    #[test]
    fn empty_pattern_does_not_match_nonempty() {
        assert!(!fnmatch("", "x"));
    }

    #[test]
    fn star_only() {
        assert!(fnmatch("*", ""));
        assert!(fnmatch("*", "any string at all"));
    }

    // ── Pathname expansion (filesystem) ──────────────────────────

    /// Create a temporary directory with a known structure for glob tests.
    fn make_test_dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();

        // Files in root.
        fs::write(base.join("alpha.rs"), "").unwrap();
        fs::write(base.join("beta.rs"), "").unwrap();
        fs::write(base.join("gamma.txt"), "").unwrap();
        fs::write(base.join(".hidden"), "").unwrap();

        // Subdirectory with files.
        fs::create_dir(base.join("src")).unwrap();
        fs::write(base.join("src").join("main.rs"), "").unwrap();
        fs::write(base.join("src").join("lib.rs"), "").unwrap();
        fs::write(base.join("src").join("util.txt"), "").unwrap();

        dir
    }

    /// A mutex to serialize tests that change the working directory.
    static CWD_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Expand a glob relative to a temp directory.
    fn glob_in(dir: &Path, pattern: &str) -> Vec<String> {
        let _guard = CWD_LOCK.lock().unwrap();
        // Save and restore CWD.
        let orig = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir).unwrap();
        let mut result = glob_expand(pattern);
        result.sort();
        std::env::set_current_dir(orig).unwrap();
        result
    }

    #[test]
    fn expand_star_rs() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "*.rs");
        assert_eq!(result, vec!["alpha.rs", "beta.rs"]);
    }

    #[test]
    fn expand_star_txt() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "*.txt");
        assert_eq!(result, vec!["gamma.txt"]);
    }

    #[test]
    fn expand_question_mark() {
        let dir = make_test_dir();
        let base = dir.path();
        // Create some single-char-name files.
        fs::write(base.join("a"), "").unwrap();
        fs::write(base.join("b"), "").unwrap();
        fs::write(base.join("c"), "").unwrap();
        let result = glob_in(dir.path(), "?");
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn expand_no_match_returns_literal() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "*.xyz");
        assert_eq!(result, vec!["*.xyz"]);
    }

    #[test]
    fn expand_hidden_not_matched_by_star() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "*");
        // Should not contain ".hidden".
        assert!(!result.contains(&".hidden".to_string()));
        // But should contain other files and dirs.
        assert!(result.contains(&"alpha.rs".to_string()));
        assert!(result.contains(&"src".to_string()));
    }

    #[test]
    fn expand_hidden_matched_by_dot_star() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), ".*");
        assert!(result.contains(&".hidden".to_string()));
    }

    #[test]
    fn expand_multi_component() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "src/*.rs");
        assert_eq!(result, vec!["src/lib.rs", "src/main.rs"]);
    }

    #[test]
    fn expand_multi_component_star_dir() {
        let dir = make_test_dir();
        let base = dir.path();
        // Create another subdir with .rs files.
        fs::create_dir(base.join("lib")).unwrap();
        fs::write(base.join("lib").join("foo.rs"), "").unwrap();
        let mut result = glob_in(dir.path(), "*/*.rs");
        result.sort();
        assert!(result.contains(&"src/lib.rs".to_string()));
        assert!(result.contains(&"src/main.rs".to_string()));
        assert!(result.contains(&"lib/foo.rs".to_string()));
    }

    #[test]
    fn expand_character_class() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "[ab]*.rs");
        assert_eq!(result, vec!["alpha.rs", "beta.rs"]);
    }

    #[test]
    fn expand_sorted_alphabetically() {
        let dir = make_test_dir();
        let result = glob_in(dir.path(), "*.rs");
        let mut sorted = result.clone();
        sorted.sort();
        assert_eq!(result, sorted);
    }

    #[test]
    fn expand_no_glob_passthrough() {
        assert_eq!(glob_expand("hello"), vec!["hello"]);
    }

    #[test]
    fn glob_expand_words_mixed() {
        // Non-glob words pass through; this doesn't need filesystem.
        let words = vec![
            "plain".to_string(),
            "also-plain".to_string(),
        ];
        let result = glob_expand_words(&words);
        assert_eq!(result, vec!["plain", "also-plain"]);
    }

    #[test]
    fn glob_expand_words_with_glob_no_match() {
        let words = vec!["no_such_*.xyz".to_string()];
        let result = glob_expand_words(&words);
        // No match — literal passthrough.
        assert_eq!(result, vec!["no_such_*.xyz"]);
    }
}
