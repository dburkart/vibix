//! POSIX shell variable expansion and field splitting.
//!
//! Implements word expansion per POSIX.1-2024 §2.6. The expand module
//! takes raw word strings from the parser's AST and produces expanded
//! field(s) with variable references resolved.
//!
//! ## Supported expansions
//!
//! - `$VAR` and `${VAR}` — simple variable lookup.
//! - Special parameters: `$?`, `$$`, `$!`, `$#`, `$@`, `$*`,
//!   `$0`–`$9`.
//! - `${VAR:-default}` — use default if unset or empty.
//! - `${VAR:=default}` — assign default if unset or empty.
//! - `${VAR:?error}` — error if unset or empty.
//! - `${VAR:+alt}` — use alt if set and non-empty.
//! - Variants without colon (`${VAR-default}`, etc.) that only test
//!   whether the variable is *set*, ignoring emptiness.
//!
//! ## Field splitting
//!
//! After expansion, unquoted results are split on `$IFS` characters
//! (default: space, tab, newline). Quoted expansions suppress splitting.

use std::collections::HashMap;

// ── Variable storage ──────────────────────────────────────────────

/// A shell variable with an optional export flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShellVar {
    /// The variable's value.
    pub value: String,
    /// Whether this variable is exported to child processes.
    pub exported: bool,
}

/// Environment for shell variable expansion.
///
/// Stores shell variables, positional parameters, and special parameter
/// state needed by the expander.
#[derive(Debug)]
pub struct Environment {
    /// Named variables (e.g. `HOME`, `PATH`, user-defined).
    pub vars: HashMap<String, ShellVar>,
    /// Positional parameters (`$1` .. `$N`).
    pub positional: Vec<String>,
    /// `$0` — the shell or script name.
    pub arg0: String,
    /// `$?` — exit status of the last command.
    pub last_status: i32,
    /// `$$` — PID of the shell.
    pub shell_pid: u32,
    /// `$!` — PID of the last background process (0 if none).
    pub last_bg_pid: u32,
}

impl Environment {
    /// Create a new, empty environment.
    pub fn new() -> Self {
        Self {
            vars: HashMap::new(),
            positional: Vec::new(),
            arg0: String::from("sh"),
            last_status: 0,
            shell_pid: 0,
            last_bg_pid: 0,
        }
    }

    /// Get the value of a named variable, or `None` if unset.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.vars.get(name).map(|v| v.value.as_str())
    }

    /// Set a named variable. If `exported` is `None`, preserve the
    /// existing export flag (or default to `false` for new variables).
    pub fn set(&mut self, name: &str, value: &str, exported: Option<bool>) {
        if let Some(var) = self.vars.get_mut(name) {
            var.value = value.to_string();
            if let Some(exp) = exported {
                var.exported = exp;
            }
        } else {
            self.vars.insert(
                name.to_string(),
                ShellVar {
                    value: value.to_string(),
                    exported: exported.unwrap_or(false),
                },
            );
        }
    }

    /// Remove a named variable.
    pub fn unset(&mut self, name: &str) {
        self.vars.remove(name);
    }

    /// Mark a variable as exported.
    pub fn export(&mut self, name: &str) {
        if let Some(var) = self.vars.get_mut(name) {
            var.exported = true;
        } else {
            // Export an empty variable (POSIX allows `export VAR`
            // without assignment).
            self.vars.insert(
                name.to_string(),
                ShellVar {
                    value: String::new(),
                    exported: true,
                },
            );
        }
    }

    /// Collect all exported variables as `(name, value)` pairs.
    pub fn exported_vars(&self) -> Vec<(&str, &str)> {
        self.vars
            .iter()
            .filter(|(_, v)| v.exported)
            .map(|(k, v)| (k.as_str(), v.value.as_str()))
            .collect()
    }

    /// Look up a special parameter or named variable. Returns `None`
    /// if the parameter is unset.
    fn lookup_param(&self, name: &str) -> Option<String> {
        match name {
            "?" => Some(self.last_status.to_string()),
            "$" => Some(self.shell_pid.to_string()),
            "!" => Some(self.last_bg_pid.to_string()),
            "#" => Some(self.positional.len().to_string()),
            "0" => Some(self.arg0.clone()),
            "@" | "*" => {
                // When not inside double quotes, $@ and $* behave the
                // same — join positional params with space.
                Some(self.positional.join(" "))
            }
            _ => {
                // Try positional $1..$9 (single digit).
                if name.len() == 1 {
                    if let Some(digit) = name.as_bytes().first() {
                        if digit.is_ascii_digit() && *digit != b'0' {
                            let idx = (*digit - b'1') as usize;
                            return self.positional.get(idx).cloned();
                        }
                    }
                }
                // Named variable.
                self.get(name).map(|s| s.to_string())
            }
        }
    }
}

impl Default for Environment {
    fn default() -> Self {
        Self::new()
    }
}

// ── Expansion errors ──────────────────────────────────────────────

/// An error encountered during variable expansion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExpandError {
    /// `${VAR:?message}` or `${VAR?message}` triggered.
    UnsetVariable { name: String, message: String },
    /// Malformed parameter expansion (bad syntax inside `${...}`).
    BadSubstitution(String),
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::UnsetVariable { name, message } => {
                write!(f, "{name}: {message}")
            }
            ExpandError::BadSubstitution(s) => {
                write!(f, "bad substitution: {s}")
            }
        }
    }
}

// ── Expander ──────────────────────────────────────────────────────

/// Expand variable references in a word string.
///
/// Returns the expanded string. Variable references (`$VAR`, `${VAR}`,
/// `${VAR:-default}`, special params) are replaced with their values.
///
/// This function does NOT perform field splitting — call
/// [`field_split`] on the result if the word appeared outside of double
/// quotes.
pub fn expand_word(word: &str, env: &mut Environment) -> Result<String, ExpandError> {
    let bytes = word.as_bytes();
    let mut out = String::new();
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'$' {
            i += 1;
            if i >= bytes.len() {
                // Bare `$` at end of word — literal.
                out.push('$');
                break;
            }
            match bytes[i] {
                b'{' => {
                    // Braced expansion: ${...}
                    i += 1; // skip '{'
                    let start = i;
                    // Find the matching '}'
                    let mut depth = 1;
                    while i < bytes.len() && depth > 0 {
                        if bytes[i] == b'{' {
                            depth += 1;
                        } else if bytes[i] == b'}' {
                            depth -= 1;
                        }
                        if depth > 0 {
                            i += 1;
                        }
                    }
                    if depth != 0 {
                        return Err(ExpandError::BadSubstitution(
                            "unterminated ${".to_string(),
                        ));
                    }
                    let inner = &word[start..i];
                    i += 1; // skip '}'
                    let expanded = expand_braced(inner, env)?;
                    out.push_str(&expanded);
                }
                // Special single-character parameters
                b'?' | b'$' | b'!' | b'#' | b'@' | b'*' => {
                    let param = &word[i..i + 1];
                    i += 1;
                    if let Some(val) = env.lookup_param(param) {
                        out.push_str(&val);
                    }
                    // If unset (unlikely for specials), expand to empty.
                }
                c if c.is_ascii_digit() => {
                    // $0..$9 positional parameters.
                    let param = &word[i..i + 1];
                    i += 1;
                    if let Some(val) = env.lookup_param(param) {
                        out.push_str(&val);
                    }
                }
                c if c.is_ascii_alphabetic() || c == b'_' => {
                    // Unbraced variable name: scan identifier chars.
                    let start = i;
                    while i < bytes.len()
                        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
                    {
                        i += 1;
                    }
                    let name = &word[start..i];
                    if let Some(val) = env.lookup_param(name) {
                        out.push_str(&val);
                    }
                }
                _ => {
                    // Unrecognized char after $ — treat $ as literal.
                    out.push('$');
                    // Don't advance i — re-process this char.
                }
            }
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }

    Ok(out)
}

/// Expand the contents of a `${...}` expression.
///
/// `inner` is the text between `{` and `}`, e.g. for `${VAR:-default}`
/// inner is `VAR:-default`.
fn expand_braced(inner: &str, env: &mut Environment) -> Result<String, ExpandError> {
    if inner.is_empty() {
        return Err(ExpandError::BadSubstitution("empty parameter".to_string()));
    }

    // Check for special single-char params at position 0 with an
    // operator following: e.g. ${?}, ${#}, ${?:-x}
    // Parse the variable name and any operator.
    let (name, rest) = parse_braced_name(inner)?;

    if rest.is_empty() {
        // Simple ${VAR} with no operator.
        Ok(env.lookup_param(name).unwrap_or_default())
    } else {
        expand_braced_op(name, rest, env)
    }
}

/// Parse the variable name from braced expansion content.
///
/// Returns `(name, rest)` where `rest` starts at the operator
/// (e.g. `:-default`).
fn parse_braced_name(inner: &str) -> Result<(&str, &str), ExpandError> {
    let bytes = inner.as_bytes();

    // Special single-char parameters: ?, $, !, #, @, *, 0-9
    match bytes[0] {
        b'?' | b'$' | b'!' | b'@' | b'*' => {
            return Ok((&inner[..1], &inner[1..]));
        }
        b'#' => {
            // Tricky: `${#VAR}` is string length (not implemented yet),
            // but `${#}` is param count, and `${#:-x}` uses `#` as
            // the parameter.
            if inner.len() == 1 {
                return Ok((&inner[..1], ""));
            }
            // If the char after `#` is an operator char, treat `#` as
            // the parameter name.
            if inner.len() > 1 {
                let next = bytes[1];
                if next == b':' || next == b'-' || next == b'=' || next == b'?' || next == b'+' || next == b'}' {
                    return Ok((&inner[..1], &inner[1..]));
                }
            }
            // Otherwise it's `${#VAR}` (string length) — not yet
            // implemented, treat as the variable named after `#`.
            // For now, just use the rest as a variable name.
            let name_start = 1;
            let mut i = name_start;
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_')
            {
                i += 1;
            }
            // Not yet implemented: ${#VAR} length expansion.
            return Err(ExpandError::BadSubstitution(format!(
                "${{{inner}}} (string length not yet implemented)"
            )));
        }
        c if c.is_ascii_digit() => {
            return Ok((&inner[..1], &inner[1..]));
        }
        _ => {}
    }

    // Named variable: scan identifier characters.
    if !(bytes[0].is_ascii_alphabetic() || bytes[0] == b'_') {
        return Err(ExpandError::BadSubstitution(format!(
            "bad parameter name: {inner}"
        )));
    }
    let mut i = 0;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    Ok((&inner[..i], &inner[i..]))
}

/// Handle braced expansion with an operator (the part after the variable
/// name).
///
/// `op_and_word` is e.g. `:-default`, `:=val`, `:?err`, `:+alt`, or
/// the colon-less variants `-default`, `=val`, `?err`, `+alt`.
fn expand_braced_op(
    name: &str,
    op_and_word: &str,
    env: &mut Environment,
) -> Result<String, ExpandError> {
    let bytes = op_and_word.as_bytes();
    let (colon, op_byte, default_word) = if bytes[0] == b':' {
        if bytes.len() < 2 {
            return Err(ExpandError::BadSubstitution(format!(
                "incomplete operator in ${{{name}{op_and_word}}}"
            )));
        }
        (true, bytes[1], &op_and_word[2..])
    } else {
        (false, bytes[0], &op_and_word[1..])
    };

    // Look up the current value.
    let current = env.lookup_param(name);
    let is_unset = current.is_none();
    let is_null = current.as_ref().map_or(true, |v| v.is_empty());

    // With colon: test unset-or-null. Without colon: test only unset.
    let condition = if colon { is_null } else { is_unset };

    match op_byte {
        b'-' => {
            // ${VAR:-default} / ${VAR-default}
            if condition {
                // Recursively expand the default word.
                expand_word(default_word, env)
            } else {
                Ok(current.unwrap_or_default())
            }
        }
        b'=' => {
            // ${VAR:=default} / ${VAR=default}
            if condition {
                let expanded = expand_word(default_word, env)?;
                env.set(name, &expanded, None);
                Ok(expanded)
            } else {
                Ok(current.unwrap_or_default())
            }
        }
        b'?' => {
            // ${VAR:?message} / ${VAR?message}
            if condition {
                let msg = if default_word.is_empty() {
                    "parameter not set".to_string()
                } else {
                    expand_word(default_word, env)?
                };
                Err(ExpandError::UnsetVariable {
                    name: name.to_string(),
                    message: msg,
                })
            } else {
                Ok(current.unwrap_or_default())
            }
        }
        b'+' => {
            // ${VAR:+alt} / ${VAR+alt}
            if condition {
                Ok(String::new())
            } else {
                expand_word(default_word, env)
            }
        }
        _ => Err(ExpandError::BadSubstitution(format!(
            "unknown operator in ${{{name}{op_and_word}}}"
        ))),
    }
}

// ── Field splitting ───────────────────────────────────────────────

/// Default IFS value: space, tab, newline.
pub const DEFAULT_IFS: &str = " \t\n";

/// Split an expanded word on IFS characters.
///
/// Per POSIX §2.6.5:
/// - IFS whitespace (space, tab, newline that appear in IFS) at the
///   beginning and end is trimmed.
/// - Sequences of IFS whitespace act as a single delimiter.
/// - Non-whitespace IFS characters each delimit a field (possibly
///   empty), and adjacent IFS whitespace is consumed with them.
///
/// If `ifs` is `None`, the default IFS is used. If `ifs` is
/// `Some("")`, no splitting occurs (the whole string is one field).
pub fn field_split(expanded: &str, ifs: Option<&str>) -> Vec<String> {
    let ifs = match ifs {
        Some(s) => s,
        None => DEFAULT_IFS,
    };

    // Empty IFS: no splitting.
    if ifs.is_empty() {
        return if expanded.is_empty() {
            vec![]
        } else {
            vec![expanded.to_string()]
        };
    }

    // Classify IFS characters.
    let is_ifs_ws = |c: char| -> bool {
        (c == ' ' || c == '\t' || c == '\n') && ifs.contains(c)
    };
    let is_ifs_nonws = |c: char| -> bool { ifs.contains(c) && !is_ifs_ws(c) };


    let chars: Vec<char> = expanded.chars().collect();
    let len = chars.len();
    let mut fields: Vec<String> = Vec::new();
    let mut i = 0;

    // Skip leading IFS whitespace.
    while i < len && is_ifs_ws(chars[i]) {
        i += 1;
    }

    if i >= len {
        return fields;
    }

    let mut current = String::new();

    while i < len {
        if is_ifs_nonws(chars[i]) {
            // Non-whitespace IFS delimiter: end current field.
            fields.push(std::mem::take(&mut current));
            i += 1;
            // Skip trailing IFS whitespace after non-ws delimiter.
            while i < len && is_ifs_ws(chars[i]) {
                i += 1;
            }
        } else if is_ifs_ws(chars[i]) {
            // IFS whitespace run: skip all adjacent whitespace.
            while i < len && is_ifs_ws(chars[i]) {
                i += 1;
            }
            // Per POSIX: if a non-whitespace IFS delimiter immediately
            // follows, the whitespace is part of that delimiter — let
            // the next iteration handle the field break.
            if i < len && is_ifs_nonws(chars[i]) {
                // The non-ws delimiter will push the field break.
                continue;
            }
            // Otherwise the whitespace run itself is the delimiter.
            // Only push a field break if there's more input (trailing
            // IFS whitespace is trimmed).
            if i < len {
                fields.push(std::mem::take(&mut current));
            }
        } else {
            current.push(chars[i]);
            i += 1;
        }
    }

    // Push the last field if non-empty.
    if !current.is_empty() {
        fields.push(current);
    }

    fields
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Environment {
        Environment::new()
    }

    // ── Environment basics ────────────────────────────────────────

    #[test]
    fn env_set_get() {
        let mut e = env();
        e.set("FOO", "bar", None);
        assert_eq!(e.get("FOO"), Some("bar"));
    }

    #[test]
    fn env_unset() {
        let mut e = env();
        e.set("FOO", "bar", None);
        e.unset("FOO");
        assert_eq!(e.get("FOO"), None);
    }

    #[test]
    fn env_export() {
        let mut e = env();
        e.set("FOO", "bar", None);
        e.export("FOO");
        assert!(e.vars.get("FOO").unwrap().exported);
    }

    #[test]
    fn env_export_unset_creates() {
        let mut e = env();
        e.export("MISSING");
        assert_eq!(e.get("MISSING"), Some(""));
        assert!(e.vars.get("MISSING").unwrap().exported);
    }

    #[test]
    fn env_exported_vars() {
        let mut e = env();
        e.set("A", "1", Some(true));
        e.set("B", "2", Some(false));
        e.set("C", "3", Some(true));
        let exported = e.exported_vars();
        assert_eq!(exported.len(), 2);
        assert!(exported.contains(&("A", "1")));
        assert!(exported.contains(&("C", "3")));
    }

    #[test]
    fn env_set_preserves_export() {
        let mut e = env();
        e.set("FOO", "1", Some(true));
        e.set("FOO", "2", None); // Should preserve exported=true
        assert!(e.vars.get("FOO").unwrap().exported);
        assert_eq!(e.get("FOO"), Some("2"));
    }

    // ── Simple $VAR expansion ─────────────────────────────────────

    #[test]
    fn expand_unbraced_var() {
        let mut e = env();
        e.set("HOME", "/usr/home", None);
        assert_eq!(expand_word("$HOME", &mut e).unwrap(), "/usr/home");
    }

    #[test]
    fn expand_braced_var() {
        let mut e = env();
        e.set("HOME", "/usr/home", None);
        assert_eq!(expand_word("${HOME}", &mut e).unwrap(), "/usr/home");
    }

    #[test]
    fn expand_unset_var_empty() {
        let mut e = env();
        assert_eq!(expand_word("$UNSET", &mut e).unwrap(), "");
    }

    #[test]
    fn expand_braced_unset_empty() {
        let mut e = env();
        assert_eq!(expand_word("${UNSET}", &mut e).unwrap(), "");
    }

    #[test]
    fn expand_var_embedded_in_text() {
        let mut e = env();
        e.set("NAME", "world", None);
        assert_eq!(
            expand_word("hello $NAME!", &mut e).unwrap(),
            "hello world!"
        );
    }

    #[test]
    fn expand_braced_adjacent_text() {
        let mut e = env();
        e.set("X", "foo", None);
        assert_eq!(expand_word("${X}bar", &mut e).unwrap(), "foobar");
    }

    #[test]
    fn expand_multiple_vars() {
        let mut e = env();
        e.set("A", "hello", None);
        e.set("B", "world", None);
        assert_eq!(expand_word("$A $B", &mut e).unwrap(), "hello world");
    }

    #[test]
    fn expand_bare_dollar_at_end() {
        let mut e = env();
        assert_eq!(expand_word("cost$", &mut e).unwrap(), "cost$");
    }

    #[test]
    fn expand_dollar_non_identifier() {
        let mut e = env();
        assert_eq!(expand_word("$=x", &mut e).unwrap(), "$=x");
    }

    // ── Special parameters ────────────────────────────────────────

    #[test]
    fn expand_exit_status() {
        let mut e = env();
        e.last_status = 42;
        assert_eq!(expand_word("$?", &mut e).unwrap(), "42");
    }

    #[test]
    fn expand_shell_pid() {
        let mut e = env();
        e.shell_pid = 1234;
        assert_eq!(expand_word("$$", &mut e).unwrap(), "1234");
    }

    #[test]
    fn expand_bg_pid() {
        let mut e = env();
        e.last_bg_pid = 5678;
        assert_eq!(expand_word("$!", &mut e).unwrap(), "5678");
    }

    #[test]
    fn expand_param_count() {
        let mut e = env();
        e.positional = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(expand_word("$#", &mut e).unwrap(), "3");
    }

    #[test]
    fn expand_arg0() {
        let mut e = env();
        e.arg0 = "/bin/sh".to_string();
        assert_eq!(expand_word("$0", &mut e).unwrap(), "/bin/sh");
    }

    #[test]
    fn expand_positional_params() {
        let mut e = env();
        e.positional = vec!["alpha".into(), "beta".into(), "gamma".into()];
        assert_eq!(expand_word("$1", &mut e).unwrap(), "alpha");
        assert_eq!(expand_word("$2", &mut e).unwrap(), "beta");
        assert_eq!(expand_word("$3", &mut e).unwrap(), "gamma");
        assert_eq!(expand_word("$4", &mut e).unwrap(), ""); // unset
    }

    #[test]
    fn expand_at_star() {
        let mut e = env();
        e.positional = vec!["a".into(), "b".into(), "c".into()];
        assert_eq!(expand_word("$@", &mut e).unwrap(), "a b c");
        assert_eq!(expand_word("$*", &mut e).unwrap(), "a b c");
    }

    #[test]
    fn expand_at_star_empty() {
        let mut e = env();
        assert_eq!(expand_word("$@", &mut e).unwrap(), "");
        assert_eq!(expand_word("$*", &mut e).unwrap(), "");
    }

    // ── Special params in braces ──────────────────────────────────

    #[test]
    fn expand_braced_question() {
        let mut e = env();
        e.last_status = 1;
        assert_eq!(expand_word("${?}", &mut e).unwrap(), "1");
    }

    #[test]
    fn expand_braced_hash() {
        let mut e = env();
        e.positional = vec!["x".into()];
        assert_eq!(expand_word("${#}", &mut e).unwrap(), "1");
    }

    #[test]
    fn expand_braced_dollar() {
        let mut e = env();
        e.shell_pid = 99;
        assert_eq!(expand_word("${$}", &mut e).unwrap(), "99");
    }

    #[test]
    fn expand_braced_bang() {
        let mut e = env();
        e.last_bg_pid = 77;
        assert_eq!(expand_word("${!}", &mut e).unwrap(), "77");
    }

    #[test]
    fn expand_braced_at() {
        let mut e = env();
        e.positional = vec!["x".into(), "y".into()];
        assert_eq!(expand_word("${@}", &mut e).unwrap(), "x y");
    }

    #[test]
    fn expand_braced_star() {
        let mut e = env();
        e.positional = vec!["x".into(), "y".into()];
        assert_eq!(expand_word("${*}", &mut e).unwrap(), "x y");
    }

    #[test]
    fn expand_braced_positional() {
        let mut e = env();
        e.positional = vec!["first".into()];
        assert_eq!(expand_word("${1}", &mut e).unwrap(), "first");
    }

    // ── ${VAR:-default} ───────────────────────────────────────────

    #[test]
    fn default_colon_dash_unset() {
        let mut e = env();
        assert_eq!(expand_word("${X:-fallback}", &mut e).unwrap(), "fallback");
    }

    #[test]
    fn default_colon_dash_empty() {
        let mut e = env();
        e.set("X", "", None);
        assert_eq!(expand_word("${X:-fallback}", &mut e).unwrap(), "fallback");
    }

    #[test]
    fn default_colon_dash_set() {
        let mut e = env();
        e.set("X", "val", None);
        assert_eq!(expand_word("${X:-fallback}", &mut e).unwrap(), "val");
    }

    #[test]
    fn default_dash_unset() {
        let mut e = env();
        assert_eq!(expand_word("${X-fallback}", &mut e).unwrap(), "fallback");
    }

    #[test]
    fn default_dash_empty() {
        // Without colon, empty is considered "set".
        let mut e = env();
        e.set("X", "", None);
        assert_eq!(expand_word("${X-fallback}", &mut e).unwrap(), "");
    }

    #[test]
    fn default_dash_set() {
        let mut e = env();
        e.set("X", "val", None);
        assert_eq!(expand_word("${X-fallback}", &mut e).unwrap(), "val");
    }

    // ── ${VAR:=default} ───────────────────────────────────────────

    #[test]
    fn assign_colon_eq_unset() {
        let mut e = env();
        assert_eq!(expand_word("${X:=default}", &mut e).unwrap(), "default");
        assert_eq!(e.get("X"), Some("default"));
    }

    #[test]
    fn assign_colon_eq_empty() {
        let mut e = env();
        e.set("X", "", None);
        assert_eq!(expand_word("${X:=default}", &mut e).unwrap(), "default");
        assert_eq!(e.get("X"), Some("default"));
    }

    #[test]
    fn assign_colon_eq_set() {
        let mut e = env();
        e.set("X", "existing", None);
        assert_eq!(expand_word("${X:=default}", &mut e).unwrap(), "existing");
        assert_eq!(e.get("X"), Some("existing"));
    }

    #[test]
    fn assign_eq_empty_no_colon() {
        let mut e = env();
        e.set("X", "", None);
        // Without colon, empty counts as set — so no assignment.
        assert_eq!(expand_word("${X=default}", &mut e).unwrap(), "");
        assert_eq!(e.get("X"), Some(""));
    }

    // ── ${VAR:?error} ─────────────────────────────────────────────

    #[test]
    fn error_colon_question_unset() {
        let mut e = env();
        let err = expand_word("${X:?not set}", &mut e).unwrap_err();
        assert_eq!(
            err,
            ExpandError::UnsetVariable {
                name: "X".to_string(),
                message: "not set".to_string()
            }
        );
    }

    #[test]
    fn error_colon_question_empty() {
        let mut e = env();
        e.set("X", "", None);
        let err = expand_word("${X:?empty}", &mut e).unwrap_err();
        assert_eq!(
            err,
            ExpandError::UnsetVariable {
                name: "X".to_string(),
                message: "empty".to_string()
            }
        );
    }

    #[test]
    fn error_colon_question_set() {
        let mut e = env();
        e.set("X", "ok", None);
        assert_eq!(expand_word("${X:?boom}", &mut e).unwrap(), "ok");
    }

    #[test]
    fn error_question_empty_no_colon() {
        let mut e = env();
        e.set("X", "", None);
        // Without colon, empty is set — no error.
        assert_eq!(expand_word("${X?boom}", &mut e).unwrap(), "");
    }

    #[test]
    fn error_question_default_message() {
        let mut e = env();
        let err = expand_word("${X:?}", &mut e).unwrap_err();
        assert_eq!(
            err,
            ExpandError::UnsetVariable {
                name: "X".to_string(),
                message: "parameter not set".to_string()
            }
        );
    }

    // ── ${VAR:+alt} ───────────────────────────────────────────────

    #[test]
    fn alt_colon_plus_unset() {
        let mut e = env();
        assert_eq!(expand_word("${X:+alt}", &mut e).unwrap(), "");
    }

    #[test]
    fn alt_colon_plus_empty() {
        let mut e = env();
        e.set("X", "", None);
        assert_eq!(expand_word("${X:+alt}", &mut e).unwrap(), "");
    }

    #[test]
    fn alt_colon_plus_set() {
        let mut e = env();
        e.set("X", "val", None);
        assert_eq!(expand_word("${X:+alt}", &mut e).unwrap(), "alt");
    }

    #[test]
    fn alt_plus_empty_no_colon() {
        let mut e = env();
        e.set("X", "", None);
        // Without colon, empty is considered set — alt applies.
        assert_eq!(expand_word("${X+alt}", &mut e).unwrap(), "alt");
    }

    #[test]
    fn alt_plus_unset_no_colon() {
        let mut e = env();
        assert_eq!(expand_word("${X+alt}", &mut e).unwrap(), "");
    }

    // ── Recursive expansion in defaults ───────────────────────────

    #[test]
    fn nested_expansion_in_default() {
        let mut e = env();
        e.set("FALLBACK", "resolved", None);
        assert_eq!(
            expand_word("${X:-$FALLBACK}", &mut e).unwrap(),
            "resolved"
        );
    }

    // ── Field splitting ───────────────────────────────────────────

    #[test]
    fn field_split_default_ifs() {
        assert_eq!(
            field_split("hello world\tfoo\nbar", None),
            vec!["hello", "world", "foo", "bar"]
        );
    }

    #[test]
    fn field_split_leading_trailing_whitespace() {
        assert_eq!(
            field_split("  hello world  ", None),
            vec!["hello", "world"]
        );
    }

    #[test]
    fn field_split_multiple_spaces() {
        assert_eq!(
            field_split("a   b   c", None),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn field_split_empty_string() {
        let result: Vec<String> = vec![];
        assert_eq!(field_split("", None), result);
    }

    #[test]
    fn field_split_only_whitespace() {
        let result: Vec<String> = vec![];
        assert_eq!(field_split("   \t\n  ", None), result);
    }

    #[test]
    fn field_split_custom_ifs() {
        assert_eq!(
            field_split("a:b:c", Some(":")),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn field_split_non_ws_ifs_empty_fields() {
        // Non-whitespace IFS chars create empty fields between them.
        assert_eq!(
            field_split("a::b", Some(":")),
            vec!["a", "", "b"]
        );
    }

    #[test]
    fn field_split_mixed_ifs() {
        // IFS contains both whitespace and non-whitespace.
        assert_eq!(
            field_split("a : b : c", Some(": ")),
            vec!["a", "b", "c"]
        );
    }

    #[test]
    fn field_split_empty_ifs_no_splitting() {
        assert_eq!(
            field_split("hello world", Some("")),
            vec!["hello world"]
        );
    }

    #[test]
    fn field_split_single_word() {
        assert_eq!(field_split("hello", None), vec!["hello"]);
    }

    #[test]
    fn field_split_trailing_delimiter() {
        // Trailing non-ws IFS delimiter produces no trailing empty field
        // (POSIX says trailing IFS whitespace is trimmed, but non-ws
        // delimiters at the end do produce an empty field).
        assert_eq!(
            field_split("a:b:", Some(":")),
            vec!["a", "b"]
        );
    }

    #[test]
    fn field_split_leading_nonws_delimiter() {
        // Leading non-ws IFS char creates an empty first field.
        assert_eq!(
            field_split(":a:b", Some(":")),
            vec!["", "a", "b"]
        );
    }

    #[test]
    fn field_split_ifs_with_tab() {
        assert_eq!(
            field_split("one\ttwo\tthree", Some("\t")),
            vec!["one", "two", "three"]
        );
    }

    // ── Edge cases ────────────────────────────────────────────────

    #[test]
    fn expand_no_variables() {
        let mut e = env();
        assert_eq!(expand_word("hello world", &mut e).unwrap(), "hello world");
    }

    #[test]
    fn expand_underscore_var() {
        let mut e = env();
        e.set("_foo", "bar", None);
        assert_eq!(expand_word("$_foo", &mut e).unwrap(), "bar");
    }

    #[test]
    fn expand_var_with_digits() {
        let mut e = env();
        e.set("VAR123", "val", None);
        assert_eq!(expand_word("$VAR123", &mut e).unwrap(), "val");
    }

    #[test]
    fn expand_adjacent_dollar_vars() {
        let mut e = env();
        e.set("A", "x", None);
        e.set("B", "y", None);
        assert_eq!(expand_word("$A$B", &mut e).unwrap(), "xy");
    }

    #[test]
    fn expand_bad_substitution_empty() {
        let mut e = env();
        let err = expand_word("${}", &mut e).unwrap_err();
        match err {
            ExpandError::BadSubstitution(_) => {}
            other => panic!("expected BadSubstitution, got {other:?}"),
        }
    }

    #[test]
    fn expand_unterminated_brace() {
        let mut e = env();
        let err = expand_word("${FOO", &mut e).unwrap_err();
        match err {
            ExpandError::BadSubstitution(msg) => {
                assert!(msg.contains("unterminated"));
            }
            other => panic!("expected BadSubstitution, got {other:?}"),
        }
    }

    // ── Expansion with special params in operator forms ───────────

    #[test]
    fn special_param_with_default() {
        let mut e = env();
        e.last_status = 0;
        assert_eq!(expand_word("${?:-unknown}", &mut e).unwrap(), "0");
    }

    #[test]
    fn positional_param_with_default() {
        let mut e = env();
        // $1 unset
        assert_eq!(expand_word("${1:-none}", &mut e).unwrap(), "none");
    }

    #[test]
    fn positional_param_set_with_default() {
        let mut e = env();
        e.positional = vec!["val".into()];
        assert_eq!(expand_word("${1:-none}", &mut e).unwrap(), "val");
    }
}
