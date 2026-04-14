//! Pure-logic line editor with a bounded history ring.
//!
//! Owns the current input line, a ring of prior lines, and a cursor into
//! that ring for up/down traversal. The caller feeds `Input` events and
//! drains `Effect`s the shell emits to its output (serial). No I/O or
//! kernel dependencies live here so the whole thing is host-testable.
//!
//! History semantics match a subset of GNU readline:
//! - Up arrow walks backwards through history, replacing the current
//!   line. The in-progress line (if any) is stashed on first up-arrow
//!   and restored when the user presses down-arrow past the newest
//!   history entry.
//! - Enter commits the trimmed-nonempty line to history, resets the
//!   history cursor to "not browsing", and clears the stash.
//! - Ctrl+C clears the current line without committing and resets the
//!   cursor.
//! - Ctrl+L asks the caller to clear the screen; the editor itself is
//!   unchanged.

use alloc::string::String;
use alloc::vec::Vec;

/// Capacity of the history ring. 32 matches the minimal-shell issue's
/// explicit suggestion; each slot holds at most `MAX_LINE_LEN` bytes
/// (256), so worst-case ~8 KiB — fine against a 16 MiB heap.
pub const HISTORY_CAP: usize = 32;

/// Same cap the caller uses when dropping over-long input. Re-exposed
/// here so the editor can refuse to push over-length strings into
/// history even if a future caller forgets the check.
pub const MAX_LINE_LEN: usize = 256;

/// An event fed to [`LineEditor::on_input`]. Callers translate raw
/// input sources (serial bytes + ANSI escape state machine, PS/2
/// decoded keys) into these before passing them in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Input {
    /// A printable character (non-control).
    Char(char),
    /// Backspace / DEL.
    Backspace,
    /// Enter / return.
    Enter,
    /// Ctrl+C — cancel current line.
    Interrupt,
    /// Ctrl+L — clear screen.
    ClearScreen,
    /// Up arrow.
    HistoryPrev,
    /// Down arrow.
    HistoryNext,
}

/// Side effect the caller must emit. Kept as a simple enum instead of a
/// direct serial writer so tests can assert on the sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Effect {
    /// Emit a single printable character.
    Put(char),
    /// Erase the last character on the terminal (backspace-space-backspace).
    EraseChar,
    /// Caller should dispatch `line` as a command, then emit a fresh prompt.
    Dispatch(String),
    /// Emit CRLF and a fresh prompt (e.g. after Ctrl+C).
    Newline,
    /// VT100 clear screen + cursor home, then redraw prompt + `line` so
    /// the user sees any in-progress input they hadn't yet submitted.
    ClearScreen { line: String },
    /// Erase the entire current input line on the terminal (N backspace-space-backspaces)
    /// then rewrite `new` in its place. Used after history navigation.
    Replace { old_len: usize, new: String },
}

pub struct LineEditor {
    line: String,
    history: Vec<String>,
    /// `None` when not browsing. Otherwise an index into `history`
    /// counted from the *oldest* end (0 = oldest), same layout as the
    /// Vec itself. We push newest-to-back, so "previous" = decrementing
    /// the index toward `history.len() - 1` downwards from len.
    cursor: Option<usize>,
    /// The line the user was composing when they first pressed up.
    /// Restored when they walk back past the newest history entry.
    stash: Option<String>,
}

impl LineEditor {
    pub fn new() -> Self {
        Self {
            line: String::new(),
            history: Vec::new(),
            cursor: None,
            stash: None,
        }
    }

    pub fn line(&self) -> &str {
        &self.line
    }

    #[cfg(test)]
    pub fn history(&self) -> &[String] {
        &self.history
    }

    pub fn on_input(&mut self, ev: Input) -> Vec<Effect> {
        match ev {
            Input::Char(c) if !c.is_control() => self.insert_char(c),
            Input::Char(_) => Vec::new(),
            Input::Backspace => self.backspace(),
            Input::Enter => self.enter(),
            Input::Interrupt => self.interrupt(),
            Input::ClearScreen => alloc::vec![Effect::ClearScreen {
                line: self.line.clone(),
            }],
            Input::HistoryPrev => self.history_prev(),
            Input::HistoryNext => self.history_next(),
        }
    }

    fn insert_char(&mut self, c: char) -> Vec<Effect> {
        if self.line.len() + c.len_utf8() > MAX_LINE_LEN {
            return Vec::new();
        }
        self.line.push(c);
        alloc::vec![Effect::Put(c)]
    }

    fn backspace(&mut self) -> Vec<Effect> {
        if self.line.pop().is_some() {
            alloc::vec![Effect::EraseChar]
        } else {
            Vec::new()
        }
    }

    fn enter(&mut self) -> Vec<Effect> {
        let committed = core::mem::take(&mut self.line);
        self.cursor = None;
        self.stash = None;
        let trimmed = committed.trim_start();
        if !trimmed.is_empty() && trimmed.len() <= MAX_LINE_LEN {
            // Dedupe: don't push a line identical to the most recent.
            if self.history.last().map(|s| s.as_str()) != Some(trimmed) {
                if self.history.len() == HISTORY_CAP {
                    self.history.remove(0);
                }
                self.history.push(String::from(trimmed));
            }
        }
        alloc::vec![Effect::Dispatch(committed)]
    }

    fn interrupt(&mut self) -> Vec<Effect> {
        self.line.clear();
        self.cursor = None;
        self.stash = None;
        alloc::vec![Effect::Newline]
    }

    fn history_prev(&mut self) -> Vec<Effect> {
        if self.history.is_empty() {
            return Vec::new();
        }
        let next_cursor = match self.cursor {
            None => {
                self.stash = Some(self.line.clone());
                self.history.len() - 1
            }
            Some(0) => return Vec::new(),
            Some(n) => n - 1,
        };
        self.cursor = Some(next_cursor);
        let old_len = self.line.len();
        let new = self.history[next_cursor].clone();
        self.line = new.clone();
        alloc::vec![Effect::Replace { old_len, new }]
    }

    fn history_next(&mut self) -> Vec<Effect> {
        let cursor = match self.cursor {
            None => return Vec::new(),
            Some(n) => n,
        };
        let old_len = self.line.len();
        if cursor + 1 >= self.history.len() {
            // Walk off the newest — restore stash.
            self.cursor = None;
            let new = self.stash.take().unwrap_or_default();
            self.line = new.clone();
            alloc::vec![Effect::Replace { old_len, new }]
        } else {
            self.cursor = Some(cursor + 1);
            let new = self.history[cursor + 1].clone();
            self.line = new.clone();
            alloc::vec![Effect::Replace { old_len, new }]
        }
    }
}

impl Default for LineEditor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    fn feed_line(ed: &mut LineEditor, s: &str) {
        for c in s.chars() {
            ed.on_input(Input::Char(c));
        }
        ed.on_input(Input::Enter);
    }

    #[test]
    fn char_and_backspace_round_trip() {
        let mut ed = LineEditor::new();
        ed.on_input(Input::Char('h'));
        ed.on_input(Input::Char('i'));
        assert_eq!(ed.line(), "hi");
        let effs = ed.on_input(Input::Backspace);
        assert_eq!(effs, alloc::vec![Effect::EraseChar]);
        assert_eq!(ed.line(), "h");
    }

    #[test]
    fn enter_commits_nonempty_to_history() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "uptime");
        feed_line(&mut ed, "help");
        assert_eq!(ed.history(), &["uptime".to_string(), "help".to_string()]);
        assert_eq!(ed.line(), "");
    }

    #[test]
    fn enter_skips_empty_and_dedupes_consecutive_duplicates() {
        let mut ed = LineEditor::new();
        ed.on_input(Input::Enter);
        feed_line(&mut ed, "help");
        feed_line(&mut ed, "help");
        feed_line(&mut ed, "   ");
        assert_eq!(ed.history(), &["help".to_string()]);
    }

    #[test]
    fn up_arrow_walks_history_backwards() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "one");
        feed_line(&mut ed, "two");
        feed_line(&mut ed, "three");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "three");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "two");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "one");
        // Past oldest is a no-op.
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "one");
    }

    #[test]
    fn down_arrow_restores_stash_past_newest() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "one");
        feed_line(&mut ed, "two");
        ed.on_input(Input::Char('p'));
        ed.on_input(Input::Char('a'));
        ed.on_input(Input::Char('r'));
        ed.on_input(Input::Char('t'));
        assert_eq!(ed.line(), "part");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "two");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "one");
        ed.on_input(Input::HistoryNext);
        assert_eq!(ed.line(), "two");
        ed.on_input(Input::HistoryNext);
        // Walked off newest — stash "part" restored.
        assert_eq!(ed.line(), "part");
        // Further down-arrow is a no-op.
        ed.on_input(Input::HistoryNext);
        assert_eq!(ed.line(), "part");
    }

    #[test]
    fn down_arrow_with_no_history_cursor_is_noop() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "one");
        ed.on_input(Input::Char('x'));
        let effs = ed.on_input(Input::HistoryNext);
        assert!(effs.is_empty());
        assert_eq!(ed.line(), "x");
    }

    #[test]
    fn ctrl_c_clears_line_and_resets_cursor() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "one");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "one");
        let effs = ed.on_input(Input::Interrupt);
        assert_eq!(effs, alloc::vec![Effect::Newline]);
        assert_eq!(ed.line(), "");
        // After Ctrl+C, a fresh up-arrow should stash the (empty) line.
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "one");
        ed.on_input(Input::HistoryNext);
        assert_eq!(ed.line(), "");
    }

    #[test]
    fn ctrl_l_emits_clear_effect_with_current_line() {
        let mut ed = LineEditor::new();
        ed.on_input(Input::Char('x'));
        let effs = ed.on_input(Input::ClearScreen);
        assert_eq!(
            effs,
            alloc::vec![Effect::ClearScreen {
                line: "x".to_string(),
            }]
        );
        // Line content preserved so subsequent chars append normally.
        assert_eq!(ed.line(), "x");
    }

    #[test]
    fn history_ring_wraps_at_capacity() {
        let mut ed = LineEditor::new();
        for i in 0..(HISTORY_CAP + 5) {
            feed_line(&mut ed, &alloc::format!("cmd{}", i));
        }
        assert_eq!(ed.history().len(), HISTORY_CAP);
        // Oldest surviving entry is cmd5.
        assert_eq!(ed.history().first().unwrap(), "cmd5");
        assert_eq!(
            ed.history().last().unwrap(),
            &alloc::format!("cmd{}", HISTORY_CAP + 4)
        );
    }

    #[test]
    fn enter_clears_history_cursor() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "one");
        feed_line(&mut ed, "two");
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "two");
        ed.on_input(Input::Enter);
        // Next up-arrow should now re-stash (empty) and start from newest.
        ed.on_input(Input::HistoryPrev);
        assert_eq!(ed.line(), "two");
    }

    #[test]
    fn replace_effect_carries_old_len() {
        let mut ed = LineEditor::new();
        feed_line(&mut ed, "hello");
        ed.on_input(Input::Char('a'));
        ed.on_input(Input::Char('b'));
        let effs = ed.on_input(Input::HistoryPrev);
        assert_eq!(
            effs,
            alloc::vec![Effect::Replace {
                old_len: 2,
                new: "hello".to_string(),
            }]
        );
    }

    #[test]
    fn control_chars_via_char_are_ignored() {
        let mut ed = LineEditor::new();
        let effs = ed.on_input(Input::Char('\x07'));
        assert!(effs.is_empty());
        assert_eq!(ed.line(), "");
    }
}
