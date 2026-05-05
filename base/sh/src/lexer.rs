//! POSIX shell lexer/tokenizer.
//!
//! Implements token recognition per POSIX.1-2024 section 2.3. The lexer
//! converts raw input bytes into a stream of [`Token`] values that a
//! parser can consume.
//!
//! ## Supported tokens
//!
//! - **Words**: unquoted, single-quoted, double-quoted, and
//!   backslash-escaped character sequences.
//! - **Operators**: `|`, `||`, `&`, `&&`, `;`, `(`, `)`, `<`, `>`,
//!   `>>`, `<<`, `>&`, `<&`, `<>`.
//! - **Newline**: preserved as a distinct token (significant in shell
//!   grammar).
//! - **EOF**: signals end of input.
//!
//! ## Quoting
//!
//! - **Single quotes** preserve everything literally until the closing
//!   `'`. A single quote cannot appear inside single quotes.
//! - **Double quotes** preserve most characters literally but recognize
//!   `$`, `` ` ``, `\`, `!`, and `"` as special (per POSIX). Within
//!   double quotes, backslash escapes only the characters `$`, `` ` ``,
//!   `"`, `\`, and newline.
//! - **Backslash** outside quotes escapes the immediately following
//!   character (including newline, which is a line continuation).

use std::fmt;

// ── Token type ──────────────────────────────────────────────────────

/// A single lexical token produced by the shell lexer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
    /// A shell word (may include quoted segments merged together).
    Word(String),
    /// `|`
    Pipe,
    /// `||`
    Or,
    /// `&`
    Ampersand,
    /// `&&`
    And,
    /// `;`
    Semi,
    /// `(`
    LParen,
    /// `)`
    RParen,
    /// `<`
    Less,
    /// `>`
    Great,
    /// `>>`
    DGreat,
    /// `<<`
    DLess,
    /// `>&`
    GreatAnd,
    /// `<&`
    LessAnd,
    /// `<>`
    LessGreat,
    /// A newline character (syntactically significant in shell grammar).
    Newline,
    /// End of input.
    Eof,
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Token::Word(w) => write!(f, "Word({w:?})"),
            Token::Pipe => write!(f, "Pipe"),
            Token::Or => write!(f, "Or"),
            Token::Ampersand => write!(f, "Ampersand"),
            Token::And => write!(f, "And"),
            Token::Semi => write!(f, "Semi"),
            Token::LParen => write!(f, "LParen"),
            Token::RParen => write!(f, "RParen"),
            Token::Less => write!(f, "Less"),
            Token::Great => write!(f, "Great"),
            Token::DGreat => write!(f, "DGreat"),
            Token::DLess => write!(f, "DLess"),
            Token::GreatAnd => write!(f, "GreatAnd"),
            Token::LessAnd => write!(f, "LessAnd"),
            Token::LessGreat => write!(f, "LessGreat"),
            Token::Newline => write!(f, "Newline"),
            Token::Eof => write!(f, "Eof"),
        }
    }
}

// ── Lexer errors ────────────────────────────────────────────────────

/// An error encountered during lexical analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexError {
    /// Unterminated single-quoted string.
    UnterminatedSingleQuote,
    /// Unterminated double-quoted string.
    UnterminatedDoubleQuote,
    /// Backslash at end of input (not followed by newline for continuation).
    TrailingBackslash,
}

impl fmt::Display for LexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LexError::UnterminatedSingleQuote => write!(f, "unterminated single quote"),
            LexError::UnterminatedDoubleQuote => write!(f, "unterminated double quote"),
            LexError::TrailingBackslash => write!(f, "trailing backslash"),
        }
    }
}

// ── Lexer ───────────────────────────────────────────────────────────

/// Shell lexer that tokenizes input one token at a time.
///
/// Create a `Lexer` with [`Lexer::new`] and call [`Lexer::next_token`]
/// repeatedly until [`Token::Eof`] is returned.
pub struct Lexer<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Lexer<'a> {
    /// Create a new lexer over the given input.
    pub fn new(input: &'a str) -> Self {
        Self {
            input: input.as_bytes(),
            pos: 0,
        }
    }

    /// Return the next token, or an error if the input is malformed.
    pub fn next_token(&mut self) -> Result<Token, LexError> {
        self.skip_blanks();

        match self.peek() {
            None => Ok(Token::Eof),
            Some(b'\n') => {
                self.advance();
                Ok(Token::Newline)
            }
            Some(b'#') => {
                self.skip_comment();
                self.next_token()
            }
            Some(c) if is_operator_start(c) => self.lex_operator(),
            _ => self.lex_word(),
        }
    }

    /// Tokenize the entire input into a vector of tokens.
    ///
    /// Stops at [`Token::Eof`] (which is included in the result).
    pub fn tokenize_all(&mut self) -> Result<Vec<Token>, LexError> {
        let mut tokens = Vec::new();
        loop {
            let tok = self.next_token()?;
            let is_eof = tok == Token::Eof;
            tokens.push(tok);
            if is_eof {
                break;
            }
        }
        Ok(tokens)
    }

    // ── helpers ─────────────────────────────────────────────────────

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn advance(&mut self) -> Option<u8> {
        let c = self.input.get(self.pos).copied();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_blanks(&mut self) {
        while let Some(c) = self.peek() {
            if c == b' ' || c == b'\t' {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn skip_comment(&mut self) {
        // A comment starts with '#' and extends to (but not including) the
        // next newline or EOF.
        while let Some(c) = self.peek() {
            if c == b'\n' {
                break;
            }
            self.advance();
        }
    }

    /// Lex an operator token. The current byte is known to be an operator
    /// start character.
    fn lex_operator(&mut self) -> Result<Token, LexError> {
        let c = self.advance().unwrap();
        match c {
            b'|' => {
                if self.peek() == Some(b'|') {
                    self.advance();
                    Ok(Token::Or)
                } else {
                    Ok(Token::Pipe)
                }
            }
            b'&' => {
                if self.peek() == Some(b'&') {
                    self.advance();
                    Ok(Token::And)
                } else {
                    Ok(Token::Ampersand)
                }
            }
            b';' => Ok(Token::Semi),
            b'(' => Ok(Token::LParen),
            b')' => Ok(Token::RParen),
            b'<' => match self.peek() {
                Some(b'<') => {
                    self.advance();
                    Ok(Token::DLess)
                }
                Some(b'&') => {
                    self.advance();
                    Ok(Token::LessAnd)
                }
                Some(b'>') => {
                    self.advance();
                    Ok(Token::LessGreat)
                }
                _ => Ok(Token::Less),
            },
            b'>' => match self.peek() {
                Some(b'>') => {
                    self.advance();
                    Ok(Token::DGreat)
                }
                Some(b'&') => {
                    self.advance();
                    Ok(Token::GreatAnd)
                }
                _ => Ok(Token::Great),
            },
            _ => unreachable!("lex_operator called on non-operator byte"),
        }
    }

    /// Lex a word token. Words are built from unquoted characters, single-
    /// quoted strings, double-quoted strings, and backslash escapes that
    /// are all concatenated together.
    fn lex_word(&mut self) -> Result<Token, LexError> {
        let mut word = String::new();
        loop {
            match self.peek() {
                None | Some(b'\n') => break,
                Some(b' ') | Some(b'\t') => break,
                Some(c) if is_operator_start(c) => break,
                Some(b'#') if word.is_empty() => {
                    // A '#' at word start is a comment (handled in
                    // next_token), but mid-word it is literal.
                    unreachable!("comment should be handled before lex_word");
                }
                Some(b'#') => {
                    // '#' in the middle of a word is literal.
                    self.advance();
                    word.push('#');
                }
                Some(b'\'') => self.lex_single_quote(&mut word)?,
                Some(b'"') => self.lex_double_quote(&mut word)?,
                Some(b'\\') => self.lex_backslash_unquoted(&mut word)?,
                Some(c) => {
                    self.advance();
                    word.push(c as char);
                }
            }
        }
        // A backslash-newline (line continuation) at the start of a word
        // leaves the buffer empty. In that case, re-enter the main
        // tokenizer loop rather than producing a spurious empty Word.
        if word.is_empty() {
            return self.next_token();
        }
        Ok(Token::Word(word))
    }

    /// Consume a single-quoted string (opening `'` already peeked but
    /// not consumed). Everything between the quotes is literal.
    fn lex_single_quote(&mut self, word: &mut String) -> Result<(), LexError> {
        self.advance(); // consume opening '
        loop {
            match self.advance() {
                Some(b'\'') => return Ok(()),
                Some(c) => word.push(c as char),
                None => return Err(LexError::UnterminatedSingleQuote),
            }
        }
    }

    /// Consume a double-quoted string. Within double quotes, `$`, `` ` ``,
    /// and `\` retain special meaning per POSIX. Backslash only escapes
    /// `$`, `` ` ``, `"`, `\`, and newline inside double quotes.
    fn lex_double_quote(&mut self, word: &mut String) -> Result<(), LexError> {
        self.advance(); // consume opening "
        loop {
            match self.advance() {
                Some(b'"') => return Ok(()),
                Some(b'\\') => {
                    match self.peek() {
                        Some(b'$') | Some(b'`') | Some(b'"') | Some(b'\\') => {
                            let c = self.advance().unwrap();
                            word.push(c as char);
                        }
                        Some(b'\n') => {
                            // Line continuation inside double quotes.
                            self.advance();
                        }
                        _ => {
                            // Backslash is literal when not followed by a
                            // special character inside double quotes.
                            word.push('\\');
                        }
                    }
                }
                Some(c) => word.push(c as char),
                None => return Err(LexError::UnterminatedDoubleQuote),
            }
        }
    }

    /// Consume a backslash escape outside of quotes. The backslash
    /// escapes the next character; if followed by newline it is a line
    /// continuation (neither character contributes to the token).
    fn lex_backslash_unquoted(&mut self, word: &mut String) -> Result<(), LexError> {
        self.advance(); // consume backslash
        match self.advance() {
            Some(b'\n') => {
                // Line continuation — skip both the backslash and the
                // newline. If the word buffer is empty so far, this
                // effectively means nothing was contributed; the caller
                // will continue scanning.
                Ok(())
            }
            Some(c) => {
                word.push(c as char);
                Ok(())
            }
            None => Err(LexError::TrailingBackslash),
        }
    }
}

/// Returns true if `c` can start a shell operator token.
fn is_operator_start(c: u8) -> bool {
    matches!(c, b'|' | b'&' | b';' | b'(' | b')' | b'<' | b'>')
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: tokenize input and return the token vec (panics on error).
    fn toks(input: &str) -> Vec<Token> {
        Lexer::new(input).tokenize_all().unwrap()
    }

    /// Helper: tokenize and expect an error.
    fn toks_err(input: &str) -> LexError {
        Lexer::new(input).tokenize_all().unwrap_err()
    }

    // ── Basic words ─────────────────────────────────────────────────

    #[test]
    fn empty_input() {
        assert_eq!(toks(""), vec![Token::Eof]);
    }

    #[test]
    fn single_word() {
        assert_eq!(toks("hello"), vec![Token::Word("hello".into()), Token::Eof]);
    }

    #[test]
    fn multiple_words() {
        assert_eq!(
            toks("echo hello world"),
            vec![
                Token::Word("echo".into()),
                Token::Word("hello".into()),
                Token::Word("world".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn tabs_and_spaces() {
        assert_eq!(
            toks("  a\t\tb  "),
            vec![
                Token::Word("a".into()),
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    // ── Operators ───────────────────────────────────────────────────

    #[test]
    fn pipe() {
        assert_eq!(
            toks("a | b"),
            vec![
                Token::Word("a".into()),
                Token::Pipe,
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn or_operator() {
        assert_eq!(
            toks("a || b"),
            vec![
                Token::Word("a".into()),
                Token::Or,
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn ampersand() {
        assert_eq!(
            toks("a &"),
            vec![Token::Word("a".into()), Token::Ampersand, Token::Eof]
        );
    }

    #[test]
    fn and_operator() {
        assert_eq!(
            toks("a && b"),
            vec![
                Token::Word("a".into()),
                Token::And,
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn semicolon() {
        assert_eq!(
            toks("a; b"),
            vec![
                Token::Word("a".into()),
                Token::Semi,
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn parens() {
        assert_eq!(
            toks("(a)"),
            vec![
                Token::LParen,
                Token::Word("a".into()),
                Token::RParen,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn redirections_basic() {
        assert_eq!(
            toks("a < in > out"),
            vec![
                Token::Word("a".into()),
                Token::Less,
                Token::Word("in".into()),
                Token::Great,
                Token::Word("out".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn append_redirect() {
        assert_eq!(
            toks("a >> out"),
            vec![
                Token::Word("a".into()),
                Token::DGreat,
                Token::Word("out".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn heredoc_operator() {
        assert_eq!(
            toks("cat << EOF"),
            vec![
                Token::Word("cat".into()),
                Token::DLess,
                Token::Word("EOF".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn great_and() {
        assert_eq!(
            toks("a >& 2"),
            vec![
                Token::Word("a".into()),
                Token::GreatAnd,
                Token::Word("2".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn less_and() {
        assert_eq!(
            toks("a <& 3"),
            vec![
                Token::Word("a".into()),
                Token::LessAnd,
                Token::Word("3".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn less_great() {
        assert_eq!(
            toks("a <> file"),
            vec![
                Token::Word("a".into()),
                Token::LessGreat,
                Token::Word("file".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn newlines() {
        assert_eq!(
            toks("a\nb\n"),
            vec![
                Token::Word("a".into()),
                Token::Newline,
                Token::Word("b".into()),
                Token::Newline,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn operators_without_spaces() {
        assert_eq!(
            toks("a|b&&c;d"),
            vec![
                Token::Word("a".into()),
                Token::Pipe,
                Token::Word("b".into()),
                Token::And,
                Token::Word("c".into()),
                Token::Semi,
                Token::Word("d".into()),
                Token::Eof,
            ]
        );
    }

    // ── Single quoting ──────────────────────────────────────────────

    #[test]
    fn single_quote_basic() {
        assert_eq!(
            toks("'hello world'"),
            vec![Token::Word("hello world".into()), Token::Eof]
        );
    }

    #[test]
    fn single_quote_preserves_special_chars() {
        assert_eq!(
            toks("'a|b&&c;d>e<f'"),
            vec![Token::Word("a|b&&c;d>e<f".into()), Token::Eof]
        );
    }

    #[test]
    fn single_quote_preserves_backslash() {
        assert_eq!(
            toks(r"'hello\nworld'"),
            vec![Token::Word(r"hello\nworld".into()), Token::Eof]
        );
    }

    #[test]
    fn single_quote_adjacent_to_word() {
        assert_eq!(
            toks("abc'def'ghi"),
            vec![Token::Word("abcdefghi".into()), Token::Eof]
        );
    }

    #[test]
    fn empty_single_quote() {
        assert_eq!(
            toks("a''b"),
            vec![Token::Word("ab".into()), Token::Eof]
        );
    }

    // ── Double quoting ──────────────────────────────────────────────

    #[test]
    fn double_quote_basic() {
        assert_eq!(
            toks("\"hello world\""),
            vec![Token::Word("hello world".into()), Token::Eof]
        );
    }

    #[test]
    fn double_quote_preserves_single_quotes() {
        assert_eq!(
            toks("\"it's\""),
            vec![Token::Word("it's".into()), Token::Eof]
        );
    }

    #[test]
    fn double_quote_backslash_special_chars() {
        // Inside double quotes, backslash escapes $, `, ", \, and newline.
        assert_eq!(
            toks(r#""\$\`\"\\""#),
            vec![Token::Word("$`\"\\".into()), Token::Eof]
        );
    }

    #[test]
    fn double_quote_backslash_non_special_is_literal() {
        // Backslash before a non-special character is preserved literally.
        assert_eq!(
            toks(r#""\a\b""#),
            vec![Token::Word("\\a\\b".into()), Token::Eof]
        );
    }

    #[test]
    fn double_quote_line_continuation() {
        assert_eq!(
            toks("\"hello\\\nworld\""),
            vec![Token::Word("helloworld".into()), Token::Eof]
        );
    }

    #[test]
    fn double_quote_adjacent_to_word() {
        assert_eq!(
            toks("abc\"def\"ghi"),
            vec![Token::Word("abcdefghi".into()), Token::Eof]
        );
    }

    #[test]
    fn empty_double_quote() {
        assert_eq!(
            toks("a\"\"b"),
            vec![Token::Word("ab".into()), Token::Eof]
        );
    }

    // ── Backslash escaping (unquoted) ───────────────────────────────

    #[test]
    fn backslash_escapes_space() {
        assert_eq!(
            toks("hello\\ world"),
            vec![Token::Word("hello world".into()), Token::Eof]
        );
    }

    #[test]
    fn backslash_escapes_operator() {
        assert_eq!(
            toks("a\\|b"),
            vec![Token::Word("a|b".into()), Token::Eof]
        );
    }

    #[test]
    fn backslash_line_continuation() {
        assert_eq!(
            toks("hel\\\nlo"),
            vec![Token::Word("hello".into()), Token::Eof]
        );
    }

    #[test]
    fn backslash_line_continuation_between_words() {
        // A line continuation between words just joins the lines;
        // the blank on the next line starts a new word.
        assert_eq!(
            toks("a \\\n b"),
            vec![
                Token::Word("a".into()),
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    // ── Mixed quoting ───────────────────────────────────────────────

    #[test]
    fn mixed_quoting_in_one_word() {
        // POSIX allows mixing quote types within a single word.
        assert_eq!(
            toks("a'b'\"c\"d"),
            vec![Token::Word("abcd".into()), Token::Eof]
        );
    }

    // ── Comments ────────────────────────────────────────────────────

    #[test]
    fn comment_at_start() {
        assert_eq!(toks("# this is a comment"), vec![Token::Eof]);
    }

    #[test]
    fn comment_after_newline() {
        assert_eq!(
            toks("a\n# comment\nb"),
            vec![
                Token::Word("a".into()),
                Token::Newline,
                Token::Newline,
                Token::Word("b".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn hash_in_middle_of_word_is_literal() {
        assert_eq!(
            toks("a#b"),
            vec![Token::Word("a#b".into()), Token::Eof]
        );
    }

    #[test]
    fn comment_after_space() {
        assert_eq!(
            toks("a # comment"),
            vec![Token::Word("a".into()), Token::Eof]
        );
    }

    // ── Error cases ─────────────────────────────────────────────────

    #[test]
    fn unterminated_single_quote() {
        assert_eq!(toks_err("'hello"), LexError::UnterminatedSingleQuote);
    }

    #[test]
    fn unterminated_double_quote() {
        assert_eq!(toks_err("\"hello"), LexError::UnterminatedDoubleQuote);
    }

    #[test]
    fn trailing_backslash() {
        assert_eq!(toks_err("hello\\"), LexError::TrailingBackslash);
    }

    // ── Realistic command lines ─────────────────────────────────────

    #[test]
    fn realistic_pipeline() {
        assert_eq!(
            toks("cat /etc/passwd | grep root > /tmp/out"),
            vec![
                Token::Word("cat".into()),
                Token::Word("/etc/passwd".into()),
                Token::Pipe,
                Token::Word("grep".into()),
                Token::Word("root".into()),
                Token::Great,
                Token::Word("/tmp/out".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn realistic_compound() {
        assert_eq!(
            toks("mkdir -p dir && cd dir; echo done"),
            vec![
                Token::Word("mkdir".into()),
                Token::Word("-p".into()),
                Token::Word("dir".into()),
                Token::And,
                Token::Word("cd".into()),
                Token::Word("dir".into()),
                Token::Semi,
                Token::Word("echo".into()),
                Token::Word("done".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn realistic_redirect_stderr() {
        assert_eq!(
            toks("cmd 2>&1"),
            vec![
                Token::Word("cmd".into()),
                Token::Word("2".into()),
                Token::GreatAnd,
                Token::Word("1".into()),
                Token::Eof,
            ]
        );
    }

    #[test]
    fn realistic_subshell() {
        assert_eq!(
            toks("(echo a; echo b)"),
            vec![
                Token::LParen,
                Token::Word("echo".into()),
                Token::Word("a".into()),
                Token::Semi,
                Token::Word("echo".into()),
                Token::Word("b".into()),
                Token::RParen,
                Token::Eof,
            ]
        );
    }

    #[test]
    fn only_whitespace() {
        assert_eq!(toks("   \t  "), vec![Token::Eof]);
    }

    #[test]
    fn only_newlines() {
        assert_eq!(
            toks("\n\n"),
            vec![Token::Newline, Token::Newline, Token::Eof]
        );
    }

    #[test]
    fn word_immediately_before_operator() {
        assert_eq!(
            toks("echo>file"),
            vec![
                Token::Word("echo".into()),
                Token::Great,
                Token::Word("file".into()),
                Token::Eof,
            ]
        );
    }
}
