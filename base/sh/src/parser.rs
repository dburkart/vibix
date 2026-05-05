//! POSIX shell parser — recursive-descent over the lexer's token stream.
//!
//! Implements the grammar from POSIX.1-2024 §2.10 (Shell Grammar). The
//! parser consumes [`Token`] values from a [`Lexer`] and builds an
//! abstract syntax tree whose root is a [`List`].
//!
//! ## Operator precedence (tightest first)
//!
//! 1. I/O redirection — attached to a [`SimpleCommand`].
//! 2. `|` — joins commands into a [`Pipeline`].
//! 3. `&&`, `||` — joins pipelines into an and-or list.
//! 4. `;`, newline — separates and-or lists into a [`List`].
//!
//! ## Grammar sketch
//!
//! ```text
//! list           = pipeline ((';' | '\n' | '&&' | '||') pipeline)* [';' | '\n']
//! pipeline       = command ('|' linebreak command)*
//! command        = simple_command | subshell [redirects]
//! subshell       = '(' list ')'
//! simple_command = (assignment | word | redirect)+
//! redirect       = [IO_NUMBER] redirect_op WORD
//! ```

use crate::lexer::{LexError, Lexer, Token};
use std::fmt;

// ── AST types ──────────────────────────────────────────────────────

/// A parsed I/O redirection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redirect {
    /// Optional file-descriptor number preceding the operator (e.g. the
    /// `2` in `2>err.log`). `None` means the shell default for that
    /// operator (0 for input, 1 for output).
    pub fd: Option<u32>,
    /// The redirection operator.
    pub op: RedirectOp,
    /// The target word (filename or fd number for `>&`/`<&`).
    pub target: String,
}

/// Redirection operators recognized by the parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirectOp {
    /// `<`  — open file for reading.
    Input,
    /// `>`  — open file for writing (truncate).
    Output,
    /// `>>` — open file for appending.
    Append,
    /// `<<` — here-document (delimiter follows).
    HereDoc,
    /// `>&` — duplicate/redirect output fd.
    DupOutput,
    /// `<&` — duplicate/redirect input fd.
    DupInput,
    /// `<>` — open file for reading and writing.
    ReadWrite,
}

/// A simple command: zero or more variable assignments, one or more
/// words (the command name and its arguments), and zero or more I/O
/// redirections. At least one of `assignments`, `words`, or `redirects`
/// is non-empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleCommand {
    /// Variable assignments that precede the command name
    /// (e.g. `FOO=bar`).
    pub assignments: Vec<String>,
    /// Command name followed by its arguments.
    pub words: Vec<String>,
    /// I/O redirections attached to this command.
    pub redirects: Vec<Redirect>,
}

/// A single element in a pipeline — either a simple command or a
/// subshell (with optional redirections).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Simple(SimpleCommand),
    Subshell {
        body: List,
        redirects: Vec<Redirect>,
    },
}

/// A pipeline: one or more commands connected by `|`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<Command>,
}

/// The connector between adjacent pipelines inside a [`List`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListOp {
    /// `;` or newline — sequential, unconditional.
    Semi,
    /// `&&` — execute next only if previous succeeded.
    And,
    /// `||` — execute next only if previous failed.
    Or,
}

/// A compound list: one or more pipelines connected by `;`, `&&`, or
/// `||`. This is the top-level AST node produced by [`Parser::parse`].
///
/// The `ops` vector has length `pipelines.len() - 1`: `ops[i]`
/// connects `pipelines[i]` to `pipelines[i+1]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct List {
    pub pipelines: Vec<Pipeline>,
    pub ops: Vec<ListOp>,
}

// ── Parse errors ───────────────────────────────────────────────────

/// An error encountered during parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The lexer returned an error.
    Lex(LexError),
    /// A token was encountered where it wasn't expected.
    UnexpectedToken(String),
    /// A redirection operator was not followed by a target word.
    MissingRedirectTarget,
    /// Unmatched `(` — no closing `)` found.
    UnmatchedParen,
    /// Empty command (e.g. bare `;` at the start).
    EmptyCommand,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ParseError::Lex(e) => write!(f, "lex error: {e}"),
            ParseError::UnexpectedToken(t) => write!(f, "unexpected token: {t}"),
            ParseError::MissingRedirectTarget => write!(f, "missing redirect target"),
            ParseError::UnmatchedParen => write!(f, "unmatched '('"),
            ParseError::EmptyCommand => write!(f, "empty command"),
        }
    }
}

impl From<LexError> for ParseError {
    fn from(e: LexError) -> Self {
        ParseError::Lex(e)
    }
}

// ── Parser ─────────────────────────────────────────────────────────

/// Recursive-descent parser for the POSIX shell grammar.
///
/// Create via [`Parser::new`], then call [`Parser::parse`] to obtain
/// the AST.
pub struct Parser<'a> {
    lexer: Lexer<'a>,
    /// One-token lookahead buffer.
    current: Token,
}

impl<'a> Parser<'a> {
    /// Create a new parser for the given input string.
    pub fn new(input: &'a str) -> Result<Self, ParseError> {
        let mut lexer = Lexer::new(input);
        let current = lexer.next_token()?;
        Ok(Self { lexer, current })
    }

    /// Parse the entire input and return the top-level [`List`].
    ///
    /// Returns `Ok` with an empty list if the input contains no
    /// commands (just whitespace, newlines, or EOF).
    pub fn parse(&mut self) -> Result<List, ParseError> {
        let list = self.parse_list()?;
        if self.current != Token::Eof {
            return Err(ParseError::UnexpectedToken(format!("{}", self.current)));
        }
        Ok(list)
    }

    // ── grammar productions ────────────────────────────────────────

    /// Parse a list of pipelines connected by `;`, newline, `&&`, or
    /// `||`.
    ///
    /// Operator precedence between `&&`/`||` and `;` is represented
    /// structurally: `|` binds inside [`Pipeline`], while `&&`/`||`/`;`
    /// are all connectors between pipelines in the flat [`List`]. The
    /// executor evaluates left-to-right with short-circuit semantics
    /// for `&&`/`||`, which matches POSIX behavior.
    fn parse_list(&mut self) -> Result<List, ParseError> {
        self.skip_newlines()?;

        if self.at_list_end() {
            return Ok(List {
                pipelines: vec![],
                ops: vec![],
            });
        }

        let mut pipelines = vec![];
        let mut ops = vec![];

        pipelines.push(self.parse_pipeline()?);

        loop {
            match &self.current {
                Token::Semi | Token::Newline => {
                    self.bump()?;
                    self.skip_newlines()?;
                    if self.at_list_end() {
                        break;
                    }
                    ops.push(ListOp::Semi);
                    pipelines.push(self.parse_pipeline()?);
                }
                Token::And => {
                    self.bump()?;
                    self.skip_newlines()?;
                    ops.push(ListOp::And);
                    pipelines.push(self.parse_pipeline()?);
                }
                Token::Or => {
                    self.bump()?;
                    self.skip_newlines()?;
                    ops.push(ListOp::Or);
                    pipelines.push(self.parse_pipeline()?);
                }
                _ => break,
            }
        }

        Ok(List { pipelines, ops })
    }

    /// ```text
    /// pipeline = command ('|' linebreak command)*
    /// ```
    fn parse_pipeline(&mut self) -> Result<Pipeline, ParseError> {
        let mut commands = vec![];
        commands.push(self.parse_command()?);

        while self.current == Token::Pipe {
            self.bump()?;
            self.skip_newlines()?;
            commands.push(self.parse_command()?);
        }

        Ok(Pipeline { commands })
    }

    /// ```text
    /// command = simple_command | subshell [redirects]
    /// ```
    fn parse_command(&mut self) -> Result<Command, ParseError> {
        if self.current == Token::LParen {
            self.bump()?; // consume '('
            self.skip_newlines()?;
            let body = self.parse_list()?;
            if self.current != Token::RParen {
                return Err(ParseError::UnmatchedParen);
            }
            self.bump()?; // consume ')'
            // Parse optional redirections after the subshell.
            let redirects = self.parse_redirect_list()?;
            Ok(Command::Subshell { body, redirects })
        } else {
            self.parse_simple_command().map(Command::Simple)
        }
    }

    /// Parse a simple command: a mix of words, assignments, and
    /// redirections in any order.
    ///
    /// Fd-number redirections (e.g. `2>file`) are handled with a
    /// consume-then-check strategy: when we see a digit-only word, we
    /// consume it and check whether the *new* current token is a
    /// redirect operator. If yes, the digit word is retroactively
    /// treated as an fd number. If no, it's a regular argument word.
    fn parse_simple_command(&mut self) -> Result<SimpleCommand, ParseError> {
        let mut assignments = Vec::new();
        let mut words = Vec::new();
        let mut redirects = Vec::new();

        loop {
            match &self.current {
                Token::Word(w) => {
                    let w_clone = w.clone();

                    // Check if this is a variable assignment (only
                    // before the command name).
                    if words.is_empty() && is_assignment(&w_clone) {
                        assignments.push(w_clone);
                        self.bump()?;
                        continue;
                    }

                    // Try fd-number redirect: consume the word, then
                    // check if we're now looking at a redirect operator.
                    if let Some(fd) = try_parse_fd(&w_clone) {
                        self.bump()?;
                        if is_redirect_token(&self.current) {
                            let op = self.parse_redirect_op()?;
                            let target = self.expect_redirect_target()?;
                            redirects.push(Redirect {
                                fd: Some(fd),
                                op,
                                target,
                            });
                            continue;
                        }
                        // Not a redirect — treat as a normal word.
                        words.push(w_clone);
                        continue;
                    }

                    // Regular word.
                    words.push(w_clone);
                    self.bump()?;
                }
                tok if is_redirect_token(tok) => {
                    let op = self.parse_redirect_op()?;
                    let target = self.expect_redirect_target()?;
                    redirects.push(Redirect {
                        fd: None,
                        op,
                        target,
                    });
                }
                _ => break,
            }
        }

        if assignments.is_empty() && words.is_empty() && redirects.is_empty() {
            return Err(ParseError::EmptyCommand);
        }

        Ok(SimpleCommand {
            assignments,
            words,
            redirects,
        })
    }

    // ── redirect helpers ───────────────────────────────────────────

    /// Parse zero or more redirections (used after subshells).
    fn parse_redirect_list(&mut self) -> Result<Vec<Redirect>, ParseError> {
        let mut redirects = Vec::new();
        loop {
            // Check for fd-number + redirect-op pattern.
            if let Token::Word(w) = &self.current {
                if let Some(fd) = try_parse_fd(w) {
                    self.bump()?;
                    if is_redirect_token(&self.current) {
                        let op = self.parse_redirect_op()?;
                        let target = self.expect_redirect_target()?;
                        redirects.push(Redirect {
                            fd: Some(fd),
                            op,
                            target,
                        });
                        continue;
                    }
                    // Not a redirect — stop. The digit word is part of
                    // whatever comes next; we can't un-consume it but
                    // for subshell redirects this is fine since we only
                    // expect redirects here.
                    break;
                }
            }
            if is_redirect_token(&self.current) {
                let op = self.parse_redirect_op()?;
                let target = self.expect_redirect_target()?;
                redirects.push(Redirect {
                    fd: None,
                    op,
                    target,
                });
            } else {
                break;
            }
        }
        Ok(redirects)
    }

    /// Consume the current token as a redirect operator and return the
    /// corresponding [`RedirectOp`].
    fn parse_redirect_op(&mut self) -> Result<RedirectOp, ParseError> {
        let op = match &self.current {
            Token::Less => RedirectOp::Input,
            Token::Great => RedirectOp::Output,
            Token::DGreat => RedirectOp::Append,
            Token::DLess => RedirectOp::HereDoc,
            Token::GreatAnd => RedirectOp::DupOutput,
            Token::LessAnd => RedirectOp::DupInput,
            Token::LessGreat => RedirectOp::ReadWrite,
            other => {
                return Err(ParseError::UnexpectedToken(format!(
                    "expected redirect operator, got {other}"
                )))
            }
        };
        self.bump()?;
        Ok(op)
    }

    /// Expect the current token to be a Word for use as a redirect
    /// target, consume it, and return its value. Returns
    /// [`ParseError::MissingRedirectTarget`] if not a word.
    fn expect_redirect_target(&mut self) -> Result<String, ParseError> {
        match &self.current {
            Token::Word(w) => {
                let w = w.clone();
                self.bump()?;
                Ok(w)
            }
            _ => Err(ParseError::MissingRedirectTarget),
        }
    }

    // ── token helpers ──────────────────────────────────────────────

    /// Advance to the next token.
    fn bump(&mut self) -> Result<(), ParseError> {
        self.current = self.lexer.next_token()?;
        Ok(())
    }

    /// Skip over consecutive newline tokens.
    fn skip_newlines(&mut self) -> Result<(), ParseError> {
        while self.current == Token::Newline {
            self.bump()?;
        }
        Ok(())
    }

    /// Returns true when the current token signals the end of a list
    /// (EOF, `)`, or anything that can't start a pipeline).
    fn at_list_end(&self) -> bool {
        matches!(self.current, Token::Eof | Token::RParen)
    }
}

// ── Standalone helpers ─────────────────────────────────────────────

/// Returns `true` if the token is a redirection operator.
fn is_redirect_token(tok: &Token) -> bool {
    matches!(
        tok,
        Token::Less
            | Token::Great
            | Token::DGreat
            | Token::DLess
            | Token::GreatAnd
            | Token::LessAnd
            | Token::LessGreat
    )
}

/// Returns `true` if the word looks like a variable assignment
/// (`NAME=VALUE`). A valid assignment name starts with a letter or `_`
/// and contains only alphanumerics and `_` before the `=`.
fn is_assignment(word: &str) -> bool {
    if let Some(eq_pos) = word.find('=') {
        if eq_pos == 0 {
            return false;
        }
        let name = &word[..eq_pos];
        let first = name.as_bytes()[0];
        if !(first.is_ascii_alphabetic() || first == b'_') {
            return false;
        }
        name.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    }
}

/// Try to parse a word as a file-descriptor number (non-negative
/// integer). Returns `None` if the word isn't purely decimal digits or
/// would overflow `u32`.
fn try_parse_fd(word: &str) -> Option<u32> {
    if word.is_empty() {
        return None;
    }
    if word.bytes().all(|b| b.is_ascii_digit()) {
        word.parse::<u32>().ok()
    } else {
        None
    }
}

// ── Public convenience ─────────────────────────────────────────────

/// Parse a shell input string and return the AST.
///
/// This is a convenience wrapper around [`Parser::new`] +
/// [`Parser::parse`].
pub fn parse(input: &str) -> Result<List, ParseError> {
    Parser::new(input)?.parse()
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: parse input and return the AST (panics on error).
    fn ast(input: &str) -> List {
        parse(input).unwrap()
    }

    /// Helper: parse and expect an error.
    fn ast_err(input: &str) -> ParseError {
        parse(input).unwrap_err()
    }

    // ── Empty / trivial inputs ─────────────────────────────────────

    #[test]
    fn empty_input() {
        let list = ast("");
        assert!(list.pipelines.is_empty());
    }

    #[test]
    fn only_newlines() {
        let list = ast("\n\n\n");
        assert!(list.pipelines.is_empty());
    }

    // ── Simple commands ────────────────────────────────────────────

    #[test]
    fn single_word_command() {
        let list = ast("ls");
        assert_eq!(list.pipelines.len(), 1);
        assert_eq!(list.ops.len(), 0);
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["ls"]);
                assert!(sc.assignments.is_empty());
                assert!(sc.redirects.is_empty());
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn multi_word_command() {
        let list = ast("echo hello world");
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["echo", "hello", "world"]);
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn command_with_assignment() {
        let list = ast("FOO=bar echo test");
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.assignments, vec!["FOO=bar"]);
                assert_eq!(sc.words, vec!["echo", "test"]);
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn multiple_assignments() {
        let list = ast("A=1 B=2 cmd");
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.assignments, vec!["A=1", "B=2"]);
                assert_eq!(sc.words, vec!["cmd"]);
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn assignment_only_no_command() {
        let list = ast("FOO=bar");
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Simple(sc) => {
                assert_eq!(sc.assignments, vec!["FOO=bar"]);
                assert!(sc.words.is_empty());
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    // ── Pipelines ──────────────────────────────────────────────────

    #[test]
    fn simple_pipeline() {
        let list = ast("ls | grep foo");
        assert_eq!(list.pipelines.len(), 1);
        let pipe = &list.pipelines[0];
        assert_eq!(pipe.commands.len(), 2);
        match &pipe.commands[0] {
            Command::Simple(sc) => assert_eq!(sc.words, vec!["ls"]),
            _ => panic!("expected SimpleCommand"),
        }
        match &pipe.commands[1] {
            Command::Simple(sc) => assert_eq!(sc.words, vec!["grep", "foo"]),
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn three_stage_pipeline() {
        let list = ast("cat file | sort | uniq");
        let pipe = &list.pipelines[0];
        assert_eq!(pipe.commands.len(), 3);
    }

    #[test]
    fn pipeline_with_newline_after_pipe() {
        // POSIX allows a newline after `|`.
        let list = ast("ls |\ngrep foo");
        assert_eq!(list.pipelines.len(), 1);
        assert_eq!(list.pipelines[0].commands.len(), 2);
    }

    // ── Compound lists (;, &&, ||) ─────────────────────────────────

    #[test]
    fn semicolon_list() {
        let list = ast("a; b; c");
        assert_eq!(list.pipelines.len(), 3);
        assert_eq!(list.ops, vec![ListOp::Semi, ListOp::Semi]);
    }

    #[test]
    fn trailing_semicolon() {
        let list = ast("a; b;");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::Semi]);
    }

    #[test]
    fn and_list() {
        let list = ast("a && b");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::And]);
    }

    #[test]
    fn or_list() {
        let list = ast("a || b");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::Or]);
    }

    #[test]
    fn mixed_and_or_semi() {
        let list = ast("a && b || c; d");
        assert_eq!(list.pipelines.len(), 4);
        assert_eq!(
            list.ops,
            vec![ListOp::And, ListOp::Or, ListOp::Semi]
        );
    }

    #[test]
    fn newline_as_separator() {
        let list = ast("a\nb\nc");
        assert_eq!(list.pipelines.len(), 3);
        assert_eq!(list.ops, vec![ListOp::Semi, ListOp::Semi]);
    }

    #[test]
    fn and_with_newline_after_operator() {
        let list = ast("a &&\nb");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::And]);
    }

    // ── Pipe binds tighter than && / || ────────────────────────────

    #[test]
    fn pipe_binds_tighter_than_and() {
        // `a | b && c | d` should parse as:
        //   pipeline(a|b) && pipeline(c|d)
        let list = ast("a | b && c | d");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::And]);
        assert_eq!(list.pipelines[0].commands.len(), 2);
        assert_eq!(list.pipelines[1].commands.len(), 2);
    }

    #[test]
    fn pipe_binds_tighter_than_or() {
        let list = ast("a | b || c | d");
        assert_eq!(list.pipelines.len(), 2);
        assert_eq!(list.ops, vec![ListOp::Or]);
        assert_eq!(list.pipelines[0].commands.len(), 2);
        assert_eq!(list.pipelines[1].commands.len(), 2);
    }

    #[test]
    fn semi_binds_looser_than_and_or() {
        // `a && b ; c || d` should parse as three+ pipelines:
        // pipeline(a) && pipeline(b) ; pipeline(c) || pipeline(d)
        let list = ast("a && b ; c || d");
        assert_eq!(list.pipelines.len(), 4);
        assert_eq!(
            list.ops,
            vec![ListOp::And, ListOp::Semi, ListOp::Or]
        );
    }

    // ── Subshells ──────────────────────────────────────────────────

    #[test]
    fn simple_subshell() {
        let list = ast("(echo hello)");
        assert_eq!(list.pipelines.len(), 1);
        let cmd = &list.pipelines[0].commands[0];
        match cmd {
            Command::Subshell { body, redirects } => {
                assert_eq!(body.pipelines.len(), 1);
                assert!(redirects.is_empty());
                match &body.pipelines[0].commands[0] {
                    Command::Simple(sc) => {
                        assert_eq!(sc.words, vec!["echo", "hello"]);
                    }
                    _ => panic!("expected SimpleCommand inside subshell"),
                }
            }
            _ => panic!("expected Subshell"),
        }
    }

    #[test]
    fn subshell_with_list() {
        let list = ast("(a; b)");
        match &list.pipelines[0].commands[0] {
            Command::Subshell { body, .. } => {
                assert_eq!(body.pipelines.len(), 2);
                assert_eq!(body.ops, vec![ListOp::Semi]);
            }
            _ => panic!("expected Subshell"),
        }
    }

    #[test]
    fn subshell_with_redirect() {
        let list = ast("(echo hello) > out.txt");
        match &list.pipelines[0].commands[0] {
            Command::Subshell { body, redirects } => {
                assert_eq!(body.pipelines.len(), 1);
                assert_eq!(redirects.len(), 1);
                assert_eq!(redirects[0].op, RedirectOp::Output);
                assert_eq!(redirects[0].target, "out.txt");
            }
            _ => panic!("expected Subshell"),
        }
    }

    #[test]
    fn nested_subshell() {
        let list = ast("((echo a))");
        match &list.pipelines[0].commands[0] {
            Command::Subshell { body, .. } => match &body.pipelines[0].commands[0] {
                Command::Subshell { body: inner, .. } => {
                    assert_eq!(inner.pipelines.len(), 1);
                }
                _ => panic!("expected nested Subshell"),
            },
            _ => panic!("expected Subshell"),
        }
    }

    #[test]
    fn subshell_in_pipeline() {
        let list = ast("(echo a) | cat");
        assert_eq!(list.pipelines[0].commands.len(), 2);
        match &list.pipelines[0].commands[0] {
            Command::Subshell { .. } => {}
            _ => panic!("expected Subshell"),
        }
        match &list.pipelines[0].commands[1] {
            Command::Simple(sc) => assert_eq!(sc.words, vec!["cat"]),
            _ => panic!("expected SimpleCommand"),
        }
    }

    // ── I/O redirections ───────────────────────────────────────────

    #[test]
    fn output_redirect() {
        let list = ast("echo hello > out.txt");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["echo", "hello"]);
                assert_eq!(sc.redirects.len(), 1);
                assert_eq!(sc.redirects[0].fd, None);
                assert_eq!(sc.redirects[0].op, RedirectOp::Output);
                assert_eq!(sc.redirects[0].target, "out.txt");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn input_redirect() {
        let list = ast("cat < input.txt");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects.len(), 1);
                assert_eq!(sc.redirects[0].op, RedirectOp::Input);
                assert_eq!(sc.redirects[0].target, "input.txt");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn append_redirect() {
        let list = ast("echo hello >> log.txt");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects[0].op, RedirectOp::Append);
                assert_eq!(sc.redirects[0].target, "log.txt");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn heredoc_redirect() {
        let list = ast("cat << EOF");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects[0].op, RedirectOp::HereDoc);
                assert_eq!(sc.redirects[0].target, "EOF");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn dup_output_redirect() {
        let list = ast("cmd >& 2");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects[0].op, RedirectOp::DupOutput);
                assert_eq!(sc.redirects[0].target, "2");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn dup_input_redirect() {
        let list = ast("cmd <& 3");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects[0].op, RedirectOp::DupInput);
                assert_eq!(sc.redirects[0].target, "3");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn read_write_redirect() {
        let list = ast("cmd <> file");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.redirects[0].op, RedirectOp::ReadWrite);
                assert_eq!(sc.redirects[0].target, "file");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn fd_number_redirect() {
        // `2> err.log` — the lexer produces Word("2"), Great, Word("err.log").
        // The parser should recognize "2" as an fd number for the redirect.
        let list = ast("cmd 2> err.log");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["cmd"]);
                assert_eq!(sc.redirects.len(), 1);
                assert_eq!(sc.redirects[0].fd, Some(2));
                assert_eq!(sc.redirects[0].op, RedirectOp::Output);
                assert_eq!(sc.redirects[0].target, "err.log");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn fd_number_dup_redirect() {
        // `2>&1`
        let list = ast("cmd 2>&1");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["cmd"]);
                assert_eq!(sc.redirects.len(), 1);
                assert_eq!(sc.redirects[0].fd, Some(2));
                assert_eq!(sc.redirects[0].op, RedirectOp::DupOutput);
                assert_eq!(sc.redirects[0].target, "1");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn multiple_redirects() {
        let list = ast("cmd < in > out 2> err");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["cmd"]);
                assert_eq!(sc.redirects.len(), 3);
                assert_eq!(sc.redirects[0].op, RedirectOp::Input);
                assert_eq!(sc.redirects[0].target, "in");
                assert_eq!(sc.redirects[1].op, RedirectOp::Output);
                assert_eq!(sc.redirects[1].target, "out");
                assert_eq!(sc.redirects[2].fd, Some(2));
                assert_eq!(sc.redirects[2].op, RedirectOp::Output);
                assert_eq!(sc.redirects[2].target, "err");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn redirect_at_start_of_command() {
        let list = ast("> out echo hello");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["echo", "hello"]);
                assert_eq!(sc.redirects.len(), 1);
                assert_eq!(sc.redirects[0].op, RedirectOp::Output);
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn digit_word_not_fd_when_no_redirect_follows() {
        // `echo 42` — "42" should be a word argument, not an fd.
        let list = ast("echo 42");
        match &list.pipelines[0].commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["echo", "42"]);
                assert!(sc.redirects.is_empty());
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    // ── Syntax errors ──────────────────────────────────────────────

    #[test]
    fn unmatched_paren() {
        let err = ast_err("(echo hello");
        assert_eq!(err, ParseError::UnmatchedParen);
    }

    #[test]
    fn unexpected_rparen() {
        let err = ast_err(")");
        match err {
            ParseError::EmptyCommand => {} // `)` where a command was expected
            ParseError::UnexpectedToken(_) => {}
            other => panic!("expected EmptyCommand or UnexpectedToken, got {other:?}"),
        }
    }

    #[test]
    fn missing_redirect_target() {
        let err = ast_err("echo >");
        assert_eq!(err, ParseError::MissingRedirectTarget);
    }

    #[test]
    fn lex_error_propagated() {
        let err = ast_err("echo 'unterminated");
        match err {
            ParseError::Lex(LexError::UnterminatedSingleQuote) => {}
            other => panic!("expected lex error, got {other:?}"),
        }
    }

    // ── Realistic command lines ────────────────────────────────────

    #[test]
    fn realistic_pipeline_with_redirect() {
        let list = ast("cat /etc/passwd | grep root > /tmp/out");
        assert_eq!(list.pipelines.len(), 1);
        let pipe = &list.pipelines[0];
        assert_eq!(pipe.commands.len(), 2);
        match &pipe.commands[1] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["grep", "root"]);
                assert_eq!(sc.redirects[0].target, "/tmp/out");
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn realistic_compound_command() {
        let list = ast("mkdir -p dir && cd dir; echo done");
        assert_eq!(list.pipelines.len(), 3);
        assert_eq!(list.ops, vec![ListOp::And, ListOp::Semi]);
    }

    #[test]
    fn realistic_stderr_redirect() {
        let list = ast("make 2>&1 | tee build.log");
        assert_eq!(list.pipelines.len(), 1);
        let pipe = &list.pipelines[0];
        assert_eq!(pipe.commands.len(), 2);
        match &pipe.commands[0] {
            Command::Simple(sc) => {
                assert_eq!(sc.words, vec!["make"]);
                assert_eq!(sc.redirects[0].fd, Some(2));
                assert_eq!(sc.redirects[0].op, RedirectOp::DupOutput);
            }
            _ => panic!("expected SimpleCommand"),
        }
    }

    #[test]
    fn realistic_subshell_pipeline() {
        let list = ast("(echo a; echo b) | wc -l");
        assert_eq!(list.pipelines.len(), 1);
        assert_eq!(list.pipelines[0].commands.len(), 2);
    }

    #[test]
    fn realistic_if_like_pattern() {
        // Common shell pattern: test && action || fallback
        let list = ast("test -f /etc/motd && cat /etc/motd || echo missing");
        assert_eq!(list.pipelines.len(), 3);
        assert_eq!(list.ops, vec![ListOp::And, ListOp::Or]);
    }
}
