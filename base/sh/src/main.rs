#![feature(restricted_std)]

mod expand;
mod lexer;
mod parser;
mod redirect;

use lexer::{Lexer, Token};

fn main() {
    // Placeholder: tokenize a hard-coded command line and print the
    // tokens. A future issue will add interactive line reading and a
    // parser/executor on top of this lexer.
    let input = "echo hello world | cat\n";
    let mut lex = Lexer::new(input);
    loop {
        match lex.next_token() {
            Ok(tok) => {
                println!("{tok}");
                if tok == Token::Eof {
                    break;
                }
            }
            Err(e) => {
                eprintln!("sh: lex error: {e}");
                break;
            }
        }
    }
}
