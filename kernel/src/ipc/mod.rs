//! Inter-process communication primitives.
//!
//! Currently: anonymous pipes (`pipe(2)` / `pipe2(2)`).
//! FIFOs (`mkfifo`) land separately (#377).

pub mod pipe;
