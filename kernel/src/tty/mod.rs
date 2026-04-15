//! TTY subsystem.
//!
//! Today this module is just the POSIX [`termios`] data type plus its
//! ioctl command numbers — the minimum needed for userspace to call
//! `tcgetattr`/`tcsetattr` on a tty-like fd. The `Tty` wrapper, line
//! discipline, and wait-queue glue land in follow-up work (RFC 0003,
//! issues #374–#376).

pub mod termios;
