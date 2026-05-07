//! Standard I/O for vibix -- delegates to `vibix_abi::stdio`.

use crate::io::{self, IoSlice, IoSliceMut};

pub struct Stdin;
pub struct Stdout;
pub struct Stderr;

impl Stdin {
    pub const fn new() -> Stdin {
        Stdin
    }
}

impl io::Read for Stdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ret = vibix_abi::stdio::read_stdin(buf);
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            Ok(ret as usize)
        }
    }

    fn read_vectored(&mut self, bufs: &mut [IoSliceMut<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            let ret = vibix_abi::stdio::read_stdin(buf);
            if ret < 0 {
                if total > 0 {
                    return Ok(total);
                }
                return Err(io::Error::from_raw_os_error(-ret as i32));
            }
            total += ret as usize;
            if ret == 0 || (ret as usize) < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    #[inline]
    fn is_read_vectored(&self) -> bool {
        false
    }
}

impl Stdout {
    pub const fn new() -> Stdout {
        Stdout
    }
}

impl io::Write for Stdout {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = vibix_abi::stdio::write_stdout(buf);
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            Ok(ret as usize)
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        // Write each slice sequentially.
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            let ret = vibix_abi::stdio::write_stdout(buf);
            if ret < 0 {
                if total > 0 {
                    return Ok(total);
                }
                return Err(io::Error::from_raw_os_error(-ret as i32));
            }
            total += ret as usize;
            if (ret as usize) < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        false
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stderr {
    pub const fn new() -> Stderr {
        Stderr
    }
}

impl io::Write for Stderr {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let ret = vibix_abi::stdio::write_stderr(buf);
        if ret < 0 {
            Err(io::Error::from_raw_os_error(-ret as i32))
        } else {
            Ok(ret as usize)
        }
    }

    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        let mut total = 0;
        for buf in bufs {
            if buf.is_empty() {
                continue;
            }
            let ret = vibix_abi::stdio::write_stderr(buf);
            if ret < 0 {
                if total > 0 {
                    return Ok(total);
                }
                return Err(io::Error::from_raw_os_error(-ret as i32));
            }
            total += ret as usize;
            if (ret as usize) < buf.len() {
                break;
            }
        }
        Ok(total)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        false
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub fn is_ebadf(err: &io::Error) -> bool {
    err.raw_os_error() == Some(9) // EBADF
}

pub const STDIN_BUF_SIZE: usize = crate::sys::io::DEFAULT_BUF_SIZE;

pub fn panic_output() -> Option<impl io::Write> {
    Some(Stderr::new())
}
