//! Process implementation for vibix.
//!
//! Uses fork+execve for Command::spawn() and wait4 for Child::wait().

use super::env::{CommandEnv, CommandEnvs};
pub use crate::ffi::OsString as EnvKey;
use crate::ffi::{CString, OsStr, OsString};
use crate::num::NonZero;
use crate::os::vibix::ffi::OsStrExt;
use crate::path::Path;
use crate::process::StdioPipes;
use crate::sys::fs::File;
use crate::sys::pipe::Pipe;
use crate::sys::unsupported;
use crate::{fmt, io};

use vibix_abi::process as vproc;

/// Convert a negative syscall return to an io::Error.
fn cvt(ret: i64) -> io::Result<i64> {
    if ret < 0 { Err(io::Error::from_raw_os_error(-ret as i32)) } else { Ok(ret) }
}

////////////////////////////////////////////////////////////////////////////////
// Command
////////////////////////////////////////////////////////////////////////////////

pub struct Command {
    program: OsString,
    args: Vec<OsString>,
    env: CommandEnv,
    cwd: Option<OsString>,
    stdin: Option<Stdio>,
    stdout: Option<Stdio>,
    stderr: Option<Stdio>,
}

#[derive(Debug)]
pub enum Stdio {
    Inherit,
    Null,
    MakePipe,
    ParentStdout,
    ParentStderr,
    #[allow(dead_code)]
    InheritFile(File),
    #[allow(dead_code)]
    InheritPipe(Pipe),
}

impl Command {
    pub fn new(program: &OsStr) -> Command {
        Command {
            program: program.to_owned(),
            args: vec![program.to_owned()],
            env: Default::default(),
            cwd: None,
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn arg(&mut self, arg: &OsStr) {
        self.args.push(arg.to_owned());
    }

    pub fn env_mut(&mut self) -> &mut CommandEnv {
        &mut self.env
    }

    pub fn cwd(&mut self, dir: &OsStr) {
        self.cwd = Some(dir.to_owned());
    }

    pub fn stdin(&mut self, stdin: Stdio) {
        self.stdin = Some(stdin);
    }

    pub fn stdout(&mut self, stdout: Stdio) {
        self.stdout = Some(stdout);
    }

    pub fn stderr(&mut self, stderr: Stdio) {
        self.stderr = Some(stderr);
    }

    pub fn get_program(&self) -> &OsStr {
        &self.program
    }

    pub fn get_args(&self) -> CommandArgs<'_> {
        let mut iter = self.args.iter();
        iter.next();
        CommandArgs { iter }
    }

    pub fn get_envs(&self) -> CommandEnvs<'_> {
        self.env.iter()
    }

    pub fn get_env_clear(&self) -> bool {
        self.env.does_clear()
    }

    pub fn get_current_dir(&self) -> Option<&Path> {
        self.cwd.as_ref().map(|cs| Path::new(cs))
    }

    pub fn spawn(
        &mut self,
        _default: Stdio,
        _needs_stdin: bool,
    ) -> io::Result<(Process, StdioPipes)> {
        // Build null-terminated argument list.
        let prog_c = CString::new(self.program.as_bytes())
            .map_err(|_| io::const_error!(io::ErrorKind::InvalidInput, "nul in program name"))?;

        let args_c: Vec<CString> = self
            .args
            .iter()
            .map(|a| {
                CString::new(a.as_bytes())
                    .map_err(|_| io::const_error!(io::ErrorKind::InvalidInput, "nul in argument"))
            })
            .collect::<io::Result<Vec<_>>>()?;

        let mut argv_ptrs: Vec<*const u8> =
            args_c.iter().map(|a| a.as_ptr() as *const u8).collect();
        argv_ptrs.push(core::ptr::null());

        // Build environment (inherit current env for now, with modifications).
        // For simplicity, pass a minimal envp with just a NULL terminator.
        // Full env support would require iterating current env + applying changes.
        let envp: [*const u8; 1] = [core::ptr::null()];

        let pid = cvt(unsafe { vproc::fork() })?;

        if pid == 0 {
            // Child process.
            // Change directory if requested.
            if let Some(ref dir) = self.cwd {
                if let Ok(dir_c) = CString::new(dir.as_bytes()) {
                    let ret = unsafe { vibix_abi::fs::chdir(dir_c.as_ptr() as *const u8) };
                    if ret < 0 {
                        unsafe { vproc::exit(127) };
                    }
                } else {
                    // Path contains NUL byte -- cannot chdir.
                    unsafe { vproc::exit(127) };
                }
            }

            // exec
            unsafe {
                vproc::execve(prog_c.as_ptr() as *const u8, argv_ptrs.as_ptr(), envp.as_ptr());
            }
            // If execve returns, it failed. Exit with error code.
            unsafe { vproc::exit(127) };
        }

        // Parent process.
        let pipes = StdioPipes { stdin: None, stdout: None, stderr: None };
        Ok((Process { pid: pid as u32 }, pipes))
    }
}

pub fn output(cmd: &mut Command) -> io::Result<(ExitStatus, Vec<u8>, Vec<u8>)> {
    let (mut process, _pipes) = cmd.spawn(Stdio::Inherit, false)?;
    let status = process.wait()?;
    Ok((status, Vec::new(), Vec::new()))
}

impl From<ChildPipe> for Stdio {
    fn from(pipe: ChildPipe) -> Stdio {
        Stdio::InheritPipe(pipe)
    }
}

impl From<io::Stdout> for Stdio {
    fn from(_: io::Stdout) -> Stdio {
        Stdio::ParentStdout
    }
}

impl From<io::Stderr> for Stdio {
    fn from(_: io::Stderr) -> Stdio {
        Stdio::ParentStderr
    }
}

impl From<File> for Stdio {
    fn from(file: File) -> Stdio {
        Stdio::InheritFile(file)
    }
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            let mut debug_command = f.debug_struct("Command");
            debug_command.field("program", &self.program).field("args", &self.args);
            if !self.env.is_unchanged() {
                debug_command.field("env", &self.env);
            }
            if self.cwd.is_some() {
                debug_command.field("cwd", &self.cwd);
            }
            debug_command.finish()
        } else {
            if let Some(ref cwd) = self.cwd {
                write!(f, "cd {cwd:?} && ")?;
            }
            if self.env.does_clear() {
                write!(f, "env -i ")?;
            } else {
                let mut any_removed = false;
                for (key, value_opt) in self.get_envs() {
                    if value_opt.is_none() {
                        if !any_removed {
                            write!(f, "env ")?;
                            any_removed = true;
                        }
                        write!(f, "-u {} ", key.to_string_lossy())?;
                    }
                }
            }
            for (key, value_opt) in self.get_envs() {
                if let Some(value) = value_opt {
                    write!(f, "{}={value:?} ", key.to_string_lossy())?;
                }
            }
            if self.program != self.args[0] {
                write!(f, "[{:?}] ", self.program)?;
            }
            write!(f, "{:?}", self.args[0])?;
            for arg in &self.args[1..] {
                write!(f, " {:?}", arg)?;
            }
            Ok(())
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// ExitStatus
////////////////////////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub struct ExitStatus(i32);

impl ExitStatus {
    pub fn exit_ok(&self) -> Result<(), ExitStatusError> {
        if self.0 == 0 { Ok(()) } else { Err(ExitStatusError(self.0)) }
    }

    pub fn code(&self) -> Option<i32> {
        // If exited normally (bits 0-6 of wait status == 0), the exit code is bits 8-15.
        if self.0 & 0x7f == 0 { Some((self.0 >> 8) & 0xff) } else { None }
    }
}

impl fmt::Display for ExitStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(code) = self.code() {
            write!(f, "exit status: {code}")
        } else {
            write!(f, "signal: {}", self.0 & 0x7f)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// ExitStatusError
////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ExitStatusError(i32);

impl Into<ExitStatus> for ExitStatusError {
    fn into(self) -> ExitStatus {
        ExitStatus(self.0)
    }
}

impl ExitStatusError {
    pub fn code(self) -> Option<NonZero<i32>> {
        let code = (self.0 >> 8) & 0xff;
        NonZero::new(code)
    }
}

////////////////////////////////////////////////////////////////////////////////
// ExitCode
////////////////////////////////////////////////////////////////////////////////

#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub struct ExitCode(u8);

impl ExitCode {
    pub const SUCCESS: ExitCode = ExitCode(0);
    pub const FAILURE: ExitCode = ExitCode(1);

    pub fn as_i32(&self) -> i32 {
        self.0 as i32
    }
}

impl From<u8> for ExitCode {
    fn from(code: u8) -> Self {
        Self(code)
    }
}

////////////////////////////////////////////////////////////////////////////////
// Process
////////////////////////////////////////////////////////////////////////////////

pub struct Process {
    pid: u32,
}

impl Process {
    pub fn id(&self) -> u32 {
        self.pid
    }

    pub fn kill(&mut self) -> io::Result<()> {
        cvt(unsafe { vproc::kill(self.pid as i32, vproc::SIGKILL) })?;
        Ok(())
    }

    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let mut status: i32 = 0;
        loop {
            let ret = cvt(unsafe { vproc::wait4(self.pid as i32, &mut status, 0, 0) })?;
            if ret == self.pid as i64 {
                return Ok(ExitStatus(status));
            }
        }
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut status: i32 = 0;
        let ret = cvt(unsafe { vproc::wait4(self.pid as i32, &mut status, vproc::WNOHANG, 0) })?;
        if ret == 0 {
            Ok(None)
        } else if ret == self.pid as i64 {
            Ok(Some(ExitStatus(status)))
        } else {
            // Unexpected pid returned; treat as not yet exited.
            Ok(None)
        }
    }
}

////////////////////////////////////////////////////////////////////////////////
// CommandArgs
////////////////////////////////////////////////////////////////////////////////

pub struct CommandArgs<'a> {
    iter: crate::slice::Iter<'a, OsString>,
}

impl<'a> Iterator for CommandArgs<'a> {
    type Item = &'a OsStr;
    fn next(&mut self) -> Option<&'a OsStr> {
        self.iter.next().map(|os| &**os)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl<'a> ExactSizeIterator for CommandArgs<'a> {
    fn len(&self) -> usize {
        self.iter.len()
    }
    fn is_empty(&self) -> bool {
        self.iter.is_empty()
    }
}

impl<'a> fmt::Debug for CommandArgs<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter.clone()).finish()
    }
}

////////////////////////////////////////////////////////////////////////////////
// Pipe / getpid
////////////////////////////////////////////////////////////////////////////////

pub type ChildPipe = Pipe;

pub fn read_output(
    out: ChildPipe,
    stdout: &mut Vec<u8>,
    err: ChildPipe,
    stderr: &mut Vec<u8>,
) -> io::Result<()> {
    // Simple sequential read: read stdout to completion, then stderr.
    out.read_to_end(stdout)?;
    err.read_to_end(stderr)?;
    Ok(())
}

pub fn getpid() -> u32 {
    unsafe { vproc::getpid() as u32 }
}
