//! Job table and signal handling for the POSIX shell.
//!
//! This module implements:
//! - A job table that tracks background and stopped processes.
//! - Signal constants and raw syscall wrappers for signal handling.
//! - Process group management helpers.
//!
//! ## Job lifecycle
//!
//! 1. A command followed by `&` creates a background job.
//! 2. Ctrl-Z (SIGTSTP) stops the foreground job, which becomes a
//!    stopped job in the table.
//! 3. `fg` brings a job to the foreground, sending SIGCONT if stopped.
//! 4. `bg` resumes a stopped job in the background via SIGCONT.
//! 5. `jobs` lists all active jobs.
//!
//! ## Signal handling
//!
//! When interactive, the shell ignores SIGINT and SIGTSTP so it stays
//! alive while forwarding these signals to the foreground process group
//! via the TTY's ISIG mechanism.

// ── Signal constants ─────────────────────────────────────────────

pub const SIGINT: i32 = 2;
pub const SIGTSTP: i32 = 20;
pub const SIGCONT: i32 = 18;
pub const SIGCHLD: i32 = 17;
pub const SIGTTOU: i32 = 22;
pub const SIGTTIN: i32 = 21;

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

// ── Wait status helpers ──────────────────────────────────────────

/// WNOHANG — return immediately if no child has exited.
pub const WNOHANG: i32 = 1;
/// WUNTRACED — also return if a child has stopped.
pub const WUNTRACED: i32 = 2;

/// Extract the exit code from a wait status (assumes normal exit).
pub fn wexitstatus(status: i32) -> i32 {
    (((status as u32) >> 8) & 0xFF) as i32
}

/// Check if the process exited normally.
pub fn wifexited(status: i32) -> bool {
    (status & 0x7F) == 0
}

/// Check if the process was stopped by a signal.
pub fn wifstopped(status: i32) -> bool {
    (status & 0xFF) == 0x7F
}

/// Check if the process was terminated by a signal.
pub fn wifsignaled(status: i32) -> bool {
    let sig = status & 0x7F;
    sig != 0 && sig != 0x7F
}

/// Extract the stop signal from a wait status.
pub fn wstopsig(status: i32) -> i32 {
    (((status as u32) >> 8) & 0xFF) as i32
}

/// Extract the termination signal from a wait status.
pub fn wtermsig(status: i32) -> i32 {
    status & 0x7F
}

// ── Job state ────────────────────────────────────────────────────

/// The state of a job in the job table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    /// Currently running in the background.
    Running,
    /// Stopped (e.g. by SIGTSTP).
    Stopped,
    /// Completed with an exit code.
    Done(i32),
    /// Terminated by a signal.
    Terminated(i32),
}

impl std::fmt::Display for JobStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JobStatus::Running => write!(f, "Running"),
            JobStatus::Stopped => write!(f, "Stopped"),
            JobStatus::Done(code) => write!(f, "Done({code})"),
            JobStatus::Terminated(sig) => write!(f, "Terminated({sig})"),
        }
    }
}

/// A single job tracked by the shell.
#[derive(Debug, Clone)]
pub struct Job {
    /// The job number (1-indexed, as shown by `jobs`).
    pub id: usize,
    /// The process group ID (typically the PID of the first process in
    /// the pipeline).
    pub pgid: i32,
    /// The PID of the last process in the pipeline (used for wait).
    pub pid: i32,
    /// Current status.
    pub status: JobStatus,
    /// The command string for display purposes.
    pub command: String,
}

// ── Job table ────────────────────────────────────────────────────

/// The shell's job table.
#[derive(Debug)]
pub struct JobTable {
    jobs: Vec<Job>,
    /// The next job ID to assign.
    next_id: usize,
}

impl JobTable {
    /// Create a new empty job table.
    pub fn new() -> Self {
        Self {
            jobs: Vec::new(),
            next_id: 1,
        }
    }

    /// Add a new job. Returns the assigned job ID.
    pub fn add(&mut self, pgid: i32, pid: i32, command: String) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        self.jobs.push(Job {
            id,
            pgid,
            pid,
            status: JobStatus::Running,
            command,
        });
        id
    }

    /// Get a reference to a job by its job ID.
    pub fn get(&self, id: usize) -> Option<&Job> {
        self.jobs.iter().find(|j| j.id == id)
    }

    /// Get a mutable reference to a job by its job ID.
    pub fn get_mut(&mut self, id: usize) -> Option<&mut Job> {
        self.jobs.iter_mut().find(|j| j.id == id)
    }

    /// Find a job by PID (any PID in the job).
    pub fn find_by_pid(&mut self, pid: i32) -> Option<&mut Job> {
        self.jobs.iter_mut().find(|j| j.pid == pid || j.pgid == pid)
    }

    /// Get the most recent job (highest ID that is Running or Stopped).
    pub fn current_job(&self) -> Option<&Job> {
        self.jobs
            .iter()
            .rev()
            .find(|j| matches!(j.status, JobStatus::Running | JobStatus::Stopped))
    }

    /// Get the most recent job ID (Running or Stopped).
    pub fn current_job_id(&self) -> Option<usize> {
        self.current_job().map(|j| j.id)
    }

    /// Remove all completed/terminated jobs from the table, printing
    /// notifications for any that just finished.
    pub fn reap_completed(&mut self) -> Vec<Job> {
        let mut reaped = Vec::new();
        self.jobs.retain(|j| {
            if matches!(j.status, JobStatus::Done(_) | JobStatus::Terminated(_)) {
                reaped.push(j.clone());
                false
            } else {
                true
            }
        });
        reaped
    }

    /// List all active jobs.
    pub fn active_jobs(&self) -> &[Job] {
        &self.jobs
    }

    /// Update a job's status by PID. Returns true if a job was found.
    pub fn update_by_pid(&mut self, pid: i32, status: JobStatus) -> bool {
        if let Some(job) = self.find_by_pid(pid) {
            job.status = status;
            true
        } else {
            false
        }
    }
}

impl Default for JobTable {
    fn default() -> Self {
        Self::new()
    }
}

// ── Extern C declarations (signal/process group) ─────────────────

#[cfg(not(test))]
extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn getpid() -> i32;
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn __errno_location() -> *mut i32;
}

// ── Signal installation ──────────────────────────────────────────

/// sigaction structure matching the Linux x86_64 ABI.
#[cfg(not(test))]
#[repr(C)]
struct SigAction {
    sa_handler: usize,
    sa_flags: u64,
    sa_restorer: usize,
    sa_mask: u64,
}

#[cfg(not(test))]
extern "C" {
    fn sigaction(signum: i32, act: *const SigAction, oldact: *mut SigAction) -> i32;
}

/// Install a signal disposition (SIG_IGN or SIG_DFL) for the given
/// signal. This is a thin wrapper around the sigaction syscall.
///
/// Returns 0 on success, -1 on error.
#[cfg(not(test))]
pub fn set_signal_disposition(sig: i32, handler: usize) -> i32 {
    let act = SigAction {
        sa_handler: handler,
        sa_flags: 0,
        sa_restorer: 0,
        sa_mask: 0,
    };
    unsafe { sigaction(sig, &act, std::ptr::null_mut()) }
}

/// No-op in tests.
#[cfg(test)]
pub fn set_signal_disposition(_sig: i32, _handler: usize) -> i32 {
    0
}

/// Set up the shell's interactive signal handlers: ignore SIGINT,
/// SIGTSTP, and SIGTTOU so the shell process itself is not killed
/// or stopped.
pub fn install_interactive_signals() {
    set_signal_disposition(SIGINT, SIG_IGN);
    set_signal_disposition(SIGTSTP, SIG_IGN);
    set_signal_disposition(SIGTTOU, SIG_IGN);
    set_signal_disposition(SIGTTIN, SIG_IGN);
}

/// Restore default signal handlers (used in child processes before
/// execve so the child gets the default behavior).
pub fn restore_default_signals() {
    set_signal_disposition(SIGINT, SIG_DFL);
    set_signal_disposition(SIGTSTP, SIG_DFL);
    set_signal_disposition(SIGTTOU, SIG_DFL);
    set_signal_disposition(SIGTTIN, SIG_DFL);
}

// ── Process group helpers ────────────────────────────────────────

/// Set the process group of `pid` to `pgid`. If both are 0, the
/// calling process is moved to its own process group.
#[cfg(not(test))]
pub fn set_process_group(pid: i32, pgid: i32) -> i32 {
    unsafe { setpgid(pid, pgid) }
}

#[cfg(test)]
pub fn set_process_group(_pid: i32, _pgid: i32) -> i32 {
    0
}

/// Get the shell's PID.
#[cfg(not(test))]
pub fn shell_getpid() -> i32 {
    unsafe { getpid() }
}

#[cfg(test)]
pub fn shell_getpid() -> i32 {
    1000
}

/// Send a signal to a process or process group.
/// If `pid` is negative, the signal is sent to the process group
/// whose PGID is `abs(pid)`.
#[cfg(not(test))]
pub fn send_signal(pid: i32, sig: i32) -> i32 {
    unsafe { kill(pid, sig) }
}

#[cfg(test)]
pub fn send_signal(_pid: i32, _sig: i32) -> i32 {
    0
}

/// Reap any finished background children without blocking.
/// Updates the job table with their exit status.
#[cfg(not(test))]
pub fn reap_children(jobs: &mut JobTable) {
    loop {
        let mut wstatus: i32 = 0;
        let pid = unsafe {
            crate::exec::wait4_raw(-1, &mut wstatus, WNOHANG | WUNTRACED, std::ptr::null())
        };
        if pid <= 0 {
            break;
        }
        let status = if wifstopped(wstatus) {
            JobStatus::Stopped
        } else if wifsignaled(wstatus) {
            JobStatus::Terminated(wtermsig(wstatus))
        } else {
            JobStatus::Done(wexitstatus(wstatus))
        };
        jobs.update_by_pid(pid, status);
    }
}

#[cfg(test)]
pub fn reap_children(_jobs: &mut JobTable) {
    // No-op in tests.
}

/// Print notifications for completed background jobs and remove them
/// from the table.
pub fn notify_completed_jobs(jobs: &mut JobTable) {
    let reaped = jobs.reap_completed();
    for job in &reaped {
        eprintln!("[{}]\t{}\t{}", job.id, job.status, job.command);
    }
}

// ── Tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Wait status helpers ──────────────────────────────────────

    #[test]
    fn wexitstatus_normal() {
        // Normal exit with code 42: status = 42 << 8 = 0x2A00
        let status = 42 << 8;
        assert!(wifexited(status));
        assert_eq!(wexitstatus(status), 42);
        assert!(!wifstopped(status));
        assert!(!wifsignaled(status));
    }

    #[test]
    fn wifstopped_by_tstp() {
        // Stopped by SIGTSTP(20): status = (20 << 8) | 0x7F = 0x147F
        let status = (SIGTSTP << 8) | 0x7F;
        assert!(wifstopped(status));
        assert_eq!(wstopsig(status), SIGTSTP);
        assert!(!wifexited(status));
        assert!(!wifsignaled(status));
    }

    #[test]
    fn wifsignaled_by_int() {
        // Killed by SIGINT(2): status = 2
        let status = SIGINT;
        assert!(wifsignaled(status));
        assert_eq!(wtermsig(status), SIGINT);
        assert!(!wifexited(status));
        assert!(!wifstopped(status));
    }

    // ── JobStatus display ────────────────────────────────────────

    #[test]
    fn job_status_display() {
        assert_eq!(format!("{}", JobStatus::Running), "Running");
        assert_eq!(format!("{}", JobStatus::Stopped), "Stopped");
        assert_eq!(format!("{}", JobStatus::Done(0)), "Done(0)");
        assert_eq!(format!("{}", JobStatus::Terminated(9)), "Terminated(9)");
    }

    // ── JobTable ─────────────────────────────────────────────────

    #[test]
    fn add_and_get_job() {
        let mut table = JobTable::new();
        let id = table.add(100, 100, "sleep 10 &".to_string());
        assert_eq!(id, 1);
        let job = table.get(id).unwrap();
        assert_eq!(job.pgid, 100);
        assert_eq!(job.pid, 100);
        assert_eq!(job.status, JobStatus::Running);
        assert_eq!(job.command, "sleep 10 &");
    }

    #[test]
    fn add_multiple_jobs() {
        let mut table = JobTable::new();
        let id1 = table.add(10, 10, "cmd1 &".to_string());
        let id2 = table.add(20, 20, "cmd2 &".to_string());
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(table.active_jobs().len(), 2);
    }

    #[test]
    fn find_by_pid() {
        let mut table = JobTable::new();
        table.add(100, 100, "cmd &".to_string());
        assert!(table.find_by_pid(100).is_some());
        assert!(table.find_by_pid(999).is_none());
    }

    #[test]
    fn current_job() {
        let mut table = JobTable::new();
        table.add(10, 10, "cmd1 &".to_string());
        table.add(20, 20, "cmd2 &".to_string());
        let current = table.current_job().unwrap();
        assert_eq!(current.id, 2); // most recent
    }

    #[test]
    fn current_job_skips_done() {
        let mut table = JobTable::new();
        table.add(10, 10, "cmd1 &".to_string());
        let id2 = table.add(20, 20, "cmd2 &".to_string());
        table.get_mut(id2).unwrap().status = JobStatus::Done(0);
        let current = table.current_job().unwrap();
        assert_eq!(current.id, 1); // only running job
    }

    #[test]
    fn reap_completed() {
        let mut table = JobTable::new();
        table.add(10, 10, "cmd1 &".to_string());
        let id2 = table.add(20, 20, "cmd2 &".to_string());
        table.get_mut(id2).unwrap().status = JobStatus::Done(0);
        let reaped = table.reap_completed();
        assert_eq!(reaped.len(), 1);
        assert_eq!(reaped[0].id, 2);
        assert_eq!(table.active_jobs().len(), 1);
    }

    #[test]
    fn update_by_pid() {
        let mut table = JobTable::new();
        table.add(100, 100, "cmd &".to_string());
        assert!(table.update_by_pid(100, JobStatus::Stopped));
        assert_eq!(table.get(1).unwrap().status, JobStatus::Stopped);
    }

    #[test]
    fn update_by_pid_not_found() {
        let mut table = JobTable::new();
        assert!(!table.update_by_pid(999, JobStatus::Done(0)));
    }

    #[test]
    fn current_job_empty_table() {
        let table = JobTable::new();
        assert!(table.current_job().is_none());
    }

    #[test]
    fn current_job_id() {
        let mut table = JobTable::new();
        assert!(table.current_job_id().is_none());
        table.add(10, 10, "cmd &".to_string());
        assert_eq!(table.current_job_id(), Some(1));
    }
}
