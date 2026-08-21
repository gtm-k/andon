//! The sandboxed spawn: default-deny environment, wall-clock timeout,
//! process-tree kill, best-effort limits.
//!
//! # The kill boundary, per OS, stated exactly
//!
//! - **Windows:** the child is assigned to a job object with
//!   `KILL_ON_JOB_CLOSE`. Processes it spawns after assignment are in the job
//!   automatically; terminating the job, or closing its last handle, kills the
//!   tree. The assignment happens immediately after spawn rather than
//!   atomically with it, so a process that spawned a child in that microsecond
//!   window would race the job — in practice the shell has not parsed its
//!   command line yet.
//! - **Unix:** the child starts its own process group (`setpgid` before exec),
//!   and the kill is `SIGKILL` to the group — which reaps everything that
//!   stayed in the group, and misses a grandchild that called `setsid`. That
//!   gap is named in the crate documentation and in `docs/sandbox.md`; this
//!   module must not be cited as killing "the entire tree" unqualified.
//!
//! Both sweeps run on *every* exit, not only on timeout: a suite that passes
//! while leaving a daemon behind has still left a process the measurement
//! spawned, and the measurement cleans up what it starts.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use andon_core::engine::{ExecOutcome, ExecSpec};

use crate::SandboxError;

/// How much of each output stream the outcome keeps, from the end.
const TAIL_BYTES: usize = 16 * 1024;

/// How often the wait loop polls the child.
const POLL: Duration = Duration::from_millis(25);

/// Run one command in `workdir` under the sandbox rules.
pub fn run(workdir: &Path, spec: &ExecSpec) -> Result<ExecOutcome, SandboxError> {
    let mut command = shell_command(&spec.command);
    command
        .current_dir(workdir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();

    // Default-deny: the base list, the operator's additions, nothing else.
    for (key, value) in std::env::vars_os() {
        let Some(name) = key.to_str() else { continue };
        if allowed(name, &spec.env_allow) {
            command.env(&key, &value);
        }
    }
    // The one variable the sandbox adds, so a suite can tell it is inside one.
    command.env("ANDON_SANDBOX", "1");

    platform::prepare(&mut command, spec);

    let started = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|e| SandboxError::Spawn(format!("{}: {e}", spec.command)))?;

    // Platform containment attaches to the live child (the job object on
    // Windows). On failure the child is killed rather than run uncontained: a
    // sandbox that cannot contain must not proceed as if it had.
    let containment = match platform::contain(&child, spec) {
        Ok(containment) => containment,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(SandboxError::Spawn(format!(
                "the process tree could not be contained, so the command was not run: {e}"
            )));
        }
    };

    let stdout = tail_reader(child.stdout.take());
    let stderr = tail_reader(child.stderr.take());

    let deadline = started + Duration::from_millis(u64::from(spec.timeout_ms));
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(e) => {
                platform::kill_tree(&child, &containment);
                let _ = child.wait();
                return Err(SandboxError::Spawn(format!("waiting on the child: {e}")));
            }
        }
        if Instant::now() >= deadline {
            timed_out = true;
            platform::kill_tree(&child, &containment);
            break child
                .wait()
                .map_err(|e| SandboxError::Spawn(format!("reaping the killed child: {e}")))?;
        }
        std::thread::sleep(POLL);
    };

    // The sweep. However the command ended, nothing it started outlives it.
    platform::kill_tree(&child, &containment);
    drop(containment);

    let stdout_tail = stdout
        .join()
        .unwrap_or_else(|_| "(the stdout reader panicked)".to_string());
    let stderr_tail = stderr
        .join()
        .unwrap_or_else(|_| "(the stderr reader panicked)".to_string());

    Ok(ExecOutcome {
        // A timed-out child's status is the kill's, not the suite's; reporting
        // it as an exit code would let a kill artifact impersonate a result.
        exit_code: if timed_out { None } else { status.code() },
        timed_out,
        duration_ms: started.elapsed().as_millis() as u64,
        stdout_tail,
        stderr_tail,
    })
}

/// Whether one environment variable crosses the boundary.
///
/// Windows environment names are case-insensitive, so the comparison is; a
/// deny that let `Path` through while blocking `PATH` would be no deny at all.
fn allowed(name: &str, extra: &[String]) -> bool {
    let matches = |candidate: &str| {
        if cfg!(windows) {
            candidate.eq_ignore_ascii_case(name)
        } else {
            candidate == name
        }
    };
    crate::BASE_ENV_ALLOW.iter().any(|base| matches(base))
        || extra.iter().any(|extra| matches(extra))
}

/// The user's command line, handed to the platform shell verbatim.
#[cfg(windows)]
fn shell_command(command_line: &str) -> Command {
    use std::os::windows::process::CommandExt;
    let mut command = Command::new("cmd");
    // `raw_arg`, because std's argument quoting is for programs that parse
    // their command line the C way, which cmd.exe does not. `/S` plus one
    // outer quote pair is cmd's own documented shape for an arbitrary command
    // line: it strips exactly the outer quotes and evaluates the rest
    // verbatim. Without it, cmd's legacy heuristic eats the first and last
    // quote of any line that starts with one — `"probe" run "file"` became
    // `probe" run "file` and nothing with two quoted paths could run.
    command.raw_arg(format!("/S /C \"{command_line}\""));
    command
}

/// The user's command line, handed to the platform shell verbatim.
#[cfg(not(windows))]
fn shell_command(command_line: &str) -> Command {
    let mut command = Command::new("sh");
    command.arg("-c").arg(command_line);
    command
}

/// Collect the last [`TAIL_BYTES`] of one stream without ever holding more
/// than twice that, whatever the suite prints.
fn tail_reader<R: Read + Send + 'static>(stream: Option<R>) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let Some(mut stream) = stream else {
            return String::new();
        };
        let mut tail: Vec<u8> = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    tail.extend_from_slice(&chunk[..n]);
                    if tail.len() > 2 * TAIL_BYTES {
                        tail.drain(..tail.len() - TAIL_BYTES);
                    }
                }
                Err(_) => break,
            }
        }
        if tail.len() > TAIL_BYTES {
            tail.drain(..tail.len() - TAIL_BYTES);
        }
        String::from_utf8_lossy(&tail).into_owned()
    })
}

#[cfg(windows)]
mod platform {
    //! Job-object containment.

    use std::os::windows::io::AsRawHandle;
    use std::process::{Child, Command};

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    use andon_core::engine::ExecSpec;

    /// An owned job-object handle. Closing it (drop) kills whatever is still
    /// in the job, which is the sweep.
    #[derive(Debug)]
    pub struct Containment {
        job: HANDLE,
    }

    // HANDLEs are not Send by default spelling, but a job handle is a kernel
    // object reference and moving it between threads is fine.
    unsafe impl Send for Containment {}

    impl Drop for Containment {
        fn drop(&mut self) {
            // KILL_ON_JOB_CLOSE turns this close into the final sweep.
            unsafe { CloseHandle(self.job) };
        }
    }

    /// Nothing to do before spawn on Windows; the job attaches after.
    pub fn prepare(_command: &mut Command, _spec: &ExecSpec) {}

    /// Create the job, set its limits, and put the child in it.
    pub fn contain(child: &Child, spec: &ExecSpec) -> Result<Containment, String> {
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err("CreateJobObject failed".to_string());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Some(mib) = spec.memory_limit_mb {
                info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
                info.JobMemoryLimit = (mib as usize).saturating_mul(1024 * 1024);
            }
            let ok = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(job);
                return Err("SetInformationJobObject failed".to_string());
            }
            if AssignProcessToJobObject(job, child.as_raw_handle() as HANDLE) == 0 {
                CloseHandle(job);
                return Err("AssignProcessToJobObject failed".to_string());
            }
            Ok(Containment { job })
        }
    }

    /// Kill everything in the job. Idempotent; the drop's close sweeps again.
    pub fn kill_tree(_child: &Child, containment: &Containment) {
        unsafe {
            TerminateJobObject(containment.job, 1);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    //! Process-group containment.

    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command};

    use andon_core::engine::ExecSpec;

    /// Unix needs no owned handle; the group id is the child's pid.
    #[derive(Debug)]
    pub struct Containment;

    /// Start the child in its own process group, with the address-space
    /// rlimit when one is configured. Runs after fork, before exec.
    pub fn prepare(command: &mut Command, spec: &ExecSpec) {
        let memory_limit = spec.memory_limit_mb;
        unsafe {
            command.pre_exec(move || {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if let Some(mib) = memory_limit {
                    let bytes = (mib as libc::rlim_t).saturating_mul(1024 * 1024);
                    let limit = libc::rlimit {
                        rlim_cur: bytes,
                        rlim_max: bytes,
                    };
                    // Best-effort by contract: a kernel that refuses the
                    // limit does not stop the suite from running.
                    let _ = libc::setrlimit(libc::RLIMIT_AS, &limit);
                }
                Ok(())
            });
        }
    }

    /// The group exists because `prepare` created it; nothing more to attach.
    pub fn contain(_child: &Child, _spec: &ExecSpec) -> Result<Containment, String> {
        Ok(Containment)
    }

    /// SIGKILL the child's process group. Misses a grandchild that called
    /// `setsid` — the named gap; see the module documentation.
    pub fn kill_tree(child: &Child, _containment: &Containment) {
        let pid = child.id() as libc::pid_t;
        unsafe {
            libc::kill(-pid, libc::SIGKILL);
        }
    }
}
