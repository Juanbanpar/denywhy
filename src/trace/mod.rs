pub mod memory;
mod privileged;
mod ptrace;
mod signals;
use ptrace::{SyscallInfo, ptrace, wait};
use std::time::SystemTime;
pub mod syscall;

use std::collections::HashMap;
use std::ffi::{CString, OsString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

pub struct Failure {
    pub tid: i32,
    pub number: u64,
    pub arch: u32,
    pub args: [u64; 6],
    pub errno: i32,
    pub decoded: Option<syscall::DecodedCall>,
    pub limitations: Vec<String>,
    pub context: Option<crate::procfs::status::ProcessContext>,
    pub paths: Vec<crate::fs::path::Walk>,
    pub causes: Vec<crate::model::Cause>,
    pub mounts: Vec<serde_json::Value>,
    pub timestamp: SystemTime,
}

pub struct Outcome {
    pub code: i32,
    pub failures: Vec<Failure>,
    pub signal: Option<i32>,
}

fn executable(command: &OsString) -> PathBuf {
    if command.as_bytes().contains(&b'/') {
        return PathBuf::from(command);
    }
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            let candidate = directory.join(command);
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(command)
}

pub fn run(command: &[OsString], redirect_stdout: bool) -> io::Result<Outcome> {
    let program = executable(&command[0]);
    privileged::check(&PathBuf::from("/"), &program, 0)
        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;
    let executable = CString::new(program.as_os_str().as_bytes())?;
    signals::install()?;
    let arguments: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()?;
    let mut argv: Vec<*const libc::c_char> = arguments.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    // All strings and pointer arrays are prepared before fork. The child performs
    // only kernel/libc operations that do not acquire Rust allocator locks.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(io::Error::last_os_error());
    }
    if child == 0 {
        // These buffers remain live in the forked address space through execv.
        unsafe {
            signals::reset_child();
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) == -1 {
                libc::_exit(125);
            }
            if redirect_stdout && libc::dup2(libc::STDERR_FILENO, libc::STDOUT_FILENO) < 0 {
                libc::_exit(125);
            }
            libc::raise(libc::SIGSTOP);
            libc::execv(executable.as_ptr(), argv.as_ptr());
            libc::_exit(if *libc::__errno_location() == libc::ENOENT {
                127
            } else {
                126
            });
        }
    }
    trace(child)
}

struct PendingSyscall {
    arch: u32,
    number: u64,
    args: [u64; 6],
    decoded: Result<Option<syscall::DecodedCall>, String>,
    timestamp: SystemTime,
    context: Option<crate::procfs::status::ProcessContext>,
}
#[derive(Default)]
struct Tracee {
    pending: Option<PendingSyscall>,
    newborn: bool,
}
struct Tracees {
    threads: HashMap<i32, Tracee>,
}
impl Drop for Tracees {
    fn drop(&mut self) {
        for tid in self.threads.keys() {
            // Only children tracked by this tracer are killed. ESRCH means that
            // a thread already exited; cleanup must tolerate that race.
            unsafe {
                libc::kill(*tid, libc::SIGKILL);
            }
        }
        if self.threads.is_empty() {
            return;
        }
        loop {
            match wait() {
                Ok((tid, status)) if libc::WIFSTOPPED(status) => {
                    // A fork/exit event can still be pending after SIGKILL.
                    unsafe {
                        libc::kill(tid, libc::SIGKILL);
                    }
                    let _ = ptrace(libc::PTRACE_CONT, tid, 0, 0);
                }
                Ok(_) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
                Err(_) => break,
            }
        }
    }
}

fn trace(child: i32) -> io::Result<Outcome> {
    let mut tracees = Tracees {
        threads: HashMap::from([(child, Tracee::default())]),
    };
    let (_, status) = wait_for_tracees(&tracees)?;
    if !libc::WIFSTOPPED(status) {
        tracees.threads.clear();
        return Err(io::Error::other(format!(
            "PTRACE_TRACEME unavailable: child status {status}; tracing may be restricted by the host"
        )));
    }
    ptrace(
        libc::PTRACE_SETOPTIONS,
        child,
        0,
        (libc::PTRACE_O_TRACESYSGOOD
            | libc::PTRACE_O_TRACEFORK
            | libc::PTRACE_O_TRACEVFORK
            | libc::PTRACE_O_TRACECLONE
            | libc::PTRACE_O_TRACEEXEC
            | libc::PTRACE_O_TRACEEXIT
            | libc::PTRACE_O_EXITKILL) as usize,
    )?;
    let mut failures = Vec::new();
    let mut main_exit = None;
    ptrace(libc::PTRACE_SYSCALL, child, 0, 0)?;
    while !tracees.threads.is_empty() {
        let (tid, status) = wait_for_tracees(&tracees)?;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            tracees.threads.remove(&tid);
            if tid == child {
                main_exit = Some(if libc::WIFEXITED(status) {
                    (libc::WEXITSTATUS(status), None)
                } else {
                    (128 + libc::WTERMSIG(status), Some(libc::WTERMSIG(status)))
                });
            }
            continue;
        }
        if !libc::WIFSTOPPED(status) {
            continue;
        }
        let signal = libc::WSTOPSIG(status);
        let event = status >> 16;
        // A newborn can report its initial SIGSTOP before its parent's fork
        // event is consumed. Keep its state instead of resetting it later.
        tracees.threads.entry(tid).or_insert_with(|| Tracee {
            newborn: true,
            pending: None,
        });
        let mut delivery = 0;
        if signal == (libc::SIGTRAP | 0x80) {
            syscall_stop(tid, tracees.threads.get_mut(&tid).unwrap(), &mut failures)?;
        } else if signal == libc::SIGTRAP && event != 0 {
            match event {
                libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                    let new_tid = event_message(tid)? as i32;
                    tracees.threads.entry(new_tid).or_insert_with(|| Tracee {
                        newborn: true,
                        pending: None,
                    });
                }
                libc::PTRACE_EVENT_EXEC => {
                    let old_tid = event_message(tid)? as i32;
                    // exec from a nonleader changes its TID to the group leader.
                    // Transfer pending entry state before consuming the exit stop.
                    if old_tid != tid
                        && let Some(old) = tracees.threads.remove(&old_tid)
                    {
                        tracees.threads.insert(tid, old);
                    }
                }
                libc::PTRACE_EVENT_EXIT => {}
                _ => {
                    return Err(io::Error::other(format!(
                        "unexpected ptrace event {event} for TID {tid}"
                    )));
                }
            }
        } else if signal == libc::SIGSTOP && tracees.threads.get(&tid).unwrap().newborn {
            tracees.threads.get_mut(&tid).unwrap().newborn = false;
        } else {
            delivery = signal;
        }
        if let Err(e) = ptrace(libc::PTRACE_SYSCALL, tid, 0, delivery as usize)
            && e.raw_os_error() != Some(libc::ESRCH)
        {
            return Err(e);
        }
    }
    let (code, signal) =
        main_exit.ok_or_else(|| io::Error::other("main command exit status was lost"))?;
    Ok(Outcome {
        code,
        failures,
        signal,
    })
}
fn event_message(tid: i32) -> io::Result<u64> {
    let mut message = 0u64;
    ptrace(
        libc::PTRACE_GETEVENTMSG,
        tid,
        0,
        &mut message as *mut _ as usize,
    )?;
    Ok(message)
}
fn wait_for_tracees(tracees: &Tracees) -> io::Result<(i32, i32)> {
    loop {
        signals::forward(tracees.threads.keys().copied());
        match wait() {
            Err(e) if e.raw_os_error() == Some(libc::EINTR) => continue,
            result => return result,
        }
    }
}
fn syscall_stop(tid: i32, tracee: &mut Tracee, failures: &mut Vec<Failure>) -> io::Result<()> {
    let mut info = SyscallInfo::default();
    let size = ptrace(
        libc::PTRACE_GET_SYSCALL_INFO,
        tid,
        std::mem::size_of::<SyscallInfo>(),
        &mut info as *mut _ as usize,
    )
    .map_err(|e| {
        if matches!(e.raw_os_error(), Some(libc::EINVAL | libc::EIO)) {
            io::Error::other("denywhy requires PTRACE_GET_SYSCALL_INFO (Linux >= 5.3)")
        } else {
            e
        }
    })?;
    match info.op {
        1 if size >= 80 => {
            let args = info.data[1..7].try_into().unwrap();
            // Read pointers at entry. Other threads can mutate pathname buffers,
            // fd tables, cwd or credentials while this thread is stopped.
            let decoded = syscall::decode(tid, info.arch, info.data[0], args);
            if let Ok(Some(call)) = &decoded
                && matches!(call.operation, syscall::Operation::Execute { .. })
            {
                let path = &call.paths[0];
                let base = path.base.as_ref().map_err(|e| {
                    io::Error::other(format!("privileged-exec inspection unavailable: {e}"))
                })?;
                let root = PathBuf::from(format!("/proc/{tid}/root"));
                let walk = crate::fs::path::walk(&root, base, &path.path, call.follows_final(0));
                if walk.limitation.is_none() && !walk.missing {
                    privileged::check(&root, &walk.target, 0)
                        .map_err(|e| io::Error::new(io::ErrorKind::Unsupported, e))?;
                }
            }
            let context = if matches!(decoded, Ok(Some(_))) {
                crate::procfs::status::capture(tid).ok()
            } else {
                None
            };
            tracee.pending = Some(PendingSyscall {
                arch: info.arch,
                number: info.data[0],
                args,
                decoded,
                timestamp: SystemTime::now(),
                context,
            });
        }
        2 if size >= 33 => {
            if let Some(pending) = tracee.pending.take() {
                let errno = -(info.data[0] as i64);
                if info.data[1] & 0xff != 0
                    && [libc::EACCES as i64, libc::EPERM as i64, libc::EROFS as i64]
                        .contains(&errno)
                {
                    let mut failure = capture_failure(tid, pending, errno as i32);
                    crate::analyze::analyze_denial(&mut failure);
                    failures.push(failure);
                }
            }
        }
        _ => {
            return Err(io::Error::other(format!(
                "incomplete syscall-info response for TID {tid}"
            )));
        }
    }
    Ok(())
}
fn capture_failure(tid: i32, pending: PendingSyscall, errno: i32) -> Failure {
    let (decoded, limitation) = match pending.decoded {
        Ok(call) => (call, None),
        Err(e) => (None, Some(e)),
    };
    let mut limitations: Vec<String> = limitation.into_iter().collect();
    let context = pending.context.or_else(|| {
        crate::procfs::status::capture(tid)
            .map_err(|e| limitations.push(format!("cannot capture /proc/{tid}/status: {e}")))
            .ok()
    });
    let paths = decoded
        .as_ref()
        .map(|call| {
            call.paths
                .iter()
                .enumerate()
                .filter_map(|(i, p)| {
                    p.base.as_ref().ok().map(|base| {
                        crate::fs::path::walk(
                            &PathBuf::from(format!("/proc/{tid}/root")),
                            base,
                            &p.path,
                            call.follows_final(i),
                        )
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    if let Some(call) = &decoded {
        for path in &call.paths {
            if let Err(e) = &path.base {
                limitations.push(e.clone());
            }
        }
    }
    Failure {
        tid,
        number: pending.number,
        arch: pending.arch,
        args: pending.args,
        errno,
        decoded,
        limitations,
        context,
        paths,
        causes: Vec::new(),
        mounts: Vec::new(),
        timestamp: pending.timestamp,
    }
}
