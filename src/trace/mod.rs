pub mod memory;
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
}

pub struct Outcome {
    pub code: i32,
    pub failures: Vec<Failure>,
}

// This is the fixed Linux UAPI layout, including the alignment before the union.
// The union is stored as words so we never read an inactive Rust union member.
#[repr(C)]
#[derive(Default)]
struct SyscallInfo {
    op: u8,
    pad: [u8; 3],
    arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    data: [u64; 8],
}

fn ptrace(request: u32, tid: i32, addr: usize, data: usize) -> io::Result<i64> {
    // The request determines whether addr/data are integers or pointers. Callers
    // provide live, suitably sized buffers for requests that write through data.
    let result = unsafe { libc::ptrace(request, tid, addr, data) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn wait() -> io::Result<(i32, i32)> {
    loop {
        let mut status = 0;
        // status is writable; __WALL includes ptrace stops from individual threads.
        let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
        if tid >= 0 {
            return Ok((tid, status));
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::EINTR) {
            return Err(error);
        }
    }
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
    let executable = CString::new(executable(&command[0]).as_os_str().as_bytes())?;
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
    let result = trace(child);
    if result.is_err() {
        // A fatal tracer error must not strand its child at a ptrace stop.
        unsafe { libc::kill(child, libc::SIGKILL) };
        while wait().is_ok() {}
    }
    result
}

fn trace(child: i32) -> io::Result<Outcome> {
    let (_, status) = wait()?;
    if !libc::WIFSTOPPED(status) {
        return Err(io::Error::other(format!(
            "PTRACE_TRACEME unavailable: child status {status}; tracing may be restricted by the host"
        )));
    }
    ptrace(
        libc::PTRACE_SETOPTIONS,
        child,
        0,
        (libc::PTRACE_O_TRACESYSGOOD | libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL) as usize,
    )?;
    let mut pending = HashMap::new();
    let mut failures = Vec::new();
    ptrace(libc::PTRACE_SYSCALL, child, 0, 0)?;
    loop {
        let (tid, status) = wait()?;
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            return Ok(Outcome {
                code: if libc::WIFEXITED(status) {
                    libc::WEXITSTATUS(status)
                } else {
                    128 + libc::WTERMSIG(status)
                },
                failures,
            });
        }
        let signal = libc::WSTOPSIG(status);
        if signal == libc::SIGTRAP | 0x80 {
            let mut info = SyscallInfo::default();
            let size = ptrace(
                libc::PTRACE_GET_SYSCALL_INFO,
                tid,
                std::mem::size_of::<SyscallInfo>(),
                &mut info as *mut _ as usize,
            )
            .map_err(|e| {
                if e.raw_os_error() == Some(libc::EINVAL) || e.raw_os_error() == Some(libc::EIO) {
                    io::Error::other("denywhy requires PTRACE_GET_SYSCALL_INFO (Linux >= 5.3)")
                } else {
                    e
                }
            })?;
            match info.op {
                1 if size >= 80 => {
                    let args = info.data[1..7].try_into().unwrap();
                    // Read pointers at entry: the application may alter or unmap
                    // the pathname before the corresponding exit stop.
                    let decoded = syscall::decode(tid, info.arch, info.data[0], args);
                    pending.insert(tid, (info.arch, info.data[0], args, decoded));
                }
                2 if size >= 33 => {
                    if let Some((arch, number, args, decoded)) = pending.remove(&tid) {
                        let errno = -(info.data[0] as i64);
                        if info.data[1] & 0xff != 0
                            && [libc::EACCES as i64, libc::EPERM as i64, libc::EROFS as i64]
                                .contains(&errno)
                        {
                            let (decoded, limitation) = match decoded {
                                Ok(call) => (call, None),
                                Err(e) => (None, Some(e)),
                            };
                            let mut limitations: Vec<String> = limitation.into_iter().collect();
                            let context = crate::procfs::status::capture(tid)
                                .map_err(|e| {
                                    limitations
                                        .push(format!("cannot capture /proc/{tid}/status: {e}"))
                                })
                                .ok();
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
                            failures.push(Failure {
                                tid,
                                number,
                                arch,
                                args,
                                errno: errno as i32,
                                decoded,
                                limitations,
                                context,
                                paths,
                            });
                        }
                    }
                }
                _ => {
                    return Err(io::Error::other(
                        "incomplete PTRACE_GET_SYSCALL_INFO response",
                    ));
                }
            }
        }
        let delivery = if signal == libc::SIGTRAP | 0x80 || status >> 16 != 0 {
            0
        } else {
            signal
        };
        ptrace(libc::PTRACE_SYSCALL, tid, 0, delivery as usize)?;
    }
}
