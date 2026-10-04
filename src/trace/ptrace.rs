use std::io;

// This is the fixed Linux UAPI layout, including the alignment before the union.
// The union is stored as words so we never read an inactive Rust union member.
#[repr(C)]
#[derive(Default)]
pub struct SyscallInfo {
    pub op: u8,
    pad: [u8; 3],
    pub arch: u32,
    instruction_pointer: u64,
    stack_pointer: u64,
    pub data: [u64; 8],
}

pub fn ptrace(request: u32, tid: i32, addr: usize, data: usize) -> io::Result<i64> {
    // The request determines whether addr/data are integers or pointers. Callers
    // provide live, suitably sized buffers for requests that write through data.
    let result = unsafe { libc::ptrace(request, tid, addr, data) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

pub fn wait() -> io::Result<(i32, i32)> {
    let mut status = 0;
    // status is writable; __WALL includes ptrace stops from individual threads.
    let tid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
    if tid < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok((tid, status))
    }
}
