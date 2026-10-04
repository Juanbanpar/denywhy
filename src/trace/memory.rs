use std::io;

pub fn read_bytes(tid: i32, address: u64, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; max];
    let local = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: max,
    };
    let remote = libc::iovec {
        iov_base: address as usize as *mut libc::c_void,
        iov_len: max,
    };
    // The local buffer is writable for max bytes. The remote pointer is never
    // dereferenced by Rust: the kernel validates it in the tracee address space.
    let count = unsafe { libc::process_vm_readv(tid, &local, 1, &remote, 1, 0) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(count as usize);
    Ok(bytes)
}

pub fn read_c_string(tid: i32, address: u64, max: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    // Reading across an inaccessible following page can fail even when the NUL
    // is on the current page. Bound each transfer to a single page.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = if page > 0 { page as usize } else { 4096 };
    while bytes.len() < max {
        let current = address
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("pathname pointer overflow"))?;
        let count = (page - current as usize % page).min(max - bytes.len());
        let chunk = read_bytes(tid, current, count)?;
        if let Some(nul) = chunk.iter().position(|b| *b == 0) {
            bytes.extend_from_slice(&chunk[..nul]);
            return Ok(bytes);
        }
        if chunk.is_empty() {
            return Err(io::Error::other("short pathname read"));
        }
        bytes.extend(chunk);
    }
    Err(io::Error::other("pathname exceeds capture limit"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reads_bytes_without_utf8_conversion() {
        let bytes = [0xff, b'a', 0];
        let result = read_c_string(std::process::id() as i32, bytes.as_ptr() as u64, 64);
        if let Err(e) = &result
            && e.raw_os_error() == Some(libc::EPERM)
        {
            return;
        }
        assert_eq!(result.unwrap(), [0xff, b'a']);
    }
    #[test]
    fn bounded_reads() {
        let bytes = [b'x'; 32];
        assert!(read_c_string(std::process::id() as i32, bytes.as_ptr() as u64, 16).is_err());
    }
}
