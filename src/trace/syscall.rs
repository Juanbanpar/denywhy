use super::memory;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[cfg(target_arch = "x86_64")]
pub const NATIVE_ARCH: u32 = 0xc000003e;
#[cfg(target_arch = "aarch64")]
pub const NATIVE_ARCH: u32 = 0xc00000b7;

#[derive(Debug, PartialEq, Eq)]
pub enum Operation {
    Open { flags: u64 },
    Execute,
    Create,
    Remove { directory: bool },
}

#[derive(Debug)]
pub struct PathArgument {
    pub dirfd: i32,
    pub path: PathBuf,
}

#[derive(Debug)]
pub struct DecodedCall {
    pub name: &'static str,
    pub operation: Operation,
    pub paths: Vec<PathArgument>,
}

pub fn decode(
    tid: i32,
    arch: u32,
    number: u64,
    args: [u64; 6],
) -> Result<Option<DecodedCall>, String> {
    if arch != NATIVE_ARCH || number & 0x40000000 != 0 {
        return Err(if arch == 0x40000003 {
            "Unsupported tracee ABI: i386 compat syscall interface. The failed syscall was captured but its arguments were not decoded.".into()
        } else {
            format!(
                "Unsupported tracee ABI: {arch:#x}, syscall {number}; arguments were not decoded"
            )
        });
    }
    let (name, operation, dirfd, pointer) = match number as libc::c_long {
        libc::SYS_openat => (
            "openat",
            Operation::Open { flags: args[2] },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_execve => ("execve", Operation::Execute, libc::AT_FDCWD, args[0]),
        libc::SYS_mkdirat => ("mkdirat", Operation::Create, args[0] as i32, args[1]),
        libc::SYS_unlinkat => (
            "unlinkat",
            Operation::Remove {
                directory: args[2] & libc::AT_REMOVEDIR as u64 != 0,
            },
            args[0] as i32,
            args[1],
        ),
        _ => return Ok(None),
    };
    let bytes = memory::read_c_string(tid, pointer, libc::PATH_MAX as usize + 256)
        .map_err(|e| format!("cannot capture {name} pathname at {pointer:#x}: {e}"))?;
    Ok(Some(DecodedCall {
        name,
        operation,
        paths: vec![PathArgument {
            dirfd,
            path: PathBuf::from(OsString::from_vec(bytes)),
        }],
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_compat_without_reading_arguments() {
        assert!(
            decode(0, 0x40000003, 5, [0; 6])
                .unwrap_err()
                .contains("i386")
        );
        assert!(decode(0, NATIVE_ARCH, 0x40000000, [0; 6]).is_err());
    }
    #[test]
    fn captures_openat_at_entry() {
        let path = b"relative/\xff\0";
        let result = decode(
            std::process::id() as i32,
            NATIVE_ARCH,
            libc::SYS_openat as u64,
            [42, path.as_ptr() as u64, libc::O_RDWR as u64, 0, 0, 0],
        );
        if result
            .as_ref()
            .is_err_and(|e| e.contains("Operation not permitted"))
        {
            eprintln!("SKIP: host disallows process_vm_readv");
            return;
        }
        let call = result.unwrap().unwrap();
        assert_eq!(call.name, "openat");
        assert_eq!(call.paths[0].dirfd, 42);
        assert_eq!(
            call.paths[0].path,
            PathBuf::from(OsString::from_vec(b"relative/\xff".to_vec()))
        );
        assert_eq!(
            call.operation,
            Operation::Open {
                flags: libc::O_RDWR as u64
            }
        );
    }
}
