use super::memory;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

#[cfg(target_arch = "x86_64")]
pub const NATIVE_ARCH: u32 = 0xc000003e;
#[cfg(target_arch = "aarch64")]
pub const NATIVE_ARCH: u32 = 0xc00000b7;

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Operation {
    Open { flags: u64, resolve: u64 },
    Access { mode: u32, flags: u32 },
    Execute { flags: u32 },
    Create,
    Rename { flags: u32 },
    Link { flags: u32 },
    Symlink,
    Chmod { mode: u32 },
    Chown { uid: u32, gid: u32, flags: u32 },
    Truncate,
    Mknod { mode: u32 },
    Remove { directory: bool },
}

#[derive(Debug)]
pub struct PathArgument {
    pub dirfd: i32,
    pub path: PathBuf,
    pub base: Result<PathBuf, String>,
}

#[derive(Debug)]
pub struct DecodedCall {
    pub name: &'static str,
    pub operation: Operation,
    pub paths: Vec<PathArgument>,
}

impl Operation {
    pub fn accepts_empty_path(&self) -> bool {
        matches!(*self, Self::Execute { flags } | Self::Access { flags, .. } | Self::Chown { flags, .. } | Self::Link { flags } if flags & libc::AT_EMPTY_PATH as u32 != 0)
    }
    pub fn name(&self) -> &'static str {
        match *self {
            Self::Open { flags, .. } => match flags as i32 & libc::O_ACCMODE {
                libc::O_WRONLY => "write",
                libc::O_RDWR => "read_write",
                _ => {
                    if flags & libc::O_PATH as u64 != 0 {
                        "path_lookup"
                    } else {
                        "read"
                    }
                }
            },
            Self::Access { mode, .. } => match mode & 7 {
                0 => "existence",
                4 => "read",
                2 => "write",
                1 => "execute",
                _ => "access",
            },
            Self::Execute { .. } => "execute",
            Self::Create => "create",
            Self::Remove { .. } => "remove",
            Self::Rename { .. } => "rename",
            Self::Link { .. } => "link",
            Self::Symlink => "symlink",
            Self::Chmod { .. } => "chmod",
            Self::Chown { .. } => "chown",
            Self::Truncate => "truncate",
            Self::Mknod { .. } => "mknod",
        }
    }
}

impl DecodedCall {
    pub fn follows_final(&self, index: usize) -> bool {
        match self.operation {
            Operation::Remove { .. }
            | Operation::Rename { .. }
            | Operation::Symlink
            | Operation::Create
            | Operation::Mknod { .. } => false,
            Operation::Link { flags } => index == 0 && flags & libc::AT_SYMLINK_FOLLOW as u32 != 0,
            Operation::Chown { flags, .. } | Operation::Access { flags, .. } => {
                flags & libc::AT_SYMLINK_NOFOLLOW as u32 == 0
            }
            Operation::Execute { flags } => flags & libc::AT_SYMLINK_NOFOLLOW as u32 == 0,
            Operation::Open { flags, .. } => flags & libc::O_NOFOLLOW as u64 == 0,
            _ => true,
        }
    }
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
            Operation::Open {
                flags: args[2],
                resolve: 0,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_execve => (
            "execve",
            Operation::Execute { flags: 0 },
            libc::AT_FDCWD,
            args[0],
        ),
        libc::SYS_mkdirat => ("mkdirat", Operation::Create, args[0] as i32, args[1]),
        libc::SYS_unlinkat => (
            "unlinkat",
            Operation::Remove {
                directory: args[2] & libc::AT_REMOVEDIR as u64 != 0,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_openat2 => {
            if args[3] < 24 {
                return Err("openat2 open_how is too short to capture".into());
            }
            let how = memory::read_bytes(tid, args[2], 24)
                .map_err(|e| format!("cannot capture openat2 open_how: {e}"))?;
            if how.len() != 24 {
                return Err("short openat2 open_how read".into());
            }
            (
                "openat2",
                Operation::Open {
                    flags: u64::from_ne_bytes(how[..8].try_into().unwrap()),
                    resolve: u64::from_ne_bytes(how[16..24].try_into().unwrap()),
                },
                args[0] as i32,
                args[1],
            )
        }
        libc::SYS_faccessat => (
            "faccessat",
            Operation::Access {
                mode: args[2] as u32,
                flags: 0,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_faccessat2 => (
            "faccessat2",
            Operation::Access {
                mode: args[2] as u32,
                flags: args[3] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_execveat => (
            "execveat",
            Operation::Execute {
                flags: args[4] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_open => (
            "open",
            Operation::Open {
                flags: args[1],
                resolve: 0,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access => (
            "access",
            Operation::Access {
                mode: args[1] as u32,
                flags: 0,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mkdir => ("mkdir", Operation::Create, libc::AT_FDCWD, args[0]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_unlink => (
            "unlink",
            Operation::Remove { directory: false },
            libc::AT_FDCWD,
            args[0],
        ),
        libc::SYS_renameat => (
            "renameat",
            Operation::Rename { flags: 0 },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_renameat2 => (
            "renameat2",
            Operation::Rename {
                flags: args[4] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_linkat => (
            "linkat",
            Operation::Link {
                flags: args[4] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_symlinkat => ("symlinkat", Operation::Symlink, args[1] as i32, args[2]),
        libc::SYS_fchmodat => (
            "fchmodat",
            Operation::Chmod {
                mode: args[2] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_fchownat => (
            "fchownat",
            Operation::Chown {
                uid: args[2] as u32,
                gid: args[3] as u32,
                flags: args[4] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        libc::SYS_truncate => ("truncate", Operation::Truncate, libc::AT_FDCWD, args[0]),
        libc::SYS_mknodat => (
            "mknodat",
            Operation::Mknod {
                mode: args[2] as u32,
            },
            args[0] as i32,
            args[1],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rename => (
            "rename",
            Operation::Rename { flags: 0 },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_link => (
            "link",
            Operation::Link { flags: 0 },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_symlink => ("symlink", Operation::Symlink, libc::AT_FDCWD, args[1]),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod => (
            "chmod",
            Operation::Chmod {
                mode: args[1] as u32,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown => (
            "chown",
            Operation::Chown {
                uid: args[1] as u32,
                gid: args[2] as u32,
                flags: 0,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lchown => (
            "lchown",
            Operation::Chown {
                uid: args[1] as u32,
                gid: args[2] as u32,
                flags: libc::AT_SYMLINK_NOFOLLOW as u32,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mknod => (
            "mknod",
            Operation::Mknod {
                mode: args[1] as u32,
            },
            libc::AT_FDCWD,
            args[0],
        ),
        _ => return Ok(None),
    };
    let mut paths = vec![capture_path(tid, name, dirfd, pointer)?];
    if matches!(operation, Operation::Rename { .. } | Operation::Link { .. }) {
        let (fd, pointer) = if name == "rename" || name == "link" {
            (libc::AT_FDCWD, args[1])
        } else {
            (args[2] as i32, args[3])
        };
        paths.push(capture_path(tid, name, fd, pointer)?);
    }
    Ok(Some(DecodedCall {
        name,
        operation,
        paths,
    }))
}

fn capture_path(tid: i32, name: &str, dirfd: i32, pointer: u64) -> Result<PathArgument, String> {
    let bytes = memory::read_c_string(tid, pointer, libc::PATH_MAX as usize + 256)
        .map_err(|e| format!("cannot capture {name} pathname at {pointer:#x}: {e}"))?;
    let path = PathBuf::from(OsString::from_vec(bytes));
    let base = crate::fs::path::capture_base(tid, dirfd, &path)
        .map_err(|e| format!("cannot resolve {name} dirfd {dirfd}: {e}"));
    Ok(PathArgument { dirfd, path, base })
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
                flags: libc::O_RDWR as u64,
                resolve: 0
            }
        );
    }
}
