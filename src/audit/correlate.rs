use super::parse::AuditEvent;
use crate::model::CauseKind;
use crate::trace::{
    Failure,
    syscall::{DecodedCall, Operation},
};
use std::time::Duration;

pub fn matches(event: &AuditEvent, failure: &Failure) -> bool {
    let Some(call) = &failure.decoded else {
        return false;
    };
    let Some(pid) = event.pid else {
        return false;
    };
    if pid != failure.tid as u32 && Some(pid) != failure.context.as_ref().map(|c| c.tgid) {
        return false;
    }
    // Audit timestamps are assigned in the kernel before the syscall returns.
    // A one-millisecond allowance covers the audit timestamp's precision.
    if event
        .timestamp
        .duration_since(failure.timestamp)
        .is_ok_and(|d| d > Duration::from_millis(1))
    {
        return false;
    }
    if failure
        .timestamp
        .duration_since(event.timestamp)
        .is_ok_and(|d| d > Duration::from_millis(250))
    {
        return false;
    }
    if event.arch.is_some_and(|arch| arch != failure.arch)
        || event.syscall.is_some_and(|n| n != failure.number)
    {
        return false;
    }
    if let (Some(a), Some(b)) = (
        &event.comm,
        failure.context.as_ref().and_then(|c| c.comm.as_ref()),
    ) && a != b
    {
        return false;
    }
    if event
        .fields
        .get("exit")
        .and_then(|v| std::str::from_utf8(v).ok())
        .and_then(|s| s.parse::<i32>().ok())
        .is_some_and(|n| n != -failure.errno)
    {
        return false;
    }
    if event.fields.get("success").is_some_and(|v| v == b"yes") {
        return false;
    }
    // Exact paths plus process identity, a narrow timestamp window, and an
    // operation/syscall match are required. Basename matches are insufficient.
    let path_match = event.path.as_ref().is_some_and(|path| {
        failure
            .paths
            .iter()
            .any(|walk| &walk.target == path || walk.components.iter().any(|c| &c.path == path))
            || call
                .paths
                .iter()
                .any(|p| p.path.is_absolute() && &p.path == path)
    });
    if !path_match {
        return false;
    }
    event.syscall == Some(failure.number)
        || event
            .operation
            .as_ref()
            .is_some_and(|operation| operation_matches(&event.mechanism, operation, call))
}
pub fn assign(event: &AuditEvent, failures: &[Failure]) -> Result<Option<usize>, ()> {
    let mut candidates: Vec<_> = failures
        .iter()
        .enumerate()
        .filter(|(_, f)| matches(event, f))
        .map(|(index, f)| {
            (
                index,
                f.timestamp
                    .duration_since(event.timestamp)
                    .or_else(|_| event.timestamp.duration_since(f.timestamp))
                    .unwrap(),
            )
        })
        .collect();
    candidates.sort_by_key(|(_, distance)| *distance);
    let Some((index, distance)) = candidates.first() else {
        return Ok(None);
    };
    if candidates
        .get(1)
        .is_some_and(|(_, next)| next.saturating_sub(*distance) <= Duration::from_millis(1))
    {
        return Err(());
    }
    Ok(Some(*index))
}

fn operation_matches(mechanism: &CauseKind, operation: &str, call: &DecodedCall) -> bool {
    let accepted: &[&str] = match mechanism {
        CauseKind::AppArmor => match call.operation {
            Operation::Open { .. } => &["open"],
            Operation::Execute { .. } => &["exec"],
            Operation::Create => &["mkdir", "mknod"],
            Operation::Remove { directory } => {
                if directory {
                    &["rmdir", "unlink"]
                } else {
                    &["unlink"]
                }
            }
            Operation::Rename { .. } => &["rename_src", "rename_dest", "rename"],
            Operation::Link { .. } => &["link"],
            Operation::Symlink => &["symlink"],
            Operation::Chmod { .. } => &["chmod"],
            Operation::Chown { .. } => &["chown"],
            Operation::Truncate => &["truncate"],
            Operation::Mknod { .. } => &["mknod"],
            Operation::Access { .. } => &["file_perm", "getattr"],
        },
        CauseKind::Selinux => match call.operation {
            Operation::Open { flags, .. } => {
                if flags as i32 & libc::O_ACCMODE == libc::O_RDONLY {
                    &["read", "open", "search", "create", "add_name", "getattr"]
                } else {
                    &[
                        "write", "append", "open", "search", "create", "add_name", "getattr",
                    ]
                }
            }
            Operation::Execute { .. } => &["execute", "execute_no_trans", "entrypoint", "search"],
            Operation::Create | Operation::Symlink | Operation::Mknod { .. } => {
                &["create", "add_name", "write", "search"]
            }
            Operation::Remove { .. } => &["unlink", "rmdir", "remove_name", "write", "search"],
            Operation::Rename { .. } => &[
                "rename",
                "remove_name",
                "add_name",
                "reparent",
                "write",
                "search",
            ],
            Operation::Link { .. } => &["link", "add_name", "search"],
            Operation::Chmod { .. } | Operation::Chown { .. } => &["setattr", "search"],
            Operation::Truncate => &["write", "setattr", "search"],
            Operation::Access { .. } => &["read", "write", "execute", "search", "getattr"],
        },
        CauseKind::Landlock => match call.operation {
            Operation::Open { .. } | Operation::Access { .. } => &[
                "fs.read_file",
                "fs.read_dir",
                "fs.write_file",
                "fs.truncate",
            ],
            Operation::Execute { .. } => &["fs.execute"],
            Operation::Create => &["fs.make_dir"],
            Operation::Remove { .. } => &["fs.remove_file", "fs.remove_dir"],
            Operation::Rename { .. } | Operation::Link { .. } => &[
                "fs.refer",
                "fs.make_reg",
                "fs.remove_file",
                "fs.remove_dir",
                "fs.make_dir",
            ],
            Operation::Symlink => &["fs.make_sym"],
            Operation::Truncate => &["fs.truncate"],
            Operation::Mknod { .. } => &[
                "fs.make_char",
                "fs.make_block",
                "fs.make_fifo",
                "fs.make_sock",
                "fs.make_reg",
            ],
            _ => &[],
        },
        _ => &[],
    };
    operation.split([' ', ',']).any(|o| accepted.contains(&o))
}

#[cfg(test)]
mod tests {
    use super::super::parse;
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    #[test]
    fn rejects_pid_reuse_wrong_paths_operations_and_timestamps() {
        let time = UNIX_EPOCH + Duration::from_secs(1700000000);
        let failure = Failure {
            tid: 42,
            number: libc::SYS_openat as u64,
            arch: crate::trace::syscall::NATIVE_ARCH,
            args: [0; 6],
            errno: libc::EACCES,
            decoded: Some(DecodedCall {
                name: "openat",
                operation: Operation::Open {
                    flags: 0,
                    resolve: 0,
                },
                paths: vec![crate::trace::syscall::PathArgument {
                    dirfd: libc::AT_FDCWD,
                    path: PathBuf::from("/private/file"),
                    base: Ok(PathBuf::from("/")),
                }],
            }),
            limitations: vec![],
            context: None,
            paths: vec![],
            causes: vec![],
            mounts: vec![],
            timestamp: time,
        };
        let mut event = parse::parse(b"type=AVC msg=audit(1700000000.001:1): apparmor=\"DENIED\" pid=42 operation=\"open\" name=\"/private/file\"\n").remove(0);
        assert_eq!(assign(&event, std::slice::from_ref(&failure)), Ok(Some(0)));
        let twin = Failure {
            tid: 42,
            number: libc::SYS_openat as u64,
            arch: crate::trace::syscall::NATIVE_ARCH,
            args: [0; 6],
            errno: libc::EACCES,
            decoded: Some(DecodedCall {
                name: "openat",
                operation: Operation::Open {
                    flags: 0,
                    resolve: 0,
                },
                paths: vec![crate::trace::syscall::PathArgument {
                    dirfd: libc::AT_FDCWD,
                    path: PathBuf::from("/private/file"),
                    base: Ok(PathBuf::from("/")),
                }],
            }),
            limitations: vec![],
            context: None,
            paths: vec![],
            causes: vec![],
            mounts: vec![],
            timestamp: time + Duration::from_micros(500),
        };
        let candidates = [failure, twin];
        assert_eq!(assign(&event, &candidates), Err(()));
        let mut failure = candidates.into_iter().next().unwrap();
        for line in [
            "type=AVC msg=audit(1700000000.001:2): avc: denied { read } for pid=42 name=\"/private/file\" permissive=0\n".to_owned(),
            format!(
                "type=SYSCALL msg=audit(1700000000.001:3): arch={:x} syscall={} pid=42 exit=-13\ntype=LANDLOCK_ACCESS msg=audit(1700000000.001:3): blockers=fs.read_file path=\"/private/file\"\n",
                failure.arch, failure.number
            ),
        ] {
            assert!(matches(&parse::parse(line.as_bytes())[0], &failure));
        }
        assert!(matches(&event, &failure));
        event.pid = None;
        assert!(!matches(&event, &failure));
        event.pid = Some(43);
        assert!(!matches(&event, &failure));
        event.pid = Some(42);
        event.path = Some(PathBuf::from("/private/other"));
        assert!(!matches(&event, &failure));
        event.path = Some(PathBuf::from("/private/file"));
        event.operation = Some("exec".into());
        assert!(!matches(&event, &failure));
        event.operation = Some("open".into());
        failure.timestamp = SystemTime::now();
        assert!(!matches(&event, &failure));
    }
}
