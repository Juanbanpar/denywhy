use crate::fs::{acl, dac};
use crate::model::{Cause, CauseKind, Confidence};
use crate::trace::{Failure, syscall::Operation};
use serde_json::json;
use std::os::unix::fs::MetadataExt;

pub fn analyze_denial(event: &mut Failure) {
    if let Some(call) = &event.decoded && (call.paths.iter().any(|p| p.path.as_os_str().is_empty() && !matches!(call.operation, Operation::Execute { flags } | Operation::Access { flags, .. } | Operation::Chown { flags, .. } | Operation::Link { flags } if flags & libc::AT_EMPTY_PATH as u32 != 0)) || matches!(call.operation, Operation::Access { mode, .. } if mode & !7 != 0)) {
        event.limitations.push("invalid pathname or access mode has no DAC/mount interpretation".into()); return;
    }
    if event.decoded.as_ref().is_some_and(
        |call| matches!(call.operation, Operation::Open { resolve, .. } if resolve != 0),
    ) {
        event.limitations.push(
            "openat2 resolution constraints are present; ordinary path resolution may differ."
                .into(),
        );
        return;
    }
    analyze_mounts(event);
    let (Some(call), Some(context)) = (&event.decoded, &event.context) else {
        return;
    };
    let mut credentials = context.credentials.clone();
    let mut capabilities = context.capabilities.effective;
    if let Operation::Access { flags, .. } = call.operation {
        let effective = flags & libc::AT_EACCESS as u32 != 0;
        credentials.fsuid = if effective {
            credentials.euid
        } else {
            credentials.ruid
        };
        credentials.fsgid = if effective {
            credentials.egid
        } else {
            credentials.rgid
        };
        capabilities = if effective {
            capabilities
        } else if credentials.ruid == 0 {
            context.capabilities.permitted
        } else {
            0
        };
    }
    let confidence = if context.user_namespace_differs == Some(false) {
        Confidence::Strong
    } else {
        Confidence::Possible
    };
    if confidence == Confidence::Possible {
        event.limitations.push("User namespace differs from tracer or cannot be inspected; capability-based conclusions may be incomplete.".into());
    }
    if event.paths.len() != call.paths.len() {
        event
            .limitations
            .push("One or more pathname bases could not be resolved.".into());
        return;
    }
    for (index, walk) in event.paths.iter().enumerate() {
        if let Some(limitation) = &walk.limitation {
            event.limitations.push(limitation.clone());
            if limitation.starts_with("non-directory") || limitation.starts_with("procfs magic") {
                continue;
            }
        }
        for (component_index, component) in walk.components.iter().enumerate() {
            let final_object = !walk.missing
                && walk.limitation.is_none()
                && component_index + 1 == walk.components.len();
            let requested = if !final_object {
                1
            } else if component.metadata.file_type().is_symlink()
                || matches!(call.operation, Operation::Execute { .. })
                    && !component.metadata.is_file()
                || matches!(call.operation, Operation::Open { flags, .. } if flags & (libc::O_CREAT | libc::O_EXCL) as u64 == (libc::O_CREAT | libc::O_EXCL) as u64)
            {
                0
            } else {
                requested(&call.operation, component.metadata.is_dir())
            };
            if requested == 0 {
                continue;
            }
            let inode = inode(&component.metadata);
            match acl::read(&component.inspection_path) {
                Ok(acl) => {
                    if !dac::allowed(&inode, &credentials, capabilities, acl.as_ref(), requested)
                        && event.errno == libc::EACCES
                    {
                        event.causes.push(Cause { kind: if acl.is_some() { CauseKind::PosixAcl } else { CauseKind::Dac }, confidence,
                            summary: if !final_object { "missing directory search permission".into() } else { format!("missing {} permission", permission_name(requested)) },
                            evidence: json!({"path": crate::output::bytes(component.path.as_os_str()), "uid": inode.uid, "gid": inode.gid, "mode": inode.mode, "requested": requested, "fsuid": credentials.fsuid, "fsgid": credentials.fsgid, "acl_present": acl.is_some()}) });
                        break;
                    }
                }
                Err(e) => event.limitations.push(format!(
                    "ACL state unavailable for {:?}: {e}",
                    component.path
                )),
            }
        }
        let target = if !walk.missing && walk.limitation.is_none() {
            walk.components.last()
        } else {
            None
        };
        let parent = if walk.limitation.is_some() {
            None
        } else if walk.missing {
            walk.components.last()
        } else {
            walk.components.iter().rev().nth(1)
        };
        if event.errno == libc::EACCES
            && requires_parent_write(&call.operation, index, walk.missing)
            && let Some(parent) = parent
        {
            let parent_inode = inode(&parent.metadata);
            match acl::read(&parent.inspection_path) {
                Ok(acl) if !dac::allowed(&parent_inode, &credentials, capabilities, acl.as_ref(), 3) => event.causes.push(Cause {
                    kind: if acl.is_some() { CauseKind::PosixAcl } else { CauseKind::Dac }, confidence,
                    summary: "missing parent directory write/search permission".into(), evidence: json!({"path": crate::output::bytes(parent.path.as_os_str()), "uid": parent_inode.uid, "gid": parent_inode.gid, "mode": parent_inode.mode, "requested": 3, "acl_present": acl.is_some()}) }),
                Err(e) => event.limitations.push(format!("ACL state unavailable for {:?}: {e}", parent.path)), _ => {},
            }
        }
        if event.errno == libc::EPERM
            && let Some(target) = target
        {
            if matches!(
                call.operation,
                Operation::Remove { .. } | Operation::Rename { .. }
            ) && let Some(parent) = parent
                && dac::sticky_denied(
                    &inode(&parent.metadata),
                    &inode(&target.metadata),
                    credentials.fsuid,
                    capabilities,
                )
            {
                event.causes.push(Cause { kind: CauseKind::StickyDirectory, confidence, summary: "sticky-directory ownership rule".into(), evidence: json!({"directory": crate::output::bytes(parent.path.as_os_str()), "directory_owner": parent.metadata.uid(), "directory_mode": parent.metadata.mode(), "target_owner": target.metadata.uid(), "fsuid": credentials.fsuid}) });
            }
            if dac::ownership_denied(
                &call.operation,
                &inode(&target.metadata),
                &credentials,
                capabilities,
            ) {
                event.causes.push(Cause { kind: CauseKind::Capability, confidence, summary: "ownership or capability requirement is not satisfied".into(), evidence: json!({"path": crate::output::bytes(target.path.as_os_str()), "owner": target.metadata.uid(), "fsuid": credentials.fsuid, "effective_capabilities": capabilities}) });
            }
        }
    }
    if event.errno == libc::EPERM
        && matches!(call.operation, Operation::Mknod { mode } if matches!(mode & libc::S_IFMT, libc::S_IFCHR | libc::S_IFBLK))
        && capabilities & dac::CAP_MKNOD == 0
    {
        event.causes.push(Cause {
            kind: CauseKind::Capability,
            confidence,
            summary: "device-node creation requires CAP_MKNOD".into(),
            evidence: json!({"required": "CAP_MKNOD", "effective_capabilities": capabilities}),
        });
    }
}
fn inode(meta: &std::fs::Metadata) -> dac::Inode {
    dac::Inode {
        uid: meta.uid(),
        gid: meta.gid(),
        mode: meta.mode(),
    }
}
fn requested(operation: &Operation, directory: bool) -> u16 {
    match *operation {
        Operation::Open { flags, .. } if flags & libc::O_PATH as u64 != 0 => 0,
        Operation::Open { flags, .. } => {
            if flags & libc::O_TMPFILE as u64 == libc::O_TMPFILE as u64 && directory {
                3
            } else {
                match flags as i32 & libc::O_ACCMODE {
                    libc::O_WRONLY => 2,
                    libc::O_RDWR => 6,
                    _ => {
                        if flags & libc::O_TRUNC as u64 != 0 {
                            6
                        } else {
                            4
                        }
                    }
                }
            }
        }
        Operation::Access { mode, .. } => mode as u16 & 7,
        Operation::Execute { .. } => 1,
        Operation::Truncate => 2,
        _ => 0,
    }
}
fn requires_parent_write(operation: &Operation, index: usize, missing: bool) -> bool {
    match *operation {
        Operation::Open { flags, .. } => missing && flags & libc::O_CREAT as u64 != 0,
        Operation::Create | Operation::Mknod { .. } | Operation::Symlink => missing,
        Operation::Remove { .. } | Operation::Rename { .. } => true,
        Operation::Link { .. } => index == 1,
        _ => false,
    }
}
fn permission_name(bits: u16) -> &'static str {
    match bits {
        1 => "execute",
        2 => "write",
        4 => "read",
        6 => "read/write",
        _ => "requested access",
    }
}

fn analyze_mounts(event: &mut Failure) {
    let Some(call) = &event.decoded else {
        return;
    };
    let mounts = std::fs::read(format!("/proc/{}/mountinfo", event.tid))
        .map_err(|e| e.to_string())
        .and_then(|b| crate::procfs::mountinfo::parse(&b));
    let mounts = match mounts {
        Ok(m) => m,
        Err(e) => {
            event
                .limitations
                .push(format!("tracee mount state unavailable: {e}"));
            return;
        }
    };
    for (index, walk) in event.paths.iter().enumerate() {
        if walk.limitation.is_some() {
            continue;
        }
        match crate::procfs::mountinfo::containing(&mounts, &walk.target) {
            Ok(Some(mount)) => {
                let mut evidence = json!({"path": crate::output::bytes(walk.target.as_os_str()), "mount_id": mount.id, "mountpoint": crate::output::bytes(mount.point.as_os_str()), "root": crate::output::bytes(mount.root.as_os_str()), "read_only": mount.read_only, "noexec": mount.noexec, "nosuid": mount.nosuid, "nodev": mount.nodev});
                if !matches!(call.operation, Operation::Execute { .. }) {
                    evidence.as_object_mut().unwrap().remove("nosuid");
                }
                event.mounts.push(evidence.clone());
                if event.errno == libc::EACCES
                    && matches!(call.operation, Operation::Execute { .. })
                    && mount.noexec
                    && !walk.missing
                    && walk.components.last().is_some_and(|c| c.metadata.is_file())
                {
                    event.causes.push(Cause {
                        kind: CauseKind::NoExecMount,
                        confidence: Confidence::Proven,
                        summary: "executable is on a noexec mount".into(),
                        evidence,
                    });
                } else if event.errno == libc::EROFS
                    && modifying(&call.operation, index)
                    && mount.read_only
                {
                    event.causes.push(Cause {
                        kind: CauseKind::ReadOnlyMount,
                        confidence: Confidence::Proven,
                        summary: "filesystem is mounted read-only".into(),
                        evidence,
                    });
                }
            }
            Ok(None) => event
                .limitations
                .push(format!("no mount matches {:?}", walk.target)),
            Err(e) => event.limitations.push(e),
        }
    }
}
fn modifying(operation: &Operation, index: usize) -> bool {
    match *operation {
        Operation::Open { flags, .. } => {
            flags & libc::O_PATH as u64 == 0
                && flags & (libc::O_ACCMODE | libc::O_CREAT | libc::O_TRUNC) as u64 != 0
        }
        Operation::Access { mode, .. } => mode & libc::W_OK as u32 != 0,
        Operation::Execute { .. } => false,
        Operation::Link { .. } => index == 1,
        _ => true,
    }
}

pub fn add_seccomp_observation(event: &mut Failure) {
    if event
        .causes
        .iter()
        .any(|c| c.confidence != Confidence::Possible)
    {
        return;
    }
    if let Some(context) = &event.context
        && context.seccomp != 0
    {
        event.causes.push(Cause { kind: CauseKind::Seccomp, confidence: Confidence::Possible,
            summary: "seccomp is active, but no direct evidence ties it to this denial".into(),
            evidence: json!({"mode": context.seccomp, "filters": context.seccomp_filters, "no_new_privs": context.no_new_privs}) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trace::syscall::{DecodedCall, PathArgument};
    use std::path::PathBuf;
    #[test]
    fn creation_only_checks_parent_write_for_new_objects() {
        assert!(requires_parent_write(&Operation::Create, 0, true));
        assert!(!requires_parent_write(&Operation::Create, 0, false));
        assert!(!requires_parent_write(&Operation::Symlink, 0, false));
        assert!(requires_parent_write(
            &Operation::Remove { directory: false },
            0,
            false
        ));
    }
    #[test]
    fn active_seccomp_does_not_become_a_proven_cause() {
        let context = crate::procfs::status::parse("Tgid: 42\nUid: 1000 1000 1000 1000\nGid: 1000 1000 1000 1000\nGroups: 1000\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapBnd: 0\nCapAmb: 0\nNoNewPrivs: 1\nSeccomp: 2\nSeccomp_filters: 2\n").unwrap();
        let mut event = Failure {
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
                paths: vec![PathArgument {
                    dirfd: libc::AT_FDCWD,
                    path: PathBuf::from("/allowed"),
                    base: Ok(PathBuf::from("/")),
                }],
            }),
            limitations: vec![],
            context: Some(context),
            paths: vec![],
            causes: vec![],
            mounts: vec![],
            timestamp: std::time::SystemTime::now(),
        };
        add_seccomp_observation(&mut event);
        assert_eq!(event.causes.len(), 1);
        assert_eq!(event.causes[0].kind, CauseKind::Seccomp);
        assert_eq!(event.causes[0].confidence, Confidence::Possible);
        event.causes = vec![Cause {
            kind: CauseKind::Dac,
            confidence: Confidence::Strong,
            summary: "search denied".into(),
            evidence: json!({}),
        }];
        add_seccomp_observation(&mut event);
        assert_eq!(event.causes.len(), 1);
    }
}
