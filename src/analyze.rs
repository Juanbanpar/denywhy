use crate::fs::{acl, dac};
use crate::model::{Cause, CauseKind, Confidence};
use crate::trace::{Failure, syscall::Operation};
use serde_json::json;
use std::os::unix::fs::MetadataExt;

pub fn analyze_denial(event: &mut Failure) {
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
    if matches!(call.operation, Operation::Open { resolve, .. } if resolve != 0) {
        event.limitations.push(
            "openat2 resolution constraints are present; ordinary path resolution may differ."
                .into(),
        );
        return;
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
        }
        for (component_index, component) in walk.components.iter().enumerate() {
            let final_object = !walk.missing
                && walk.limitation.is_none()
                && component_index + 1 == walk.components.len();
            let requested = if !final_object {
                1
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
        let target = if !walk.missing {
            walk.components.last()
        } else {
            None
        };
        let parent = if walk.missing {
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
        Operation::Create
        | Operation::Mknod { .. }
        | Operation::Symlink
        | Operation::Remove { .. }
        | Operation::Rename { .. } => true,
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
