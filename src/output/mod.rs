use crate::trace::Failure;
use std::collections::HashMap;
pub mod human;
pub mod json;
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

// Preserve non-UTF-8 names in JSON. Human conversion happens only at rendering.
pub fn bytes(value: &OsStr) -> Value {
    match value.to_str() {
        Some(s) => json!(s),
        None => json!({"bytes": value.as_bytes()}),
    }
}

pub fn errno(errno: i32) -> &'static str {
    match errno {
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EROFS => "EROFS",
        _ => "unknown",
    }
}

pub struct Group<'a> {
    pub event: &'a Failure,
    pub count: u64,
    pub threads: Vec<(u32, i32, u64)>,
}
pub fn groups(failures: &[Failure]) -> Vec<Group<'_>> {
    let mut groups: Vec<Group<'_>> = Vec::new();
    let mut keys = HashMap::new();
    for event in failures {
        let causes: Vec<_> = event.causes.iter().map(|cause| {
            let mut evidence = cause.evidence.clone();
            if let Some(object) = evidence.as_object_mut() { object.remove("audit_id"); }
            json!({"kind": cause.kind, "confidence": cause.confidence, "summary": cause.summary, "evidence": evidence})
        }).collect();
        let paths: Vec<_> = event.decoded.as_ref().map(|call| call.paths.iter().enumerate().map(|(index, path)| {
            match event.paths.get(index) {
                Some(walk) if walk.limitation.is_none() => bytes(walk.target.as_os_str()),
                _ => json!({"path": bytes(path.path.as_os_str()), "base": path.base.as_ref().ok().map(|p| bytes(p.as_os_str()))}),
            }
        }).collect()).unwrap_or_default();
        let key = json!({"syscall": event.number, "arch": event.arch, "errno": event.errno, "operation": event.decoded.as_ref().map(|c| &c.operation), "paths": paths, "causes": causes, "security_context": event.context.as_ref().map(|c| json!({"credentials": c.credentials, "capabilities": c.capabilities, "seccomp": c.seccomp, "filters": c.seccomp_filters, "no_new_privs": c.no_new_privs, "user_namespace_differs": c.user_namespace_differs, "apparmor": c.apparmor, "selinux": c.selinux})),
            "unsupported_arguments": if event.decoded.is_none() { Some(event.args) } else { None }}).to_string();
        let pid = event.context.as_ref().map_or(event.tid as u32, |c| c.tgid);
        if let Some(index) = keys.get(&key).copied() {
            let group: &mut Group<'_> = &mut groups[index];
            group.count += 1;
            if let Some(thread) = group
                .threads
                .iter_mut()
                .find(|(p, t, _)| *p == pid && *t == event.tid)
            {
                thread.2 += 1;
            } else {
                group.threads.push((pid, event.tid, 1));
            }
        } else {
            keys.insert(key, groups.len());
            groups.push(Group {
                event,
                count: 1,
                threads: vec![(pid, event.tid, 1)],
            });
        }
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Cause, CauseKind, Confidence};
    use crate::trace::syscall::{DecodedCall, Operation, PathArgument};
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;
    use std::path::PathBuf;
    fn failure(tid: i32, confidence: Confidence) -> Failure {
        Failure {
            tid,
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
                    path: PathBuf::from(OsString::from_vec(b"/raw\xff".to_vec())),
                    base: Ok(PathBuf::from("/")),
                }],
            }),
            context: None,
            limitations: vec![],
            paths: vec![],
            mounts: vec![],
            timestamp: std::time::SystemTime::now(),
            causes: vec![Cause {
                kind: CauseKind::Seccomp,
                confidence,
                summary: "no direct evidence".into(),
                evidence: json!({"mode":2}),
            }],
        }
    }
    #[test]
    fn groups_equivalent_denials_without_losing_threads_or_causes() {
        let failures = vec![
            failure(1, Confidence::Possible),
            failure(2, Confidence::Possible),
            failure(1, Confidence::Strong),
        ];
        let groups = groups(&failures);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].count, 2);
        assert_eq!(groups[0].threads, [(1, 1, 1), (2, 2, 1)]);
    }
    #[test]
    fn json_preserves_bytes_and_human_possible_is_undetermined() {
        let cli = crate::cli::parse([OsString::from("--"), OsString::from("true")])
            .unwrap()
            .unwrap();
        let outcome = crate::trace::Outcome {
            code: 0,
            signal: None,
            failures: vec![failure(1, Confidence::Possible)],
        };
        let groups = groups(&outcome.failures);
        let value = json::report(&cli, &outcome, &groups);
        assert_eq!(
            value["denials"][0]["path"]["bytes"],
            json!(b"/raw\xff".to_vec())
        );
        let mut buffer = Vec::new();
        human::render(&cli, &outcome, &groups, &mut buffer).unwrap();
        assert!(
            String::from_utf8(buffer)
                .unwrap()
                .contains("Cause\n    undetermined")
        );
    }
}
