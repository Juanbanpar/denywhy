use crate::trace::{Failure, Outcome};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

// Preserve non-UTF-8 names in JSON. Human conversion happens only at rendering.
pub fn bytes(value: &OsStr) -> Value {
    match value.to_str() {
        Some(s) => json!(s),
        None => json!({"bytes": value.as_bytes()}),
    }
}

pub fn json_report(cli: &crate::cli::Cli, outcome: &Outcome) -> Value {
    json!({"schema_version": 1, "command": cli.command.iter().map(|a| bytes(a)).collect::<Vec<_>>(),
        "exit": {"code": outcome.code}, "denials": outcome.failures.iter().map(event_json).collect::<Vec<_>>(), "limitations": []})
}
fn event_json(event: &Failure) -> Value {
    json!({"pid": event.context.as_ref().map(|c| c.tgid).unwrap_or(event.tid as u32), "tid": event.tid,
        "syscall": event.decoded.as_ref().map(|c| c.name), "syscall_number": event.number, "arch": event.arch,
        "arguments": event.args, "errno": errno(event.errno),
        "paths": event.decoded.as_ref().map(|c| c.paths.iter().map(|p| json!({"path": bytes(p.path.as_os_str()), "dirfd": p.dirfd, "base": p.base.as_ref().ok().map(|b| bytes(b.as_os_str()))})).collect::<Vec<_>>()),
        "causes": event.causes, "process": event.context, "limitations": event.limitations,
        "filesystem": event.paths.iter().map(|w| json!({"target": bytes(w.target.as_os_str()), "missing": w.missing, "limitation": w.limitation, "components": w.components.iter().map(|c| json!({"path": bytes(c.path.as_os_str()), "inspection_path": bytes(c.inspection_path.as_os_str()), "uid": c.metadata.uid(), "gid": c.metadata.gid(), "mode": c.metadata.mode()})).collect::<Vec<_>>()})).collect::<Vec<_>>()})
}
pub fn errno(errno: i32) -> &'static str {
    match errno {
        libc::EACCES => "EACCES",
        libc::EPERM => "EPERM",
        libc::EROFS => "EROFS",
        _ => "unknown",
    }
}
