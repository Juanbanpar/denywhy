use super::{Group, bytes, errno};
use crate::trace::Outcome;
use serde_json::{Value, json};
use std::os::unix::fs::MetadataExt;

pub fn report(cli: &crate::cli::Cli, outcome: &Outcome, groups: &[Group<'_>]) -> Value {
    let count = if cli.all {
        groups.len()
    } else {
        groups.len().min(10)
    };
    json!({"schema_version": 1, "command": cli.command.iter().map(|a| bytes(a)).collect::<Vec<_>>(),
        "exit": {"code": outcome.code, "signal": outcome.signal},
        "denials": groups.iter().take(count).map(event).collect::<Vec<_>>(),
        "omitted_groups": groups.len() - count, "limitations": ["ptrace changes timing; filesystem metadata inspection can race with other threads or processes"]})
}
fn event(group: &Group<'_>) -> Value {
    let event = group.event;
    let path = event
        .paths
        .first()
        .filter(|walk| walk.limitation.is_none())
        .map(|p| p.target.as_os_str())
        .or_else(|| {
            event
                .decoded
                .as_ref()
                .and_then(|c| c.paths.first().map(|p| p.path.as_os_str()))
        });
    let mut value = json!({"pid": group.threads[0].0, "tid": event.tid,
        "syscall": event.decoded.as_ref().map(|c| c.name), "syscall_number": event.number, "arch": event.arch,
        "errno": errno(event.errno), "operation": event.decoded.as_ref().map(|c| c.operation.name()),
        "parameters": event.decoded.as_ref().map(|c| &c.operation), "path": path.map(bytes),
        "paths": event.decoded.as_ref().map(|c| c.paths.iter().map(|p| json!({"path": bytes(p.path.as_os_str()), "dirfd": p.dirfd, "base": p.base.as_ref().ok().map(|b| bytes(b.as_os_str()))})).collect::<Vec<_>>()),
        "count": group.count, "threads": group.threads.iter().map(|(p,t,c)| json!({"pid": p, "tid": t, "count": c})).collect::<Vec<_>>(),
        "timestamp": event.timestamp, "causes": event.causes, "process": event.context, "mounts": event.mounts, "limitations": event.limitations,
        "filesystem": event.paths.iter().map(|w| json!({"target": bytes(w.target.as_os_str()), "missing": w.missing, "limitation": w.limitation,
            "components": w.components.iter().map(|c| json!({"path": bytes(c.path.as_os_str()), "uid": c.metadata.uid(), "gid": c.metadata.gid(), "mode": c.metadata.mode()})).collect::<Vec<_>>()})).collect::<Vec<_>>()});
    if event.decoded.is_none() {
        value["arguments"] = json!(event.args);
    }
    value
}
