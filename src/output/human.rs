use super::{Group, errno};
use crate::model::{CauseKind, Confidence};
use crate::trace::{Outcome, syscall::Operation};
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;

pub fn render(
    cli: &crate::cli::Cli,
    outcome: &Outcome,
    groups: &[Group<'_>],
    out: &mut impl Write,
) -> io::Result<()> {
    if let Some(signal) = outcome.signal {
        writeln!(
            out,
            "Command terminated by signal {signal} (status {}).",
            outcome.code
        )?;
    } else {
        writeln!(out, "Command exited with status {}.", outcome.code)?;
    }
    let count = if cli.all {
        groups.len()
    } else {
        groups.len().min(10)
    };
    for (index, group) in groups.iter().take(count).enumerate() {
        let event = group.event;
        writeln!(out, "\nDENIAL {}\n", index + 1)?;
        if let Some(call) = &event.decoded {
            write!(out, "{}(", call.name)?;
            for (index, path) in call.paths.iter().enumerate() {
                if index > 0 {
                    write!(out, ", ")?;
                }
                if matches!(
                    call.name,
                    "openat"
                        | "openat2"
                        | "execveat"
                        | "faccessat"
                        | "faccessat2"
                        | "mkdirat"
                        | "unlinkat"
                        | "renameat"
                        | "renameat2"
                        | "linkat"
                        | "symlinkat"
                        | "fchmodat"
                        | "fchownat"
                        | "mknodat"
                ) {
                    if call.name == "symlinkat" {
                        write!(out, "..., ")?;
                    }
                    if path.dirfd == libc::AT_FDCWD {
                        write!(out, "AT_FDCWD, ")?;
                    } else {
                        write!(out, "{}, ", path.dirfd)?;
                    }
                }
                write!(out, "{:?}", path.path)?;
            }
            if let Operation::Open { flags, .. } = call.operation {
                write!(out, ", {}", open_flags(flags))?;
            }
            writeln!(out, ")\n    -> {}", errno(event.errno))?;
        } else {
            writeln!(
                out,
                "syscall {} (ABI {:#x})\n    -> {}",
                event.number,
                event.arch,
                errno(event.errno)
            )?;
        }
        if group.count > 1 {
            writeln!(
                out,
                "occurred {} times across {} thread(s)",
                group.count,
                group.threads.len()
            )?;
        }
        writeln!(out, "\nCause")?;
        let mut established: Vec<_> = event
            .causes
            .iter()
            .filter(|c| c.confidence != Confidence::Possible)
            .collect();
        established.sort_by_key(|c| {
            if c.confidence == Confidence::Proven {
                0
            } else {
                1
            }
        });
        if established.is_empty() {
            writeln!(out, "    undetermined")?;
        }
        for cause in established {
            writeln!(
                out,
                "    {}    {}",
                kind(&cause.kind),
                confidence(cause.confidence)
            )?;
            writeln!(out, "    {}", cause.summary)?;
            if let Some(path) = cause.evidence.get("path") {
                writeln!(out, "    path: {}", display_value(path))?;
            }
            if let Some(directory) = cause.evidence.get("directory") {
                writeln!(out, "    directory: {}", display_value(directory))?;
            }
            if let Some(evidence) = cause.evidence.get("fields") {
                writeln!(out, "    audit fields: {evidence}")?;
            }
            if cli.verbose {
                writeln!(out, "    evidence: {}", cause.evidence)?;
            }
        }
        if let Some(context) = &event.context {
            let c = &context.credentials;
            writeln!(
                out,
                "\nProcess\n    PID/TID: {} / {}\n    fsuid: {}\n    fsgid: {}\n    groups: {:?}",
                context.tgid, event.tid, c.fsuid, c.fsgid, c.supplementary_groups
            )?;
            if cli.verbose {
                writeln!(
                    out,
                    "    credentials: {}\n    capabilities: {}\n    NoNewPrivs: {}",
                    serde_json::to_value(c)?,
                    serde_json::to_value(&context.capabilities)?,
                    context.no_new_privs
                )?;
            }
            writeln!(
                out,
                "\nOther enforcement\n    AppArmor: {}\n    SELinux: {}\n    seccomp: {} (filters: {})",
                context.apparmor.as_deref().unwrap_or("unavailable"),
                context.selinux.as_deref().unwrap_or("unavailable"),
                match context.seccomp {
                    0 => "disabled",
                    1 => "strict",
                    2 => "filter mode",
                    _ => "unknown mode",
                },
                context
                    .seccomp_filters
                    .map_or_else(|| "unavailable".into(), |n| n.to_string())
            )?;
        }
        for cause in event
            .causes
            .iter()
            .filter(|c| c.confidence == Confidence::Possible)
        {
            writeln!(out, "\nPossible: {}. {}.", kind(&cause.kind), cause.summary)?;
        }
        if !event.paths.is_empty() {
            writeln!(out, "\nPath")?;
        }
        for path in &event.paths {
            for c in &path.components {
                writeln!(
                    out,
                    "    {:?}    mode {:04o}    {}:{}",
                    c.path,
                    c.metadata.mode() & 0o7777,
                    c.metadata.uid(),
                    c.metadata.gid()
                )?;
            }
            if path.missing {
                writeln!(out, "    {:?}    absent", path.target)?;
            }
        }
        for limitation in &event.limitations {
            writeln!(out, "\n{limitation}")?;
        }
        if cli.verbose {
            for mount in &event.mounts {
                writeln!(out, "mount: {mount}")?;
            }
        }
    }
    if groups.len() > count {
        writeln!(
            out,
            "\n{} distinct denial groups omitted; use --all to display them.",
            groups.len() - count
        )?;
    }
    Ok(())
}
fn display_value(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), |s| format!("{s:?}"))
}
fn kind(kind: &CauseKind) -> &'static str {
    match kind {
        CauseKind::Dac => "filesystem permissions",
        CauseKind::PosixAcl => "POSIX ACL",
        CauseKind::StickyDirectory => "sticky-directory ownership rule",
        CauseKind::Capability => "ownership/capability requirement",
        CauseKind::NoExecMount => "noexec mount",
        CauseKind::ReadOnlyMount => "read-only mount",
        CauseKind::AppArmor => "AppArmor",
        CauseKind::Selinux => "SELinux",
        CauseKind::Landlock => "Landlock",
        CauseKind::Seccomp => "seccomp",
    }
}
fn confidence(confidence: Confidence) -> &'static str {
    match confidence {
        Confidence::Proven => "proven",
        Confidence::Strong => "strong",
        Confidence::Possible => "possible",
    }
}
fn open_flags(flags: u64) -> String {
    let mut names = vec![match flags as i32 & libc::O_ACCMODE {
        libc::O_WRONLY => "O_WRONLY",
        libc::O_RDWR => "O_RDWR",
        _ => "O_RDONLY",
    }];
    for (flag, name) in [
        (libc::O_CREAT, "O_CREAT"),
        (libc::O_TRUNC, "O_TRUNC"),
        (libc::O_APPEND, "O_APPEND"),
        (libc::O_PATH, "O_PATH"),
        (libc::O_DIRECTORY, "O_DIRECTORY"),
        (libc::O_NOFOLLOW, "O_NOFOLLOW"),
        (libc::O_EXCL, "O_EXCL"),
    ] {
        if flags & flag as u64 != 0 {
            names.push(name);
        }
    }
    names.join("|")
}
