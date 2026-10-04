mod correlate;
mod parse;

use crate::model::{Cause, Confidence};
use crate::trace::Failure;
use serde_json::json;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_LOG_BYTES: u64 = 4 * 1024 * 1024;

fn audit_log() -> Result<Vec<u8>, String> {
    let mut file = File::open("/var/log/audit/audit.log").map_err(|e| format!("audit.log: {e}"))?;
    let size = file.metadata().map_err(|e| e.to_string())?.len();
    let offset = size.saturating_sub(MAX_LOG_BYTES);
    file.seek(SeekFrom::Start(offset))
        .map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if offset > 0 {
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            bytes.drain(..=end);
        } else {
            bytes.clear();
        }
    }
    Ok(bytes)
}

fn journal(since: SystemTime, until: SystemTime) -> Result<Vec<u8>, String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_nanos();
    let path = std::env::temp_dir().join(format!("denywhy-journal-{}-{nonce}", std::process::id()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .map_err(|e| e.to_string())?;
    // Unlink immediately: the private log buffer cannot survive a tracer crash.
    std::fs::remove_file(path).map_err(|e| e.to_string())?;
    let since = since
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let until = until
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs()
        + 1;
    let mut child = Command::new("journalctl")
        .args([
            "--kernel",
            "--no-pager",
            "--quiet",
            "--output=cat",
            "--lines=10000",
        ])
        .arg(format!("--since=@{since}"))
        .arg(format!("--until=@{until}"))
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .stdout(file.try_clone().map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("journalctl: {e}"))?;
    // pidfd + poll gives this external query a bounded deadline without sleeps.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, child.id() as libc::pid_t, 0) };
    if fd < 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("journal query deadline unavailable (pidfd_open failed)".into());
    }
    // The successful syscall returned a newly owned descriptor.
    let pidfd = unsafe { File::from_raw_fd(fd as i32) };
    let mut pollfd = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // pollfd is a writable, single-element array; timeout bounds journal access.
    let ready = unsafe { libc::poll(&mut pollfd, 1, 1000) };
    if ready <= 0 {
        let _ = child.kill();
        let _ = child.wait();
        return Err("journal query interrupted or exceeded its one-second deadline".into());
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("journalctl exited with {status}"));
    }
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_LOG_BYTES {
        return Err("journal audit window exceeded 4 MiB".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut bytes = Vec::new();
    file.take(MAX_LOG_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

pub fn correlate_after_exit(failures: &mut [Failure]) {
    if failures.is_empty() {
        return;
    }
    let since = failures
        .iter()
        .map(|f| f.timestamp)
        .min()
        .unwrap()
        .checked_sub(Duration::from_millis(250))
        .unwrap_or(UNIX_EPOCH);
    let until = SystemTime::now();
    let file = audit_log();
    let mut events = file.as_ref().map(|b| parse::parse(b)).unwrap_or_default();
    let mut journal_error = None;
    if failures
        .iter()
        .any(|f| !events.iter().any(|e| correlate::matches(e, f)))
    {
        match journal(since, until) {
            Ok(bytes) => events.extend(parse::parse(&bytes)),
            Err(e) => journal_error = Some(e),
        }
    }
    let mut assignments: Vec<Vec<&parse::AuditEvent>> =
        (0..failures.len()).map(|_| Vec::new()).collect();
    let mut ambiguous = false;
    for event in &events {
        match correlate::assign(event, failures) {
            Ok(Some(index)) => assignments[index].push(event),
            Ok(None) => {}
            Err(()) => ambiguous = true,
        }
    }
    for (failure, assigned) in failures.iter_mut().zip(assignments) {
        let mut matched_ids = std::collections::HashSet::new();
        for event in assigned {
            if correlate::matches(event, failure)
                && matched_ids.insert((event.raw_id.clone(), format!("{:?}", event.mechanism)))
            {
                let fields: serde_json::Map<String, serde_json::Value> = event
                    .fields
                    .iter()
                    .filter(|(k, _)| {
                        matches!(
                            k.as_str(),
                            "profile"
                                | "requested_mask"
                                | "denied_mask"
                                | "scontext"
                                | "tcontext"
                                | "tclass"
                                | "domain"
                                | "blockers"
                        )
                    })
                    .map(|(k, v)| {
                        (
                            k.clone(),
                            crate::output::bytes(std::ffi::OsStr::from_bytes(v)),
                        )
                    })
                    .collect();
                failure.causes.insert(0, Cause { kind: event.mechanism.clone(), confidence: Confidence::Proven, summary: "matching MAC audit denial".into(), evidence: json!({"audit_id": event.raw_id, "operation": event.operation, "path": event.path.as_ref().map(|p| crate::output::bytes(p.as_os_str())), "fields": fields}) });
            }
        }
        if ambiguous {
            failure.limitations.push(
                "Some audit records could not be assigned uniquely to repeated syscalls.".into(),
            );
        }
        if matched_ids.is_empty() {
            failure.limitations.push(if let (Err(file_error), Some(journal_error)) = (&file, &journal_error) {
                format!("MAC audit evidence unavailable ({file_error}; {journal_error}). Run with sufficient journal/audit permissions for SELinux/AppArmor/Landlock attribution.")
            } else { "No matching MAC audit denial was available; logging may be restricted, delayed, disabled or rate-limited.".into() });
        }
    }
}
