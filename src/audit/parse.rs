use crate::model::CauseKind;
use std::collections::HashMap;
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug)]
pub struct AuditEvent {
    pub timestamp: SystemTime,
    pub pid: Option<u32>,
    pub comm: Option<String>,
    pub path: Option<PathBuf>,
    pub mechanism: CauseKind,
    pub operation: Option<String>,
    pub raw_id: String,
    pub syscall: Option<u64>,
    pub arch: Option<u32>,
    pub fields: HashMap<String, Vec<u8>>,
}

fn tokens(line: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut fields = HashMap::new();
    let mut i = 0;
    while i < line.len() {
        if !line[i].is_ascii_alphabetic() && line[i] != b'_' {
            i += 1;
            continue;
        }
        let start = i;
        while i < line.len() && (line[i].is_ascii_alphanumeric() || line[i] == b'_') {
            i += 1;
        }
        if i == line.len() || line[i] != b'=' {
            continue;
        }
        let key = String::from_utf8(line[start..i].to_vec()).unwrap();
        i += 1;
        let mut value = Vec::new();
        if i < line.len() && line[i] == b'"' {
            i += 1;
            while i < line.len() && line[i] != b'"' {
                if line[i] == b'\\' && i + 1 < line.len() && matches!(line[i + 1], b'\\' | b'"') {
                    i += 1;
                }
                value.push(line[i]);
                i += 1;
            }
            if i < line.len() {
                i += 1;
            }
        } else {
            let start = i;
            while i < line.len() && !line[i].is_ascii_whitespace() {
                i += 1;
            }
            value.extend_from_slice(&line[start..i]);
            if matches!(key.as_str(), "name" | "path" | "comm" | "cwd")
                && !value.is_empty()
                && value.len().is_multiple_of(2)
                && value.iter().all(u8::is_ascii_hexdigit)
            {
                value = value
                    .chunks_exact(2)
                    .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                    .collect();
            }
        }
        fields.insert(key, value);
    }
    fields
}
fn avc_denied(line: &[u8]) -> bool {
    let Some(end) = line.windows(2).position(|w| w == b"):") else {
        return false;
    };
    line[end + 2..]
        .trim_ascii_start()
        .strip_prefix(b"avc:")
        .is_some_and(|rest| rest.trim_ascii_start().starts_with(b"denied "))
}

fn audit_id(line: &[u8]) -> Option<(String, SystemTime)> {
    let index = line.windows(6).position(|w| w == b"audit(")? + 6;
    let end = line[index..].iter().position(|b| *b == b')')? + index;
    let id = std::str::from_utf8(&line[index..end]).ok()?;
    let (time, serial) = id.split_once(':')?;
    serial.parse::<u64>().ok()?;
    let (seconds, fraction) = time.split_once('.').unwrap_or((time, "0"));
    if fraction.len() > 9 || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let duration = Duration::new(
        seconds.parse().ok()?,
        fraction.parse::<u32>().ok()? * 10u32.pow(9 - fraction.len() as u32),
    );
    Some((id.into(), UNIX_EPOCH.checked_add(duration)?))
}
fn text(fields: &HashMap<String, Vec<u8>>, key: &str) -> Option<String> {
    std::str::from_utf8(fields.get(key)?)
        .ok()
        .map(str::to_owned)
}
fn path(fields: &HashMap<String, Vec<u8>>, key: &str) -> Option<PathBuf> {
    fields
        .get(key)
        .filter(|v| v.as_slice() != b"(null)")
        .map(|v| PathBuf::from(OsString::from_vec(v.clone())))
}

pub fn parse(bytes: &[u8]) -> Vec<AuditEvent> {
    let mut groups: HashMap<String, (SystemTime, Vec<&[u8]>)> = HashMap::new();
    for line in bytes.split(|b| *b == b'\n') {
        if let Some((id, time)) = audit_id(line) {
            groups.entry(id).or_insert((time, Vec::new())).1.push(line);
        }
    }
    let mut events = Vec::new();
    for (raw_id, (timestamp, lines)) in groups {
        let records: Vec<_> = lines.iter().map(|line| tokens(line)).collect();
        let mut common = HashMap::new();
        for fields in &records {
            if fields
                .get("type")
                .is_some_and(|v| v == b"SYSCALL" || v == b"1300")
            {
                common.extend(fields.clone());
            }
            if fields
                .get("type")
                .is_some_and(|v| v == b"CWD" || v == b"1307")
                && let Some(cwd) = fields.get("cwd")
            {
                common.insert("cwd".into(), cwd.clone());
            }
        }
        let audit_paths: Vec<PathBuf> = records
            .iter()
            .filter(|f| f.get("type").is_some_and(|v| v == b"PATH" || v == b"1302"))
            .filter_map(|f| path(f, "name"))
            .collect();
        for (line, fields) in lines.iter().zip(records) {
            let mechanism = if fields.get("apparmor").is_some_and(|v| v == b"DENIED") {
                CauseKind::AppArmor
            } else if avc_denied(line) {
                CauseKind::Selinux
            } else if fields.get("type").is_some_and(|v| {
                v == b"LANDLOCK_ACCESS"
                    || v == b"AUDIT_LANDLOCK_ACCESS"
                    || v == b"1423"
                    || v == b"UNKNOWN[1423]"
            }) {
                CauseKind::Landlock
            } else {
                continue;
            };
            // Permissive/complain records describe allowed requests and cannot
            // identify the source of an observed errno.
            if fields.get("permissive").is_some_and(|v| v == b"1") {
                continue;
            }
            let mut all = common.clone();
            all.extend(fields);
            let operation = if mechanism == CauseKind::Selinux {
                line.iter()
                    .position(|b| *b == b'{')
                    .zip(line.iter().position(|b| *b == b'}'))
                    .filter(|(a, b)| a < b)
                    .and_then(|(a, b)| std::str::from_utf8(&line[a + 1..b]).ok())
                    .map(|s| s.trim().to_owned())
            } else if mechanism == CauseKind::Landlock {
                text(&all, "blockers")
            } else {
                text(&all, "operation")
            };
            let pid = text(&all, "pid").and_then(|v| v.parse().ok());
            let syscall = text(&all, "syscall").and_then(|v| v.parse().ok());
            let arch = text(&all, "arch").and_then(|v| u32::from_str_radix(&v, 16).ok());
            let direct = path(&all, "path").or_else(|| path(&all, "name"));
            let paths = if !audit_paths.is_empty() {
                audit_paths.clone()
            } else {
                direct.into_iter().collect()
            };
            for mut path in if paths.is_empty() {
                vec![None]
            } else {
                paths.into_iter().map(Some).collect()
            } {
                if let Some(p) = &path
                    && !p.is_absolute()
                    && let Some(cwd) = path_from_cwd(&all)
                {
                    path = Some(cwd.join(p));
                }
                events.push(AuditEvent {
                    timestamp,
                    pid,
                    comm: text(&all, "comm"),
                    path,
                    mechanism: mechanism.clone(),
                    operation: operation.clone(),
                    raw_id: raw_id.clone(),
                    syscall,
                    arch,
                    fields: all.clone(),
                });
            }
        }
    }
    events.sort_by_key(|e| e.timestamp);
    events
}
fn path_from_cwd(fields: &HashMap<String, Vec<u8>>) -> Option<PathBuf> {
    path(fields, "cwd").filter(|p| p.is_absolute())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn parses_apparmor_selinux_and_grouped_landlock() {
        let bytes = br#"type=AVC msg=audit(1700000000.100:1): apparmor="DENIED" operation="open" profile="/usr/bin/x" name="/private/file" pid=42 comm="x" requested_mask="r" denied_mask="r"
type=AVC msg=audit(1700000000.200:2): avc: denied { read } for pid=42 comm="x" name="file" scontext=a tcontext=b tclass=file permissive=0
type=PATH msg=audit(1700000000.200:2): item=0 name="/private/file" inode=123
type=SYSCALL msg=audit(1700000000.300:3): arch=c000003e syscall=257 pid=42 comm="x"
type=LANDLOCK_ACCESS msg=audit(1700000000.300:3): domain=123 blockers=fs.read_file path="/private/file"
"#;
        let events = parse(bytes);
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].mechanism, CauseKind::AppArmor);
        assert_eq!(
            events[1].path.as_deref(),
            Some(std::path::Path::new("/private/file"))
        );
        assert_eq!(events[2].pid, Some(42));
        assert_eq!(events[2].syscall, Some(257));
        assert!(
            parse(b"type=AVC msg=audit(1.0:1): avc: granted { read } pid=42 comm=\"denied\"\n")
                .is_empty()
        );
        assert!(parse(b"type=AVC msg=audit(bad): avc: denied { read }").is_empty());
        assert!(
            parse(b"type=AVC msg=audit(1.0:1): avc: denied { read } pid=42 permissive=1")
                .is_empty()
        );
    }
    #[test]
    fn preserves_hex_encoded_audit_paths() {
        let events = parse(
            b"type=AVC msg=audit(1.0:1): apparmor=\"DENIED\" pid=42 name=2FFF operation=\"open\"\n",
        );
        assert_eq!(
            events[0].path,
            Some(PathBuf::from(OsString::from_vec(vec![b'/', 0xff])))
        );
    }
}
