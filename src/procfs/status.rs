use serde::Serialize;
use std::fs;
use std::io;

#[derive(Debug, Clone, Serialize)]
pub struct Credentials {
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub fsuid: u32,
    pub rgid: u32,
    pub egid: u32,
    pub sgid: u32,
    pub fsgid: u32,
    pub supplementary_groups: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct Capabilities {
    pub inheritable: u64,
    pub permitted: u64,
    pub effective: u64,
    pub bounding: u64,
    pub ambient: u64,
}

#[derive(Debug, Serialize)]
pub struct ProcessContext {
    pub tgid: u32,
    pub credentials: Credentials,
    pub capabilities: Capabilities,
    pub no_new_privs: bool,
    pub seccomp: u32,
    pub seccomp_filters: Option<u32>,
    pub user_namespace_differs: Option<bool>,
    pub apparmor: Option<String>,
    pub selinux: Option<String>,
    pub comm: Option<String>,
}

fn field<'a>(text: &'a [u8], name: &str) -> io::Result<&'a str> {
    let value = text
        .split(|b| *b == b'\n')
        .find_map(|line| {
            line.strip_prefix(name.as_bytes())
                .and_then(|s| s.strip_prefix(b":"))
        })
        .ok_or_else(|| io::Error::other(format!("/proc/status missing {name}")))?;
    std::str::from_utf8(value)
        .map(str::trim)
        .map_err(|_| io::Error::other(format!("malformed /proc/status {name}")))
}
fn number(text: &[u8], name: &str) -> io::Result<u32> {
    field(text, name)?
        .parse()
        .map_err(|_| io::Error::other(format!("malformed /proc/status {name}")))
}
fn ids(text: &[u8], name: &str) -> io::Result<[u32; 4]> {
    let values: Vec<u32> = field(text, name)?
        .split_whitespace()
        .map(str::parse)
        .collect::<Result<_, _>>()
        .map_err(|_| io::Error::other(format!("malformed /proc/status {name}")))?;
    values
        .try_into()
        .map_err(|_| io::Error::other(format!("/proc/status {name} needs four IDs")))
}
fn cap(text: &[u8], name: &str) -> io::Result<u64> {
    u64::from_str_radix(field(text, name)?, 16)
        .map_err(|_| io::Error::other(format!("malformed /proc/status {name}")))
}

pub fn parse(text: impl AsRef<[u8]>) -> io::Result<ProcessContext> {
    let text = text.as_ref();
    let [ruid, euid, suid, fsuid] = ids(text, "Uid")?;
    let [rgid, egid, sgid, fsgid] = ids(text, "Gid")?;
    Ok(ProcessContext {
        tgid: number(text, "Tgid")?,
        credentials: Credentials {
            ruid,
            euid,
            suid,
            fsuid,
            rgid,
            egid,
            sgid,
            fsgid,
            supplementary_groups: field(text, "Groups")?
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| io::Error::other("malformed /proc/status Groups"))?,
        },
        capabilities: Capabilities {
            inheritable: cap(text, "CapInh")?,
            permitted: cap(text, "CapPrm")?,
            effective: cap(text, "CapEff")?,
            bounding: cap(text, "CapBnd")?,
            ambient: cap(text, "CapAmb")?,
        },
        no_new_privs: number(text, "NoNewPrivs")? != 0,
        seccomp: number(text, "Seccomp")?,
        seccomp_filters: field(text, "Seccomp_filters")
            .ok()
            .map(str::parse)
            .transpose()
            .map_err(|_| io::Error::other("malformed Seccomp_filters"))?,
        user_namespace_differs: None,
        apparmor: None,
        selinux: None,
        comm: None,
    })
}

pub fn capture(tid: i32) -> io::Result<ProcessContext> {
    let mut context = parse(fs::read(format!("/proc/{tid}/status"))?)?;
    context.user_namespace_differs = fs::read_link(format!("/proc/{tid}/ns/user"))
        .ok()
        .zip(fs::read_link("/proc/self/ns/user").ok())
        .map(|(a, b)| a != b);
    context.apparmor = fs::read_to_string(format!("/proc/{tid}/attr/apparmor/current"))
        .ok()
        .or_else(|| {
            fs::read_to_string(format!("/proc/{tid}/attr/current"))
                .ok()
                .filter(|s| {
                    s.trim() == "unconfined"
                        || s.contains(" (enforce)")
                        || s.contains(" (complain)")
                })
        })
        .map(|s| s.trim().to_owned());
    context.selinux = match fs::read_to_string("/sys/fs/selinux/enforce") {
        Ok(s) => Some(
            if s.trim() == "1" {
                "enforcing"
            } else {
                "permissive"
            }
            .into(),
        ),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::read_to_string("/sys/kernel/security/lsm")
                .ok()
                .filter(|s| !s.trim().split(',').any(|lsm| lsm == "selinux"))
                .map(|_| "disabled".into())
        }
        _ => None,
    };
    context.comm = fs::read_to_string(format!("/proc/{tid}/comm"))
        .ok()
        .map(|s| s.trim_end_matches('\n').to_owned());
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credentials_are_not_collapsed() {
        let text = "Tgid:\t42\nUid:\t1 2 3 4\nGid:\t5 6 7 8\nGroups:\t9 10\nCapInh:\t01\nCapPrm:\t02\nCapEff:\t03\nCapBnd:\t04\nCapAmb:\t05\nNoNewPrivs:\t1\nSeccomp:\t2\nSeccomp_filters:\t2\n";
        let c = parse(text).unwrap();
        assert_eq!(
            (c.credentials.ruid, c.credentials.fsuid, c.credentials.fsgid),
            (1, 4, 8)
        );
        assert_eq!(c.credentials.supplementary_groups, [9, 10]);
        let mut raw = b"Name: \xff\n".to_vec();
        raw.extend(text.as_bytes());
        assert_eq!(parse(raw).unwrap().credentials.fsuid, 4);
        assert_eq!(c.capabilities.effective, 3);
        assert_eq!(c.seccomp_filters, Some(2));
        assert!(parse(text.replace("1 2 3 4", "1 2")).is_err());
        assert!(parse(text.replace("CapEff:\t03", "CapEff:\tx")).is_err());
        assert_eq!(
            parse(text.replace("Seccomp_filters:\t2\n", ""))
                .unwrap()
                .seccomp_filters,
            None
        );
    }
}
