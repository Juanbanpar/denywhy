use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Mount {
    pub id: u32,
    pub root: PathBuf,
    pub point: PathBuf,
    pub read_only: bool,
    pub noexec: bool,
    pub nosuid: bool,
    pub nodev: bool,
}
fn unescape(bytes: &[u8]) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            if i + 3 >= bytes.len()
                || !bytes[i + 1..i + 4]
                    .iter()
                    .all(|b| (b'0'..=b'7').contains(b))
            {
                return Err("invalid mountinfo escape".into());
            }
            let value = (bytes[i + 1] - b'0') as u16 * 64
                + (bytes[i + 2] - b'0') as u16 * 8
                + (bytes[i + 3] - b'0') as u16;
            if value > 255 || value == 0 {
                return Err("invalid mountinfo escaped byte".into());
            }
            result.push(value as u8);
            i += 4;
        } else {
            result.push(bytes[i]);
            i += 1;
        }
    }
    Ok(result)
}
fn option(bytes: &[u8], name: &[u8]) -> bool {
    bytes.split(|b| *b == b',').any(|o| o == name)
}

pub fn parse(bytes: &[u8]) -> Result<Vec<Mount>, String> {
    bytes
        .split(|b| *b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|line| {
            let fields: Vec<&[u8]> = line.split(|b| *b == b' ').collect();
            let separator = fields
                .iter()
                .position(|f| *f == b"-")
                .ok_or("mountinfo missing separator")?;
            if separator < 6 || fields.len() != separator + 4 {
                return Err("malformed mountinfo fields".into());
            }
            let id = std::str::from_utf8(fields[0])
                .ok()
                .and_then(|s| s.parse().ok())
                .ok_or("invalid mount ID")?;
            Ok(Mount {
                id,
                root: PathBuf::from(OsString::from_vec(unescape(fields[3])?)),
                point: PathBuf::from(OsString::from_vec(unescape(fields[4])?)),
                read_only: option(fields[5], b"ro") || option(fields[separator + 3], b"ro"),
                noexec: option(fields[5], b"noexec"),
                nosuid: option(fields[5], b"nosuid"),
                nodev: option(fields[5], b"nodev"),
            })
        })
        .collect()
}

pub fn containing<'a>(mounts: &'a [Mount], path: &Path) -> Result<Option<&'a Mount>, String> {
    let Some(depth) = mounts
        .iter()
        .filter(|m| path.starts_with(&m.point))
        .map(|m| m.point.components().count())
        .max()
    else {
        return Ok(None);
    };
    let mut matches = mounts
        .iter()
        .filter(|m| path.starts_with(&m.point) && m.point.components().count() == depth);
    let first = matches.next();
    if matches.next().is_some() {
        return Err("stacked mountpoints cannot be distinguished by pathname".into());
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selects_nested_and_bind_mounts_with_escaped_names() {
        let m = parse(b"1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 0:1 / /srv ro,noexec,nosuid,nodev - tmpfs tmpfs rw\n3 2 8:1 /original /srv/a\\040b rw - ext4 /dev/a ro\n4 1 8:1 / /raw\\377 rw - ext4 /dev/a rw\n").unwrap();
        assert_eq!(
            containing(&m, Path::new("/srv/a b/file"))
                .unwrap()
                .unwrap()
                .id,
            3
        );
        let n = containing(&m, Path::new("/srv/file")).unwrap().unwrap();
        assert!(n.read_only && n.noexec && n.nosuid && n.nodev);
        assert_eq!(m[2].root, Path::new("/original"));
        assert_eq!(
            m[3].point,
            PathBuf::from(OsString::from_vec(b"/raw\xff".to_vec()))
        );
        assert_eq!(
            containing(&m, Path::new("/srv-other")).unwrap().unwrap().id,
            1
        );
        assert!(parse(b"broken").is_err());
    }
    #[test]
    fn rejects_ambiguous_stacked_mounts() {
        let m = parse(b"1 0 8:1 / / rw - ext4 x rw\n2 1 0:1 / / rw - tmpfs x rw\n").unwrap();
        assert!(containing(&m, Path::new("/foo")).is_err());
    }
}
