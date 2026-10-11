use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug, PartialEq, Eq, serde::Serialize)]
pub struct Entry {
    pub tag: u16,
    pub permissions: u16,
    pub id: u32,
}
#[derive(Debug, serde::Serialize)]
pub struct Acl {
    entries: Vec<Entry>,
}

pub fn xattr(path: &Path, name: &std::ffi::CStr) -> io::Result<Option<Vec<u8>>> {
    let path = CString::new(path.as_os_str().as_bytes())?;
    // Both C strings are NUL-terminated and live for the call. A null buffer
    // requests the size; no user memory is written on this first call.
    let size = unsafe { libc::getxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        return if matches!(error.raw_os_error(), Some(libc::ENODATA | libc::EOPNOTSUPP)) {
            Ok(None)
        } else {
            Err(error)
        };
    }
    if size > 65536 {
        return Err(io::Error::other("xattr exceeds Linux's 64 KiB limit"));
    }
    let mut bytes = vec![0; size as usize];
    // The buffer has exactly the queried capacity. A concurrent xattr change
    // returns ERANGE, which is retained as unavailable evidence rather than retried.
    let count = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            bytes.as_mut_ptr().cast(),
            bytes.len(),
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    bytes.truncate(count as usize);
    Ok(Some(bytes))
}

pub fn read(path: &Path) -> Result<Option<Acl>, String> {
    xattr(path, c"system.posix_acl_access")
        .map_err(|e| e.to_string())?
        .map(|bytes| parse(&bytes))
        .transpose()
}

pub fn parse(bytes: &[u8]) -> Result<Acl, String> {
    if bytes.len() < 4 || !(bytes.len() - 4).is_multiple_of(8) || bytes[..4] != 2u32.to_le_bytes() {
        return Err("invalid Linux POSIX ACL xattr header or length".into());
    }
    let entries: Vec<Entry> = bytes[4..]
        .as_chunks::<8>()
        .0
        .iter()
        .map(|e| Entry {
            tag: u16::from_le_bytes(e[..2].try_into().unwrap()),
            permissions: u16::from_le_bytes(e[2..4].try_into().unwrap()),
            id: u32::from_le_bytes(e[4..].try_into().unwrap()),
        })
        .collect();
    let mut phase = 0;
    let mut users = Vec::new();
    let mut groups = Vec::new();
    let mut base = [0; 4];
    for e in &entries {
        let rank = match e.tag {
            1 => 0,
            2 => 1,
            4 => 2,
            8 => 3,
            16 => 4,
            32 => 5,
            _ => return Err("unknown POSIX ACL tag".into()),
        };
        if rank < phase || e.permissions & !7 != 0 {
            return Err("invalid POSIX ACL order or permissions".into());
        }
        phase = rank;
        match e.tag {
            2 => users.push(e.id),
            8 => groups.push(e.id),
            1 => base[0] += 1,
            4 => base[1] += 1,
            16 => base[2] += 1,
            32 => base[3] += 1,
            _ => unreachable!(),
        }
        if matches!(e.tag, 2 | 8) == (e.id == u32::MAX) {
            return Err("invalid POSIX ACL qualifier".into());
        }
    }
    if base[0] != 1
        || base[1] != 1
        || base[3] != 1
        || base[2] > 1
        || ((!users.is_empty() || !groups.is_empty()) && base[2] != 1)
        || users.windows(2).any(|w| w[0] >= w[1])
        || groups.windows(2).any(|w| w[0] >= w[1])
    {
        return Err("missing or duplicate POSIX ACL entries".into());
    }
    Ok(Acl { entries })
}

impl Acl {
    pub fn allows(
        &self,
        uid: u32,
        gid: u32,
        supplementary: &[u32],
        owner: u32,
        group: u32,
        requested: u16,
    ) -> bool {
        let mask = self
            .entries
            .iter()
            .find(|e| e.tag == 16)
            .map_or(7, |e| e.permissions);
        let grants = |permissions: u16| permissions & requested == requested;
        if uid == owner {
            return grants(
                self.entries
                    .iter()
                    .find(|e| e.tag == 1)
                    .unwrap()
                    .permissions,
            );
        }
        if let Some(e) = self.entries.iter().find(|e| e.tag == 2 && e.id == uid) {
            return grants(e.permissions & mask);
        }
        let member = |id| gid == id || supplementary.contains(&id);
        let mut matched = false;
        for e in &self.entries {
            if (e.tag == 4 && member(group)) || (e.tag == 8 && member(e.id)) {
                matched = true;
                // Linux requires one matching group entry to grant the whole
                // request; combining read from one and write from another is wrong.
                if grants(e.permissions & mask) {
                    return true;
                }
            }
        }
        !matched
            && grants(
                self.entries
                    .iter()
                    .find(|e| e.tag == 32)
                    .unwrap()
                    .permissions,
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Vec<u8> {
        let mut bytes = 2u32.to_le_bytes().to_vec();
        for (tag, permissions, id) in [
            (1u16, 7u16, u32::MAX),
            (2, 7, 1000),
            (4, 4, u32::MAX),
            (8, 2, 27),
            (16, 4, u32::MAX),
            (32, 1, u32::MAX),
        ] {
            bytes.extend(tag.to_le_bytes());
            bytes.extend(permissions.to_le_bytes());
            bytes.extend(id.to_le_bytes());
        }
        bytes
    }
    #[test]
    fn applies_owner_named_user_group_mask_and_other() {
        let acl = parse(&fixture()).unwrap();
        assert!(acl.allows(0, 0, &[], 0, 0, 7));
        assert!(acl.allows(1000, 1000, &[], 0, 0, 4));
        assert!(!acl.allows(1000, 1000, &[], 0, 0, 2));
        assert!(acl.allows(2000, 0, &[27], 0, 0, 4));
        assert!(!acl.allows(2000, 27, &[], 0, 0, 2));
        assert!(acl.allows(2000, 2000, &[], 0, 0, 1));
        let mut bytes = fixture();
        bytes[38] = 7;
        let acl = parse(&bytes).unwrap();
        assert!(!acl.allows(2000, 0, &[27], 0, 0, 6));
    }
    #[test]
    fn malformed_acl_is_unavailable_not_ignored() {
        assert!(parse(&[]).is_err());
        let mut bytes = fixture();
        bytes[4] = 3;
        assert!(parse(&bytes).is_err());
        let mut bytes = fixture();
        bytes.truncate(bytes.len() - 1);
        assert!(parse(&bytes).is_err());
    }
}
