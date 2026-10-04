use super::acl::Acl;
use crate::procfs::status::Credentials;

pub const CAP_CHOWN: u64 = 1 << 0;
pub const CAP_DAC_OVERRIDE: u64 = 1 << 1;
pub const CAP_DAC_READ_SEARCH: u64 = 1 << 2;
pub const CAP_FOWNER: u64 = 1 << 3;
pub const CAP_MKNOD: u64 = 1 << 27;

pub struct Inode {
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
}

pub fn allowed(
    inode: &Inode,
    credentials: &Credentials,
    capabilities: u64,
    acl: Option<&Acl>,
    requested: u16,
) -> bool {
    let grants = acl.map_or_else(
        || {
            let shift = if credentials.fsuid == inode.uid {
                6
            } else if credentials.fsgid == inode.gid
                || credentials.supplementary_groups.contains(&inode.gid)
            {
                3
            } else {
                0
            };
            ((inode.mode >> shift) & 7) as u16 & requested == requested
        },
        |acl| {
            acl.allows(
                credentials.fsuid,
                credentials.fsgid,
                &credentials.supplementary_groups,
                inode.uid,
                inode.gid,
                requested,
            )
        },
    );
    if grants {
        return true;
    }
    let directory = inode.mode & libc::S_IFMT == libc::S_IFDIR;
    if capabilities & CAP_DAC_OVERRIDE != 0
        && (requested & 1 == 0 || directory || inode.mode & 0o111 != 0)
    {
        return true;
    }
    capabilities & CAP_DAC_READ_SEARCH != 0
        && requested & 2 == 0
        && (directory || requested & 1 == 0)
}

pub fn sticky_denied(parent: &Inode, target: &Inode, fsuid: u32, capabilities: u64) -> bool {
    parent.mode & libc::S_ISVTX != 0
        && fsuid != parent.uid
        && fsuid != target.uid
        && capabilities & CAP_FOWNER == 0
}

pub fn ownership_denied(
    operation: &crate::trace::syscall::Operation,
    inode: &Inode,
    credentials: &Credentials,
    capabilities: u64,
) -> bool {
    use crate::trace::syscall::Operation;
    match *operation {
        Operation::Chmod { .. } => credentials.fsuid != inode.uid && capabilities & CAP_FOWNER == 0,
        Operation::Chown { uid, gid, .. } => {
            capabilities & CAP_CHOWN == 0
                && (credentials.fsuid != inode.uid
                    || (uid != u32::MAX && uid != inode.uid)
                    || (gid != u32::MAX
                        && gid != inode.gid
                        && gid != credentials.fsgid
                        && !credentials.supplementary_groups.contains(&gid)))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn credentials() -> Credentials {
        Credentials {
            ruid: 1000,
            euid: 1000,
            suid: 1000,
            fsuid: 1000,
            rgid: 1000,
            egid: 1000,
            sgid: 1000,
            fsgid: 1000,
            supplementary_groups: vec![27],
        }
    }
    #[test]
    fn owner_group_other_and_capability_bypasses() {
        let c = credentials();
        let file = Inode {
            uid: 1000,
            gid: 0,
            mode: libc::S_IFREG | 0o600,
        };
        assert!(allowed(&file, &c, 0, None, 6));
        let file = Inode {
            uid: 0,
            gid: 27,
            mode: libc::S_IFREG | 0o040,
        };
        assert!(allowed(&file, &c, 0, None, 4));
        assert!(!allowed(&file, &c, 0, None, 2));
        assert!(allowed(&file, &c, CAP_DAC_OVERRIDE, None, 6));
        assert!(!allowed(&file, &c, CAP_DAC_OVERRIDE, None, 1));
        assert!(allowed(&file, &c, CAP_DAC_READ_SEARCH, None, 4));
        assert!(!allowed(&file, &c, CAP_DAC_READ_SEARCH, None, 2));
        let directory = Inode {
            uid: 0,
            gid: 0,
            mode: libc::S_IFDIR | 0o700,
        };
        assert!(!allowed(&directory, &c, 0, None, 1));
        assert!(allowed(&directory, &c, CAP_DAC_READ_SEARCH, None, 1));
        let other = Inode {
            uid: 0,
            gid: 0,
            mode: libc::S_IFREG | 0o004,
        };
        assert!(allowed(&other, &c, 0, None, 4));
    }
    #[test]
    fn sticky_rules_use_directory_and_target_owners() {
        let parent = Inode {
            uid: 0,
            gid: 0,
            mode: libc::S_IFDIR | 0o1777,
        };
        let target = Inode {
            uid: 2000,
            gid: 2000,
            mode: libc::S_IFREG | 0o666,
        };
        assert!(sticky_denied(&parent, &target, 1000, 0));
        assert!(!sticky_denied(&parent, &target, 0, 0));
        assert!(!sticky_denied(&parent, &target, 2000, 0));
        assert!(!sticky_denied(&parent, &target, 1000, CAP_FOWNER));
        assert!(ownership_denied(
            &crate::trace::syscall::Operation::Chmod { mode: 0o600 },
            &target,
            &credentials(),
            0
        ));
        assert!(!ownership_denied(
            &crate::trace::syscall::Operation::Mknod {
                mode: libc::S_IFIFO
            },
            &target,
            &credentials(),
            0
        ));
    }
}
