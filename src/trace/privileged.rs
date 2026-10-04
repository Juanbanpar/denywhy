use crate::fs::acl::xattr;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub fn check(root: &Path, path: &Path, depth: usize) -> Result<(), String> {
    let view = if path.is_absolute() {
        root.join(path.strip_prefix("/").unwrap())
    } else {
        root.join(path)
    };
    let meta = match fs::metadata(&view) {
        Ok(meta) => meta,
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
            ) =>
        {
            return Ok(());
        }
        Err(e) => return Err(format!("cannot inspect executable {path:?}: {e}")),
    };
    if !meta.is_file() {
        return Ok(());
    }
    let privileged = if meta.mode() & 0o6000 != 0 {
        true
    } else {
        xattr(&view, c"security.capability")
            .map_err(|e| format!("cannot inspect file capabilities on executable {path:?}: {e}"))?
            .is_some_and(|c| !c.is_empty())
    };
    if privileged {
        return Err(format!(
            "refusing to trace privileged executable\n\nTracing can change setuid/setgid or file-capability exec semantics, which would make the diagnosis unreliable.\n\nExecutable: {path:?}"
        ));
    }
    // A script's interpreter is executed by the kernel without a second user
    // execve stop. Inspect shebang interpreters before permitting that execution.
    if depth < 4
        && let Ok(mut file) = fs::File::open(&view)
    {
        let mut header = [0; 256];
        if let Ok(n) = file.read(&mut header)
            && header[..n].starts_with(b"#!")
        {
            let line = header[2..n].split(|b| *b == b'\n').next().unwrap();
            let interpreter = line
                .split(|b| *b == b' ' || *b == b'\t')
                .find(|p| !p.is_empty());
            if let Some(interpreter) = interpreter {
                check(
                    root,
                    Path::new(std::ffi::OsStr::from_bytes(interpreter)),
                    depth + 1,
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn refuses_setid_before_tracing() {
        let path = std::env::temp_dir().join(format!("denywhy-setid-{}", std::process::id()));
        fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o4755)).unwrap();
        let result = check(Path::new("/"), &path, 0);
        fs::remove_file(&path).unwrap();
        assert!(result.unwrap_err().contains("privileged executable"));
    }
}
