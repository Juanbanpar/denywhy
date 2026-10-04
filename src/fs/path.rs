use std::collections::VecDeque;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};

pub fn capture_base(tid: i32, dirfd: i32, path: &Path) -> io::Result<PathBuf> {
    if path.is_absolute() {
        return Ok(PathBuf::from("/"));
    }
    let root = fs::read_link(format!("/proc/{tid}/root"))?;
    let base = fs::read_link(if dirfd == libc::AT_FDCWD {
        format!("/proc/{tid}/cwd")
    } else {
        format!("/proc/{tid}/fd/{dirfd}")
    })?;
    if base.as_os_str().as_encoded_bytes().ends_with(b" (deleted)") {
        return Err(io::Error::other("pathname base has been deleted"));
    }
    base.strip_prefix(&root)
        .map(|p| Path::new("/").join(p))
        .map_err(|_| io::Error::other("pathname base lies outside tracee root"))
}

#[derive(Debug)]
pub struct ComponentState {
    pub path: PathBuf,
    pub inspection_path: PathBuf,
    pub metadata: fs::Metadata,
}

pub struct Walk {
    pub components: Vec<ComponentState>,
    pub target: PathBuf,
    pub missing: bool,
    pub limitation: Option<String>,
}

fn pieces(path: &Path) -> VecDeque<OsString> {
    path.components()
        .filter_map(|c| match c {
            Component::Normal(p) => Some(p.to_owned()),
            Component::ParentDir => Some(OsString::from("..")),
            Component::CurDir => Some(OsString::from(".")),
            _ => None,
        })
        .collect()
}

pub fn walk(root: &Path, base: &Path, path: &Path, follow_final: bool) -> Walk {
    let mut queue = pieces(if path.is_absolute() { path } else { base });
    if !path.is_absolute() {
        queue.extend(pieces(path));
    }
    let mut current = PathBuf::from("/");
    let mut components = Vec::new();
    let mut links = 0;
    let mut missing = false;
    let mut limitation = None;
    // Absolute symlink targets must restart at the tracee root, rather than
    // letting the tracer's kernel path walk escape through /proc/<tid>/root.
    loop {
        let inspection_path = root.join(current.strip_prefix("/").unwrap());
        match fs::symlink_metadata(&inspection_path) {
            Ok(metadata) => components.push(ComponentState {
                path: current.clone(),
                inspection_path,
                metadata,
            }),
            Err(e) => {
                missing = e.kind() == io::ErrorKind::NotFound && queue.is_empty();
                if !missing {
                    limitation = Some(format!("cannot inspect {current:?}: {e}"));
                }
                break;
            }
        }
        let Some(piece) = queue.pop_front() else {
            break;
        };
        if piece == ".." {
            current.pop();
            if current.as_os_str().is_empty() {
                current.push("/");
            }
            continue;
        }
        if piece == "." {
            continue;
        }
        let next = current.join(&piece);
        let inspection = root.join(next.strip_prefix("/").unwrap());
        match fs::symlink_metadata(&inspection) {
            Ok(meta) if meta.file_type().is_symlink() && (follow_final || !queue.is_empty()) => {
                links += 1;
                if links > 40 {
                    limitation = Some("symlink resolution exceeds Linux's 40-link limit".into());
                    break;
                }
                match fs::read_link(&inspection) {
                    Ok(target) => {
                        if target.is_absolute() {
                            current = PathBuf::from("/");
                        }
                        let mut new = pieces(&target);
                        new.append(&mut queue);
                        queue = new;
                    }
                    Err(e) => {
                        limitation = Some(format!("cannot read symlink {next:?}: {e}"));
                        break;
                    }
                }
            }
            _ => {
                current = next;
            }
        }
    }
    Walk {
        components,
        target: current,
        missing,
        limitation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn root_relative_symlinks_and_parent_components() {
        let root = std::env::temp_dir().join(format!("denywhy-path-{}", std::process::id()));
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/file"), b"").unwrap();
        std::os::unix::fs::symlink("/a/file", root.join("link")).unwrap();
        let result = walk(&root, Path::new("/"), Path::new("link"), true);
        assert_eq!(result.target, Path::new("/a/file"));
        assert!(result.limitation.is_none());
        let result = walk(&root, Path::new("/a/b"), Path::new("../file"), true);
        assert_eq!(result.target, Path::new("/a/file"));
        let result = walk(&root, Path::new("/a"), Path::new("new"), true);
        assert!(result.missing);
        fs::remove_dir_all(root).unwrap();
    }
}
