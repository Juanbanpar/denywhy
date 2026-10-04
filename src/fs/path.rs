use std::collections::VecDeque;
use std::ffi::CString;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

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
    // Path::components normalizes interior '.' and trailing slashes. The kernel
    // still requires the preceding object to be a directory in those cases.
    let mut pieces: VecDeque<_> = path
        .as_os_str()
        .as_bytes()
        .split(|b| *b == b'/')
        .filter(|p| !p.is_empty())
        .map(|p| OsString::from_vec(p.to_vec()))
        .collect();
    if path.as_os_str().as_bytes().ends_with(b"/") {
        pieces.push_back(OsString::from("."));
    }
    pieces
}
fn procfs(path: &Path) -> bool {
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // statfs is POD. The C string and output structure remain live for the call.
    let mut state: libc::statfs = unsafe { std::mem::zeroed() };
    // The kernel fills the full statfs buffer; no tracee pointer is dereferenced.
    unsafe { libc::statfs(path.as_ptr(), &mut state) == 0 && state.f_type == 0x9fa0 }
}

pub fn walk(root: &Path, base: &Path, path: &Path, follow_final: bool) -> Walk {
    let mut queue = pieces(path);
    // A relative dirfd/cwd walk starts at that directory. Its ancestors are not
    // traversed by the syscall and must not become false DAC explanations.
    let mut current = if path.is_absolute() {
        PathBuf::from("/")
    } else {
        base.to_path_buf()
    };
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
        if !queue.is_empty() && components.last().is_some_and(|c| !c.metadata.is_dir()) {
            limitation = Some(format!("non-directory path component {current:?}"));
            break;
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
                if procfs(&root.join(current.strip_prefix("/").unwrap())) {
                    limitation = Some(format!(
                        "procfs magic-link resolution unavailable at {next:?}"
                    ));
                    break;
                }
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
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        fs::create_dir_all(root.join("a/b")).unwrap();
        fs::write(root.join("a/file"), b"").unwrap();
        std::os::unix::fs::symlink("/a/file", root.join("link")).unwrap();
        let result = walk(root, Path::new("/"), Path::new("link"), true);
        assert_eq!(result.target, Path::new("/a/file"));
        assert!(result.limitation.is_none());
        let result = walk(root, Path::new("/a/b"), Path::new("../file"), true);
        assert_eq!(result.target, Path::new("/a/file"));
        let result = walk(root, Path::new("/a"), Path::new("new"), true);
        assert!(result.missing);
        let result = walk(root, Path::new("/"), Path::new("a/file/../b"), true);
        assert!(result.limitation.unwrap().contains("non-directory"));
        let result = walk(root, Path::new("/a/b"), Path::new("../file"), true);
        assert_eq!(result.components[0].path, Path::new("/a/b"));
    }
}

#[cfg(test)]
mod proc_tests {
    use super::*;
    #[test]
    fn does_not_resolve_proc_self_as_the_tracer() {
        let result = walk(
            Path::new("/"),
            Path::new("/"),
            Path::new("/proc/self/exe"),
            true,
        );
        assert!(
            result
                .limitation
                .as_deref()
                .is_some_and(|s| s.contains("procfs magic-link"))
        );
    }
}
