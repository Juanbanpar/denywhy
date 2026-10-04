use serde_json::Value;
use std::ffi::CString;
use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

fn output(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let out = std::thread::spawn(move || {
        let mut b = Vec::new();
        stdout.read_to_end(&mut b).unwrap();
        b
    });
    let err = std::thread::spawn(move || {
        let mut b = Vec::new();
        stderr.read_to_end(&mut b).unwrap();
        b
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("tracer exceeded test deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    Output {
        status,
        stdout: out.join().unwrap(),
        stderr: err.join().unwrap(),
    }
}
fn available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let result = output(Command::new(env!("CARGO_BIN_EXE_denywhy")).args(["--", "/bin/true"]));
        if result.status.code() == Some(125) && String::from_utf8_lossy(&result.stderr).contains("PTRACE_TRACEME unavailable") {
            assert!(std::env::var_os("DENYWHY_REQUIRE_PTRACE").is_none(), "CI requires ptrace but the host disallows it");
            eprintln!("SKIP: host disallows PTRACE_TRACEME; set DENYWHY_REQUIRE_PTRACE=1 to require integration coverage");
            return false;
        }
        assert!(result.status.success(), "{}", String::from_utf8_lossy(&result.stderr));
        true
    })
}
fn fixture() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(dir.path().join("blocked")).unwrap();
    fs::write(dir.path().join("blocked/file"), b"secret").unwrap();
    fs::write(dir.path().join("file"), b"secret").unwrap();
    fs::write(dir.path().join("allowed"), b"public").unwrap();
    fs::write(dir.path().join("noexec"), b"#!/bin/sh\nexit 0\n").unwrap();
    for (path, mode) in [
        ("file", 0),
        ("allowed", 0o644),
        ("noexec", 0o644),
        ("blocked", 0),
    ] {
        fs::set_permissions(dir.path().join(path), fs::Permissions::from_mode(mode)).unwrap();
    }
    dir
}
fn run_output(mode: &str, dir: &Path) -> Output {
    output(
        Command::new(env!("CARGO_BIN_EXE_denywhy"))
            .args([
                "--json",
                "--",
                std::env::current_exe().unwrap().to_str().unwrap(),
                "--ignored",
                "--exact",
                "tracee_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("DENYWHY_FIXTURE_MODE", mode)
            .env("DENYWHY_FIXTURE_DIR", dir),
    )
}
fn run(mode: &str, dir: &Path) -> Value {
    let result = run_output(mode, dir);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON: {e}: {}",
            String::from_utf8_lossy(&result.stdout)
        )
    })
}
#[test]
fn captures_filesystem_syscalls_and_relative_paths() {
    if !available() {
        return;
    }
    // Root's DAC capabilities defeat mode-based EACCES fixtures. Pure evaluator
    // tests still run as root; the ordinary integration suite needs no privileges.
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("SKIP: root bypasses DAC fixture modes");
        return;
    }
    let dir = fixture();
    for (mode, name) in [
        ("open", "openat"),
        ("relative", "openat"),
        ("dirfd", "openat"),
        ("mkdir", "mkdirat"),
        ("unlink", "unlinkat"),
        ("rename", "renameat2"),
        ("exec", "execve"),
    ] {
        let report = run(mode, dir.path());
        let denied = report["denials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["syscall"] == name)
            .unwrap_or_else(|| panic!("missing {name}: {report}"));
        assert_eq!(denied["errno"], "EACCES");
        assert!(denied["tid"].as_u64().unwrap() > 0);
        assert!(denied["syscall_number"].as_u64().is_some());
        assert!(
            denied["paths"][0]["path"]
                .as_str()
                .unwrap()
                .contains(if mode == "exec" {
                    "noexec"
                } else if mode == "mkdir" {
                    "new"
                } else {
                    "file"
                })
        );
        if mode == "dirfd" {
            assert!(denied["paths"][0]["dirfd"].as_i64().unwrap() >= 0);
        }
        if mode == "relative" {
            assert_eq!(denied["paths"][0]["dirfd"], libc::AT_FDCWD);
        }
        assert!(
            denied["causes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|c| c["kind"] == "dac" && c["confidence"] == "strong"),
            "{report}"
        );
    }
    fs::set_permissions(
        dir.path().join("blocked"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}
#[test]
fn seccomp_errno_does_not_become_dac() {
    if !available() {
        return;
    }
    let dir = fixture();
    for mode in ["seccomp_eacces", "seccomp_eperm"] {
        let report = run(mode, dir.path());
        let denied = report["denials"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["syscall"] == "openat")
            .unwrap();
        let causes = denied["causes"].as_array().unwrap();
        assert!(
            !causes
                .iter()
                .any(|c| c["kind"] == "dac" || c["kind"] == "posix_acl"),
            "{report}"
        );
        assert!(
            causes
                .iter()
                .any(|c| c["kind"] == "seccomp" && c["confidence"] == "possible"),
            "{report}"
        );
    }
    fs::set_permissions(
        dir.path().join("blocked"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}
#[test]
fn follows_fork_and_threads_without_losing_denials() {
    if !available() {
        return;
    }
    let dir = fixture();
    for mode in ["race", "race", "race", "race", "race", "exec_thread"] {
        let report = run(mode, dir.path());
        let denials = report["denials"].as_array().unwrap();
        assert!(!denials.is_empty());
        assert!(denials.iter().all(|d| d["tid"].as_u64().unwrap() > 0));
    }
    fs::set_permissions(
        dir.path().join("blocked"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
}
#[test]
fn preserves_signal_termination() {
    if !available() {
        return;
    }
    let result = output(Command::new(env!("CARGO_BIN_EXE_denywhy")).args([
        "--",
        "/bin/sh",
        "-c",
        "kill -TERM $$",
    ]));
    assert_eq!(result.status.code(), Some(143));
}

#[test]
fn diagnoses_private_noexec_and_read_only_mounts_when_namespaces_are_available() {
    if !available() {
        return;
    }
    for (mode, kind, errno) in [
        ("mount_noexec", "no_exec_mount", "EACCES"),
        ("mount_ro", "read_only_mount", "EROFS"),
    ] {
        let dir = fixture();
        fs::create_dir(dir.path().join("mount")).unwrap();
        let result = run_output(mode, dir.path());
        fs::set_permissions(
            dir.path().join("blocked"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        if result.status.code() == Some(77) {
            eprintln!("SKIP: host disallows private user/mount namespaces");
            continue;
        }
        assert_eq!(
            result.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(
            report["denials"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d["errno"] == errno
                    && d["causes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|c| c["kind"] == kind && c["confidence"] == "proven")),
            "{report}"
        );
    }
}

#[test]
fn forwards_interrupt_and_termination_without_stranding_tracees() {
    if !available() {
        return;
    }
    for signal in [libc::SIGINT, libc::SIGTERM] {
        let dir = fixture();
        let marker = dir.path().join("ready");
        let mut wrapper = Command::new(env!("CARGO_BIN_EXE_denywhy"))
            .args([
                "--",
                std::env::current_exe().unwrap().to_str().unwrap(),
                "--ignored",
                "--exact",
                "tracee_helper",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("DENYWHY_FIXTURE_MODE", "pause")
            .env("DENYWHY_FIXTURE_DIR", dir.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            if Instant::now() > deadline {
                let _ = wrapper.kill();
                let _ = wrapper.wait();
                panic!("tracee did not become ready");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let tracee: i32 = fs::read_to_string(marker).unwrap().parse().unwrap();
        // The PID belongs to the spawned diagnostic wrapper, not another process.
        assert_eq!(unsafe { libc::kill(wrapper.id() as i32, signal) }, 0);
        let status = loop {
            if let Some(status) = wrapper.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = wrapper.kill();
                let _ = wrapper.wait();
                panic!("signal left wrapper waiting");
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(128 + signal));
        // Once the wrapper reaped its command, this PID must not be left stopped.
        assert_eq!(unsafe { libc::kill(tracee, 0) }, -1);
        fs::set_permissions(
            dir.path().join("blocked"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
}

#[test]
#[ignore = "executed as the traced helper by integration tests"]
fn tracee_helper() {
    let mode = std::env::var("DENYWHY_FIXTURE_MODE").unwrap();
    let dir = PathBuf::from(std::env::var_os("DENYWHY_FIXTURE_DIR").unwrap());
    let path = CString::new(
        dir.join(if mode.starts_with("seccomp") || mode == "race" {
            "allowed"
        } else if mode == "exec" {
            "noexec"
        } else if mode == "open" {
            "file"
        } else {
            "blocked/file"
        })
        .as_os_str()
        .as_bytes(),
    )
    .unwrap();
    let new = CString::new(dir.join("blocked/new").as_os_str().as_bytes()).unwrap();
    let absolute_dir = CString::new(dir.as_os_str().as_bytes()).unwrap();
    let relative = c"blocked/file";
    if mode.starts_with("mount_") {
        mount_helper(&dir, mode == "mount_ro");
    }
    if mode == "pause" {
        fs::write(dir.join("ready"), std::process::id().to_string()).unwrap();
        loop {
            // pause waits for the externally forwarded signal.
            unsafe {
                libc::pause();
            }
        }
    }
    if mode == "exec_thread" {
        let binary = CString::new(std::env::current_exe().unwrap().as_os_str().as_bytes()).unwrap();
        let arguments: Vec<CString> = [
            binary.clone(),
            CString::new("--ignored").unwrap(),
            CString::new("--exact").unwrap(),
            CString::new("tracee_helper").unwrap(),
            CString::new("--nocapture").unwrap(),
            CString::new("--test-threads=1").unwrap(),
        ]
        .into();
        let environment = [
            CString::new("DENYWHY_FIXTURE_MODE=race").unwrap(),
            CString::new(
                [
                    b"DENYWHY_FIXTURE_DIR=".as_slice(),
                    dir.as_os_str().as_bytes(),
                ]
                .concat(),
            )
            .unwrap(),
        ];
        std::thread::spawn(move || {
            let mut argv: Vec<_> = arguments.iter().map(|a| a.as_ptr()).collect();
            argv.push(std::ptr::null());
            let mut envp: Vec<_> = environment.iter().map(|a| a.as_ptr()).collect();
            envp.push(std::ptr::null());
            // All argument and environment buffers remain live through execve.
            unsafe {
                libc::execve(binary.as_ptr(), argv.as_ptr(), envp.as_ptr());
            }
            panic!("helper execve failed");
        })
        .join()
        .unwrap();
        panic!("helper execve unexpectedly returned");
    }
    // Pointers refer to live CString storage. Every syscall below is a deliberate
    // fixture operation; its return value is checked before the helper exits.
    unsafe {
        if mode.starts_with("seccomp") || mode == "race" {
            install_filter(if mode == "seccomp_eperm" {
                libc::EPERM
            } else {
                libc::EACCES
            });
        }
        let result = match mode.as_str() {
            "open" | "seccomp_eacces" | "seccomp_eperm" => libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::O_RDONLY,
            ),
            "relative" => {
                assert_eq!(libc::chdir(absolute_dir.as_ptr()), 0);
                libc::syscall(
                    libc::SYS_openat,
                    libc::AT_FDCWD,
                    relative.as_ptr(),
                    libc::O_RDONLY,
                )
            }
            "dirfd" => {
                let fd = libc::open(absolute_dir.as_ptr(), libc::O_PATH | libc::O_DIRECTORY);
                assert!(fd >= 0);
                let result = libc::syscall(libc::SYS_openat, fd, relative.as_ptr(), libc::O_RDONLY);
                libc::close(fd);
                result
            }
            "mkdir" => libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, new.as_ptr(), 0o700),
            "unlink" => libc::syscall(libc::SYS_unlinkat, libc::AT_FDCWD, path.as_ptr(), 0),
            "rename" => libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                libc::AT_FDCWD,
                new.as_ptr(),
                0,
            ),
            "exec" => {
                let argv = [path.as_ptr(), std::ptr::null()];
                libc::execv(path.as_ptr(), argv.as_ptr()) as libc::c_long
            }
            "race" => {
                for _ in 0..8 {
                    let child = libc::fork();
                    assert!(child >= 0);
                    if child == 0 {
                        libc::syscall(
                            libc::SYS_openat,
                            libc::AT_FDCWD,
                            path.as_ptr(),
                            libc::O_RDONLY,
                        );
                        libc::_exit(0);
                    }
                    let mut status = 0;
                    assert_eq!(libc::waitpid(child, &mut status, 0), child);
                    let copy = path.clone();
                    std::thread::spawn(move || {
                        libc::syscall(
                            libc::SYS_openat,
                            libc::AT_FDCWD,
                            copy.as_ptr(),
                            libc::O_RDONLY,
                        );
                    })
                    .join()
                    .unwrap();
                }
                libc::_exit(0);
            }
            _ => panic!("unknown helper mode {mode}"),
        };
        assert_eq!(result, -1);
        assert_eq!(
            *libc::__errno_location(),
            if mode == "seccomp_eperm" {
                libc::EPERM
            } else {
                libc::EACCES
            }
        );
        libc::_exit(0);
    }
}
unsafe fn install_filter(errno: i32) {
    let mut filters = [
        libc::sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: 0x15,
            jt: 0,
            jf: 1,
            k: libc::SYS_openat as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x00050000 | errno as u32,
        },
        libc::sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: 0x7fff0000,
        },
    ];
    let program = libc::sock_fprog {
        len: filters.len() as u16,
        filter: filters.as_mut_ptr(),
    };
    // The kernel copies the live filter array during prctl. no_new_privs permits
    // installing this deterministic ERRNO filter without root.
    unsafe {
        assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
        assert_eq!(libc::prctl(libc::PR_SET_SECCOMP, 2, &program), 0);
    }
}

fn mount_helper(dir: &Path, read_only: bool) {
    // Prepare every buffer before fork: libtest has other threads, so the child
    // must avoid allocator and Rust I/O locks while preparing its private mount.
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };
    let uid_map = format!("0 {uid} 1\n");
    let gid_map = format!("0 {gid} 1\n");
    let target = CString::new(dir.join("mount").as_os_str().as_bytes()).unwrap();
    let program = CString::new(dir.join("mount/program").as_os_str().as_bytes()).unwrap();
    let new = CString::new(dir.join("mount/new").as_os_str().as_bytes()).unwrap();
    // Only private namespaces and paths beneath the test's temporary directory
    // are mutated. All C strings remain live until the child exits or execs.
    unsafe {
        let child = libc::fork();
        assert!(child >= 0);
        if child == 0 {
            if libc::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS) < 0 {
                libc::_exit(77);
            }
            for (path, bytes) in [
                (c"/proc/self/setgroups", b"deny".as_slice()),
                (c"/proc/self/uid_map", uid_map.as_bytes()),
                (c"/proc/self/gid_map", gid_map.as_bytes()),
            ] {
                let fd = libc::open(path.as_ptr(), libc::O_WRONLY);
                if fd < 0
                    || libc::write(fd, bytes.as_ptr().cast(), bytes.len()) != bytes.len() as isize
                {
                    libc::_exit(77);
                }
                libc::close(fd);
            }
            if libc::mount(
                c"tmpfs".as_ptr(),
                target.as_ptr(),
                c"tmpfs".as_ptr(),
                libc::MS_NOSUID | libc::MS_NODEV,
                std::ptr::null(),
            ) < 0
            {
                libc::_exit(77);
            }
            let fd = libc::open(program.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o755);
            let script = b"#!/bin/sh\nexit 0\n";
            if fd < 0
                || libc::write(fd, script.as_ptr().cast(), script.len()) != script.len() as isize
            {
                libc::_exit(78);
            }
            libc::close(fd);
            let flags = libc::MS_REMOUNT
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | if read_only {
                    libc::MS_RDONLY
                } else {
                    libc::MS_NOEXEC
                };
            if libc::mount(
                std::ptr::null(),
                target.as_ptr(),
                std::ptr::null(),
                flags,
                std::ptr::null(),
            ) < 0
            {
                libc::_exit(77);
            }
            let result = if read_only {
                libc::syscall(libc::SYS_mkdirat, libc::AT_FDCWD, new.as_ptr(), 0o700)
            } else {
                let argv = [program.as_ptr(), std::ptr::null()];
                libc::execv(program.as_ptr(), argv.as_ptr()) as libc::c_long
            };
            libc::_exit(
                if result == -1
                    && *libc::__errno_location()
                        == if read_only { libc::EROFS } else { libc::EACCES }
                {
                    0
                } else {
                    79
                },
            );
        }
        let mut status = 0;
        assert_eq!(libc::waitpid(child, &mut status, 0), child);
        libc::_exit(if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else {
            80
        });
    }
}
