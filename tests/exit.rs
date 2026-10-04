use std::process::Command;

#[test]
fn preserves_exit_status() {
    let result = Command::new(env!("CARGO_BIN_EXE_denywhy"))
        .args(["--", "/bin/sh", "-c", "exit 17"])
        .output()
        .unwrap();
    if result.status.code() == Some(125)
        && String::from_utf8_lossy(&result.stderr).contains("PTRACE_TRACEME unavailable")
    {
        eprintln!("SKIP: host disallows child ptrace");
        return;
    }
    assert_eq!(
        result.status.code(),
        Some(17),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn refuses_relative_privileged_executables_before_ptrace() {
    use std::os::unix::fs::PermissionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("program");
    std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o4755)).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_denywhy"))
        .current_dir(temporary.path())
        .args(["--", "./program"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(124));
    assert!(String::from_utf8_lossy(&result.stderr).contains("privileged executable"));
}
