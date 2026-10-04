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
