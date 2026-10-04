use std::process::Command;

#[test]
fn preserves_exit_status() {
    let status = Command::new(env!("CARGO_BIN_EXE_denywhy"))
        .args(["--", "/bin/sh", "-c", "exit 17"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(17));
}
