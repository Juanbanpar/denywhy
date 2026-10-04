#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::os::unix::process::ExitStatusExt;

fn main() {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|a| a == "--help" || a == "-h") {
        println!(
            "Usage: denywhy -- command [args...]\n\nRun a command and explain permission-related syscall failures."
        );
        return;
    }
    if args.first().is_none_or(|a| a != "--") || args.len() < 2 {
        eprintln!("denywhy: expected -- command [args...]");
        std::process::exit(125);
    }
    match std::process::Command::new(&args[1])
        .args(&args[2..])
        .status()
    {
        Ok(status) => std::process::exit(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)),
        ),
        Err(error) => {
            eprintln!("denywhy: cannot run {:?}: {error}", args[1]);
            std::process::exit(125);
        }
    }
}
