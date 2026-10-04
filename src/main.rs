#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::OsString;
use std::path::PathBuf;
mod fs;
mod trace;

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
    match trace::run(&args[1..]) {
        Ok(outcome) => {
            for event in outcome.failures {
                if let Some(call) = &event.decoded {
                    eprintln!("{} {:?}", call.name, call.operation);
                    for path in &call.paths {
                        eprintln!(
                            "dirfd={} path={:?} base={:?}",
                            path.dirfd, path.path, path.base
                        );
                        if let Ok(base) = &path.base {
                            let walk = fs::path::walk(
                                &PathBuf::from(format!("/proc/{}/root", event.tid)),
                                base,
                                &path.path,
                                true,
                            );
                            eprintln!(
                                "resolved={:?} missing={} limitation={:?}",
                                walk.target, walk.missing, walk.limitation
                            );
                            for c in walk.components {
                                eprintln!("{:?} {:?} {:?}", c.path, c.inspection_path, c.metadata);
                            }
                        }
                    }
                }
                if let Some(limitation) = &event.limitation {
                    eprintln!("{limitation}");
                }
                eprintln!(
                    "DENIED tid={} syscall={} arch={:#x} args={:?} errno={}",
                    event.tid, event.number, event.arch, event.args, event.errno
                );
            }
            std::process::exit(outcome.code);
        }
        Err(error) => {
            eprintln!("denywhy: {error}");
            std::process::exit(125);
        }
    }
}
