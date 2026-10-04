#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("denywhy supports native Linux x86_64 and aarch64 only");

mod cli;
mod fs;
mod output;
mod procfs;
mod trace;

fn main() {
    let cli = match cli::parse(std::env::args_os().skip(1)) {
        Ok(Some(cli)) => cli,
        Ok(None) => {
            println!(
                "Usage: denywhy [--json] [--verbose] [--all] [--no-color] -- command [args...]\n\nExplain permission-related Linux syscall failures."
            );
            return;
        }
        Err(e) => {
            eprintln!("denywhy: {e}");
            std::process::exit(125);
        }
    };
    match trace::run(&cli.command, cli.json) {
        Ok(outcome) => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output::json_report(&cli, &outcome)).unwrap()
                );
            } else {
                eprintln!("Command exited with status {}.", outcome.code);
                for event in outcome
                    .failures
                    .iter()
                    .take(if cli.all { usize::MAX } else { 10 })
                {
                    eprintln!(
                        "DENIED tid={} syscall={} -> {}",
                        event.tid,
                        event
                            .decoded
                            .as_ref()
                            .map(|c| c.name)
                            .unwrap_or("unsupported"),
                        output::errno(event.errno)
                    );
                    if let Some(call) = &event.decoded {
                        eprintln!("operation: {:?}", call.operation);
                        for path in &call.paths {
                            eprintln!(
                                "dirfd={} path={:?} base={:?}",
                                path.dirfd, path.path, path.base
                            );
                        }
                    }
                    if cli.verbose {
                        eprintln!("{:?}", event.context);
                    }
                    for limitation in &event.limitations {
                        eprintln!("{limitation}");
                    }
                }
            }
            std::process::exit(outcome.code);
        }
        Err(error) => {
            eprintln!("denywhy: {error}");
            std::process::exit(125);
        }
    }
}
