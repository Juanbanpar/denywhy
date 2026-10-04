#![deny(unsafe_op_in_unsafe_fn)]
#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
compile_error!("denywhy supports native Linux x86_64 and aarch64 only");

mod analyze;
mod audit;
mod cli;
mod fs;
mod model;
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
        Ok(mut outcome) => {
            audit::correlate_after_exit(&mut outcome.failures);
            for event in &mut outcome.failures {
                analyze::add_seccomp_observation(event);
            }
            let groups = output::groups(&outcome.failures);
            let result = if cli.json {
                use std::io::Write;
                let mut out = std::io::stdout().lock();
                serde_json::to_writer_pretty(
                    &mut out,
                    &output::json::report(&cli, &outcome, &groups),
                )
                .map_err(std::io::Error::other)
                .and_then(|_| writeln!(out))
            } else {
                output::human::render(&cli, &outcome, &groups, &mut std::io::stderr().lock())
            };
            if let Err(error) = result {
                eprintln!("denywhy: cannot write diagnostic output: {error}");
                std::process::exit(125);
            }
            std::process::exit(outcome.code);
        }
        Err(error) => {
            eprintln!("denywhy: {error}");
            std::process::exit(if error.kind() == std::io::ErrorKind::Unsupported {
                124
            } else {
                125
            });
        }
    }
}
