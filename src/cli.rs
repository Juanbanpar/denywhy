use std::ffi::OsString;

pub struct Cli {
    pub json: bool,
    pub verbose: bool,
    pub all: bool,
    pub command: Vec<OsString>,
}

pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Option<Cli>, String> {
    let mut cli = Cli {
        json: false,
        verbose: false,
        all: false,
        command: Vec::new(),
    };
    let mut args = args.into_iter();
    for arg in args.by_ref() {
        match arg.to_str() {
            Some("--json") => cli.json = true,
            Some("--verbose") => cli.verbose = true,
            Some("--all") => cli.all = true,
            Some("--no-color") => {}
            Some("--help" | "-h") => return Ok(None),
            Some("--") => {
                cli.command.extend(args);
                break;
            }
            _ => {
                return Err(format!(
                    "unrecognized option {arg:?}; expected -- command [args...]"
                ));
            }
        }
    }
    if cli.command.is_empty() {
        return Err("expected -- command [args...]".into());
    }
    Ok(Some(cli))
}
