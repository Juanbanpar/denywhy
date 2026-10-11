# denywhy

Denywhy explains permission-related failures in Linux commands. It runs a
command and traces its descendants, recording `EACCES`, `EPERM` and `EROFS`
syscall errors. It checks file permissions, POSIX ACLs, capabilities, mount
flags and available security audit records for a cause. When the evidence
is insufficient, the human report shows `undetermined`.

## Install

Requires Linux 5.3 or later on native x86_64 or aarch64, Rust with edition
2024 support, and a C linker.

```sh
git clone https://github.com/Juanbanpar/denywhy.git
cd denywhy
cargo install --locked --path .
```

The invoking user must be allowed to trace child processes with `ptrace` and
read their memory with `process_vm_readv`. Containers and security policies
may restrict this access.

## Run

Put denywhy options before `--` and the command after it:

```sh
denywhy -- cat /srv/private/report
denywhy -- ./program args
denywhy --verbose --all -- ./program args
denywhy --json -- ./program args > report.json
```

| Option | Behavior |
| --- | --- |
| `--verbose` | Include credentials, capabilities, mount state and cause evidence. |
| `--all` | Show all distinct denial groups; the default is ten. |
| `--json` | Write a JSON report to stdout and redirect command stdout to stderr. |
| `--help` | Show invocation syntax. |

Human reports go to stderr, leaving command stdout unchanged. Repeated denials
are grouped with occurrence counts. Reports are produced after the command and
its traced descendants exit.

Denywhy returns the main command's exit code, or `128 + signal` if it was killed
by a signal. It uses 124 when privileged execution is unsupported or cannot be
verified, and 125 for its own fatal errors. A recorded denial does not change a
successful command's exit code.

## What it can explain

Filesystem diagnosis covers opening and executing files, access checks,
creation, deletion, renaming, linking, permission and ownership changes,
truncation, and device-node creation. Other syscall failures are recorded with
raw arguments. Network and IPC failures have no detailed diagnosis, and i386
and x32 arguments are not decoded.

Reports label causes as `proven`, `strong` or `possible`. Mount flags and
matching enforcing audit denials can provide proof; observed filesystem state
can provide strong evidence. An enabled security mechanism alone does not
establish a cause.

SELinux, AppArmor and Landlock attribution requires matching denial records
from `/var/log/audit/audit.log` or kernel journal messages read through
`journalctl`. Missing or inaccessible records can leave a cause undetermined.
Active seccomp filters are reported only as a possible cause when stronger
evidence is absent.

Tracing changes timing and can suppress privilege transitions. Denywhy refuses
setuid/setgid and file-capability executables. Filesystem state can change
during inspection, and some namespace, idmapped-mount and path-resolution
cases cannot be fully interpreted; reports include these limitations.

## Development

```sh
cargo fmt --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets -- --nocapture
cargo build --locked --release
```

Run tests as an unprivileged user. Live tracing tests skip when the host blocks
ptrace; set `DENYWHY_REQUIRE_PTRACE=1` to make this a failure, as CI does.
Mount tests also need private user and mount namespaces.

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
