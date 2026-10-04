# denywhy

For a process with fsuid 1000 opening a file below a root-owned `0700`
directory, the relevant part of a report is:

```text
$ denywhy -- cat /srv/private/report

DENIAL 1

openat(AT_FDCWD, "/srv/private/report", O_RDONLY)
    -> EACCES

Cause
    filesystem permissions    strong
    missing directory search permission
    path: "/srv/private"

Process
    fsuid: 1000
```

Denywhy runs a command, traces permission-related syscall failures, and checks
Linux enforcement state that could explain them. When the available evidence
does not identify a cause, it reports `undetermined`. It does not change
permissions or policies, attach to existing processes, or replace auditd.

## Installation

Requires Linux 5.3 or later, a native x86_64 or aarch64 process, stable Rust
with edition 2024 support, and a C linker for the Linux target.

```sh
cargo install --locked --path .
```

The invoking user must be allowed to trace their child and inspect its memory
with `process_vm_readv`. Containers and host security policies can prohibit
these operations. Denywhy does not re-execute itself through sudo.

## Usage

```sh
denywhy -- cat /srv/private/report
denywhy -- ./program
denywhy -- rm /shared/file
denywhy -- mkdir /srv/application/cache
denywhy -- mv a b
denywhy --json -- command args
denywhy --verbose --all -- command args
```

Options precede the required `--` separator:

| Option | Behavior |
| --- | --- |
| `--json` | Write a versioned JSON report to stdout; send command stdout to stderr. |
| `--verbose` | Include full credentials, capability sets, mount state and cause evidence. |
| `--all` | Show all distinct denial groups instead of the first ten. |
| `--no-color` | Accepted; output is currently always plain text. |
| `--help` | Show invocation syntax. |

Human reports go to stderr; command stdout is otherwise unchanged. Equivalent
denials are grouped by syscall, errno, paths, operation, cause and security
context. Reports retain occurrence counts and the contributing PID/TID pairs.
Denywhy waits for traced descendants before producing the report.

Normal completion preserves the main command's exit code, including zero when
a program deliberately probes inaccessible paths. Signal termination returns
`128 + signal`. Denywhy reserves 125 for its own fatal failures and 124 for
unsupported privileged-execution semantics or inability to verify them.
`check` is not implemented.

## Supported syscalls

Denywhy records `EACCES`, `EPERM` and `EROFS`. Detailed pathname decoding covers:

- `openat`, `openat2`, `execve`, `execveat`
- `faccessat`, `faccessat2`, `mkdirat`, `unlinkat`
- `renameat`, `renameat2`, `linkat`, `symlinkat`
- `fchmodat`, `fchownat`, `truncate`, `mknodat`
- Native x86_64 legacy calls: `open`, `access`, `mkdir`, `unlink`, `rename`,
  `link`, `symlink`, `chmod`, `chown`, `lchown`, `mknod`

Other failing syscalls are retained with their number, ABI and raw arguments,
without detailed filesystem attribution. Compat i386 and x32 arguments are not
decoded. Network, IPC, mount operations and other syscall families are outside
the diagnostic scope.

## Attribution

The tracer uses `PTRACE_GET_SYSCALL_INFO`, captures path bytes and cwd/dirfd
bases at entry, and keeps pending calls per TID. It follows fork, vfork, clone
and exec events. At a permission failure it inspects the tracee's root view,
filesystem credentials, capability sets and mountinfo.

Filesystem analysis checks directory search permission, final-object access,
creation/deletion/rename parent permissions, sticky ownership rules, and the
relevant DAC, ownership and device-node capabilities. Linux POSIX ACL xattrs
are parsed directly, including named users/groups and mask semantics. If an
ACL cannot be read, the affected permission conclusion is withheld.

| Confidence | Evidence |
| --- | --- |
| `proven` | A correlated enforcing MAC denial, a noexec mount for a failed executable, or a read-only mount for a failed modifying operation. |
| `strong` | Observed credentials, capabilities, inode permissions and ACL state sufficiently explain the failure. |
| `possible` | A mechanism or incomplete namespace interpretation could explain the failure, without identifying its source. |

Enabled SELinux, an AppArmor profile, or active seccomp filters alone never
establish a cause. Seccomp is offered as a possible source only when no stronger
cause is available. Multiple supported explanations can appear together;
`strong` evidence does not establish which kernel check ran first.

## MAC audit access

After the command and its descendants exit, Denywhy first reads the recent tail
of `/var/log/audit/audit.log`, then queries kernel journal messages with
`journalctl` if needed. Queries are bounded; no tracee waits for audit output.
There is no fixed sleep to wait for records.

AppArmor DENIED records, enforcing SELinux AVC records, and supported Landlock
access records are joined with their associated audit records. Correlation
requires process identity, a narrow timestamp window, an exact path and a
matching operation or syscall. Ambiguous repeated syscalls are left unattributed.
PID-only, basename-only and path-only matches are insufficient.

Readable audit or journal records are necessary for MAC attribution. Missing,
delayed, disabled or rate-limited audit records can leave the cause undetermined.
Denywhy reports unavailable sources and does not evaluate or generate MAC
policies. Landlock rulesets are not reconstructed; only matching denial evidence
is used.

## ptrace and privileged executables

Ptrace changes timing and can suppress setuid/setgid and file-capability exec
transitions. Denywhy refuses known privileged executables before tracing the
initial command or allowing a later exec. Shebang interpreters are inspected
where readable, and the actual executable is checked again at the exec stop
before its user code resumes. There is no force option. A fatal tracer error
terminates and reaps tracked tracees; `PTRACE_O_EXITKILL` also covers tracer death.
SIGINT, SIGTERM and SIGHUP received by the wrapper are forwarded to traced TIDs.
This is not a job-control shell.

See [ptrace(2)](https://man7.org/linux/man-pages/man2/ptrace.2.html) for tracing
and execution semantics.

## Namespaces and path limitations

Paths are inspected through `/proc/<tid>/root`; cwd, directory descriptors and
mountinfo come from the tracee. Absolute symlink targets restart at the tracee's
root. A relative operation starts at its captured cwd or dirfd, so inaccessible
ancestors above that base are not treated as traversed directories.

A different or unreadable user namespace lowers DAC/capability confidence.
The tool does not model a full hierarchy of namespace capabilities or idmapped
mount ownership. Procfs magic-link resolution, deleted/outside-root pathname
bases, ambiguous stacked mounts, and `openat2` resolution constraints are
reported as limitations. Their ordinary filesystem interpretation is withheld.
Other LSMs may not expose enough information to explain a denial.

Other threads and processes can change memory, credentials, directories,
symlinks, mounts or metadata during tracing. Entry snapshots and stopped-thread
inspection reduce these races but do not eliminate them. Reports describe the
observed state, not an atomic replay of the kernel's permission checks.

Background: [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html),
[acl(5)](https://man7.org/linux/man-pages/man5/acl.5.html).

## JSON

The top-level report contains `schema_version: 1`, `command`, `exit`, `denials`
and `limitations`, plus the number of omitted groups. Each denial includes its
syscall/ABI, errno, operation parameters, original paths and bases, resolved
filesystem components, process context, mounts, structured causes and
limitations. PID/TID and timestamp describe the group's first occurrence;
`threads` and `count` describe all contributing occurrences.

Paths and command arguments remain byte strings internally. Valid UTF-8 is
encoded as a JSON string; other values use `{"bytes": [47, 255]}`. Human output
quotes paths for display. JSON output can redirect the command's normal stdout
behavior, so use it when that redirection is acceptable.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets -- --nocapture
cargo build --release
```

The normal suite does not require root. It includes pure DAC/ACL/mount/audit
fixtures and helper processes for syscall capture, relative paths, descendants,
thread exec, seccomp errno injection and signal cleanup. Filesystem denial tests
need an unprivileged user. Namespace mount tests run only when private user and
mount namespaces are available.

Restricted hosts explicitly skip live tracing tests. Set
`DENYWHY_REQUIRE_PTRACE=1` to make unavailable child tracing a test failure;
CI does so on native x86_64 and aarch64 Ubuntu runners. These configurations do
not establish validation on Debian, Fedora, or real enforcing SELinux/AppArmor
systems. Release acceptance needs live validation on those environments too.

## License

MIT OR Apache-2.0. See [LICENSE-MIT](LICENSE-MIT) and
[LICENSE-APACHE](LICENSE-APACHE).
