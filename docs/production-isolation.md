# Production isolation boundary

WASI capability restrictions are not an OS multi-tenant sandbox. A component
cannot inherit host arguments, environment, files, or sockets through this
crate, but a defect in the embedding process or native runtime remains inside
that process's operating-system authority.

Use one host process per mutually distrusting tenant or trust domain. Apply a
separate cgroup or container boundary with explicit CPU, memory, process, file,
and wall-clock limits. Run as an unprivileged identity with no host mounts,
read-only application files, a private writable AOT directory, no container
runtime socket, no device access, and no privilege escalation.

Network policy must default deny. Permit only the destinations represented by
the runtime's outbound HTTP grants, and keep infrastructure metadata,
loopback, private ranges, and cluster control planes unreachable unless a
trusted service explicitly needs them. The host policy is the defense against
DNS rebinding and connector vulnerabilities.

Do not share an AOT authentication key or writable cache across trust domains.
Mount the key read-only and separately from the cache. Stop the host before key
rotation, Wasmtime upgrades, CPU-floor changes, or cache deletion; clear the
old cache and restart so no process holds stale native code.

The template in `deploy/systemd/runtrue-wasm-host.service` demonstrates the
minimum Linux process restrictions for an embedding host. Its executable name,
network policy, memory limit, and writable cache path are deployment inputs;
the crate does not install a service by itself.

Apply the runtime-level rules in the [security and capability model](security.md)
inside this OS boundary. Neither layer replaces the other.

## WASIX worker startup

Install the `runtrue-wasix-worker` executable at a root- or
administrator-controlled, non-symlink path. Run it from a dedicated service
account with no supplementary groups. A worker started with root
credentials drops all real, effective, saved, and filesystem user and group
IDs to numeric ID 65534 and clears supplementary groups before reporting
Ready; an already unprivileged worker retains its deployment identity. The
parent rejects all supplementary groups by default; deployments that genuinely
require non-root groups must list the exact IDs with
`with_allowed_supplementary_groups`.

For every execution, the parent must create the worker process group, attach
the process to its per-invocation cgroup, validate the isolated Ready frame,
and only then send framed guest-controlled bytes. CPU, RSS memory, process
count, wall-clock time, network access, and writable paths remain host policy.
The Ready frame is a compatibility and postcondition report from a trusted
executable, not cryptographic proof of isolation.
