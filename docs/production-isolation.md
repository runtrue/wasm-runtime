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

Worker protocol version 7 requires Linux 5.6 or newer. Install the
`runtrue-wasix-worker` executable as a nonempty regular file. The file and every
directory in its configured absolute path must be owned by root or the host
process's effective user ID. Neither the file nor an ancestor may be group- or
world-writable; the file must also have no
set-user-ID or set-group-ID bits. No configured path component may be a symlink.
These checks intentionally reject workers reached through common writable
directories such as `/tmp`. Additional hard links, if used by packaging, must
remain under the same administrative control because they name the same inode.

The parent resolves the path with Linux `openat2(NO_SYMLINKS | NO_MAGICLINKS)`,
validates and SHA-256 hashes that open descriptor, and executes the same inode
with `execveat(AT_EMPTY_PATH)`. Replacing or renaming the configured pathname
after validation therefore cannot select another executable. Do not replace
this descriptor-based launch with a second pathname lookup.

Run the worker from a dedicated service account with no supplementary groups.
A worker started with root
credentials drops all real, effective, saved, and filesystem user and group
IDs to numeric ID 65534 and clears supplementary groups before reporting
Ready; an already unprivileged worker retains its deployment identity. The
parent rejects all supplementary groups by default; deployments that genuinely
require non-root groups must list the exact IDs with
`with_allowed_supplementary_groups`.

Before isolation, the worker hashes `/proc/self/exe`; its Ready frame reports
that immutable build digest. The parent compares it with the digest computed
from the pinned descriptor before accepting any guest input. Checkpoint format
version 2 authenticates the same source-worker digest, and restore or transport
fails closed unless the destination uses the byte-identical worker executable.
Deploy worker upgrades only after draining or deliberately invalidating
outstanding checkpoints. The runtime continues to reject this process boundary
on non-Linux targets rather than falling back to pathname execution.

For every execution, the parent must create the worker process group, attach
the process to its per-invocation cgroup, validate the isolated Ready frame,
and only then send framed guest-controlled bytes. CPU, RSS memory, process
count, wall-clock time, network access, and writable paths remain host policy.
The Ready frame is a compatibility and postcondition report from a trusted
executable, not cryptographic proof of isolation.
