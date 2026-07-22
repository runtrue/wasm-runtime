# Security and capability model

This runtime treats a WebAssembly component as untrusted code. Loading a
component grants no ambient arguments, environment variables, filesystem,
host process handles, or outbound network access. Each command invocation gets
a fresh Store and each HTTP service is bounded by explicit admission, reuse,
memory, fuel, and time limits.

## Outbound HTTP

Outbound HTTP is denied when `HttpServiceConfig::outbound_grants` is empty. A
grant matches one exact `http` or `https` scheme, authority (host plus optional
port), and an explicit method list. It also limits request and response body
bytes. Wildcards, URL user information, inherited credentials, implicit
redirect policy, and ambient proxy configuration are not capabilities.

Private, loopback, link-local, multicast, unspecified, and other non-public IP
destinations are rejected after DNS resolution unless the exact grant opts in
with `allow_private_network(true)`. Use this opt-in only for a trusted local
service; do not expose it directly to an untrusted tenant.

The 0.1 connector performs DNS validation before the default Wasmtime HTTP
connector resolves and connects. It does not pin the validated address to the
connection, so a malicious or compromised DNS service may exploit a rebinding
window. Use exact HTTPS origins, trusted DNS, and network-level egress controls
for defense in depth.

## AOT artifacts

AOT bytes are native executable material and are never accepted as ordinary
untrusted package input. Disk artifacts are keyed by component digest, exact
WASI profile, Wasmtime version, target, and compiler profile, then authenticated
with an installation-private HMAC key before unsafe Wasmtime deserialization.
The crate denies unsafe Rust everywhere except this single reviewed boundary.

The cache directory and files are private on Unix. Operators must keep the
authentication key and cache directory out of tenant control. Changing a
component, profile, target, Wasmtime version, compiler profile, artifact length,
metadata, or authentication key makes an entry incompatible.

## Resource and lifecycle boundaries

- Inbound and outbound bodies are bounded before they can grow without limit.
- A semaphore caps admitted HTTP requests; request and idle deadlines expire
  workers.
- A paused resident worker retains guest state only until its configured TTL.
  Eviction drops it and a later request starts a fresh instance from warmish
  AOT.
- HTTP 0.2 workers handle one request at a time. HTTP 0.3 workers use an
  explicitly bounded concurrent reuse count.
- Cache entries are bounded by count and bytes with deterministic LRU
  eviction.

The optional WASIX backend is deployed as a separate Linux worker. Before a
worker emits its Ready frame, it lowers its core-file and open-file limits,
removes root credentials and Linux capabilities, sets `no_new_privs`, and
disables dumpability. It also closes inherited host file descriptors above
standard error. The parent rejects a Ready frame that does not report every
required postcondition or the deployment's exact supplementary-group
allowlist. No guest request, module, package, or checkpoint may be sent before
that validation succeeds.

This worker bootstrap is an inner hardening layer, not a complete tenant
sandbox. In particular, rlimits do not provide reliable resident-memory,
aggregate-process, wall-clock, network, mount, or filesystem isolation.

This model does not yet claim multi-tenant process isolation. Run mutually
hostile tenants in separate OS sandboxes and add host network policy around the
process. See the [production isolation boundary](production-isolation.md) for
host requirements and [AOT cache operations](cache-operations.md) for key
rotation and recovery procedures.
