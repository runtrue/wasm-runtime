# runtrue-wasm-runtime

A Rust runtime for standard WebAssembly Components with cold, disk-AOT,
warmish, and warm execution tiers.

| Property | Value |
| --- | --- |
| Status | `0.1` alpha |
| Platform | Linux x86_64 |
| Rust | 1.94 |
| Wasmtime | 46.0.1 |
| Primary WASI profile | 0.3 |
| Compatibility profile | 0.2 |

## Supported components

The runtime accepts WebAssembly components exporting one supported standard
world:

| Workload | WASI 0.3 | WASI 0.2 |
| --- | --- | --- |
| Commands | `wasi:cli/command` | `wasi:cli/command` |
| HTTP services | `wasi:http/handler` | `wasi:http/incoming-handler` |

Native binaries, core Wasm modules, and components outside these worlds are
rejected.

## Optional WASIX features

- `wasix` enables the isolated worker protocol with WASIX's minimal native
  system surface.
- `wasix-checkpoint` additionally enables the pinned native journal cohort
  required for checkpoint capture and replay. It is opt-in because the WASIX
  0.701 journal is part of its broader `sys` preset.

The checkpoint feature does not relax the worker trust boundary: guest input
is still withheld until the fresh worker reports the required compatibility
and Linux isolation state. On Linux 5.6 or newer, the host pins a trusted
regular worker inode with `openat2`, executes that descriptor with `execveat`,
and verifies the worker's self-reported executable SHA-256 before sending input.

Every Linux worker arms `SIGKILL` as its parent-death signal before `exec` and
checks for a parent-loss race, so a worker cannot continue when its immediate
runtime parent disappears. This protects the worker process itself; deployments
that permit native descendants must additionally use a cgroup whose lifecycle
is owned by the supervisor.

`WasixWorkerConfig::with_worker_placement` installs a synchronous, fail-closed
placement policy that runs with the fresh PID before the parent sends module,
checkpoint, request, or Execute bytes. A production scheduler can use it to
attach each invocation to a pre-created cgroup v2 and verify membership before
returning. A placement error kills and reaps the worker. The default config has
no placement policy and does **not** claim cgroup CPU, memory, PID, or descendant
containment; deployments requiring those controls must configure the policy.

`restore_wasix_checkpoint` accepts an authenticated checkpoint and its exact
module, starts a fresh isolated destination worker, and resumes without any
destination arguments. Restored arguments and process state come only from the
checkpoint journal. The destination waits for native WASIX thread-pool work to
quiesce and tears down its task runtime before returning independently bounded
guest stdout and stderr. Worker-process diagnostics are separately bounded and
redacted from ordinary `Display` and `Debug` error formatting; callers must
explicitly access them from a structured checkpoint restore failure. When a
failed worker exits before supervision terminates it, the same failure reports
its portable exit code or Unix termination signal.

`capture_wasix_checkpoint` starts a fresh isolated source worker with bounded
arguments and environment, stops at an explicit WASIX snapshot, and returns a
trusted journal for `WasixCheckpointCodec::seal`. Standard input is not yet
supported by the capture path.

To move the checkpoint, authenticate the captured journal with
`WasixCheckpointCodec`, transfer the sealed artifact and exact module to the
destination, reopen the artifact, and pass it to `restore_wasix_checkpoint`.
Checkpoint format version 2 binds the artifact to the exact source worker
executable; the destination must run the byte-identical worker build. Drain
checkpoints before deploying a different worker binary.
The integration suite proves this flow with a Rust/WASIX program that captures
the argument `424242` in one worker and prints it after resuming in a different
worker without destination arguments.

## Execution tiers

| Tier | Retained material | Work before execution |
| --- | --- | --- |
| `Cold` | Source component | Validate and compile |
| `DiskAot` | Authenticated native AOT file | Read, authenticate, and deserialize |
| `Warmish` | AOT bytes in memory | Deserialize |
| `Warm` | Compiled component in memory | Create or reuse an eligible worker |

Loading a component schedules bounded background promotion when a Tokio
runtime is available. Concurrent callers join the same preparation operation
for a component digest.

Code tier and HTTP worker state are separate. A service reports whether it has
no resident worker, an active worker, or a paused resident worker. Idle worker
eviction can demote its code from warm to warmish.

## Commands

Each command run gets a fresh Store, instance, resource table, WASI context,
fuel budget, deadline, and I/O streams.

```rust
use runtrue_wasm_runtime::{CommandInput, Runtime};

# async fn example() -> runtrue_wasm_runtime::Result<()> {
let runtime = Runtime::with_defaults()?;
let program = runtime.load_file("tool.wasm")?;
let output = program
    .run(CommandInput::new(br#"{"name":"Ada"}"#.to_vec()))
    .await?;

println!("tier: {:?}", output.measurement.prepared_from);
println!("total: {:?}", output.measurement.phases.total);
# Ok(())
# }
```

## HTTP services

`Program::http_service` creates a reusable standard WASI HTTP service:

```rust
# use runtrue_wasm_runtime::{HttpRequest, HttpServiceConfig, Result, Runtime};
# async fn example() -> Result<()> {
let runtime = Runtime::with_defaults()?;
let program = runtime.load_file("service.wasm")?;
let service = program
    .http_service(HttpServiceConfig::default())
    .await?;

let response = service
    .handle(HttpRequest::new("POST", "http://localhost/run", b"{}"))
    .await?;
# let _ = response;
# Ok(())
# }
```

- `HttpService::handle` is the buffered function-style API.
- `HttpService::handle_streaming` accepts standard `http::Request` bodies and
  streams the response without rebuilding headers, the URI, or the body.

Both APIs enforce admission, worker reuse, request deadlines, body limits, and
outbound capabilities. Outbound HTTP is denied unless an exact origin, method,
network, and byte-limit grant is configured.

Run the included streaming HTTP/1 host with:

```text
cargo run --release --example http_server
cargo run --release --example http_server -- service.wasm 127.0.0.1:8080
```

## Telemetry

| API | Value |
| --- | --- |
| `service.startup_from()` | Tier before service preparation |
| `service.startup_prepare()` | Code-preparation time |
| `service.startup_total()` | Total service-construction time |
| `response.body().metadata()` | Request ID, tier at admission, worker creation, and time to headers |
| `service.state()` | Worker residency state |
| `service.metrics()` | Worker, eviction, in-flight, and completion counters |

Cold and disk-AOT are normally service-startup observations. Warm and warmish
remain visible for each streaming request.

## Pause and resume

`Program::start` returns a controllable command invocation. `pause()` retains
the same Store and guest state; `resume()` continues that invocation. A paused
invocation is evicted after `RuntimeConfig::paused_resident_ttl`, which defaults
to 30 seconds. Eviction returns `Error::IdleEvicted`; a later run starts a new
invocation.

## Security

Components receive no ambient environment, arguments, filesystem, process
handles, sockets, proxies, or credentials. Outbound HTTP is default-deny. AOT
files are deserialized only after identity checks and HMAC authentication.

WASI capability restrictions are not an OS multi-tenant sandbox. Isolate
mutually distrusting workloads in separate unprivileged processes or
containers. See [Security](docs/security.md) and [Production
isolation](docs/production-isolation.md).

## Benchmarks

Direct tier, TCP, capacity, and soak harnesses are under `benchmarks/`. Run
scripts through `uv` and retain raw JSON with every performance claim. See
[Benchmark methodology](docs/benchmark-methodology.md) and [Performance
regressions](docs/performance-regressions.md).

## Development

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
scripts/release-check.sh
```

Additional documentation:

- [API stability](docs/api-stability.md)
- [AOT cache operations](docs/cache-operations.md)
- [Release gates](docs/release-gates.md)
- [Soak testing](docs/soak-testing.md)
