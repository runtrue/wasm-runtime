# RunTrue Wasm Runtime

Private 0.1 incubation of a standards-first WebAssembly Component runtime.
It targets standard `wasi:cli/command` and `wasi:http/handler` components
instead of requiring a RunTrue-owned world. WASI 0.3 is primary and WASI 0.2
is an explicit compatibility profile.

The Rust crate is the primary implementation. It has no custom RunTrue guest
world and does not depend on another application runtime. Release artifacts
are built from standard Cargo source packages; see
[`docs/releasing.md`](docs/releasing.md) for the guarded release process.

The private alpha is gated on Linux x86_64. Wasmtime 46's stack-switching
implementation required by WASI 0.3 is not supported on the current macOS
runner toolchain; additional targets will be added only when their full test
matrix passes.

The package promotes component code through four observable states:

| State | Retained material | Typical work before invocation |
| --- | --- | --- |
| cold | source component | validate and compile |
| disk AOT | authenticated serialized component | authenticate and deserialize |
| warmish | immutable AOT bytes in memory | deserialize |
| warm | compiled Component in memory | create a fresh Store and instance |

Every invocation receives a fresh Store, instance, resource table, WASI
context, fuel budget, deadline, stdin, stdout, and stderr. Host environment,
arguments, filesystem, and network are never inherited. Arguments and
environment variables must be supplied explicitly. Outbound HTTP is available
only through exact, bounded grants.

```rust
use runtrue_wasm_runtime::{CommandInput, Runtime};

# async fn example() -> runtrue_wasm_runtime::Result<()> {
let runtime = Runtime::with_defaults()?;
let program = runtime.load_file("tool.wasm")?;
let output = program
    .run(CommandInput::new(br#"{"name":"Ada"}"#.to_vec()))
    .await?;
println!("tier: {:?}", output.measurement.prepared_from);
# Ok(())
# }
```

## Pause, resume, and idle eviction

`Program::start` returns a controllable live invocation. A pause preserves the
same Store and guest state and is observed cooperatively at async and epoch
yield points:

```rust
# use runtrue_wasm_runtime::{CommandInput, Result, Runtime};
# async fn example() -> Result<()> {
# let runtime = Runtime::with_defaults()?;
# let program = runtime.load_file("tool.wasm")?;
let running = program.start(CommandInput::default())?;
running.pause()?;
running.resume()?;
let output = running.wait().await?;
# Ok(())
# }
```

A paused Store remains resident only for `RuntimeConfig::paused_resident_ttl`
(30 seconds by default). Expiry drops the live invocation, returns
`Error::IdleEvicted`, and demotes its package from warm to warmish when the AOT
entry is retained. A later run is fresh; the runtime never silently replays a
component and calls it a resume. Suspended and active execution durations are
reported separately.

## WASI HTTP and tool calls

`Program::http_service` dispatches buffered requests to the standard WASI HTTP
0.3 handler (or the 0.2 compatibility handler). The host owns the listener,
admission control, deadlines, and response limits. Guest outbound HTTP remains
denied unless the service receives an explicit origin, method, and byte-limit
capability.

```rust
# use runtrue_wasm_runtime::{HttpRequest, HttpServiceConfig, OutboundHttpGrant, Result, Runtime};
# async fn example() -> Result<()> {
let runtime = Runtime::with_defaults()?;
let program = runtime.load_file("tool-server.wasm")?;
let service = program.http_service(HttpServiceConfig {
    outbound_grants: vec![
        OutboundHttpGrant::new("https", "api.example.com")
            .with_methods(["GET"])
            .with_body_limits(1, 256 * 1024),
    ],
    ..HttpServiceConfig::default()
}).await?;
let response = service
    .handle(
        HttpRequest::new(
            "POST",
            "http://localhost/tools/call",
            br#"{"name":"search","arguments":{"query":"wasm"}}"#,
        )
        .with_header("content-type", "application/json"),
    )
    .await?;
# let _ = response;
# Ok(())
# }
```

An idle reusable worker is observable as `PausedResident`: it retains the live
Store and guest state for the fastest next request. When `idle_worker_ttl`
expires, the service drops the live worker and its pre-instance, then demotes
the package to warmish. The next request rebuilds from in-memory AOT without
recompiling. This is automatic, bounded tier movement—not serialization of a
live Store.

The minimal HTTP/1 host can serve the included standard fixture or a supplied
component:

```text
cargo run --release --example http_server
cargo run --release --example http_server -- tool-server.wasm 127.0.0.1:8080
```

`load_*` returns immediately and schedules bounded background preparation when
called inside Tokio. An immediate call joins the same per-digest preparation
lock, so concurrent callers do not duplicate compilation.

## Incubation policy

The crate remains unpublished until the 0.1 gates in
[`docs/release-gates.md`](docs/release-gates.md) pass. Publishing requires an
explicit choice in the protected release workflow. Crates.io source packages
are public, so private GitHub releases are the only supported distribution
channel during incubation.

## Development

```text
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
scripts/release-check.sh
```

Wasmtime 46's WASI 0.3 module is still labeled experimental by its embedding
API. The runtime pins the exact release and keeps those types behind this
crate's stable surface.

## Tier benchmark

Run the same standard no-op command through all preparation tiers. The first
argument selects WASI and the second is the sample count:

```text
cargo run --release --example tier_benchmark -- 0.3 100 > wasi-0.3.json
cargo run --release --example tier_benchmark -- 0.2 100 > wasi-0.2.json
cargo run --release --example pause_benchmark -- 100 > pause.json
cargo run --release --example http_benchmark -- 20 1000 > http.json
cargo run --release --example http_capacity_benchmark -- 10000 > capacity.json
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/build_fixtures.py
uv run benchmarks/http_compare.py --cold-iterations 20 --warm-requests 1000 > tcp.json
```

The JSON includes every raw sample plus p50 and p95 runtime initialization,
preparation, instantiation, execution, call-total, and harness-total timings.
The pause report records acknowledgement and resume-call percentiles, observed
idle-eviction time and tier, and Linux process RSS around eviction. The HTTP
report separately measures cold service construction plus first request,
paused-resident requests, post-eviction warmish restarts, and throughput at
concurrency 1, 8, and 32 using a standard WASI HTTP 0.3 component. It also
reports authenticated disk-AOT HTTP startup and artifact size. See
[`docs/benchmark-methodology.md`](docs/benchmark-methodology.md) and
[`docs/security.md`](docs/security.md) before interpreting or publishing data.
