# RunTrue Wasm Runtime

Private 0.1 incubation of a standards-first WebAssembly Component runtime.
It targets standard `wasi:cli/command` components instead of requiring a
RunTrue-owned world. WASI 0.3 is primary and WASI 0.2 is an explicit
compatibility profile.

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
environment variables must be supplied explicitly; filesystem and network
capability builders will be added only with confinement tests.

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

For request-driven services with no guest state to preserve, do not keep an
idle Store: retain the package at warm or warmish and create a fresh invocation
for each request. Generic stateful hibernation would require an explicit guest
checkpoint/restore contract because Wasmtime does not serialize live Stores.

`load_*` returns immediately and schedules bounded background preparation when
called inside Tokio. An immediate call joins the same per-digest preparation
lock, so concurrent callers do not duplicate compilation.

## Incubation policy

The crate is `publish = false` until the 0.1 gates in
[`docs/release-gates.md`](docs/release-gates.md) pass. crates.io source packages
are public, so private GitHub and private CI artifacts are the only supported
distribution channels during incubation.

## Development

```text
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
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
```

The JSON includes every raw sample plus p50 and p95 runtime initialization,
preparation, instantiation, execution, call-total, and harness-total timings.
The pause report records acknowledgement and resume-call percentiles, observed
idle-eviction time and tier, and Linux process RSS around eviction.
