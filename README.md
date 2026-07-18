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
```

The JSON includes every raw sample plus p50 and p95 runtime initialization,
preparation, instantiation, execution, call-total, and harness-total timings.
