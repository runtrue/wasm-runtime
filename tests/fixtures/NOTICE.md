# WASI HTTP test component

`p3-http-hello.component.wasm` is built from Wasmtime's
`crates/test-programs/src/bin/p3_cli_serve_hello_world.rs` at tag `v46.0.1`.
It exports the standard `wasi:http/handler@0.3.x` interface and returns
`Hello, WASI!`.

Upstream: <https://github.com/bytecodealliance/wasmtime/tree/v46.0.1>

Wasmtime is licensed under Apache-2.0 WITH LLVM-exception. The component's
SHA-256 is `f6871cc812bb5102105f9498c2a135d4cf08969dd9a2d58f514a2a32d69b6681`.

Additional standard fixtures from the same tag and license:

- `p3-http-proxy.component.wasm` from `p3_http_proxy.rs`, SHA-256
  `f09271ee8f359790ec2c606dceb591912d1155156c1bc2f5c168f4957c669e4b`.
- `p3-http-sleep.component.wasm` from `p3_cli_serve_sleep.rs`, SHA-256
  `40114ffe2db05d91bb5ae27de49306f3df4e29bdb2efb86ec5c26c7c84b49060`.

`json-http-tool.component.wasm` is built from this repository's
`benchmarks/fixtures/json-http-tool` source using the standard `wasip2` 1.0.4
bindings for WASI HTTP 0.2.12. Its SHA-256 is
`62ee6ddbb780da2e249b2f65e703cded860afa3897bb6f4bbca8f3d0b69274e0`.

`p2-http-hello.component.wasm` is built from this repository's
`benchmarks/fixtures/p2-http-hello` source using the same standard `wasip2`
bindings. Its SHA-256 is
`26fa5f901aa88de442d856fd63d43b96f4944a44775de4480f9c219310403ede`.

Both WASI HTTP 0.2 fixtures are componentized with Wasmtime 46.0.1's official
`wasi_snapshot_preview1.proxy.wasm` adapter (SHA-256
`82b0c20205fe8fab16c9e6a48fb044c61f8e439a1d40a456f5bb2f9b31518b4e`).

`oversized-output.component.wasm` is built from the adjacent
`oversized_output.rs` source with the pinned Rust toolchain's standard
`wasm32-wasip2` target. It is used only to prove bounded stdout handling. Its
SHA-256 is `d27c3e2904499dc70ef601009763dd8867adc811320cdbedce2628a1635fdbbf`.

`wasix-checkpoint-number.wasm` is built from the adjacent `no_std` Rust source
with Rust 1.94.0's `wasm32-unknown-unknown` target, then transformed with
Binaryen `version_131` Asyncify. Binaryen is licensed under Apache-2.0. The
fixture's SHA-256 is
`8be7489cc7ab13ea4c33cf7d6547a6a9ba00da257baf12b803caef29bb63698a`.
