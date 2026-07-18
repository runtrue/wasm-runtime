# WASI HTTP test component

`p3-http-hello.component.wasm` is built from Wasmtime's
`crates/test-programs/src/bin/p3_cli_serve_hello_world.rs` at tag `v46.0.1`.
It exports the standard `wasi:http/handler@0.3.x` interface and returns
`Hello, WASI!`.

Upstream: <https://github.com/bytecodealliance/wasmtime/tree/v46.0.1>

Wasmtime is licensed under Apache-2.0 WITH LLVM-exception. The component's
SHA-256 is `f6871cc812bb5102105f9498c2a135d4cf08969dd9a2d58f514a2a32d69b6681`.
