# Contributing

The runtime is in private incubation until the 0.1 release. Keep changes small,
standards-based, and measurable. Runtime policy must remain outside guest ABI
definitions so standard WASI components continue to work without a RunTrue
world.

## Development setup

Install the toolchain declared in `rust-toolchain.toml`; Cargo will select it
automatically. Use `uv` for the benchmark Python scripts.

Run the local CI checks before opening a pull request:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo package --locked
```

When fixture sources change, regenerate the checked-in standard components:

```text
rustup target add wasm32-wasip1
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/build_fixtures.py
```

## Change expectations

- Add tests for observable behavior and failure paths.
- Update `CHANGELOG.md` for user-visible changes.
- Include before-and-after raw samples for performance claims and describe the
  host, component digest, concurrency, and measurement boundary.
- Document any new capability, host resource, unsafe boundary, or dependency.
- Keep dependency versions intentional and update `Cargo.lock` in the same
  change.

Security reports do not belong in public issues; follow `SECURITY.md`.
