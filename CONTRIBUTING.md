# Contributing

Keep changes small, standards-based, and measurable. Preserve compatibility
with the supported standard WASI worlds and express runtime policy through host
configuration.

## Development setup

Install the toolchain declared in `rust-toolchain.toml`; Cargo selects it
automatically. Use `uv`, never an ad hoc `pip` environment, for benchmark and
fixture scripts.

Run the local CI checks before opening a pull request:

```text
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo test --locked --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps
cargo package --locked
```

`scripts/release-check.sh` runs the canonical release subset, including a clean
consumer built only from the packaged crate.

When fixture sources change, regenerate the checked-in standard components:

```text
rustup target add wasm32-wasip1 wasm32-wasip2
uv run benchmarks/bootstrap_tools.py
uv run benchmarks/build_fixtures.py
```

## Change expectations

- Add tests for observable behavior and failure paths.
- Update `CHANGELOG.md` for user-visible changes.
- Include before-and-after raw samples for performance claims and describe the
  host, component digest, concurrency, and measurement boundary.
- Rotate TCP runner order as described in
  [`docs/benchmark-methodology.md`](docs/benchmark-methodology.md).
- Document any new capability, host resource, unsafe boundary, or dependency.
- Keep dependency versions intentional and update `Cargo.lock` in the same
  change.

Security reports do not belong in public issues; follow the
[security policy](SECURITY.md).
