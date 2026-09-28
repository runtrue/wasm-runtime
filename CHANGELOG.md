# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-alpha.6] - 2026-09-28

### Added

- Opt-in WASIX worker execution and authenticated checkpoint capture, transport,
  and restore across isolated workers, with a checkpoint migration CI gate.

### Changed

- Update Tokio, Serde, serde_json, thiserror, and wit-component; regenerate the
  WASI HTTP fixtures with the updated component encoder.
- Refresh pinned GitHub Actions dependencies and keep the fuzz lockfile and
  packaged-consumer checks compatible with runtime dependency updates.
- Allow releases to use crates.io trusted publishing when no API key is set.


### Security

- Update Wasmtime to 46.0.3 and patch h2 and rustls to resolve published
  RustSec advisories in both runtime and fuzz dependencies.

- Pin the trusted WASIX worker inode across validation and launch with Linux
  `openat2` and `execveat`, reject unsafe executable paths and permissions, and
  authenticate the exact worker build in Ready frames and checkpoint artifacts.

## [0.1.0-alpha.5] - 2026-07-19

### Changed

- Soak reports now record the crate version without embedding a local checkout
  path.

## [0.1.0-alpha.4] - 2026-07-19

### Added

- A bounded streaming HTTP host API that avoids request and response rebuilding
  while preserving admission, timeout, capability, metric, and body limits.
  Inline dispatch metadata reports request ID, admission tier, worker creation,
  and time to response headers for control-plane correlation.
- Failure-containment, cache-operations, package-consumer, and fuzz release
  gates for untrusted components and authenticated native artifacts.
- Alert-first performance regression collection with raw host metadata and a
  stable-runner enforcement path.
- Public API stability and production OS-isolation guidance.

### Changed

- Standard WASI linkers are initialized on first use for the selected profile,
  reducing process-to-ready work without changing component behavior.
- TCP comparisons rotate runner order to reduce cache-heat and CPU-boost bias.
- Public state and error enums are non-exhaustive so new standards versions
  and lifecycle states can be added compatibly.

## [0.1.0-alpha.3] - 2026-07-18

### Added

- Standard WASI 0.3-first command and HTTP component execution with an
  explicit WASI 0.2 compatibility profile.
- Cold, authenticated disk-AOT, warmish in-memory AOT, and resident warm
  placement states with per-phase measurements.
- Cooperative pause and resume, idle worker eviction, and bounded background
  preparation.
- Default-deny outbound HTTP capabilities with exact origin, method, network,
  and body limits.
- Direct-handler, TCP, capacity, cache eviction, timeout, and concurrent
  service benchmarks and tests.

[Unreleased]: https://github.com/runtrue/wasm-runtime/compare/v0.1.0-alpha.6...HEAD
[0.1.0-alpha.6]: https://github.com/runtrue/wasm-runtime/compare/v0.1.0-alpha.5...v0.1.0-alpha.6
[0.1.0-alpha.5]: https://github.com/runtrue/wasm-runtime/compare/v0.1.0-alpha.4...v0.1.0-alpha.5
[0.1.0-alpha.4]: https://github.com/runtrue/wasm-runtime/compare/v0.1.0-alpha.3...v0.1.0-alpha.4
[0.1.0-alpha.3]: https://github.com/runtrue/wasm-runtime/compare/v0.1.0-alpha.2...v0.1.0-alpha.3
