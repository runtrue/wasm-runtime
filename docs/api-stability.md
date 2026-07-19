# Public API stability

## Scope

The Rust crate owns the runtime implementation and its stable public surface.
Standard WASI worlds define component contracts; runtime policy is expressed
through host configuration.

The 0.1 core surface is `RuntimeBuilder`, `Runtime`,
`Program`, `CommandInput`, `CommandOutput`, `HttpService`, `HttpRequest`,
`HttpResponse`, `StreamingHttpBody`, `HttpDispatchMetadata`,
`OutboundHttpGrant`, tier measurements, cancellation, and pause/resume
controls. The streaming HTTP surface uses the standard `http`/`http-body`
model without exposing Wasmtime engines, stores, linkers, component handles,
generated WASI bindings, or Wasmtime error types. Its dispatch metadata is
stored inline with the response body so control-plane correlation does not
require a per-request extension allocation.

Public state and error enums plus runtime-produced output structures are
non-exhaustive so standards versions, measurements, and observable states can
be added without forcing an immediate breaking release.

## Compatibility during 0.1

WASI 0.3 integration, resident HTTP reuse, and cooperative pause semantics are
experimental during 0.1. Patch releases may correct behavior that violates the
documented capability or isolation model. Additive API changes use a minor
pre-1.0 release; removal or semantic incompatibility requires an explicit
changelog entry and migration guidance.

Configuration structures currently expose fields to keep early embedding
simple. Consumers should construct them with `Default` and struct update syntax
instead of assuming the complete field set. Configuration fields are not a
stable extension point during the 0.1 series.

## Release checks

`cargo-semver-checks` requires a published registry baseline, so it is not a
release gate until one exists.
