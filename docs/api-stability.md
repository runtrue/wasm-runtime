# Public API stability

The Rust crate is the primary implementation and owns the stable surface used
by future Python bindings. Standard WASI worlds are guest contracts; RunTrue
policy must remain host configuration rather than a custom guest ABI.

For the 0.1 series, the intended core surface is `RuntimeBuilder`, `Runtime`,
`Program`, `CommandInput`, `CommandOutput`, `HttpService`, `HttpRequest`,
`HttpResponse`, `OutboundHttpGrant`, tier measurements, cancellation, and
pause/resume controls. Public APIs do not expose Wasmtime engines, stores,
linkers, component handles, or generated WASI bindings.
Public state and error enums plus runtime-produced output structures are
non-exhaustive so standards versions, measurements, and observable states can
be added without forcing an immediate breaking release.

WASI 0.3 integration, resident HTTP reuse, and cooperative pause semantics are
experimental during 0.1. Patch releases may correct behavior that violates the
documented capability or isolation model. Additive API changes use a minor
pre-1.0 release; removal or semantic incompatibility requires an explicit
changelog entry and migration guidance.

Configuration structures currently expose fields to keep early embedding
simple. Consumers should construct them with `Default` and struct update syntax
instead of assuming the complete field set. Before 1.0, migrate long-lived
configuration surfaces to builders so fields can be added compatibly.

After the first public crate release, run `cargo-semver-checks` against the last
published version in release pull requests. It is intentionally not a useful
gate before a registry baseline exists.

Python bindings should wrap this crate rather than duplicate runtime policy.
Start them only after the 0.1 Rust surface has completed at least one private
consumer cycle.
