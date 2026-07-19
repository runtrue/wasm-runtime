# Release process

Releases are tag-driven. Pushing a `v*` tag starts GitHub Actions, which builds
the exact tagged source, repeats all quality checks, verifies the Cargo source
package, and produces a CycloneDX 1.5 SBOM and SHA-256 checksums. If that
version is not already on crates.io, the workflow publishes it through trusted
publishing. The `release` environment should restrict deployments to release
tags and require approval where the repository plan supports it.

## One-time repository configuration

1. On a GitHub plan that supports private-repository rules, protect `main` and
   require the `Rust quality and package`, `Dependency policy and advisories`,
   and `Reproducible WASI fixtures` checks. Until then, merging is an owner-only
   manual control and public release must be treated as blocked by policy.
2. Require pull requests, at least one approval, resolved conversations, and
   dismissal of stale approvals for security-sensitive changes.
3. Create a GitHub environment named `release`, add required reviewers, and
   prevent self-review where the organization plan supports it.
4. Enable private vulnerability reporting and Dependabot security updates.
5. Publish the first crate version once with an owner-scoped crates.io token.
   Then configure a trusted publisher for repository `runtrue/wasm-runtime`,
   workflow `release.yml`, and environment `release`. No long-lived registry
   token is used by GitHub Actions.

GitHub artifact attestations are generated automatically once the repository
is public. GitHub does not provide that feature to every private-repository
plan, so the workflow skips the attestation while the repository is private;
checksums and the SBOM are still included in the release bundle.

## Cutting a release

1. Make the [release-gate evidence](release-gates.md) current and resolve every
   blocking item.
2. Update the version in `Cargo.toml` and `Cargo.lock`.
3. Move the changelog entries from `Unreleased` into a dated version heading.
4. Run `scripts/release-check.sh` and merge the release pull request.
5. For the first release only, publish the verified crate with an owner-scoped
   token and configure the trusted publisher described above.
6. Create and push a signed, annotated tag:

   ```text
   git tag -s v0.1.0 -m "runtrue-wasm-runtime 0.1.0"
   git push origin v0.1.0
   ```

7. The tag starts the `Release` workflow. It publishes the crate only when the
   tagged version is absent from crates.io, then publishes the GitHub release.
8. Download the release assets, verify `SHA256SUMS`, and smoke-test the crate
   in a new empty consumer project before announcing it.

Crates.io packages permanently expose their included source. Do not push a
release tag until public source publication is approved.
