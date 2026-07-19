# Release process

Releases are tag-driven. Pushing a `v*` tag starts GitHub Actions, which builds
the exact tagged source, repeats all quality checks, verifies the Cargo source
package, and produces a CycloneDX 1.5 SBOM and SHA-256 checksums. If that
version is not already on crates.io, the workflow publishes it with the
`CRATES_APIKEY` secret. The `release` environment should restrict deployments
to release tags and require approval where the repository plan supports it.

## One-time repository configuration

1. Protect `main` and require the `Rust quality and package`, `Dependency
   policy and advisories`, and `Reproducible WASI fixtures` checks.
2. Require pull requests, at least one approval, resolved conversations, and
   dismissal of stale approvals for security-sensitive changes.
3. Create a GitHub environment named `release`, add required reviewers, and
   prevent self-review where the organization plan supports it.
4. Enable private vulnerability reporting and Dependabot security updates.
5. Store a crates.io token as the `CRATES_APIKEY` secret. Restrict the token to
   publishing `runtrue-wasm-runtime`, place it in the `release` environment or
   make it available to this repository, and rotate it if disclosure is
   suspected.

GitHub artifact attestations are generated automatically for public releases;
checksums and the SBOM are included in every release bundle.

## Cutting a release

1. Make the [release-gate evidence](release-gates.md) current and resolve every
   blocking item.
2. Update the version in `Cargo.toml` and `Cargo.lock`.
3. Move the changelog entries from `Unreleased` into a dated version heading.
4. Run `scripts/release-check.sh` and merge the release pull request.
5. Confirm that `CRATES_APIKEY` is available to the `release` environment.
6. Create and push a signed, annotated tag:

   ```text
   git tag -s v0.1.0 -m "runtrue-wasm-runtime 0.1.0"
   git push origin v0.1.0
   ```

7. The tag starts the `Release` workflow. It publishes the crate only when the
   tagged version is absent from crates.io, then publishes the GitHub release.
8. Download the release assets, verify `SHA256SUMS`, and smoke-test the crate
   in a new empty consumer project before announcing it.

Crates.io packages permanently expose their included source. Review the
packaged source before pushing a release tag.
