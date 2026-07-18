# Release process

Releases are deliberately manual. Pushing a tag never publishes the crate by
itself. GitHub Actions builds the exact tagged source, repeats all quality
checks, verifies the Cargo source package, and produces a CycloneDX 1.5 SBOM
and SHA-256 checksums. The `release` environment should be configured to
require approval before the publication job can continue.

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
5. Before the first crates.io publication, configure a crates.io trusted
   publisher for repository `runtrue/wasm-runtime`, workflow `release.yml`, and
   environment `release`. No long-lived registry token is needed.

GitHub artifact attestations are generated automatically once the repository
is public. GitHub does not provide that feature to every private-repository
plan, so the workflow skips the attestation while the repository is private;
checksums and the SBOM are still included in the release bundle.

## Cutting a release

1. Make the release-gate evidence current and resolve every blocking item in
   `docs/release-gates.md`.
2. Update the version in `Cargo.toml` and `Cargo.lock`.
3. Move the changelog entries from `Unreleased` into a dated version heading.
4. Run `scripts/release-check.sh` and merge the release pull request.
5. Create and push a signed, annotated tag:

   ```text
   git tag -s v0.1.0 -m "runtrue-wasm-runtime 0.1.0"
   git push origin v0.1.0
   ```

6. Run the `Release` workflow with that tag. Leave `publish_crate` disabled for
   a private GitHub-only release. To enable it, also enter `publish <tag>` in
   the confirmation field after approving public source publication to
   crates.io.
7. Download the release assets, verify `SHA256SUMS`, and smoke-test the crate
   in a new empty consumer project before announcing it.

Crates.io packages permanently expose their included source. Do not enable
`publish_crate` while the source is intended to remain private.
