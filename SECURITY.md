# Security policy

## Supported versions

The project is pre-1.0. Only the latest commit on `main` receives security
fixes.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for `runtrue/wasm-runtime`. Do not
open a public issue or include exploit details in an ordinary pull request. If
private reporting is unavailable, contact the maintainers through a private
channel and include:

- affected version or commit;
- impact and required attacker access;
- a minimal reproduction;
- suggested mitigations, if known.

We aim to acknowledge a report within three business days and provide an
initial assessment within seven business days. Timelines for a fix and
coordinated disclosure depend on severity and ecosystem impact.

The runtime threat model, capability boundaries, AOT authentication design,
and current limitations are documented in the [security and capability
model](docs/security.md). Deployment requirements are separate and documented
in the [production isolation boundary](docs/production-isolation.md).
