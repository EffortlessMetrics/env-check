# env-check-probe

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Probe adapters for machine observations (presence, versions, and hashes).

## What This Crate Does

- Probes tools on PATH and captures version output.
- Probes rustup-managed toolchain presence.
- Computes and compares SHA-256 hashes for file-hash requirements.
- Produces `Observation` records used by domain evaluation.

## Core Ports And Adapters

- `CommandRunner` / `OsCommandRunner`
- `PathResolver` / `OsPathResolver`
- `Hasher` / `Sha256Hasher`
- `Clock` / `SystemClock`

## Public API Highlights

- `Prober::new(...)`
- `Prober::probe(root, requirement) -> Observation`
- `LoggingCommandRunner` and `FileLogWriter` for optional debug transcripts
- `fakes` module for deterministic tests

## Boundaries

- Does not perform policy/severity decisions.
- Does not shape final receipts.
- Keeps OS interaction behind injectable traits for testability.
