# env-check-types

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Shared data model and stable external identifiers for env-check.

## What This Crate Owns

- Receipt envelope types (`ReceiptEnvelope`, `RunMeta`, `Verdict`, `Finding`, `ArtifactRef`).
- Requirement/probe model (`Requirement`, `Observation`, `ProbeKind`, `SourceKind`).
- Policy enums and config (`Profile`, `FailOn`, `PolicyConfig`).
- Stable finding/check registries (`codes`, `checks`) and explain registry (`explain_entries`, `explain_message`).
- Deterministic finding sort key (`finding_sort_key`).

## Boundaries

- No filesystem or process I/O.
- No parsing/probing orchestration logic.
- Kept dependency-light so every other crate can depend on it safely.

## Position In The Workspace

`env-check-types` is the foundation crate in the dependency direction:

`types <- (sources|probe|domain|evidence|render) <- app <- cli`
