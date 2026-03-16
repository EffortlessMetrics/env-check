# env-check-cli

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Clap-based CLI entry point for env-check.

## Commands

- `env-check check`: run discovery, probe, evaluate, and write artifacts.
- `env-check md`: render markdown from an existing `report.json`.
- `env-check explain`: explain finding codes/check IDs from the shared registry.

## What This Crate Does

- Parses command-line arguments and maps them to app-layer options.
- Writes canonical output artifacts and optional markdown/annotations.
- Applies stable exit-code behavior for policy fail vs tool/runtime error.

## Boundaries

- Keeps command parsing and UX concerns in CLI.
- Delegates business/orchestration logic to `env-check-app`.
- Reuses shared types/codes from `env-check-types`.
