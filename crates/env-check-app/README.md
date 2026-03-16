# env-check-app

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Application composition root for the env-check pipeline.

## What This Crate Does

- Loads config and chooses effective profile/fail_on settings.
- Orchestrates source parsing, requirement normalization, probing, and domain evaluation.
- Builds the canonical receipt envelope and markdown output payload.
- Re-exports `write_atomic` and provides runtime-error receipt fallback for CLI callers.

## Public API Highlights

- `run_check(...) -> CheckOutput`
- `run_check_with_options(...) -> CheckOutput`
- `run_check_with_clock(...) -> CheckOutput`
- `runtime_error_receipt(...)`
- `write_atomic(path, bytes)`

## Configuration

`AppConfig` supports these top-level keys:

- `profile = "oss|team|strict"`
- `fail_on = "error|warn|never"`
- `hash_manifests = ["path/to/file.sha256"]`
- `ignore_tools = ["optional-tool"]`
- `force_required = ["required-tool"]`

Parser control is under `[sources]`:

- `enabled = ["node|python|go"]` (optional allowlist)
- `disabled = ["node|python|go"]` (optional denylist)

## Boundaries

- This is the intended I/O boundary for app-layer orchestration.
- Delegates parsing/probing/evaluation/rendering to dedicated crates.
- Keeps receipt semantics aligned with `sensor.report.v1` and env-check runtime error rules.
