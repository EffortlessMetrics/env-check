# env-check-runtime

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Small runtime helper crate used by the app/cli orchestration boundary.

- Atomic file write helper (`write_atomic`) for artifact emission.
- Re-exported metadata/runtime helpers from `env-check-runtime-metadata`:
  - host metadata (`os`, `arch`, `hostname`)
  - CI provider metadata (`GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TF_BUILD`, `CI`)
  - GitHub event parsing (`$GITHUB_EVENT_PATH`)
  - git repository metadata (`git` + merge-base helpers)

This split keeps I/O and process metadata concerns split into separate microcrate
layers while preserving compatibility for existing call sites.

## Feature flags

- `metadata` (default): enable metadata and event parsing re-exports from
  `env-check-runtime-metadata`.
- Atomic file write helper used for artifact emission.

This crate keeps metadata I/O logic isolated so the app composition layer can
remain deterministic and SRP-oriented.
