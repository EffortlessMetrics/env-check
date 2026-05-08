# Coverage

Codecov coverage is Rust execution-surface evidence for the `env-check` repository.

It answers:
> Did tests execute this Rust surface?

## What Coverage Does NOT Answer

Codecov coverage does not answer:
- whether declared tool requirements are interpreted correctly,
- whether source parsers are complete,
- whether runtime metadata detection is correct,
- whether probes classify installed tools correctly,
- whether version normalization is correct,
- whether `sensor.report.v1` receipts are schema-conformant,
- whether BDD coverage is adequate,
- whether mutation adequacy is strong,
- whether publish or release readiness is proven.

Those are separate proof lanes.

## Coverage Workflow

The Coverage workflow runs on:
- `push` to `main`
- `workflow_dispatch` (manual trigger)
- PRs labeled `coverage`, `full-ci`, or `ci:full`

## Artifacts

Durable receipts are:
- `coverage.json` — detailed coverage metrics in JSON format
- `coverage.txt` — human-readable coverage summary
- `lcov.info` — LCOV format for Codecov upload
- GitHub Actions coverage artifact (14-day retention)
- Codecov dashboard at https://codecov.io/gh/EffortlessMetrics/env-check

## Configuration

Coverage is configured via `codecov.yml`:
- Project-level target: auto, threshold 5%, informational
- Patch-level target: 70%, threshold 20%, informational
- Comments and annotations disabled (silent/advisory mode)
- Build tooling (`xtask/`, `crates/*/benches/`, `crates/*/examples/`) ignored

## Baseline and Thresholds

Initial rollout uses advisory-only statuses. Thresholds will be ratcheted after stable baseline data exists on the main branch.
