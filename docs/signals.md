# Signals: Laboratory and Ledger

env-check separates its output into two layers with different stability guarantees.

## Ledger

The **Ledger** is the strict `sensor.report.v1` receipt at:

```
artifacts/env-check/report.json
```

This file is consumed by `cockpitctl` and any downstream automation. Its schema is versioned, validated in CI, and changes require a schema migration.

The `artifacts[]` array inside the receipt provides machine-readable pointers from the Ledger into the Laboratory, so consumers can discover depth files without hard-coding paths.

## Laboratory

The **Laboratory** lives under:

```
artifacts/env-check/extras/
```

This directory is the fast-changing playground for depth artifacts that are useful for debugging and experimentation but are not part of the stable contract. Files here may appear, change format, or disappear between minor releases.

## Artifact kinds

| Kind | Path | Description |
|------|------|-------------|
| `debug_log` | `extras/raw.log` | Probe debug transcript (commands, stdout/stderr) |

## Promotion path

New depth artifacts follow this lifecycle:

1. **Prototype** in `extras/` with a new `kind` value.
2. **Stabilize** over 2+ releases with consistent schema and consumer feedback.
3. **Promote** to `data{}` (structured payload inside the receipt) or a new top-level field via a schema version bump.

## Current promotion candidates

| Candidate | Status | Notes |
|-----------|--------|-------|
| Structured probe transcript | Experimental | Currently unstructured text in `extras/raw.log` |
| Dependency graph | Not started | Would capture tool dependency relationships |
