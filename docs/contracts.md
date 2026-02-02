# Contracts

env-check speaks in receipts. This is a deliberately small API.

## Envelope

All receipts conform to `receipt.envelope.v1`:

- `schema` — identifies the concrete report schema (e.g., `env-check.report.v1`)
- `tool` — `{ name, version, commit? }`
- `run` — timestamps + (optional) host/ci/git metadata
- `verdict` — `{ status, counts, reasons[] }`
- `findings[]` — stable codes, human messages, best-effort locations
- `data` — tool-specific extension point (structured; schema-defined per tool)

See: `schemas/receipt.envelope.v1.json`.

## env-check report

`env-check.report.v1` constrains:

- `schema == "env-check.report.v1"`
- `tool.name == "env-check"`
- `data` shape (sources used, policy hints, truncation markers)

See: `schemas/env-check.report.v1.json`.

## Finding codes (MVP)

These are stable external identifiers. Treat changes as breaking.

- `env.missing_tool`
- `env.version_mismatch`
- `env.hash_mismatch`
- `env.toolchain_missing`
- `env.source_parse_error`
- `tool.runtime_error` (shared)

Each emitted code must have an `env-check explain` entry.
