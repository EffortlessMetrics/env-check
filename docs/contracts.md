# Contracts

env-check speaks in receipts. This is a deliberately small API.

## Envelope

All receipts conform to `sensor.report.v1`:

- `schema` — identifies the concrete report schema (e.g., `sensor.report.v1`)
- `tool` — `{ name, version, commit? }`
- `run` — timestamps + (optional) host/ci/git metadata
- `verdict` — `{ status, counts, reasons[] }`
- `findings[]` — stable codes, human messages, best-effort locations
- `data` — tool-specific extension point (structured; schema-defined per tool)

See: `schemas/sensor.report.v1.schema.json`.

## env-check report

`env-check.report.v1` constrains:

- `schema == "sensor.report.v1"`
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

## Compatibility contract

The receipt schema (`sensor.report.v1`) and finding codes are public APIs.
Compatibility rules:

- **Patch releases**: no schema or code changes.
- **Minor releases**: additive fields under `data` or `finding.data` only.
- **Major releases**: required for breaking schema or code changes.

Deprecations must be documented, kept for at least one minor release, and
removed only in the next major release.

## Source kinds

Supported source file types (defined in `env-check-types::SourceKind`):

| SourceKind | File(s) | Description |
|------------|---------|-------------|
| `ToolVersions` | `.tool-versions` | asdf version manager |
| `MiseToml` | `.mise.toml` | mise version manager |
| `RustToolchain` | `rust-toolchain.toml`, `rust-toolchain` | Rust toolchain |
| `NodeVersion` | `.node-version` | Node.js version |
| `Nvmrc` | `.nvmrc` | nvm version |
| `PackageJson` | `package.json` | npm/Node.js engines |
| `PythonVersion` | `.python-version` | pyenv version |
| `PyprojectToml` | `pyproject.toml` | Python project |
| `GoMod` | `go.mod` | Go module |
| `HashManifest` | `scripts/tools.sha256` | Binary hashes |

## Probe kinds

How requirements are verified (defined in `env-check-types::ProbeKind`):

| ProbeKind | Description |
|-----------|-------------|
| `PathTool` | Check PATH presence and run `<tool> --version` |
| `RustupToolchain` | Check `rustup toolchain list` for installed toolchain |
| `FileHash` | Compute SHA256 of local file and compare |

## Profiles

Policy profiles that map findings to severities:

| Profile | Missing required | Missing optional | Version mismatch |
|---------|-----------------|------------------|------------------|
| `oss` | Warn | Info | Warn |
| `team` | Error | Warn | Error (required) / Warn (optional) |
| `strict` | Error | Error | Error |
