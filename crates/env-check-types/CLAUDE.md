# env-check-types

Shared domain types and stable APIs. This is a deliberately boring, dependency-safe foundation that all other crates depend on.

## Purpose

This crate defines the core data structures and stable finding codes used throughout the env-check system. It has minimal dependencies and is safe to import from any layer.

## Key Types

### Requirements & Observations
- `Requirement`: Normalized tool requirement with tool name, version constraint, required flag, source reference, probe kind, and optional hash spec
- `Observation`: Result of probing a machine (presence, version, hash match, probe transcript)
- `ProbeKind`: PathTool, RustupToolchain, FileHash
- `SourceKind`: ToolVersions, MiseToml, RustToolchain, NodeVersion, Nvmrc, PackageJson, PythonVersion, PyprojectToml, GoMod, HashManifest

### Findings & Verdicts
- `Finding`: Domain output record with severity, code, message, location, help text
- `Severity`: Info, Warn, Error
- `VerdictStatus`: Pass, Warn, Fail, Skip
- `ReceiptEnvelope`: Complete result envelope with schema, tool meta, run meta, verdict, findings

### Policy
- `PolicyConfig`: Profile (Oss/Team/Strict) and fail_on strategy
- `Profile`: Oss (lenient), Team (balanced), Strict (fail on any mismatch)

## Stable Finding Codes

Defined in `codes` module:
- `env.missing_tool` - Required tool not found on PATH
- `env.version_mismatch` - Installed version doesn't match constraint
- `env.hash_mismatch` - File hash doesn't match expected
- `env.toolchain_missing` - Rustup toolchain not installed
- `env.source_parse_error` - Failed to parse source file
- `tool.runtime_error` - Probe command failed to execute

## Working Agreements

- All types must implement `Serialize + Deserialize` for JSON compatibility
- Finding codes are stable API; never rename or remove existing codes
- New codes must be documented in root CLAUDE.md and receive explain coverage
- Types should be `Clone`, `Debug`, and `PartialEq` where practical
- Use `BTreeMap` over `HashMap` when iteration order matters for determinism
- This crate must remain dependency-light (serde, chrono, thiserror only)

## Testing

- Unit tests for serialization round-trips
- Snapshot tests for JSON schema stability when adding new types
