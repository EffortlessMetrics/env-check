# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
# Build all crates
cargo build

# Run all tests (unit + integration)
cargo test

# Run tests for a specific crate
cargo test -p env-check-domain

# Run BDD tests
cargo test -p env-check-cli --test bdd

# Update snapshots (insta)
cargo insta accept

# Schema validation (xtask)
cargo run -p xtask -- schema-check

# Mutation testing (timeboxed, requires cargo-mutants)
cargo mutants -p env-check-domain

# Fuzzing (requires cargo-fuzz)
cargo fuzz list
cargo fuzz run parse_tool_versions
```

## Architecture

env-check is a **machine-truth** sensor that validates whether a machine/CI runner has the required tools installed for a repo. It uses a hexagonal (ports/adapters) architecture with microcrates.

### Crate Dependency Direction

```
cli → app → (sources, probe, domain, render) → types
```

- **env-check-types**: Shared DTOs, receipt envelope, domain types, stable finding codes. Safe to depend on from any layer.
- **env-check-sources**: Parses repo tool requirements from `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, and hash manifests.
- **env-check-probe**: Probes local machine (PATH, versions, hashes) via injectable port traits (`CommandRunner`, `PathResolver`, `Hasher`, `Clock`).
- **env-check-domain**: Pure policy/evaluation logic. No I/O. Maps `(Requirements × Observations × Policy) → Findings + Verdict`.
- **env-check-render**: Pure markdown renderer from receipt.
- **env-check-app**: Composition root. Wires adapters, runs the pipeline, writes artifacts.
- **env-check-cli**: Clap-based CLI entry point.

### Key Abstractions

- **Requirement**: Normalized tool requirement with constraint, source provenance, and probe kind.
- **Observation**: Result of probing (present, version, hash match, probe transcript).
- **Finding**: Domain output record with severity, code, message, location, help.
- **Verdict**: Final status (`pass|warn|fail|skip`) with counts and reasons.

### Stable Finding Codes (defined in `env-check-types::codes`)

- `env.missing_tool`, `env.version_mismatch`, `env.hash_mismatch`, `env.toolchain_missing`, `env.source_parse_error`
- `tool.runtime_error`

### Profiles

- `oss`: Safe for strangers; prefers `warn/skip` over `fail`
- `team`: Fails on missing required tools, warns on optional mismatches
- `strict`: Fails on any mismatch for required requirements

### Determinism Requirements

- All outputs must be byte-stable given identical inputs
- Findings sorted by: severity desc → path → check_id → code → message
- Use `BTreeMap` and explicit sort keys throughout domain logic

## Testing Strategy

- **Unit tests**: Parsers, domain evaluation, rendering (all pure)
- **Integration tests**: CLI with `assert_cmd`
- **BDD (cucumber)**: Workflow-level behavior with fake probe adapters
- **Property tests (proptest)**: Version parsing, `.tool-versions` parsing, path normalization
- **Fuzzing**: Parsers must never panic on arbitrary bytes
- **Mutation testing**: Focus on domain evaluation and parser branching

## Working Agreements

- New source/parser requires: fixtures, fuzz target, proptest case
- New finding code requires: explain entry, snapshot test coverage
- Probes use fixed argv vectors (no shell parsing)
- No "run arbitrary command from config" in v0.1
