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

# Mutation testing via xtask (recommended)
cargo run -p xtask -- mutants

# Mutation testing directly (requires cargo-mutants)
cargo mutants -p env-check-domain

# Fuzzing (requires cargo-fuzz, nightly toolchain)
cargo fuzz list                        # List all fuzz targets
cargo fuzz run parse_tool_versions     # Run specific target
cargo fuzz run fuzz_go_mod -- -max_total_time=300  # Run with timeout
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

### Mutation Testing

Mutation testing validates test quality by introducing small code changes (mutants) and verifying tests catch them. This is a **scheduled/manual lane** activity, not part of default CI.

**Run via xtask (recommended):**
```bash
cargo run -p xtask -- mutants
```

**Pass extra arguments to cargo-mutants:**
```bash
cargo run -p xtask -- mutants --jobs 4
cargo run -p xtask -- mutants --list  # Show mutants without running
```

**Configuration:**
- `mutants.toml` in workspace root controls exclusions and timeouts
- Default target: `env-check-domain` (pure logic, highest mutation testing value)
- 60-second timeout per mutant prevents hanging
- BDD and integration tests excluded (too slow)

**Prerequisites:**
```bash
cargo install cargo-mutants
```

**Output:** Results written to `mutants.out/` (git-ignored).

### Fuzzing

Fuzzing validates that parsers never panic on arbitrary input. All source parsers have corresponding fuzz targets.

**Prerequisites:**
```bash
rustup install nightly
cargo install cargo-fuzz
```

**Available fuzz targets:**
- `parse_tool_versions` - .tool-versions parser
- `parse_mise_toml` - .mise.toml parser
- `parse_rust_toolchain` - rust-toolchain.toml parser
- `parse_hash_manifest` - hash manifest parser
- `fuzz_node_version` - .node-version parser
- `fuzz_nvmrc` - .nvmrc parser
- `fuzz_package_json` - package.json parser
- `fuzz_python_version` - .python-version parser
- `fuzz_pyproject_toml` - pyproject.toml parser
- `fuzz_go_mod` - go.mod parser

**Running fuzzing:**
```bash
# List all targets
cargo fuzz list

# Run a specific target (runs indefinitely until stopped)
cargo fuzz run parse_tool_versions

# Run with time limit (in seconds)
cargo fuzz run fuzz_go_mod -- -max_total_time=300

# Run with multiple jobs
cargo fuzz run fuzz_package_json --jobs 4
```

**Seed corpora:**
Each target has seed corpus files in `fuzz/corpus/<target>/` derived from test fixtures.

**Output:**
- Crashes saved to `fuzz/artifacts/<target>/`
- Corpus files accumulated in `fuzz/corpus/<target>/`

## Working Agreements

- New source/parser requires: fixtures, fuzz target, proptest case
- New finding code requires: explain entry, snapshot test coverage
- Probes use fixed argv vectors (no shell parsing)
- No "run arbitrary command from config" in v0.1
