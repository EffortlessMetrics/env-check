# Contributing to env-check

Thank you for your interest in contributing to env-check! This guide will help you get started with development and understand our contribution process.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Building the Project](#building-the-project)
  - [Running Tests](#running-tests)
- [Development Workflow](#development-workflow)
  - [Creating a Fork](#creating-a-fork)
  - [Making Changes](#making-changes)
  - [Running Tests](#running-tests-1)
  - [Submitting a PR](#submitting-a-pr)
- [Code Style](#code-style)
  - [Rust Formatting Guidelines](#rust-formatting-guidelines)
  - [Clippy Requirements](#clippy-requirements)
  - [Documentation Comments](#documentation-comments)
- [Testing Strategy](#testing-strategy)
  - [Unit Tests](#unit-tests)
  - [Integration Tests](#integration-tests)
  - [BDD Tests](#bdd-tests)
  - [Property Tests](#property-tests)
  - [Fuzz Testing](#fuzz-testing)
  - [Mutation Testing](#mutation-testing)
- [Documentation](#documentation)
  - [Updating Docs](#updating-docs)
  - [ADR Process](#adr-process)
  - [README Updates](#readme-updates)
- [Release Process](#release-process)
  - [Version Numbering](#version-numbering)
  - [Changelog Updates](#changelog-updates)

## Getting Started

### Prerequisites

- **Rust 1.75+** - The project requires Rust 1.75 or later. Install via [rustup](https://rustup.rs/):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **cargo** - Comes with Rust installation

- **Optional Tools** (for specific testing):
  ```bash
  # For mutation testing
  cargo install cargo-mutants

  # For fuzz testing (requires nightly toolchain)
  rustup install nightly
  cargo install cargo-fuzz

  # For coverage reporting
  cargo install cargo-llvm-cov

  # For snapshot test review
  cargo install cargo-insta
  ```

### Building the Project

```bash
# Clone the repository
git clone https://github.com/EffortlessMetrics/env-check.git
cd env-check

# Build all crates
cargo build

# Build in release mode
cargo build --release
```

### Running Tests

```bash
# Run all tests (unit + integration)
cargo test

# Run tests for a specific crate
cargo test -p env-check-domain

# Run tests with verbose output
cargo test -- --nocapture
```

## Development Workflow

### Creating a Fork

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/env-check.git
   cd env-check
   ```
3. Add the upstream repository:
   ```bash
   git remote add upstream https://github.com/EffortlessMetrics/env-check.git
   ```
4. Keep your fork updated:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

### Making Changes

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following the [Code Style](#code-style) guidelines

3. Ensure all tests pass:
   ```bash
   cargo test
   cargo clippy --all-targets --all-features -- -D warnings
   cargo fmt -- --check
   ```

### Running Tests

Before submitting a PR, run the full test suite:

```bash
# All tests
cargo test --workspace

# BDD scenarios
cargo test -p env-check-cli --test bdd

# CLI integration tests
cargo test -p env-check-cli --test cli

# Schema validation
cargo run -p xtask -- schema-check

# Full conformance suite
cargo run -p xtask -- conform
```

### Submitting a PR

1. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request on GitHub

3. Ensure all CI checks pass

4. Request review from maintainers

5. Address any review feedback

## Code Style

### Rust Formatting Guidelines

- Use `cargo fmt` to format code before committing:
  ```bash
  cargo fmt
  ```

- Follow standard Rust naming conventions:
  - `snake_case` for functions, variables, and modules
  - `PascalCase` for types, traits, and enums
  - `SCREAMING_SNAKE_CASE` for constants

- Keep lines under 100 characters where practical

- Use meaningful variable names that convey intent

### Clippy Requirements

The project enforces Clippy linting with warnings as errors:

```bash
# Run Clippy on all targets
cargo clippy --all-targets --all-features -- -D warnings
```

Address all Clippy warnings before submitting a PR. If a warning is a false positive, document why with an inline allow attribute.

### Documentation Comments

- Document all public APIs with doc comments (`///` or `//!`)
- Include examples in doc comments where helpful
- Keep documentation up-to-date with code changes

Example:
```rust
/// Evaluates requirements against observations and produces findings.
///
/// # Arguments
///
/// * `requirements` - The normalized tool requirements
/// * `observations` - The results from probing the environment
/// * `policy` - The evaluation policy to apply
///
/// # Returns
///
/// A tuple of findings and the final verdict.
pub fn evaluate(
    requirements: &[Requirement],
    observations: &[Observation],
    policy: &Policy,
) -> (Vec<Finding>, Verdict) {
    // ...
}
```

## Testing Strategy

env-check employs a multi-layered testing strategy to ensure correctness at every level.

### Unit Tests

Unit tests cover pure functions and isolated components:

- **Parsers**: `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, hash manifests, `.node-version`, `.nvmrc`, `package.json`, `.python-version`, `pyproject.toml`, `go.mod`
- **Domain evaluation**: Mapping requirements + observations → findings + verdict
- **Rendering**: Report → markdown transformation

Unit tests are located alongside source code using Rust's `#[cfg(test)]` module pattern.

```bash
# Run unit tests only
cargo test --workspace --lib
```

### Integration Tests

Integration tests verify component interactions:

- **CLI end-to-end tests** using `assert_cmd` crate
- **Artifact layout** and default path verification
- **Full pipeline** execution with real file system operations

Integration tests are located in each crate's `tests/` directory.

```bash
# Run CLI integration tests
cargo test -p env-check-cli --test cli
```

### BDD Tests

Behavior-driven development tests cover workflow-level behavior using Cucumber:

- Profile/policy semantics (oss, team, strict)
- Failure modes and error handling
- End-to-end scenarios with fake probe adapters

BDD tests use fakes for probes to ensure deterministic results.

```bash
# Run BDD scenarios
cargo test -p env-check-cli --test bdd
```

**Location**: [`features/env_check.feature`](features/env_check.feature)

### Property Tests

Property-based testing validates invariants across random inputs using proptest:

- **Version parsing**: Non-panicking and stable under random input
- **Whitespace handling**: `.tool-versions` parsing tolerates various whitespace patterns
- **Path normalization**: Stays repo-relative and uses forward slashes
- **Parser robustness**: All parsers handle edge cases gracefully

```bash
# Run property tests
cargo test -p env-check-sources-hash --test proptest
```

### Fuzz Testing

Fuzzing ensures parsers never panic on arbitrary bytes. All source parsers must have corresponding fuzz targets.

**Prerequisites**:
```bash
rustup install nightly
cargo install cargo-fuzz
```

**Running fuzzing**:
```bash
# List all fuzz targets
cargo fuzz list

# Run a specific target (runs indefinitely until stopped)
cargo fuzz run parse_tool_versions

# Run with time limit (in seconds)
cargo fuzz run fuzz_go_mod -- -max_total_time=300

# Run with multiple jobs
cargo fuzz run fuzz_package_json --jobs 4
```

**Available fuzz targets**:
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

**Seed corpora**: Each target has seed corpus files in [`fuzz/corpus/<target>/`](fuzz/corpus/)

### Mutation Testing

Mutation testing validates test quality by introducing small code changes (mutants):

```bash
# Run via xtask (recommended)
cargo run -p xtask -- mutants

# Pass extra arguments
cargo run -p xtask -- mutants --jobs 4
cargo run -p xtask -- mutants --list  # Show mutants without running
```

**Configuration**: [`mutants.toml`](mutants.toml) controls exclusions and timeouts

**Output**: Results written to `mutants.out/` (git-ignored)

### Snapshot Testing

env-check uses `insta` for snapshot testing, particularly in the render crate:

```bash
# Review pending snapshot changes
cargo insta review

# Accept all pending snapshots (intentional changes only)
cargo insta accept

# Run snapshot tests
cargo test -p env-check-render
```

**Snapshot locations**: [`crates/env-check-render/tests/snapshots/`](crates/env-check-render/tests/snapshots/)

### Coverage

env-check enforces 100% line coverage:

```bash
# Run with coverage (requires cargo-llvm-cov)
cargo llvm-cov --all --fail-under-lines 100

# Generate HTML coverage report
cargo llvm-cov --all --html
```

## Documentation

### Updating Docs

- Documentation is located in the [`docs/`](docs/) directory
- Update relevant documentation when changing behavior
- Keep code examples in documentation up-to-date

Key documentation files:
- [`docs/architecture.md`](docs/architecture.md) - System architecture
- [`docs/contracts.md`](docs/contracts.md) - API contracts
- [`docs/testing.md`](docs/testing.md) - Full testing guide
- [`docs/cli-reference.md`](docs/cli-reference.md) - CLI usage

### ADR Process

Architecture Decision Records (ADRs) document significant design decisions:

1. ADRs are located in [`docs/adr/`](docs/adr/)
2. Copy [`docs/adr/ADR-000-template.md`](docs/adr/ADR-000-template.md) (if available) or use existing ADRs as templates
3. Follow the naming convention: `ADR-NNN-brief-description.md`
4. Include: Context, Decision, Consequences

Existing ADRs:
- [ADR-001: Microcrate Architecture](docs/adr/ADR-001-microcrate-architecture.md)
- [ADR-002: Hexagonal Architecture](docs/adr/ADR-002-hexagonal-architecture.md)
- [ADR-003: Feature-Gated Parsers](docs/adr/ADR-003-feature-gated-parsers.md)
- [ADR-004: Receipt Schema](docs/adr/ADR-004-receipt-schema.md)
- [ADR-005: Determinism](docs/adr/ADR-005-determinism.md)

### README Updates

- Update [`README.md`](README.md) for user-facing changes
- Update crate-level READMEs (e.g., [`crates/env-check-domain/README.md`](crates/env-check-domain/README.md)) for crate-specific changes

## Release Process

### Version Numbering

env-check follows [Semantic Versioning](https://semver.org/):

- **Patch** (`0.0.X`): Bug fixes, no schema or finding code changes
- **Minor** (`0.X.0`): New features, additive changes only under `data` or `finding.data`
- **Major** (`X.0.0`): Breaking changes to schema, codes, or their semantics

Schema and finding codes are public APIs. Changes must follow semver.

### Changelog Updates

- Update [`CHANGELOG.md`](CHANGELOG.md) with your changes
- Follow the existing format
- Include changes under the appropriate section:
  - `Added` for new features
  - `Changed` for changes in existing functionality
  - `Deprecated` for soon-to-be removed features
  - `Removed` for removed features
  - `Fixed` for bug fixes
  - `Security` for vulnerability fixes

### Deprecation Policy

- Mark deprecated codes/fields in docs first
- Keep them emitted for at least one minor release
- Remove only in the next major release

### Publishing

The workspace publishes all microcrates in dependency order. Release binaries are produced via cargo-dist.

Current release targets:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-apple-darwin`

Tag releases as `vX.Y.Z` and let the release workflow build and upload assets.

## Architecture Overview

env-check uses a hexagonal (ports/adapters) architecture with microcrates:

```
cli → app → (sources, probe, domain, evidence, render) → types
```

Key crates:
- **env-check-types**: Shared DTOs, receipt envelope, domain types, stable finding codes
- **env-check-sources**: Parses repo tool requirements from various config files
- **env-check-probe**: Probes local machine (PATH, versions, hashes)
- **env-check-domain**: Pure policy/evaluation logic (no I/O)
- **env-check-evidence**: Pure deterministic evidence shaping
- **env-check-render**: Pure markdown renderer from receipt
- **env-check-app**: Composition root
- **env-check-cli**: CLI entry point

## Key Principles

### Determinism

All outputs must be byte-stable given identical inputs:
- Findings sorted by: severity desc → path → check_id → code → message
- Use `BTreeMap` and explicit sort keys throughout domain logic
- Source discovery order must not depend on filesystem traversal order

### No Network by Default

env-check does not reach the network by default. Avoid introducing new OS or network dependencies without explicit approval.

### Deterministic Tests

Prefer deterministic tests and fixtures over host-dependent behavior. BDD tests use fakes for probes to avoid relying on host PATH/tooling.

## Questions?

If you have questions, feel free to:
- Open an issue for discussion
- Check existing documentation in [`docs/`](docs/)
- Review the [Architecture Decision Records](docs/adr/)

Thank you for contributing to env-check!
