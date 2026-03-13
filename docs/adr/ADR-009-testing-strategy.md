# ADR-009: Testing Strategy Mix

## Status

Accepted

## Context

The env-check project has high quality requirements:
- **100% test coverage** enforced in CI
- **Deterministic outputs** that must remain stable
- **Multiple parsers** for different file formats that must handle edge cases
- **Domain logic** that must correctly evaluate policies

A single testing approach cannot adequately cover all these concerns. Different testing strategies catch different classes of bugs.

## Decision

We employ a **defense-in-depth testing strategy** combining multiple complementary approaches:

### 1. BDD (Behavior-Driven Development)

**Tool**: Cucumber (`cucumber` crate)

**Purpose**: Validate workflow-level behavior from user perspective

**Coverage**:
- Profile behavior (oss/team/strict)
- Missing sources handling
- Mismatch remediation flows
- End-to-end CLI scenarios

**Location**: `features/env_check.feature`, `crates/env-check-cli/tests/bdd.rs`

### 2. Golden Fixtures (Snapshot Testing)

**Tool**: Insta (`insta` crate)

**Purpose**: Ensure output stability and catch unexpected changes

**Coverage**:
- Receipt JSON outputs
- Markdown render outputs
- Error message formats

**Location**: `crates/env-check-render/tests/snapshots/`

### 3. Property-Based Testing

**Tool**: Proptest (`proptest` crate)

**Purpose**: Validate invariants across large input spaces

**Coverage**:
- Version parsing (semver, PEP 440)
- Path normalization
- Whitespace handling in parsers
- `.tool-versions` parsing

**Location**: `crates/env-check-sources/tests/proptest.rs`

### 4. Fuzzing

**Tool**: `cargo fuzz`

**Purpose**: Ensure parsers never panic on arbitrary input

**Targets**:
- `parse_tool_versions`
- `parse_mise_toml`
- `parse_rust_toolchain`
- `parse_hash_manifest`
- `fuzz_node_version`
- `fuzz_nvmrc`
- `fuzz_package_json`
- `fuzz_python_version`
- `fuzz_pyproject_toml`
- `fuzz_go_mod`

**Location**: `fuzz/fuzz_targets/`, `fuzz/corpus/`

### 5. Mutation Testing

**Tool**: cargo-mutants

**Purpose**: Verify test quality by injecting bugs

**Coverage**:
- Domain evaluation logic
- Parser edge cases
- Timeboxed runs in CI

**Location**: Configured in `Cargo.toml`

## Consequences

### Positive

- **Defense in depth**: Different strategies catch different bug classes
- **High confidence**: Multiple layers of verification
- **Regression prevention**: Snapshots catch unexpected output changes
- **Edge case coverage**: Fuzzing and proptest explore edge cases humans miss
- **Test quality**: Mutation testing verifies tests actually catch bugs

### Negative

- **CI time**: Multiple testing strategies increase CI duration
- **Complexity**: Contributors must understand multiple testing tools
- **Maintenance**: Each testing approach has its own infrastructure

### Neutral

- Fuzzing runs separately from normal CI (long-running)
- Mutation testing is timeboxed, not exhaustive
- 100% line coverage is a minimum bar, not a guarantee

## References

- [docs/design.md:271-279](../design.md) - Testing strategy overview
- [docs/testing.md](../testing.md) - Detailed testing instructions
- [CLAUDE.md](../../CLAUDE.md) - Test commands
- [fuzz/README.md](../../fuzz/README.md) - Fuzzing instructions
