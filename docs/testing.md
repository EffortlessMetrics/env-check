# env-check Testing Strategy

env-check is a gatekeeper tool. The test posture is intentionally heavy to ensure reliability and correctness.

## Testing Strategy Overview

env-check employs a multi-layered testing strategy to ensure correctness at every level:

### Unit Tests

Unit tests cover pure functions and isolated components:

- **Parsers**: `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, hash manifests, `.node-version`, `.nvmrc`, `package.json`, `.python-version`, `pyproject.toml`, `go.mod`
- **Domain evaluation**: Mapping requirements + observations → findings + verdict
- **Rendering**: Report → markdown transformation (pure)
- **Adapters**: Small, focused tests for port implementations

Unit tests are located alongside source code in each crate's `src/` directory using Rust's `#[cfg(test)]` module pattern.

### Integration Tests

Integration tests verify component interactions:

- **CLI end-to-end tests** using `assert_cmd` crate
- **Artifact layout** and default path verification
- **Full pipeline** execution with real file system operations

Integration tests are located in each crate's `tests/` directory.

### BDD Tests (Cucumber)

Behavior-driven development tests cover workflow-level behavior:

- Profile/policy semantics (oss, team, strict)
- Failure modes and error handling
- End-to-end scenarios with fake probe adapters

BDD tests use fakes for probes to avoid relying on host PATH/tooling, ensuring deterministic results.

**Location**: `features/env_check.feature`

### Property Tests (Proptest)

Property-based testing validates invariants across random inputs:

- **Version parsing**: Non-panicking and stable under random input
- **Whitespace handling**: `.tool-versions` parsing tolerates various whitespace patterns
- **Path normalization**: Stays repo-relative and uses forward slashes
- **Parser robustness**: All parsers handle edge cases gracefully

**Location**: `crates/env-check-sources-hash/tests/proptest.rs` and similar locations

### Fuzzing (cargo-fuzz)

Fuzzing ensures parsers never panic on arbitrary bytes:

- **Goal**: Robustness, not correctness over every invalid input
- **Requirement**: All source parsers must have corresponding fuzz targets
- **Corpus**: Seed files derived from test fixtures

See the [Fuzz targets](#fuzz-targets) section for the complete list.

### Mutation Testing (cargo-mutants)

Mutation testing validates test quality by introducing small code changes (mutants):

- **Focus**: Domain evaluation and parser branching logic
- **Approach**: Treat "mutant survived" as a reason to add a test
- **Schedule**: Timeboxed in CI; scheduled/manual lane activity

## Running Tests

### Basic Test Commands

```bash
# Run all tests (unit + integration)
cargo test --workspace

# Run tests for a specific crate
cargo test -p env-check-domain
cargo test -p env-check-sources
cargo test -p env-check-render

# Run a specific test by name
cargo test test_version_parsing
```

### Running Specific Test Types

```bash
# BDD scenarios
cargo test -p env-check-cli --test bdd

# CLI integration tests
cargo test -p env-check-cli --test cli

# Property tests (proptest)
cargo test -p env-check-sources-hash --test proptest

# Unit tests only (skip integration)
cargo test --workspace --lib
```

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

**Snapshot locations**: `crates/env-check-render/tests/snapshots/`

### Coverage

env-check enforces 100% line coverage:

```bash
# Run with coverage (requires cargo-llvm-cov)
cargo llvm-cov --all --fail-under-lines 100

# Generate HTML coverage report
cargo llvm-cov --all --html
```

**Coverage target**: 100% line coverage for the workspace (enforced in CI on Linux).

### Mutation Testing

```bash
# Run via xtask (recommended)
cargo run -p xtask -- mutants

# Pass extra arguments to cargo-mutants
cargo run -p xtask -- mutants --jobs 4
cargo run -p xtask -- mutants --list  # Show mutants without running

# Run directly (requires cargo-mutants)
cargo mutants -p env-check-domain
```

**Configuration**: `mutants.toml` in workspace root controls exclusions and timeouts.
**Output**: Results written to `mutants.out/` (git-ignored).

### Fuzzing

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

**Prerequisites**:
```bash
rustup install nightly
cargo install cargo-fuzz
```

### Conformance Testing

```bash
# Run full conformance suite (schema + determinism + survivability + adoption)
cargo run -p xtask -- conform

# Run schema validation only
cargo run -p xtask -- schema-check

# Run adoption checks only
cargo run -p xtask -- adoption-check
```

## Test Fixtures

### Location

Test fixtures are organized by crate:

- `crates/env-check-cli/tests/fixtures/` - CLI integration test fixtures
- `crates/env-check-app/tests/fixtures/` - Application-level fixtures
- `crates/*/tests/fixtures/` - Crate-specific fixtures

### Fixture Structure

Each fixture directory represents a complete test scenario:

```
crates/env-check-cli/tests/fixtures/valid_tools/
├── .tool-versions          # Input file(s)
├── expected_report.json    # Expected receipt (optional)
└── expected_comment.md     # Expected markdown (optional)
```

### Adding New Fixtures

1. **Create the fixture directory**:
   ```bash
   mkdir -p crates/env-check-cli/tests/fixtures/my_scenario
   ```

2. **Add input files**:
   - Include all source files needed for the scenario (`.tool-versions`, `.mise.toml`, etc.)
   - Use realistic but minimal content

3. **Document expected behavior**:
   - Add a BDD scenario in `features/env_check.feature` for workflow-level tests
   - Or add an integration test that references the fixture

4. **Verify determinism**:
   - Run tests multiple times to ensure consistent output
   - All outputs must be byte-for-byte deterministic

### Golden Fixtures

Golden fixtures include expected output files:

- Input files (source configurations)
- Expected `report.json` (receipt envelope)
- Expected `comment.md` (when relevant)

These are used for regression testing and documentation.

## Snapshot Testing

env-check uses the `insta` crate for snapshot testing, primarily in the render layer.

### How Snapshots Work

1. Tests generate output (e.g., rendered markdown)
2. `insta` compares against stored snapshots
3. New or changed snapshots require review

### Snapshot Locations

```
crates/env-check-render/tests/snapshots/
├── render__render_pass_no_findings.snap
├── render__render_verdict_fail_simple.snap
└── ... (other snapshots)
```

### Updating Snapshots

```bash
# Interactive review (recommended)
cargo insta review

# Accept all pending changes
cargo insta accept

# Reject pending changes
cargo insta reject
```

**Important**: Only accept snapshots after verifying the changes are intentional and correct.

### Adding New Snapshot Tests

```rust
use insta::assert_snapshot;

#[test]
fn test_my_rendering() {
    let output = render_something();
    assert_snapshot!(output);
}
```

## BDD Features

### Location

BDD tests are defined in Gherkin syntax:

```
features/
└── env_check.feature    # Main feature file
```

### Feature File Structure

```gherkin
Feature: Environment sanity

  Scenario: No sources yields skip
    Given a repo fixture "no_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the verdict status is "skip"
    And the verdict reasons contain "no_sources"
```

### Running BDD Tests

```bash
# Run all BDD scenarios
cargo test -p env-check-cli --test bdd

# Run specific scenario (by name pattern)
cargo test -p env-check-cli --test bdd -- "missing tool"
```

### Adding New Scenarios

1. **Edit the feature file**:
   ```bash
   # In features/env_check.feature
   ```

2. **Add your scenario**:
   ```gherkin
   Scenario: My new test case
     Given a repo fixture "my_fixture"
     When I run env-check with profile "team"
     Then the exit code is 0
     And the report contains finding code "env.missing_tool"
   ```

3. **Create the fixture** if needed (see [Test Fixtures](#test-fixtures))

4. **Run the test** to verify:
   ```bash
   cargo test -p env-check-cli --test bdd
   ```

### Available Step Definitions

Common steps include:

- `Given a repo fixture "<name>"` - Load a test fixture
- `When I run env-check with profile "<profile>"` - Execute with profile
- `Then the exit code is <n>` - Verify exit code
- `And the verdict status is "<status>"` - Check verdict (pass/warn/fail/skip)
- `And the report contains finding code "<code>"` - Verify finding exists
- `And the finding code "<code>" has help containing "<text>"` - Check help text

## Fuzz Targets

All source parsers have corresponding fuzz targets:

| Target | Parser | Seed Corpus |
|--------|--------|-------------|
| `parse_tool_versions` | `.tool-versions` | `fuzz/corpus/parse_tool_versions/` |
| `parse_mise_toml` | `.mise.toml` | `fuzz/corpus/parse_mise_toml/` |
| `parse_rust_toolchain` | `rust-toolchain.toml` | `fuzz/corpus/parse_rust_toolchain/` |
| `parse_hash_manifest` | hash manifest | `fuzz/corpus/parse_hash_manifest/` |
| `fuzz_node_version` | `.node-version` | `fuzz/corpus/fuzz_node_version/` |
| `fuzz_nvmrc` | `.nvmrc` | `fuzz/corpus/fuzz_nvmrc/` |
| `fuzz_package_json` | `package.json` | `fuzz/corpus/fuzz_package_json/` |
| `fuzz_python_version` | `.python-version` | `fuzz/corpus/fuzz_python_version/` |
| `fuzz_pyproject_toml` | `pyproject.toml` | `fuzz/corpus/fuzz_pyproject_toml/` |
| `fuzz_go_mod` | `go.mod` | `fuzz/corpus/fuzz_go_mod/` |

### Seed Corpus

Each target has seed corpus files in `fuzz/corpus/<target>/` derived from test fixtures. These provide initial inputs for the fuzzer to mutate.

### Fuzzer Output

- **Crashes**: Saved to `fuzz/artifacts/<target>/`
- **Corpus accumulation**: New inputs added to `fuzz/corpus/<target>/`

### Adding New Fuzz Targets

When adding a new parser, create a corresponding fuzz target:

1. **Create the target** in `fuzz/fuzz_targets/`:
   ```rust
   // fuzz/fuzz_targets/fuzz_my_parser.rs
   #![no_main]
   
   use libfuzzer_sys::fuzz_target;
   use env_check_sources::parse_my_format;
   
   fuzz_target!(|data: &[u8]| {
       let _ = parse_my_format(data);  // Must never panic
   });
   ```

2. **Add seed corpus** in `fuzz/corpus/fuzz_my_parser/`

3. **Update the target list** in this documentation

## Conformance Testing

The `xtask conform` command runs comprehensive validation:

### Schema Validation

Verifies all outputs conform to `schemas/` definitions:

```bash
cargo run -p xtask -- schema-check
```

### Determinism Check

Ensures outputs are byte-for-byte identical for identical inputs:

- Findings sorted by: severity desc → path → check_id → code → message
- `BTreeMap` usage for stable ordering
- Explicit sort keys throughout domain logic

### Survivability

Validates that the tool produces a valid receipt even on runtime errors:

- Exit code 1 on error
- Valid receipt with `verdict.status="fail"`
- Exactly one `tool.runtime_error` finding

### Adoption Checks

Phase 7 repo-only adoption surface checks:

```bash
cargo run -p xtask -- adoption-check
```

## Testing Best Practices

### Determinism

All outputs must be deterministic:

- Use `BTreeMap` instead of `HashMap` for ordered output
- Sort findings by the canonical order: severity → path → check_id → code → message
- Avoid depending on filesystem traversal order

### Test Isolation

- BDD tests use fake probe adapters to avoid host dependencies
- Unit tests should not access the network or filesystem
- Integration tests should use temporary directories

### Coverage Requirements

- 100% line coverage is enforced in CI
- All new code must have corresponding tests
- Use `#[cfg(test)]` for test-only code

### Adding New Features

When adding new functionality:

1. **Source/parser**: Add fixtures, fuzz target, and proptest case
2. **Finding code**: Add explain entry in `env-check-types`, snapshot test coverage
3. **Domain logic**: Ensure mutation testing passes
4. **Rendering**: Add snapshot tests for new output formats
