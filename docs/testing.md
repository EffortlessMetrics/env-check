# env-check testing strategy

env-check is a gatekeeper tool. The test posture is intentionally heavy.

## Test layers

### Unit tests
- Parsers: `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, hash manifests, `.node-version`, `.nvmrc`, `package.json`, `.python-version`, `pyproject.toml`, `go.mod`
- Domain evaluation: mapping requirements + observations → findings + verdict
- Rendering: report → markdown (pure)

### Integration tests
- CLI end-to-end tests using `assert_cmd`
- Artifact layout and default paths

### BDD (cucumber)
- Workflow-level behavior, especially profile/policy semantics and failure modes.
- These tests use fakes for probes to avoid relying on host PATH/tooling.

### Property tests (proptest)
- Version parsing is non-panicking and stable under random input.
- `.tool-versions` parsing tolerates whitespace/comments.
- Path normalization stays repo-relative and uses forward slashes.

### Fuzzing (cargo fuzz)
- Parsers never panic on arbitrary bytes.
- The goal is robustness, not correctness over every invalid input.
- See "Fuzz targets" section below for complete list.

### Mutation testing (cargo-mutants)
- Timeboxed in CI.
- Focus on domain evaluation and parser branching logic.
- Treat "mutant survived" as a reason to add a test, not as a debate.
- Run via `cargo run -p xtask -- mutants`

### Coverage (cargo-llvm-cov)
- **Gate:** 100% line coverage for the workspace.
- Enforced in CI on Linux.
- Run locally:
  ```bash
  cargo llvm-cov --all --fail-under-lines 100
  ```

### Conformance (xtask conform)
- Ensures deterministic output and schema compliance.
- Validates that the tool produces a valid receipt even on runtime errors (survivability).
- Run locally:
  ```bash
  cargo run -p xtask -- conform
  ```

## Running tests locally

```bash
# Unit + integration
cargo test

# Snapshot updates (intentional only)
cargo insta accept

# BDD
cargo test -p env-check-cli --test bdd

# Mutation testing (via xtask, recommended)
cargo run -p xtask -- mutants

# Mutation testing (direct)
cargo mutants -p env-check-domain

# Fuzzing (requires cargo-fuzz and nightly)
cargo fuzz list
cargo fuzz run parse_tool_versions
cargo fuzz run fuzz_go_mod -- -max_total_time=300
```

## Fuzz targets

All source parsers have corresponding fuzz targets:

| Target | Parser |
|--------|--------|
| `parse_tool_versions` | `.tool-versions` |
| `parse_mise_toml` | `.mise.toml` |
| `parse_rust_toolchain` | `rust-toolchain.toml` |
| `parse_hash_manifest` | hash manifest |
| `fuzz_node_version` | `.node-version` |
| `fuzz_nvmrc` | `.nvmrc` |
| `fuzz_package_json` | `package.json` |
| `fuzz_python_version` | `.python-version` |
| `fuzz_pyproject_toml` | `pyproject.toml` |
| `fuzz_go_mod` | `go.mod` |

Each target has seed corpus files in `fuzz/corpus/<target>/` derived from test fixtures.

## Golden fixtures

Fixtures live in `tests/fixtures/` (per crate where appropriate).
Every fixture set includes:

- input files
- expected `report.json`
- expected `comment.md` (when relevant)

Outputs must be deterministic byte-for-byte.
