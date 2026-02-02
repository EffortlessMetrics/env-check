# env-check testing strategy

env-check is a gatekeeper tool. The test posture is intentionally heavy.

## Test layers

### Unit tests
- Parsers: `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, hash manifests
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

### Mutation testing (cargo-mutants)
- Timeboxed in CI.
- Focus on domain evaluation and parser branching logic.
- Treat “mutant survived” as a reason to add a test, not as a debate.

## Running tests locally

```bash
# Unit + integration
cargo test

# Snapshot updates (intentional only)
cargo insta accept

# BDD
cargo test -p env-check-cli --test bdd

# Mutation testing (timeboxed)
cargo mutants -p env-check-domain

# Fuzzing (requires cargo-fuzz)
cargo fuzz list
cargo fuzz run parse_tool_versions
```

## Golden fixtures

Fixtures live in `tests/fixtures/` (per crate where appropriate).
Every fixture set includes:

- input files
- expected `report.json`
- expected `comment.md` (when relevant)

Outputs must be deterministic byte-for-byte.
