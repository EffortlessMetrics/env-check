# env-check-domain

Pure evaluation logic mapping requirements + observations + policy → findings + verdict.

## Purpose

This crate contains all business logic with zero I/O. Given parsed requirements, probe observations, and policy configuration, it produces findings and a verdict. This separation makes the core logic easy to test and reason about.

## Key Functions

```rust
pub fn evaluate(
    requirements: &[Requirement],
    observations: &BTreeMap<String, Observation>,
    policy: &PolicyConfig,
    sources: &[SourceRef],
) -> DomainOutcome

pub fn evaluate_with_extras(
    requirements: &[Requirement],
    observations: &BTreeMap<String, Observation>,
    policy: &PolicyConfig,
    sources: &[SourceRef],
    extra_findings: Vec<Finding>,
) -> DomainOutcome
```

## Evaluation Logic

### 1. Per-Requirement Evaluation
For each requirement-observation pair:
1. Check for probe runtime errors → `tool.runtime_error`
2. Route to probe-kind-specific logic (PathTool, RustupToolchain, FileHash)
3. Generate appropriate findings for mismatches

### 2. Presence Checks
- Missing tool → Error in Team/Strict, Warn in Oss
- Optional tools → Info in Oss, Warn in Team

### 3. Version Matching
- Presence-only constraints (`latest`, `system`, `*`) skip version checking
- Uses `semver::VersionReq` for semantic version matching
- Coerces partial versions (e.g., `20` → `20.0.0`)
- Falls back to exact string match if semver parsing fails

### 4. Severity Mapping
Profile-based policy determines Error/Warn/Info:
- **Oss**: Lenient; prefers warn/skip over fail
- **Team**: Balanced; fails on missing required tools
- **Strict**: Fails on any mismatch for required tools

## Determinism Requirements

**Critical**: All outputs must be byte-stable given identical inputs.

- Findings sorted by: severity desc → path → check_id → code → message
- Use `BTreeMap` and explicit sort keys throughout
- No random or time-based ordering

## Truncation

Findings are capped at `policy.max_findings` with a truncation flag set in the verdict.

## Verdict Computation

1. No sources → Skip
2. Errors present → Fail (unless fail_on=Never)
3. Warnings present → Fail if fail_on=Warn, else Warn
4. Otherwise → Pass

## Working Agreements

- **No I/O in this crate** - all effects isolated to app layer
- New finding code requires: explain entry, snapshot test coverage
- Extensive unit tests for all profile/policy combinations
- Version matching logic must handle edge cases gracefully
- Mutation testing focuses on this crate (highest value for pure logic)

## Testing

```bash
# Run unit tests
cargo test -p env-check-domain

# Run mutation testing (validates test quality)
cargo run -p xtask -- mutants
```

## Test Coverage

50+ unit tests covering:
- All three profiles (Oss, Team, Strict)
- Version matching (semver, partial, exact fallback)
- Presence vs version findings
- Truncation behavior
- Sorting determinism
- Policy modes (fail_on: Error, Warn, Never)
- Edge cases (empty input, malformed versions, etc.)

## Adding a New Finding Code

1. Add code constant in `env-check-types::codes`
2. Add evaluation logic that emits the finding
3. Add explain entry in `env-check-cli` explain command
4. Add snapshot test coverage
5. Update root CLAUDE.md with new code
