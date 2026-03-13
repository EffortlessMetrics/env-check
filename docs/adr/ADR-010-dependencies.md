# ADR-010: Dependency Choices

## Status

Accepted

## Context

Rust has a rich ecosystem of crates, but dependency choices have long-term implications:

- **Maintenance burden**: Dependencies must be updated for security and compatibility
- **Compile time**: More dependencies increase build time
- **Binary size**: Each dependency contributes to final binary size
- **Transitive dependencies**: Dependency trees can balloon unexpectedly
- **License compliance**: Dependencies must have compatible licenses
- **Community trust**: Well-maintained crates reduce risk

env-check needs dependencies for error handling, CLI parsing, serialization, version parsing, and more.

## Decision

We select dependencies based on **ecosystem standard status**, **maintenance quality**, and **feature set**:

### Core Dependencies

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `anyhow` | 1.0 | Error handling | Ecosystem standard for applications; ergonomic error propagation |
| `thiserror` | 2.0 | Error types | Ecosystem standard for library error types; derive macro |
| `serde` | 1.0 | Serialization | Rust standard for serialization; widely supported |
| `serde_json` | 1.0 | JSON | Official serde JSON implementation; fast and correct |

### CLI / UX

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `clap` | 4.5 | CLI parsing | Ecosystem standard; derive macros; excellent help generation |

### Parsing / Data

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `toml` | 0.9 | TOML parsing | Official `toml-rs` successor; serde integration |
| `toml_edit` | 0.23 | TOML manipulation | Preserves formatting/comments; complementary to `toml` |
| `regex` | 1.12 | Regex | Rust standard; excellent performance |
| `globset` | 0.4 | Glob patterns | From ripgrep ecosystem; efficient pattern matching |
| `semver` | 1.0 | Semantic versioning | Official semver crate; serde support |

### Runtime Helpers

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `chrono` | 0.4 | Date/time | Ecosystem standard; serde support |
| `which` | 8.0 | PATH resolution | Simple, well-maintained |
| `sha2` | 0.10 | SHA-256 | RustCrypto project; pure Rust |
| `hex` | 0.4 | Hex encoding | Simple, no dependencies |

### Testing

| Crate | Version | Purpose | Rationale |
|-------|---------|---------|-----------|
| `insta` | 1.46 | Snapshot testing | Excellent snapshot diffs; inline snapshots |
| `proptest` | 1.10 | Property testing | Hypothesis-inspired; good shrinking |
| `assert_cmd` | 2.1 | CLI testing | Integrates with `cargo test` |
| `predicates` | 3.1 | Assertions | Composable predicates |
| `tempfile` | 3.24 | Temp files | Secure temp file handling |
| `cucumber` | 0.22 | BDD | Gherkin support; async support |
| `tokio` | 1.49 | Async runtime | Required for cucumber; standard |
| `jsonschema` | 0.41 | Schema validation | JSON Schema validation |

### Dependency Principles

1. **Prefer ecosystem standards**: `anyhow`, `clap`, `serde`, `regex` are widely trusted
2. **Minimize transitive deps**: Check `cargo tree` before adding
3. **Check maintenance**: Look for recent releases and issue responsiveness
4. **License compatibility**: Prefer MIT/Apache-2.0 dual-licensed

## Consequences

### Positive

- **Familiarity**: Most Rust developers know these crates
- **Documentation**: Ecosystem standards have excellent docs and examples
- **Security**: Widely-used crates receive prompt security attention
- **Compatibility**: Standards tend to have stable APIs and migration paths

### Negative

- **Transitive deps**: Some crates (e.g., `clap`, `tokio`) bring many transitive dependencies
- **Compile time**: Test dependencies increase dev build time
- **Version churn**: Keeping versions synchronized requires maintenance

### Neutral

- Workspace-level dependency management in `Cargo.toml` ensures version consistency
- Some crates (`toml_edit`, `globset`) are specialized needs, not universal choices

## References

- [Cargo.toml:55-88](../../Cargo.toml) - Dependency definitions
- [Cargo.toml:50-54](../../Cargo.toml) - Workspace dependencies
- [docs/testing.md](../testing.md) - Testing dependency usage
