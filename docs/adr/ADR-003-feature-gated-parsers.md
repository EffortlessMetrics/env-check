# ADR-003: Feature-Gated Parsers

## Status

Accepted

## Context

The env-check project supports parsing multiple source file formats:

- **Node.js**: `.node-version`, `.nvmrc`, `package.json`
- **Python**: `.python-version`, `pyproject.toml`
- **Go**: `go.mod`
- **Rust**: `rust-toolchain.toml`
- **Version managers**: `.tool-versions`, `.mise.toml`
- **Hash manifests**: `scripts/tools.sha256`

Not all users need all parsers. A project without Python code shouldn't need Python parsing dependencies. Additionally:

- Each parser may have different dependency trees (e.g., Python parsing needs PEP 440 version parsing)
- Some environments may want minimal builds with only essential parsers
- Reducing compiled code reduces attack surface and binary size

## Decision

We implement **feature-gated parsers** using Cargo's feature system. Each parser family is optional and can be disabled at compile time.

### Feature Flags

```toml
[features]
default = ["parser-node", "parser-python", "parser-go"]
parser-node = ["env-check-sources-node"]
parser-python = ["env-check-sources-python"]
parser-go = ["env-check-sources-go"]
```

### Implementation Pattern

When a parser feature is disabled, the module provides stub functions that return clear errors:

```rust
#[cfg(feature = "parser-node")]
pub mod node {
    pub use env_check_sources_node::*;
}

#[cfg(not(feature = "parser-node"))]
pub mod node {
    pub fn parse_node_version(_root: &Path, path: &Path) -> Result<Vec<Requirement>> {
        Err(anyhow::anyhow!(
            "node parser was disabled at build-time; this source cannot be parsed: {}",
            path.display()
        ))
    }
}
```

This ensures:
1. Code always compiles regardless of feature configuration
2. Attempting to use a disabled parser yields a clear, actionable error
3. The error message indicates this is a build-time decision, not a runtime failure

## Consequences

### Positive

- **Reduced compile time**: Fewer enabled features means less code to compile
- **Smaller binaries**: Unused parsers don't contribute to final binary size
- **Minimal attack surface**: Disabled parsers cannot have vulnerabilities exploited
- **User choice**: Teams can customize builds to their tech stack
- **Dependency reduction**: Python version parsing dependencies only included when needed

### Negative

- **Feature complexity**: More Cargo feature flags to document and test
- **Error discoverability**: Users only discover missing parsers at runtime when they try to parse an unsupported file
- **Testing matrix**: CI should test multiple feature combinations
- **Documentation burden**: Must clearly document which features enable which parsers

### Neutral

- Default features include all common parsers for out-of-box compatibility
- Custom builds require explicit `--no-default-features` usage

## References

- [crates/env-check-sources/src/lib.rs:3-57](../../crates/env-check-sources/src/lib.rs) - Feature gating implementation
- [Cargo.toml](../../Cargo.toml) - Feature definitions
- [Cargo Features Documentation](https://doc.rust-lang.org/cargo/reference/features.html)
