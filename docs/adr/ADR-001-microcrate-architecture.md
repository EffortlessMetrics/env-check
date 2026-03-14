# ADR-001: Microcrate Architecture

## Status

Accepted

## Context

The env-check project needs to parse multiple source file formats (Node.js, Python, Go, Rust, hash manifests) and support various runtime operations. A monolithic crate structure would create several challenges:

- **Compile time**: Changes to any parser would require recompiling the entire project
- **Dependency coupling**: All parsers would share the same dependency tree
- **Feature flexibility**: Users cannot easily opt out of unused parsers
- **Parallel compilation**: A single crate limits Rust's ability to parallelize compilation
- **Testing isolation**: Domain logic becomes entangled with parsing implementation

The project also needs clear dependency boundaries to maintain a clean hexagonal architecture where domain logic remains pure and testable.

## Decision

We adopt a **microcrate architecture** with 18 separate crates organized into a strict dependency hierarchy:

```
crates/
  env-check-types    # DTOs: receipt envelope + domain types + codes
  env-check-config   # config parsing/merging for env-check policy and source filters
  env-check-parser-flags # parser-feature negotiation and aliasing
  env-check-requirement-normalizer # deterministic requirement normalization policies
  env-check-runtime-metadata # host/CI/git metadata + repo introspection
  env-check-sources-node # Node parser microcrate
  env-check-sources-python # Python parser microcrate
  env-check-sources-go # Go parser microcrate
  env-check-sources-hash # Hash manifest parser microcrate
  env-check-sources  # parse source files into Requirements
  env-check-probe    # probe local machine (PATH/version/hash) via ports
  env-check-domain   # policy + evaluation (pure)
  env-check-evidence # deterministic evidence shaping for data{} (pure)
  env-check-reporting # deterministic receipt data/capability assembly (pure)
  env-check-render   # markdown renderer (pure)
  env-check-app      # orchestration: wire adapters and write artifacts
  env-check-cli      # clap CLI
```

### Dependency Direction (Enforced)

- `domain` depends on `types` only
- `render` depends on `types` only
- `evidence` depends on `types` only
- `sources` depends on `types` (and parsing crates)
- `probe` depends on `types` (and OS crates)
- `runtime-metadata` depends on `types`
- `runtime` depends on `types` and `runtime-metadata`
- `reporting` depends on `types`, `domain`, `sources`, and `evidence`
- `app` depends on everything; it is the composition root
- `cli` depends on `app` and `types`

## Consequences

### Positive

- **Faster incremental builds**: Changes to a single parser only recompile that microcrate
- **Parallel compilation**: Rust can compile independent crates concurrently
- **Clear boundaries**: Dependency rules prevent circular dependencies and keep domain pure
- **Feature gating**: Parsers can be disabled at compile time via Cargo features
- **Testability**: Pure crates (`domain`, `render`, `evidence`) have no OS/runtime dependencies
- **Reduced attack surface**: Unused parsers can be excluded from builds

### Negative

- **Crate management overhead**: More `Cargo.toml` files to maintain
- **Workspace complexity**: Dependency versions must be synchronized across crates
- **Learning curve**: New contributors must understand the crate structure
- **Publishing overhead**: If published separately, each crate needs version management

### Neutral

- The composition root (`env-check-app`) becomes the only place where all dependencies converge

## References

- [docs/design.md:22-44](../design.md) - Microcrate layout definition
- [docs/design.md:46-59](../design.md) - Dependency direction rules
- [Cargo.toml](../../Cargo.toml) - Workspace member definitions
