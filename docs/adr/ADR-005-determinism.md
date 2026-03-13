# ADR-005: Determinism Requirements

## Status

Accepted

## Context

The env-check tool produces receipts consumed by the cockpit system and stored for auditing. Several use cases require deterministic output:

- **Git diffs**: When receipts are committed, changes should reflect actual differences, not random ordering
- **Caching**: CI systems may cache results; non-determinism defeats caching
- **Testing**: Golden file tests (snapshots) require stable outputs
- **Auditing**: Historical receipts should be comparable
- **Reproducibility**: Same inputs should always produce identical outputs

Without explicit determinism rules, outputs could vary based on:
- Filesystem traversal order (directory entry ordering is OS-dependent)
- Hash map iteration order (non-deterministic in Rust's default hasher)
- Parallel execution scheduling

## Decision

We enforce **strict determinism requirements** for all outputs:

### Source Discovery Order

Source files must be discovered in a deterministic order:
- Paths sorted lexicographically within each source type
- Source types processed in a fixed order
- No dependence on filesystem readdir order

### Requirement Ordering

Requirements are sorted by:
1. `tool_id` (alphabetically)
2. Source path (alphabetically)

### Finding Ordering

Findings are sorted by:
1. **Severity** (descending): `error` > `warn` > `info`
2. **Path** (alphabetically)
3. **check_id** (alphabetically)
4. **code** (alphabetically)
5. **message** (alphabetically)

This multi-level sort ensures complete determinism even when multiple findings share the same severity and path.

### JSON Serialization

- Object keys serialized in sorted order
- No trailing whitespace
- Consistent indentation (2 spaces)
- No optional fields omitted when they have default values (explicit nulls/empty arrays)

### Truncation Behavior

When output is truncated due to limits:
- Truncation is deterministic (keep highest-priority findings per sort order)
- `data.truncated = true` flag set
- `data.summary` contains complete counts

## Consequences

### Positive

- **Stable diffs**: Git commits show only actual changes
- **Reliable caching**: CI can cache receipts confidently
- **Test reliability**: Golden file tests don't flake
- **Auditability**: Historical comparisons are meaningful
- **Byte-identical**: Same inputs always produce identical files

### Negative

- **Implementation care required**: Must use `BTreeMap` instead of `HashMap`, explicit sorting
- **Performance cost**: Sorting has O(n log n) cost
- **Debugging difficulty**: Original discovery order is lost

### Neutral

- The sort order is a convention; any consistent order would work
- Debug logs (`extras/raw.log`) are exempt from determinism requirements

## References

- [docs/architecture.md:139-145](../architecture.md) - Determinism requirements
- [docs/design.md:231-252](../design.md) - Ordering and truncation rules
- [AGENTS.md](../../AGENTS.md) - Determinism rules in project guidelines
