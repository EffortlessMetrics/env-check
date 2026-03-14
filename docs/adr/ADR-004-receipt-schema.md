# ADR-004: Receipt Schema Contract

## Status

Accepted

## Context

The env-check tool produces output consumed by the cockpit system and potentially other automation tools. This output needs to be:

- **Machine-readable**: For automated processing by cockpit and CI systems
- **Versioned**: To support backward-compatible evolution
- **Stable**: Same inputs must produce byte-identical outputs
- **Validatable**: Consumers should be able to verify schema compliance
- **Extensible**: Tool-specific data needs a designated extension point

Without a formal schema contract, output format changes could silently break downstream consumers, and different tools might produce incompatible receipt formats.

## Decision

We adopt a **strict receipt schema contract** with the following characteristics:

### Schema Identity

- **Schema ID**: `sensor.report.v1`
- All receipts must include `"schema": "sensor.report.v1"` at the top level
- Schema defined in `schemas/sensor.report.v1.schema.json`

### Envelope Structure

The receipt uses a strict top-level envelope with fixed keys:

```json
{
  "schema": "sensor.report.v1",
  "tool": {
    "name": "env-check",
    "version": "0.1.0"
  },
  "verdict": {
    "status": "pass|warn|fail|skip",
    "reasons": []
  },
  "findings": [],
  "sources": [],
  "data": {}
}
```

### Extension Point

Tool-specific and future extensions are **only** allowed via:
- The `data` object at the top level
- The `finding.data` field within each finding

Top-level keys are fixed and must not be added without schema version changes.

### Validation

- Receipts must conform to `schemas/sensor.report.v1.schema.json`
- Tool-specific constraints defined in `schemas/env-check.report.v1.json`
- Schema validation can be performed by `xtask` tooling

## Consequences

### Positive

- **API stability**: Consumers can rely on the envelope structure remaining constant
- **Machine readability**: JSON schema enables automatic validation and code generation
- **Version compatibility**: Schema ID allows consumers to handle multiple versions
- **Clear extension path**: New data goes in `data`, not as new top-level keys
- **Cockpit integration**: Standardized format enables multi-tool aggregation

### Negative

- **Schema governance**: Changes require formal version bump process
- **Rigidity**: Cannot add top-level fields without version change
- **Validation overhead**: CI should validate receipts against schema

### Neutral

- The `data` field is opaque to generic consumers; tool-specific consumers understand its contents
- Schema versioning follows semantic versioning principles

## References

- [docs/architecture.md:89-93](../architecture.md) - Receipt contract definition
- [schemas/sensor.report.v1.schema.json](../../schemas/sensor.report.v1.schema.json) - Canonical schema
- [docs/contracts.md](../contracts.md) - Detailed contract specification
