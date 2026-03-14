# ADR-006: Profile-Based Severity Mapping

## Status

Accepted

## Context

Different teams and projects have different risk tolerances for environment issues:

- **Open source projects** may want to be non-blocking by default, only warning about issues
- **Team projects** may want to fail on missing required tools but tolerate version mismatches
- **Strict environments** (regulated industries, security-sensitive) may want to fail on any deviation

Hardcoding severity levels would force all users into the same posture, or require extensive per-rule configuration.

## Decision

We implement **profile-based severity mapping** with three predefined profiles:

### Profiles

| Profile | Missing Required Tool | Version Mismatch | Hash Mismatch |
|---------|----------------------|------------------|---------------|
| `oss` | warn | warn | warn |
| `team` | error | warn | error |
| `strict` | error | error | error |

### Implementation Principle

Profiles are applied as a **final mapping step** over findings:

1. Domain evaluation produces findings with baseline severity
2. Profile is applied to map baseline → final severity
3. Mapped findings are returned in the receipt

This avoids scattered branching logic (`if profile == "strict" { error } else { warn }`) throughout the codebase.

### Configuration

Profiles can be selected via:
- CLI flag: `--profile oss|team|strict`
- Configuration file: `profile = "team"` in `env-check.toml`
- Default: `oss` (safest for open source)

### Extensibility

Future versions may support:
- Custom profiles defined in configuration
- Per-tool severity overrides
- Per-source severity adjustments

## Consequences

### Positive

- **User flexibility**: Teams choose their own enforcement level
- **Policy-as-code**: Profile selection is explicit and version-controlled
- **Gradual adoption**: Start with `oss`, graduate to `team` or `strict`
- **Clean implementation**: Single mapping pass, not scattered conditionals
- **Easy reasoning**: Three well-defined profiles instead of many per-rule flags

### Negative

- **Limited granularity**: Cannot customize individual rules without code changes
- **Profile proliferation risk**: Resisting pressure to add many profiles
- **Discovery**: Users must understand profile semantics

### Neutral

- The profile only affects severity mapping, not which checks are performed
- `fail_on` setting (`error|warn|never`) determines exit behavior independently

## References

- [docs/architecture.md:105-114](../architecture.md) - Profile definitions
- [docs/design.md:205-222](../design.md) - Evaluation rules by profile
- [crates/env-check-domain/src/lib.rs](../../crates/env-check-domain/src/lib.rs) - Profile implementation
