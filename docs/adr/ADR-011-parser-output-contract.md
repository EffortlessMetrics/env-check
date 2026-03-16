# ADR-011: Parser Output Contract

## Status
Accepted

## Context
Each source parser produces `Requirement` objects that are consumed by the domain evaluation layer. The relationship between parser output fields and evaluation semantics needs to be clearly defined.

## Decision
All parsers MUST produce output conforming to the following contract:

### Requirement Structure
- `tool`: Normalized tool ID (e.g., "node", not "nodejs")
- `constraint`: Version constraint string (format depends on source type)
- `source`: File path and kind for finding location
- `probe_kind`: How to verify (PathTool, RustupToolchain, FileHash)
- `hash`: Optional SHA256 for hash verification

### Constraint Semantics by Source
| Source Type | Constraint Format | Evaluation |
|-------------|-------------------|------------|
| asdf/mise | Exact version | String equality |
| Node.js files | Exact or LTS alias | String equality |
| package.json | Semver range | semver crate matching |
| pyproject.toml | PEP 440 range | Preserved as-is |
| go.mod | Version | >= minimum |
| Hash manifest | SHA256 | Exact hex comparison |

### Version Normalization
Parsers MUST normalize versions for consistent evaluation:
- Strip `v` prefix from versions
- Strip `go` prefix from Go versions
- Coerce partial versions to semver (20 → 20.0.0)

### Error Handling
Parse errors MUST be returned as `Err(anyhow!)` with context, NOT as requirements with error findings. The app layer converts parse errors to findings.

## Consequences
- Consistent evaluation regardless of source format
- Clear separation between parsing and evaluation
- Easier to add new parsers

## References
- [Parsers Reference](../parsers.md)
- [ADR-003: Feature-Gated Parsers](ADR-003-feature-gated-parsers.md)
