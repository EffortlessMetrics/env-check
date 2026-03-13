# ADR-012: Tool ID Normalization

## Status
Accepted

## Context
Different source file formats use different naming conventions for the same tool. For example:
- asdf uses `nodejs`
- mise uses `node`
- go.mod uses implicit `go` tool
- Some formats use `golang`

Without normalization, these would be treated as different tools.

## Decision
Tool IDs are normalized at parse time using a fixed mapping:

| Raw ID | Normalized ID |
|--------|---------------|
| `nodejs` | `node` |
| `golang` | `go` |

### Normalization Rules
1. Normalization happens in the parser layer, not evaluation
2. The normalized ID is used for:
   - Matching requirements to observations
   - Generating findings
   - Probe command selection
3. Original ID is NOT preserved in the receipt

### Extension Policy
New normalizations MUST:
1. Be documented in `docs/parsers.md`
2. Have a clear ecosystem precedent
3. Not create ambiguity (one-to-one mapping only)

## Consequences
- Requirements from different sources can be merged
- Simpler probe implementation (one command per tool)
- Users see consistent tool names in findings

## References
- [Parsers Reference - Tool ID Normalization](../parsers.md#tool-id-normalization)
