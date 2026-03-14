# env-check-evidence

Pure deterministic helpers that shape receipt evidence under `data`.

## What This Crate Does

- Normalizes observed source kinds and probe kinds.
- Condenses probe observations into stable, serializable summaries.
- Builds deterministic dependency graph payloads for receipt data.

## Public API Highlights

- `source_kind_id`, `probe_kind_id`
- `source_kinds(sources) -> Vec<String>`
- `probe_kinds(requirements) -> Vec<String>`
- `summarize_probes(requirements, observations) -> Vec<ProbeSummary>`
- `dependency_graph(requirements) -> DependencyGraph`

## Boundaries

- No I/O.
- No policy/verdict evaluation.
- No markdown/CLI rendering concerns.
