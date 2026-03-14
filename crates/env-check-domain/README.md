# env-check-domain

Pure policy evaluation from requirements and observations to findings and verdicts.

## What This Crate Does

- Evaluates each `Requirement` against its paired `Observation`.
- Maps mismatches into stable finding codes and severities.
- Computes deterministic verdict counts/reasons/status.
- Applies deterministic sorting and truncation rules.

## Public API Highlights

- `evaluate(requirements, observations, policy, sources_used) -> DomainOutcome`
- `evaluate_with_extras(...)` for injecting parser/runtime extra findings
- `DomainOutcome { findings, verdict, truncated, requirements_total, requirements_failed }`

## Boundaries

- No filesystem/process/network I/O.
- No command execution or source file parsing.
- Pure logic only, suitable for unit-heavy and mutation testing.

## Determinism Contract

Findings are sorted by:

`severity desc -> path -> check_id -> code -> message`
