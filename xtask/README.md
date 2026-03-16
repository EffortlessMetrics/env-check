# xtask

Workspace maintenance commands for env-check development workflows.

## What This Crate Does

- `schema-check`: compile/validate schemas and example fixtures.
- `conform`: run conformance checks across schema, determinism, survivability, and adoption expectations.
- `adoption-check`: run repo adoption checks for contracts/offline/action/docs/release surfaces.
- `mutants`: run mutation testing workflow for domain-focused quality checks.

## Boundaries

- Developer tooling only; not part of env-check runtime artifacts.
- Not published (`publish = false`).
