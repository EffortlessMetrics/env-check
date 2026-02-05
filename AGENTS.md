# AGENTS.md

env-check is the machine-truth sensor: it verifies whether a machine/runner satisfies a repo's declared tool requirements. This file is a parallelization map plus non-negotiables for contributors.

**Non-Negotiables**
- Do not run builds/tests/coverage/benchmarks.
- Do not enforce repo policy or mutate the repository.
- Do not reach the network by default.
- Canonical artifacts: `artifacts/env-check/report.json` (always), `artifacts/env-check/comment.md` (optional), `artifacts/env-check/raw.log` (debug only).
- Receipt contract: `schema = "env-check.report.v1"`, strict top-level envelope, extension only via `data` and `finding.data`.
- Tool/runtime error semantics: exit code `1`, write a valid receipt when possible, set `verdict.status="fail"`, add `"tool_error"` to `verdict.reasons`, include exactly one `tool.runtime_error` finding.
- Determinism: stable ordering and sorting rules; findings ordered by `severity desc -> path -> check_id -> code -> message`.
- Dependency direction: `types <- (sources|probe|domain|render) <- app <- cli`.

**Parallelization Map**
- Contracts & schemas: `schemas/`, `crates/env-check-types`, `docs/contracts.md`.
- Sources & parsing: `crates/env-check-sources`, `fuzz/`, `features/`, fixtures under `crates/.../tests` as applicable.
- Probing & runtime IO: `crates/env-check-probe`.
- Domain evaluation: `crates/env-check-domain`.
- Rendering & artifacts: `crates/env-check-render`, `crates/env-check-app`.
- CLI & UX surface: `crates/env-check-cli`.
- Release & adoption surface: `action.yml`, `.github/workflows/`, `Cargo.toml` (`[workspace.metadata.dist]`), `docs/release.md`, `docs/cockpit.md`, `README.md`.

**Coordination Notes**
- New finding code: update `crates/env-check-types` (codes + explain registry), domain evaluation, schemas, and snapshots.
- New source/parser: add fixtures, fuzz target, and proptest case alongside parser changes.
- Receipt/schema changes: update `schemas/` and any schema validation in `xtask`.

Build/test commands live in `CLAUDE.md`.
