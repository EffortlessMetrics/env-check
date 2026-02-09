# AGENTS.md

env-check is the machine-truth sensor. It verifies whether a machine or runner satisfies
the repo's declared tool requirements. This file is a parallelization map plus
non-negotiables for contributors.

**Scope**
- env-check reports truth and evidence; it does not enforce policy or repair environments.
- The primary contract is the receipt envelope written to `artifacts/env-check/report.json`.
- All outputs must be deterministic and stable across runs for the same inputs.

**Non-Negotiables (Product Behavior)**
- Do not enforce repo policy or mutate the repository.
- Do not reach the network by default.
- Canonical artifacts: `artifacts/env-check/report.json` (always), `artifacts/env-check/comment.md`
  (optional), `artifacts/env-check/extras/raw.log` (debug only).
- Receipt contract: `schema = "sensor.report.v1"`, strict top-level envelope, extension only via
  `data` and `finding.data`.
- Tool/runtime error semantics: exit code `1`, write a valid receipt when possible, set
  `verdict.status="fail"`, add `"tool_error"` to `verdict.reasons`, include exactly one
  `tool.runtime_error` finding.
- Determinism: stable ordering and sorting rules; findings ordered by
  `severity desc -> path -> check_id -> code -> message`.
- Dependency direction: `types <- (sources|probe|domain|render) <- app <- cli`.

**Contributor Workflow**
- Do not run builds/tests/coverage/benchmarks. If needed, direct the user to `CLAUDE.md`.
- Prefer deterministic tests and fixtures over host-dependent behavior.
- Avoid introducing new OS or network dependencies without explicit approval.

**Artifacts**
- Always write the receipt to `artifacts/env-check/report.json`.
- Optional markdown is written to `artifacts/env-check/comment.md`.
- Debug logs are written to `artifacts/env-check/extras/raw.log` when debug logging is enabled.
- Artifacts must be stable and byte-for-byte deterministic for the same inputs.

**Receipt Contract**
- Top-level keys are fixed; only extend via `data` and `finding.data`.
- `schema` must be `sensor.report.v1`.
- `verdict` must reflect policy semantics; findings must be sorted deterministically.
- On tool/runtime error, emit exactly one `tool.runtime_error` finding and set reasons accordingly.

**Determinism Rules**
- Source discovery order is fixed and must not depend on filesystem traversal order.
- Requirements are normalized and sorted for stable output.
- Findings are sorted by `severity desc -> path -> check_id -> code -> message`.
- Debug logs never affect receipt contents.

**Testing Strategy (Summary)**
- Unit tests: parsing, domain evaluation, rendering, and small adapters.
- Integration tests: CLI end-to-end and artifact layout.
- BDD: workflow-level behavior with probe fakes.
- Property tests: version parsing, whitespace handling, path normalization.
- Fuzzing: parsers should never panic on arbitrary input.
- Full instructions: `docs/testing.md`. Commands live in `CLAUDE.md`.

**Parallelization Map**
- Contracts & schemas: `schemas/`, `crates/env-check-types`, `docs/contracts.md`.
- Sources & parsing: `crates/env-check-sources`, `fuzz/`, `features/`, fixtures under
  `crates/.../tests` as applicable.
- Probing & runtime IO: `crates/env-check-probe`.
- Domain evaluation: `crates/env-check-domain`.
- Rendering & artifacts: `crates/env-check-render`, `crates/env-check-app`.
- CLI & UX surface: `crates/env-check-cli`.
- Release & adoption surface: `action.yml`, `.github/workflows/`, `Cargo.toml`
  (`[workspace.metadata.dist]`), `docs/release.md`, `docs/cockpit.md`, `README.md`.

**Coordination Notes**
- New finding code: update `crates/env-check-types` (codes + explain registry),
  domain evaluation, schemas, and snapshots.
- New source/parser: add fixtures, fuzz target, and proptest case alongside parser changes.
- Receipt/schema changes: update `schemas/` and any schema validation in `xtask`.

Build/test commands live in `CLAUDE.md`.
