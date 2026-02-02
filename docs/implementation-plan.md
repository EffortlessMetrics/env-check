# env-check implementation plan

This plan is sequenced to land small, reversible increments while keeping contracts stable.

## Phase 0 — Contracts and scaffolding

### Deliverables

- Workspace and microcrate layout (types/sources/probe/domain/render/app/cli)
- JSON schemas:
  - `schemas/receipt.envelope.v1.json`
  - `schemas/env-check.report.v1.json`
- Canonical artifact paths baked into CLI defaults
- Initial `env-check explain` registry (codes + remediation stubs)
- Conformance harness hooks (schema validation command in xtask)

### Definition of done

- [ ] `env-check check --root <fixture>` produces `report.json`
- [ ] Receipt validates against `env-check.report.v1.json`
- [ ] `env-check md` renders a markdown summary deterministically
- [ ] `xtask schema-check` validates schemas and example fixtures

## Phase 1 — Source discovery + parsing (repo side)

### Work

1. Implement discovery for:
   - `.tool-versions`
   - `.mise.toml`
   - `rust-toolchain.toml`
   - optional hash manifest (default `scripts/tools.sha256`)

2. Implement parsers with:
   - deterministic ordering
   - strong error reporting (source path + reason)
   - best-effort locations (path always; line optional later)

3. Build fixture corpus:
   - representative source files
   - malformed cases
   - empty/no sources case

### Tests

- Unit tests per parser (table-driven)
- Proptest for `.tool-versions` whitespace/comment tolerance
- Fuzz targets for each parser (never panic; bounded allocations)

### Definition of done

- [ ] `discover(root)` returns stable, predictable sources
- [ ] parsers produce normalized requirements with provenance
- [ ] malformed sources produce findings with `env.source_parse_error` (not panics)

## Phase 2 — Probing (machine side)

### Work

1. Implement PATH presence probe:
   - using `which` (cross-platform)
2. Implement version probe:
   - run `<tool> --version` (argv vector)
   - parse semver-ish patterns conservatively
   - record raw output
3. Implement rustup toolchain probe:
   - detect rustup presence
   - verify toolchain declared by rust-toolchain exists (best-effort)
4. Implement hash probe:
   - compute sha256 for repo-local paths
   - compare against manifest hash

### Tests

- Port-based unit tests with fakes:
  - Fake PATH resolver and fake command runner
- Golden tests for probe transcript condensation (what is stored in `data`)
- Proptest for version string parsing (non-panicking, monotonic comparisons)

### Definition of done

- [ ] probes are injected via ports (no hard dependencies in domain)
- [ ] probe failures do not crash; they become findings or tool errors as appropriate
- [ ] no shell execution anywhere

## Phase 3 — Evaluation engine (domain)

### Work

1. Implement policy/profile mapping:
   - profiles map findings to severities
   - `fail_on` maps warn→fail semantics
2. Implement evaluation rules:
   - missing tool
   - version mismatch
   - toolchain missing
   - hash mismatch
3. Implement verdict computation:
   - counts derived from findings
   - reasons list computed from highest-impact issues
4. Implement stable sorting and truncation rules

### Tests

- Table-driven unit tests for each rule
- Golden fixtures: `(requirements + observations + policy) -> report.json`
- Mutation testing focuses on:
  - severity mapping
  - verdict computation
  - truncation logic

### Definition of done

- [ ] Domain has no IO and can be tested purely
- [ ] Deterministic ordering enforced (BTreeMap + explicit sort keys)
- [ ] Mutation testing catches removed/altered condition branches

## Phase 4 — CLI UX + renderers

### Work

1. CLI commands:
   - `check`
   - `md` (render-only)
   - `explain`
2. Artifact writer:
   - ensures `artifacts/env-check/` exists
   - writes `report.json` atomically (write-temp + rename)
3. Markdown renderer:
   - concise, capped, link-oriented
4. Optional GitHub annotations renderer (future):
   - emit top N findings as workflow commands

### Tests

- Integration tests for CLI with `assert_cmd`
- Golden markdown snapshots with `insta`

### Definition of done

- [ ] One-line quickstart works with defaults
- [ ] CLI exit codes match requirements
- [ ] Artifacts written in canonical paths without heuristics

## Phase 5 — Conformance + hardening

### Work

- Conformance test kit:
  - schema validation for emitted receipts
  - deterministic output tests (byte-stable)
  - explain registry completeness
- Error handling sweep:
  - shallow checkouts, unreadable files, permission issues
- Security sweep:
  - ensure config cannot inject arbitrary commands (v0.1)

### Definition of done

- [ ] CI includes: unit + integration + BDD + proptest + fuzz smoke + mutants (timeboxed)
- [ ] “no sources” and “partial failure” cases emit meaningful receipts

## Phase 6 — Release + adoption surface

### Work

- Prebuilt binaries (Linux/macOS/Windows) via GitHub Releases
- Minimal docs for adoption:
  - README quickstart
  - `examples/` configs
  - cockpit policy snippet
- Version pinning story:
  - recommend installing via workflow bundle/toolpack

### Definition of done

- [ ] A repo can adopt env-check with one workflow step and one config stanza
- [ ] Output is stable enough that cockpit can treat it as an API

## BDD scenarios (minimum set)

Feature: “Environment sanity”

- Scenario: No sources in repo → skip
- Scenario: Required tool missing under team profile → fail + remediation
- Scenario: Version mismatch under oss profile → warn
- Scenario: Hash mismatch for repo-local tool → fail under strict
- Scenario: Malformed .tool-versions → warn + source_parse_error finding

These are covered by cucumber feature files with fixtures and fake probe adapters.

## Working agreements (for contributors)

- Add a new source/parser only with:
  - fixtures
  - a fuzz target
  - proptest case for edge handling
- Add a new finding code only with:
  - explain entry
  - deterministic ordering covered by snapshot tests
