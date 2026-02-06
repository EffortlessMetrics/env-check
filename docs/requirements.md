# env-check requirements

## Goal

Provide a machine-truth preflight that makes environment drift visible and actionable without contaminating the PR fast lane with “what’s installed” assumptions.

## Questions answered

- “Do I have the tools this repo expects?”
- “Are my versions compatible with the repo’s declared constraints?”
- “If the repo vendors binaries, do my local copies match the repo’s hashes?”

## Non-goals

- Not a build runner.
- Not a repo policy engine.
- Not an installer.
- Not a network-dependent tool.

## Functional requirements

### R1 — Source discovery

env-check MUST discover requirements from any subset of supported sources.

**Supported sources (v0.1):**

*Version managers:*
- `.tool-versions` (asdf)
- `.mise.toml`

*Rust:*
- `rust-toolchain.toml` / `rust-toolchain`

*Node.js:*
- `.node-version`
- `.nvmrc`
- `package.json` (engines.node, engines.npm)

*Python:*
- `.python-version`
- `pyproject.toml` (requires-python)

*Go:*
- `go.mod` (go directive)

*Binary verification:*
- `scripts/tools.sha256` (configurable; optional)

If no supported sources exist, env-check MUST produce a receipt with `verdict.status="skip"` and reason `no_sources`.

### R2 — Normalized requirement model

env-check MUST normalize all sources into a single internal representation:

- tool id (e.g., `rustc`, `cargo`, `rustup`, `just`, `node`, `npm`, `python`, `go`)
- version constraint (optional)
- required vs optional
- source provenance (which file declared it)
- optional hash spec (when provided by repo)
- probe strategy (how to check it)

The normalized representation MUST be deterministic (stable ordering, stable identity key).

### R3 — Probing / evaluation

env-check MUST support these checks:

- **presence:** tool exists (PATH) or rustup toolchain exists
- **version:** tool’s reported version satisfies constraint (best-effort parsing; conservative comparison)
- **hash:** when a repo provides hashes for a local binary, verify the hash

env-check SHOULD provide enough provenance to debug mismatches:
- raw version output captured (in `data` or `raw.log`)
- which command was executed (argv vector)

env-check MUST NOT execute probes through a shell.

### R4 — Policy and profiles

env-check MUST support profiles as presets:

- `oss` (default): prefer skip/warn for non-critical issues
- `team`: treat missing required tools as errors
- `strict`: treat required mismatches as errors; more warns elevated by default

Profiles MUST be applied after findings are generated (no scattered branching).

env-check MUST support a local `fail_on` policy:
- `error` (default)
- `warn`
- `never`

### R5 — CLI surface (stable)

Commands:

- `env-check check`
  - discovers sources, probes tools, evaluates policy, writes receipt
- `env-check md`
  - render-only from a `report.json` receipt
- `env-check explain <code|check_id>`
  - prints stable remediation guidance

Required flags (v0.1):

- `--root <path>` (default `.`)
- `--profile oss|team|strict`
- `--out <path>` for receipt output (default `artifacts/env-check/report.json`)
- `--md <path>` for markdown (optional)
- `--config <path>` (optional)

### R6 — Artifacts and receipt semantics

env-check MUST write:

- `artifacts/env-check/report.json` (canonical)
- `artifacts/env-check/comment.md` when `--md` is requested (recommended)
- optional `raw.log` (future: behind flag)

Receipt requirements:

- schema id: `sensor.report.v1`
- envelope required fields present even when early failures occur (best-effort)
- top-level keys strict; tool-specific payload under `data` only

Exit codes:

- `0` ok (pass or warn, unless `fail_on=warn`)
- `2` policy fail
- `1` tool/runtime error

### R7 — Finding identity and explainability

Findings MUST include:

- `severity` ∈ `{ info, warn, error }`
- `code` (stable, namespaced)
- `message` (human actionable)

Findings SHOULD include:

- `check_id` (stable producer id)
- `location.path` for the declaring source file

The following code set is the MVP (small, durable):

- `env.missing_tool`
- `env.version_mismatch`
- `env.hash_mismatch`
- `env.toolchain_missing`
- `env.source_parse_error`
- `tool.runtime_error` (shared)

`env-check explain` MUST have entries for all codes emitted by built-in checks.

### R8 — Determinism

Given identical inputs (repo files + probe outputs), env-check MUST produce:

- byte-stable `report.json`
- byte-stable markdown rendering (when requested)

Determinism requirements:

- stable ordering for requirements, probes, and findings
- stable truncation/capping behavior with explicit “truncated” markers

### R9 — Conformance harness compatibility

env-check MUST be testable with a shared conformance harness that validates:

- schema compliance (`sensor.report.v1`)
- deterministic ordering (golden fixtures)
- explain registry completeness for emitted codes

## Non-functional requirements

### N1 — Cross-platform

Must run on Linux/macOS/Windows. Where behavior diverges (PATH rules, executable suffix), document it and keep receipt semantics consistent.

### N2 — Offline-first

Must not require network access for normal operation.

### N3 — Fast

Target: sub-second on typical repos (excluding the cost of probes themselves).

### N4 — Safe execution

- No shell execution.
- Configurable probes must be allowlisted and reviewed (v0.1: no arbitrary probe commands).

## Acceptance criteria (v0.1)

- [x] Running `env-check check` in a repo with no sources yields `skip` receipt.
- [x] `.tool-versions` and `.mise.toml` are parsed into normalized requirements deterministically.
- [x] Missing required tool under `team` yields error finding + exit code `2`.
- [x] Version mismatch yields warn/error depending on profile.
- [x] Receipt validates against `schemas/sensor.report.v1.schema.json`.
- [x] Golden fixtures cover parsing + evaluation + markdown rendering.
- [x] A fuzz target exists for each parser (never panic).
- [x] Mutation testing is wired and timeboxed in CI.

## Extended source support (implemented)

- [x] `.node-version` and `.nvmrc` parsed for Node.js version
- [x] `package.json` engines field parsed for node/npm constraints
- [x] `.python-version` parsed for Python version
- [x] `pyproject.toml` requires-python parsed
- [x] `go.mod` go directive parsed for Go version
