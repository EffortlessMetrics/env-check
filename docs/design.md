# env-check design

This document describes the internal design in a **hexagonal (ports/adapters)** style with microcrates, with a bias toward deterministic outputs and testability.

## Design constraints

- **Machine truth only:** env-check validates “what’s installed” and “what the runner looks like”.
- **Receipts-first:** output is a versioned receipt that the cockpit ingests.
- **Deterministic:** identical inputs → byte-stable artifacts.
- **Test-heavy:** BDD + golden fixtures + proptest + fuzzing + mutation testing.

## High-level flow

1. Discover sources in repo root
2. Parse each source → `Requirement` set (+ provenance)
3. Normalize + merge requirements (stable identity keys)
4. Probe environment for each requirement → `Observation` set
5. Evaluate `Requirement × Observation × Policy` → `Finding[]` + `Verdict`
6. Write receipt (`report.json`)
7. Optionally render markdown (`comment.md`)

## Microcrate layout

```
crates/
  env-check-types    # DTOs: receipt envelope + domain types + codes
  env-check-sources  # parse source files into Requirements
  env-check-probe    # probe local machine (PATH/version/hash) via ports
  env-check-domain   # policy + evaluation (pure)
  env-check-render   # markdown renderer (pure)
  env-check-app      # orchestration: wire adapters and write artifacts
  env-check-cli      # clap CLI
xtask/               # schema checks, fixture tooling
```

### Dependency direction (enforced)

- `domain` depends on `types` only.
- `render` depends on `types` only.
- `sources` depends on `types` (and parsing crates).
- `probe` depends on `types` (and OS crates).
- `app` depends on everything; it is the composition root.
- `cli` depends on `app` and `types`.

This keeps the domain pure and testable.

## Core domain types

### Requirement

A normalized tool requirement:

- `tool_id`: stable identifier (`rustc`, `cargo`, `node`, `just`, …)
- `constraint`: optional version constraint
- `required`: bool
- `source`: `SourceRef` (path + source kind)
- `hash`: optional hash spec (for repo-provided binaries)
- `probe_kind`: how to check it (PATH command, rustup toolchain, file hash)

### Observation

Result of probing a requirement:

- `present`: bool
- `version`: optional parsed version + raw string
- `hash_ok`: optional bool
- `probe`: argv executed, exit code, stderr/stdout samples (debuggable)

### Policy

Local evaluation policy:

- profile: `oss|team|strict`
- fail_on: `error|warn|never`
- caps: max findings, max probes recorded
- allow/deny: tool ids, source kinds, paths

### Finding

The domain output record, later surfaced by the cockpit:

- severity: `info|warn|error`
- check_id: stable producer id (`env.presence`, `env.version`, …)
- code: stable classification (`env.missing_tool`, …)
- message: one-line human explanation
- location: best-effort (`path` required when available)
- help/url: remediation guidance
- data: opaque structured hints (probe output, constraint, etc.)

## Ports and adapters

### Ports (traits) in `env-check-probe`

- `CommandRunner`
  - runs an argv vector and returns stdout/stderr/exit
- `PathResolver`
  - resolves executable presence in PATH (`which`)
- `Hasher`
  - computes sha256 for a local file
- `Clock`
  - provides timestamps for receipts (injectable)

### Adapters

- `OsCommandRunner` uses `std::process::Command`
- `OsPathResolver` uses `which`
- `Sha256Hasher` uses `sha2`
- `SystemClock` uses `chrono::Utc`

In tests, use fakes:

- `FakeCommandRunner` (pre-programmed outputs)
- `FakePathResolver`
- `FakeClock`

This keeps probing logic testable without depending on the host environment.

## Source parsing

### Source discovery

`env-check-sources::parse_all(root) -> ParsedSources`

Returns discovered sources, parsed requirements, and any parse error findings.

Rules:

- deterministic order (sorted paths)
- include only known sources unless configured otherwise

### Supported sources

#### Version managers

**`.tool-versions` (asdf)**
- ignore blank lines and comments
- parse `tool version` pairs
- normalize common aliases (`nodejs` → `node`, etc.)

**`.mise.toml`**
- read `[tools]` table
- interpret values:
  - `"1.2.3"` as exact constraint
  - `"latest"` or `"system"` treated as "present only" (no strict version constraint)
  - arrays and nested tables are preserved in `data` (future)

#### Rust

**`rust-toolchain.toml` / `rust-toolchain`**
- read `toolchain.channel` as a rust toolchain requirement
- record components/targets as additional requirements (optional in v0.1; can be warn-only)

#### Node.js

**`.node-version`**
- single line with Node.js version
- supports optional `v` prefix

**`.nvmrc`**
- single line with Node.js version
- supports optional `v` prefix and LTS aliases

**`package.json`**
- extract `engines.node` and `engines.npm` constraints
- supports semver range syntax

#### Python

**`.python-version`**
- single line with Python version
- supports pyenv format (version per line, optional comments)
- handles pypy and other implementations

**`pyproject.toml`**
- extract `project.requires-python` constraint
- supports PEP 440 version specifiers

#### Go

**`go.mod`**
- extract `go` directive version
- extract `toolchain` directive if present (Go 1.21+)

#### Binary verification

**Hash manifests** (default `scripts/tools.sha256`)
- parse lines like: `<sha256>  <relative_path>`
- produce requirements with hash specs for those paths
- hash verification is only performed for files under the repo root (no arbitrary paths)

## Evaluation rules (domain)

### Presence

- required tool missing:
  - `oss`: warn
  - `team/strict`: error

### Version mismatch

- default: warn in `oss`, error in `team/strict` (configurable)
- version parsing is best-effort; if parsing fails, emit:
  - `env.version_unparseable` (warn) or treat as mismatch (config)

### Hash mismatch

- warn in `oss`, error in `team/strict` (since it implies drift)

### No sources

- `skip` with reason `no_sources`

### Tool/runtime failures

- `exit 1`, `verdict.fail`, reason `tool_error`, plus `tool.runtime_error`

## Determinism

### Ordering

All domain outputs must be stable:

- requirements sorted by `tool_id`, then source path
- findings sorted by:
  1) severity desc (`error > warn > info`)
  2) source path
  3) check_id
  4) code
  5) message

### Truncation

If output is capped:

- keep totals in `data.summary`
- include `data.truncated = true`
- render “truncated, see report” marker in markdown

## Rendering (markdown)

Rendering is a pure function from `Report`:

- summary line: status + counts
- sources used
- top N findings with terse remediation
- a single repro line

The cockpit director should not parse this markdown; it is primarily for standalone use or as an optional artifact link.

## Schemas

- `schemas/receipt.envelope.v1.json` is the shared bus schema
- `schemas/env-check.report.v1.json` constrains `schema` and `tool.name`

The code should include a `schema_id` constant and a schema version string in the output to support compatibility checks.

## Testing strategy

- **BDD (cucumber):** workflow-level behavior (profiles, missing sources, mismatch remediation)
- **Golden fixtures (insta):** stable receipts and markdown outputs
- **Proptest:** version parsing, path normalization, `.tool-versions` parsing
- **Fuzzing (cargo fuzz):** parsers never panic on arbitrary bytes
  - Targets: `parse_tool_versions`, `parse_mise_toml`, `parse_rust_toolchain`, `parse_hash_manifest`, `fuzz_node_version`, `fuzz_nvmrc`, `fuzz_package_json`, `fuzz_python_version`, `fuzz_pyproject_toml`, `fuzz_go_mod`
- **Mutation testing (cargo-mutants):** timeboxed, focused on domain evaluation and parsers
