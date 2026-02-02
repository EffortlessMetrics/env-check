# env-check architecture

## Role

env-check is the **machine-truth** sensor in the cockpit ecosystem.

It answers:

> “Is this machine/runner set up to work with the repo’s declared tool requirements?”

It exists to keep other sensors honest:

- **Repo truth sensors** must not depend on local installs or runner state.
- **env-check** is the correct place for PATH/version/hash validation and onboarding friction.

## Truth layer boundary

- **Truth layer:** machine truth
- **Lane:** onboarding / CI runner sanity
- **Cockpit defaults:** informational, non-blocking, missing receipt = skip

env-check should never become “the repo policy gate”. If a repo wants it to block, that is an explicit opt-in at the cockpit level.

## Hard boundaries

env-check **does**:

- Parse repo-declared tool requirements from common sources (`rust-toolchain.toml`, `.mise.toml`, `.tool-versions`, hash manifests).
- Probe the local environment (PATH, rustup) to verify presence and versions.
- Optionally verify local binary hashes when a repo provides a hash manifest.
- Emit a versioned receipt + (optional) PR-friendly markdown.

env-check **does not**:

- Run builds/tests/coverage/benchmarks.
- Fetch from the network by default.
- Write to the repo.
- “Fix” problems (actuation belongs elsewhere).

## Inputs

### Auto-discovered sources (best-effort)

- `rust-toolchain.toml` / `rust-toolchain`
- `.mise.toml`
- `.tool-versions` (asdf)
- repo-provided hash manifests (default path configurable)

If none exist, env-check should emit a **skip** receipt with reason `no_sources`.

### Optional explicit config

- `env-check.toml` for overrides and policy knobs:
  - which sources to consider
  - custom probes per tool
  - allow/deny lists
  - fail-on rules and caps

## Outputs

### Canonical artifact layout

```
artifacts/env-check/report.json   # canonical receipt (required)
artifacts/env-check/comment.md    # optional markdown summary
artifacts/env-check/raw.log       # optional probe transcript (debugging)
```

### Receipt contract

- `schema`: `env-check.report.v1`
- Must conform to `schemas/receipt.envelope.v1.json`
- Tool-specific details are stored under `data` only (one extension point).

### Verdict semantics

- `verdict.status` ∈ `{ pass, warn, fail, skip }`
- Tool/runtime errors are represented as:
  - process exit `1`
  - `verdict.status="fail"`, `reasons=["tool_error"]`
  - one canonical finding `tool.runtime_error`

## Policy and adoption

### Profiles

Profiles are presets for enabled checks and severity mapping:

- `oss`: safe for strangers; prefer `warn/skip` over `fail`
- `team`: fail on missing required tools, warn on optional mismatches
- `strict`: fail on any mismatch for required requirements; treat many warns as fail

Profiles should be applied as a final mapping step over findings (avoid scattered branching).

### Missing inputs

- Missing sources ⇒ `skip` (with reason), not `fail`.
- Missing base/head (if you ever add diff-scoped behavior) should be a tool error unless an explicit diff file is provided.

## Integration with cockpit

A typical `cockpit.toml` posture:

```toml
[sensors.env-check]
blocking = false
missing = "skip"
```

If a repo wants env-check to block merges, it should do so explicitly:

```toml
[sensors.env-check]
blocking = true
missing = "warn" # or "fail" once adopted
```

## Determinism requirements

Given identical inputs (repo files + probe results), outputs must be byte-stable:

- Receipt fields and ordering are deterministic.
- Findings sorted: `severity desc → tool → path → line → code → message`
- Truncation behavior is deterministic and explicitly noted in `data`.

## Security posture

env-check executes external commands as part of probing. Constraints:

- Commands are fixed argv vectors (no shell parsing).
- Probes are allowlisted by tool name (no “run arbitrary command from config” in v0.1).
- The probe transcript (`raw.log`) should redact obvious secrets (future enhancement).
