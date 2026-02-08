# env-check

Machine-truth preflight for the cockpit ecosystem.

env-check answers one question:

> “Is this machine/CI runner set up to work with the repo’s declared tool requirements?”

It is deliberately **not** a repo policy engine and **not** a build runner. It exists to keep
repo-truth sensors deterministic by ejecting “what’s installed” checks into a dedicated,
opt-in tool.

## Where it fits

- **Truth layer:** machine truth
- **Lane:** onboarding / runner sanity (optional by default)
- **Cockpit posture:** non-blocking unless the repo explicitly opts in via `cockpit.toml`

## What it checks (v0.1)

- Tool presence on PATH (or rustup-managed toolchains where applicable)
- Version constraints (best-effort parsing; conservative comparison)
- Optional local hash verification for repo-provided binaries (when a hash manifest exists)

## Inputs (auto-discovered)

env-check will attempt to read any of these if present:

- `.tool-versions` (asdf)
- `.mise.toml` (mise)
- `rust-toolchain.toml` / `rust-toolchain`
- `.node-version`
- `.nvmrc`
- `package.json` (engines field)
- `.python-version`
- `pyproject.toml`
- `go.mod`
- Hash manifest (`scripts/tools.sha256` or configured)

If none exist, env-check emits a **skip** receipt (it does not fail a random repo).

## Outputs (artifacts)

Canonical output paths:

```
artifacts/env-check/report.json        # required (receipt envelope)
artifacts/env-check/comment.md         # optional (PR-friendly summary)
artifacts/env-check/extras/raw.log     # optional (probe transcript)
```

## Install

### GitHub Releases (prebuilt binaries)

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh \
  | sh
```

PowerShell:

```powershell
irm https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.ps1 | iex
```

### GitHub Action (one-step adoption)

```yaml
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  with:
    profile: oss
    root: .
    md: artifacts/env-check/comment.md
```

## Quickstart

```bash
# In CI (recommended): write artifacts into artifacts/env-check
env-check check \
  --root . \
  --profile oss \
  --out artifacts/env-check/report.json \
  --md  artifacts/env-check/comment.md
```

Render-only (useful when the check ran elsewhere):

```bash
env-check md --report artifacts/env-check/report.json --out artifacts/env-check/comment.md
```

Explain codes:

```bash
env-check explain env.missing_tool
```

## Exit codes

- `0` — ok (pass or warn unless warn-as-fail is enabled in local config)
- `2` — policy fail (e.g., missing required tool under a strict profile)
- `1` — tool/runtime error (I/O, parse error, internal failure)

## Contract compatibility

env-check emits `sensor.report.v1`, which is an instance of the shared sensor report schema.
Tool-specific details live under `data` only.

See:

- `schemas/sensor.report.v1.schema.json`
- `schemas/env-check.report.v1.json`

## Final statement

env-check is intentionally machine-truth and optional by default. It emits a standard receipt
and minimal PR-friendly output, and it never runs builds, enforces repo policy, or modifies
the repository.

## License

MIT (placeholder; adjust as needed).
