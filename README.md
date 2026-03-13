# env-check

Machine-truth sensor for repository tool requirements.

env-check answers:

> Is this machine/runner set up for the tools this repo declares?

It is deliberately not a build runner, not a policy repair tool, and not a repo mutator.

## Core Contract

- Canonical artifact is always `artifacts/env-check/report.json`.
- Optional artifacts are `artifacts/env-check/comment.md` and `artifacts/env-check/extras/*`.
- Receipt envelope schema is `sensor.report.v1`.
- Determinism is required for identical inputs.
- No network access by default.
- Runtime/tool errors map to exit code `1`, `verdict.status = "fail"`, reason `tool_error`, and exactly one `tool.runtime_error` finding.

## Workspace Crates

| Crate | Responsibility |
|---|---|
| `env-check-types` | Shared receipt/domain types, stable finding codes, explain registry |
| `env-check-config` | Config loading and source-filter model (`env-check.toml`) |
| `env-check-parser-flags` | Parser feature/alias resolution for source intake |
| `env-check-requirement-normalizer` | Deterministic requirement dedupe/filter normalization |
| `env-check-sources-node` | Node parser microcrate (`.node-version`, `.nvmrc`, `package.json`) |
| `env-check-sources-python` | Python parser microcrate (`.python-version`, `pyproject.toml`) |
| `env-check-sources-go` | Go parser microcrate (`go.mod`) |
| `env-check-sources-hash` | Hash manifest parser microcrate (`scripts/tools.sha256`) |
| `env-check-sources` | Deterministic source discovery and parsing into normalized requirements |
| `env-check-runtime-metadata` | Host/CI/git metadata discovery helpers |
| `env-check-runtime` | Runtime boundary helpers and metadata re-export seam |
| `env-check-probe` | Probing adapters for tool presence/version/hash observations |
| `env-check-domain` | Pure evaluation from requirements/observations to findings/verdict |
| `env-check-evidence` | Pure evidence shaping for receipt `data` payloads |
| `env-check-reporting` | Receipt `data` and capability assembly helpers |
| `env-check-render` | Deterministic markdown + GitHub annotation renderers |
| `env-check-app` | Composition root: config, orchestration, receipt assembly, runtime-error receipts |
| `env-check-cli` | Clap CLI (`check`, `md`, `explain`) |
| `xtask` | Workspace maintenance tasks (schema/conformance/adoption/mutants) |

Dependency direction:

`types <- (sources|probe|domain|evidence|render) <- app <- cli`

## Inputs (Auto-Discovered)

- `.tool-versions`
- `.mise.toml`
- `rust-toolchain.toml` / `rust-toolchain`
- `.node-version`
- `.nvmrc`
- `package.json`
- `.python-version`
- `pyproject.toml`
- `go.mod`
- hash manifests (default `scripts/tools.sha256`, configurable)

If none are present, env-check emits a skip receipt (`no_sources`), not a failure.

## Output Artifacts

```text
artifacts/env-check/report.json              # required receipt
artifacts/env-check/comment.md               # optional markdown summary
artifacts/env-check/extras/raw.log           # optional debug probe log
artifacts/env-check/extras/annotations.txt   # optional GitHub workflow annotations
```

## CLI Quickstart

```bash
env-check check \
  --root . \
  --profile oss \
  --out artifacts/env-check/report.json \
  --md artifacts/env-check/comment.md
```

Render markdown from an existing receipt:

```bash
env-check md --report artifacts/env-check/report.json --out artifacts/env-check/comment.md
```

Explain finding codes/check IDs:

```bash
env-check explain env.missing_tool
env-check explain --list
```

## Exit Codes

- `0`: success path (including pass/warn depending on mode/policy settings)
- `2`: policy failure verdict
- `1`: tool/runtime error

## Documentation

- [CLI Reference](docs/cli-reference.md) - Command-line interface documentation
- [Configuration](docs/configuration.md) - Configuration options and profiles
- [CI Integration](docs/ci-integration.md) - GitHub Actions and CI/CD integration
- [Architecture](docs/architecture.md) - System design and boundaries
- [Design](docs/design.md) - Technical design decisions
- [Requirements](docs/requirements.md) - Acceptance criteria
- [Implementation Plan](docs/implementation-plan.md) - Phase tracking
- [Roadmap](docs/now-next-later.md) - Now/Next/Later priorities
- [Testing](docs/testing.md) - Testing strategy and commands
- [Release](docs/release.md) - Release process
- [Contracts](docs/contracts.md) - Schema and interface contracts
- [Source Parsers](docs/parsers.md) - Parser reference for all supported sources
- [Finding Codes](docs/finding-codes.md) - Finding codes reference
- [ADRs](docs/adr/) - Architecture Decision Records
- [Changelog](CHANGELOG.md) - Release history

## License

Licensed under either:

- MIT
- Apache-2.0
