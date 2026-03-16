# env-check

**Machine-truth environment sensor** — validates that your machine (or CI runner) has the tools a repository requires.

env-check reads source files like `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, `.node-version`, `pyproject.toml`, `go.mod`, and others to discover required tools, then probes the local machine to verify they are installed at the correct versions.

## Installation

```sh
cargo install env-check
```

Or via the install scripts from a [GitHub release](https://github.com/EffortlessMetrics/env-check/releases):

```sh
# macOS / Linux
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.ps1 | iex"
```

## Quick start

```sh
# Run in any repo with .tool-versions, .mise.toml, etc.
env-check check

# Stricter for team CI
env-check check --profile team

# Write a markdown summary
env-check check --md comment.md

# Explain a finding code
env-check explain env.missing_tool
```

## What it checks

| Source file | Tools detected |
|---|---|
| `.tool-versions` | Any tool listed (asdf format) |
| `.mise.toml` | Any tool listed (mise format) |
| `rust-toolchain.toml` | Rust toolchain channel and components |
| `.node-version` / `.nvmrc` | Node.js |
| `package.json` (engines) | Node.js, npm |
| `.python-version` | Python |
| `pyproject.toml` (requires-python) | Python |
| `go.mod` (toolchain) | Go |
| Hash manifests | SHA-256 binary integrity |

## Profiles

| Profile | Behavior |
|---|---|
| `oss` (default) | Warn on missing tools, skip optional |
| `team` | Fail on missing required tools |
| `strict` | Fail on any mismatch |

## Output

- **JSON receipt** at `artifacts/env-check/report.json` (schema: `sensor.report.v1`)
- **Markdown summary** (optional, `--md`)
- **GitHub annotations** (optional, `--annotations`)
- Exit code: `0` pass, `2` policy fail, `1` runtime error

## CI Integration

```yaml
# GitHub Actions
- uses: actions/checkout@v4
- run: cargo install env-check
- run: env-check check --profile team --md comment.md
```

See the [CI integration guide](https://github.com/EffortlessMetrics/env-check/blob/main/docs/ci-integration.md) for GitLab CI, CircleCI, and Azure Pipelines examples.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT License](LICENSE) at your option.
