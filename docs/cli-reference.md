# CLI Reference

This document provides a comprehensive reference for the env-check command-line interface.

## Installation

### From Release

Download the latest binary from [GitHub Releases](https://github.com/example/env-check/releases).

### From Source

```bash
cargo install --path crates/env-check-cli
```

### Verify Installation

```bash
env-check --version
env-check --help
```

---

## Commands

### `env-check check`

Run the environment verification pipeline. This command discovers source files, probes the local machine for installed tools, evaluates policy, and writes a receipt.

**Usage:**

```bash
env-check check [OPTIONS]
```

**Description:**

Reads `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, and other source files to determine required tools, then probes the local machine to verify they are installed.

#### Options

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--root <PATH>` | `PathBuf` | `.` | Repository root directory to scan for source files |
| `--config <PATH>` | `PathBuf` | *(none)* | Path to `env-check.toml` configuration file |
| `--profile <PROFILE>` | `string` | `oss` | Policy profile: `oss`, `team`, or `strict` |
| `--fail_on <LEVEL>` | `string` | `error` | Verdict escalation level: `error`, `warn`, or `never` |
| `--out <PATH>` | `PathBuf` | `artifacts/env-check/report.json` | JSON receipt output path |
| `--md <PATH>` | `PathBuf` | *(none)* | Optional markdown summary output path |
| `--mode <MODE>` | `string` | `default` | Output mode: `default` or `cockpit` |
| `--debug` | `flag` | `false` | Enable debug logging (writes to `artifacts/env-check/extras/raw.log`) |
| `--log_file <PATH>` | `PathBuf` | *(none)* | Custom debug log file path (implies `--debug`) |
| `--annotations <PATH>` | `PathBuf` | *(none)* | GitHub Actions annotations output path |
| `--annotations_max <N>` | `usize` | `20` | Maximum findings to include in GitHub annotations |

#### Profiles

| Profile | Missing Required Tool | Version Mismatch | Hash Mismatch |
|---------|----------------------|------------------|---------------|
| `oss` | warn | warn | warn |
| `team` | error | warn | error |
| `strict` | error | error | error |

#### Fail-On Levels

| Level | Behavior |
|-------|----------|
| `error` | Exit with code `2` if any error-level findings exist |
| `warn` | Exit with code `2` if any warning or error findings exist |
| `never` | Always exit with code `0` (unless a runtime error occurs) |

#### Output Modes

| Mode | Description |
|------|-------------|
| `default` | Exit code reflects verdict: `0` for pass/warn/skip, `1` for runtime error, `2` for policy failure |
| `cockpit` | Always exit `0` if receipt was written successfully. Designed for CI orchestrators that parse the receipt to determine next steps |

#### Examples

```bash
# Basic check with defaults (oss profile, current directory)
env-check check

# Strict profile with markdown output
env-check check --profile strict --md artifacts/comment.md

# Team profile with custom root directory
env-check check --profile team --root ./my-project

# Generate GitHub Actions annotations
env-check check --annotations annotations.txt --annotations_max 50

# Cockpit mode for CI orchestration
env-check check --mode cockpit --out report.json

# With custom configuration file
env-check check --config ./env-check.toml

# Fail on any warning
env-check check --fail_on warn

# Never fail (useful for reporting only)
env-check check --fail_on never

# Enable debug logging
env-check check --debug

# Custom debug log location
env-check check --log_file /tmp/env-check-debug.log

# Combined options for CI
env-check check --profile team --fail_on warn --out artifacts/report.json --md artifacts/comment.md --annotations annotations.txt
```

---

### `env-check md`

Render markdown from an existing `report.json` receipt. Useful for generating markdown summaries from receipts created in previous runs.

**Usage:**

```bash
env-check md [REPORT_PATH] [OPTIONS]
env-check md --report <PATH> [OPTIONS]
```

**Description:**

Reads a JSON receipt file and renders it as a markdown summary. The report path can be provided as a positional argument or via the `--report` flag.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `[REPORT_PATH]` | No* | Path to the `report.json` file (positional) |
| `--report <PATH>` | No* | Path to the `report.json` file (flag alternative) |

*Either the positional argument or `--report` flag is required.

#### Options

| Flag | Default | Description |
|------|---------|-------------|
| `--out <PATH>` | `artifacts/env-check/comment.md` | Output markdown file path |

#### Examples

```bash
# Render from positional argument (default output)
env-check md artifacts/env-check/report.json

# Render with explicit report flag
env-check md --report artifacts/env-check/report.json

# Render to custom output location
env-check md report.json --out ./output/summary.md

# Full example with all options
env-check md --report artifacts/env-check/report.json --out docs/env-check-summary.md
```

---

### `env-check explain`

Explain finding codes and check IDs. Finding codes are stable identifiers used in CI integrations to filter or handle specific types of findings.

**Usage:**

```bash
env-check explain [CODE]
env-check explain --list
```

**Description:**

Provides human-readable explanations for stable finding codes (e.g., `env.missing_tool`, `env.version`) and check IDs. Use `--list` to see all available codes.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `[CODE]` | No* | The finding code or check ID to explain |
| `--list` | No* | List all known explainable codes and check IDs |

*Either `CODE` or `--list` is required.

#### Common Finding Codes

| Code | Description |
|------|-------------|
| `env.missing_tool` | A required tool is not installed or not found in PATH |
| `env.version` | Installed tool version does not match requirement |
| `env.presence` | Tool presence check (alias for missing_tool) |
| `tool.runtime_error` | Error executing tool probe |
| `tool.runtime` | Generic runtime error during probing |

#### Examples

```bash
# List all known codes and check IDs
env-check explain --list

# Explain a specific finding code
env-check explain env.missing_tool

# Explain version mismatch code
env-check explain env.version

# Explain runtime error code
env-check explain tool.runtime_error
```

---

## Exit Codes

env-check uses a three-tier exit code scheme:

| Code | Name | Meaning | Condition |
|------|------|---------|-----------|
| `0` | OK | Success | Pass, warn, or skip (unless `fail_on=warn`) |
| `1` | Tool/Runtime Error | Tool failed to run | Unexpected failure during execution (I/O error, parse failure, probe failure) |
| `2` | Policy Fail | Environment failed check | Environment does not meet requirements based on profile and `fail_on` settings |

### Exit Code Interaction with Mode

The `--mode` flag modifies exit code behavior:

| Mode | Success | Runtime Error | Policy Fail |
|------|---------|---------------|-------------|
| `default` | `0` | `1` | `2` |
| `cockpit` | `0` | `0` | `0` |

**Note:** In cockpit mode, the exit code is always `0` as long as the receipt was written successfully. The receipt contains the verdict and findings, allowing the cockpit orchestrator to handle the result programmatically.

### Exit Code Interaction with Fail-On

The `--fail_on` flag determines which findings trigger exit code `2`:

| `fail_on` | Error Findings | Warning Findings | Exit Code |
|-----------|----------------|------------------|-----------|
| `error` | Present | Any | `2` |
| `warn` | Any | Any | `2` |
| `never` | Any | Any | `0` |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ENV_CHECK_DEBUG_LOG` | Path to debug log file. When set, enables debug logging and writes to the specified path. Equivalent to `--log_file` flag. |

### Environment Variable Examples

```bash
# Enable debug logging via environment variable
ENV_CHECK_DEBUG_LOG=/tmp/debug.log env-check check

# Override with CLI flag (CLI takes precedence)
ENV_CHECK_DEBUG_LOG=/default/path.log env-check check --log_file /custom/path.log
```

---

## Output Artifacts

### Primary Artifact: `report.json`

The JSON receipt is always written to the path specified by `--out` (default: `artifacts/env-check/report.json`).

**Schema:** `sensor.report.v1`

**Key Fields:**
- `schema`: Schema version identifier
- `verdict`: Contains `status` (`pass`, `warn`, `fail`, `skip`) and `reasons`
- `findings`: Array of findings with `code`, `severity`, `message`, and optional `path`
- `sources`: Array of discovered source files
- `artifacts`: References to side artifacts (debug logs, annotations)

### Optional Artifact: `comment.md`

Markdown summary written when `--md` is specified. Contains a human-readable summary of findings.

### Optional Artifact: Annotations

GitHub Actions workflow command annotations written when `--annotations` is specified. Contains `::error::` and `::warning::` commands for CI integration.

### Debug Artifact: `raw.log`

Debug transcript written when `--debug` or `--log_file` is specified. Contains detailed probe execution logs. Does not affect receipt determinism.

---

## Common Use Cases

### Local Development

```bash
# Quick check with defaults
env-check check

# Check with debug output for troubleshooting
env-check check --debug
```

### CI Pipeline (Fail Fast)

```bash
# Strict profile, fail on any issue
env-check check --profile strict --fail_on error
```

### CI Pipeline (Report Only)

```bash
# Generate report without failing the build
env-check check --fail_on never --md comment.md
```

### GitHub Actions Integration

```bash
# Generate all artifacts for GitHub Actions
env-check check \
  --profile team \
  --out artifacts/env-check/report.json \
  --md artifacts/env-check/comment.md \
  --annotations annotations.txt
```

### Cockpit Orchestration

```bash
# Run in cockpit mode for external orchestrator
env-check check --mode cockpit --out report.json

# Orchestrator then parses report.json and handles verdict
```

### Multi-Project Repository

```bash
# Check a specific subdirectory
env-check check --root ./services/api --profile team

# Check with project-specific config
env-check check --root ./services/frontend --config ./services/frontend/env-check.toml
```

---

## See Also

- [Configuration Reference](configuration.md) - Configuration file format
- [Finding Codes](finding-codes.md) - Complete list of finding codes
- [Architecture](architecture.md) - System architecture overview
- [ADR-006: Profile-Based Severity Mapping](adr/ADR-006-profile-severity.md) - Profile design decisions
- [ADR-008: Exit Code Semantics](adr/ADR-008-exit-codes.md) - Exit code design decisions
