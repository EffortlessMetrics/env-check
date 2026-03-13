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

## Global Options

These options apply to all commands:

| Flag | Description |
|------|-------------|
| `--version` | Print version information and exit |
| `--help` | Print help information and exit |

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
| `--probe-timeout <SEcs>` | `u64` | `30` | Timeout in seconds for individual tool probing operations |
| `--annotations <PATH>` | `PathBuf` | *(none)* | GitHub Actions annotations output path |
| `--annotations_max <N>` | `usize` | `20` | Maximum findings to include in GitHub annotations |

#### Profiles

Profiles control how findings are classified (error, warn, info). See [ADR-006](adr/ADR-006-profile-severity.md) for design rationale.

| Profile | Missing Required Tool | Version Mismatch | Hash Mismatch |
|---------|----------------------|------------------|---------------|
| `oss` | warn | warn | warn |
| `team` | error | warn | error |
| `strict` | error | error | error |

#### Fail-On Levels

The `--fail_on` flag controls which findings trigger exit code `2` (policy failure):

| Level | Behavior |
|-------|----------|
| `error` | Exit with code `2` if any error-level findings exist |
| `warn` | Exit with code `2` if any warning or error findings exist |
| `never` | Always exit with code `0` (unless a runtime error occurs) |

#### Output Modes

The `--mode` flag controls exit code behavior for CI integrations:

| Mode | Description |
|------|-------------|
| `default` | Exit code reflects verdict: `0` for pass/warn/skip, `1` for runtime error, `2` for policy failure |
| `cockpit` | Always exit `0` if receipt was written successfully. Designed for CI orchestrators that parse the receipt to determine next steps |

##### Cockpit Mode

When using `--mode cockpit`, env-check always exits with code `0` as long as the receipt was written successfully. The receipt contains the verdict and findings, allowing an external orchestrator (such as the cockpit system) to handle the result programmatically.

**When to use cockpit mode:**
- CI pipelines with external result processing
- Orchestrated workflows where another tool decides actions based on findings
- Scenarios where you want to collect results without failing the build

**Example:**

```bash
# Run in cockpit mode - exit code is always 0 if receipt is written
env-check check --mode cockpit --out report.json

# The orchestrator then parses report.json and handles verdict
if grep -q '"status": "fail"' report.json; then
    echo "Environment check failed"
    exit 1
fi
```

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

### `env-check completions`

Generate shell completion scripts for env-check. Supports bash, zsh, fish, and PowerShell.

**Usage:**

```bash
env-check completions <SHELL>
```

**Description:**

Generates shell completion scripts that enable tab completion for env-check commands and options. The script is printed to stdout and should be redirected to the appropriate location for your shell.

#### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `<SHELL>` | Yes | The shell to generate completions for: `bash`, `zsh`, `fish`, or `powershell` |

#### Supported Shells

| Shell | Name | Installation Location |
|-------|------|----------------------|
| `bash` | Bash | `/usr/share/bash-completion/completions/` or `~/.bash_completion` |
| `zsh` | Zsh | Site-functions directory or `~/.zfunc/` |
| `fish` | Fish | `~/.config/fish/completions/` |
| `powershell` | PowerShell | Profile directory |

#### Shell-Specific Installation

##### Bash

**System-wide installation (requires sudo):**

```bash
env-check completions bash | sudo tee /usr/share/bash-completion/completions/env-check
```

**User installation:**

```bash
# Create completions directory if it doesn't exist
mkdir -p ~/.local/share/bash-completion/completions

# Generate completions
env-check completions bash > ~/.local/share/bash-completion/completions/env-check
```

**Alternative: Add to ~/.bash_completion:**

```bash
# Append to existing file or create new one
env-check completions bash >> ~/.bash_completion
```

After installation, restart your shell or run:

```bash
source ~/.bashrc  # or source /etc/bash_completion
```

##### Zsh

**Using site-functions (system-wide, requires sudo):**

```bash
env-check completions zsh | sudo tee /usr/local/share/zsh/site-functions/_env-check
```

**User installation:**

```bash
# Create user completions directory
mkdir -p ~/.zfunc

# Generate completions
env-check completions zsh > ~/.zfunc/_env-check
```

**Add to fpath in ~/.zshrc:**

```zsh
# Add early in your .zshrc, before any compinit call
fpath+=~/.zfunc

# Initialize completions (if not already present)
autoload -U compinit && compinit
```

After installation, restart your shell or run:

```zsh
autoload -U compinit && compinit
```

##### Fish

**User installation:**

```bash
# Create completions directory if it doesn't exist
mkdir -p ~/.config/fish/completions

# Generate completions
env-check completions fish > ~/.config/fish/completions/env-check.fish
```

Fish automatically loads completions from this directory. Start a new shell session or run:

```fish
source ~/.config/fish/completions/env-check.fish
```

##### PowerShell

**Find your profile path:**

```powershell
echo $PROFILE
```

**Generate and save completions:**

```powershell
# Create profile directory if it doesn't exist
$profileDir = Split-Path -Parent $PROFILE
if (-not (Test-Path $profileDir)) {
    New-Item -ItemType Directory -Path $profileDir -Force
}

# Generate completions
env-check completions powershell >> $PROFILE
```

**Alternative: Save to separate file and source:**

```powershell
# Save completions to a separate file
env-check completions powershell > $HOME\Documents\PowerShell\env-check-completions.ps1

# Add to profile
Add-Content $PROFILE '. $HOME\Documents\PowerShell\env-check-completions.ps1'
```

After installation, restart PowerShell or reload your profile:

```powershell
. $PROFILE
```

#### Examples

```bash
# Generate bash completions
env-check completions bash

# Generate zsh completions and save to user directory
env-check completions zsh > ~/.zfunc/_env-check

# Generate fish completions
env-check completions fish > ~/.config/fish/completions/env-check.fish

# Generate PowerShell completions
env-check completions powershell > env-check.ps1

# View completions without saving
env-check completions bash | less
```

#### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success - completions generated and printed to stdout |
| `1` | Invalid shell name - the provided shell is not supported |

---

## Exit Codes

env-check uses a three-tier exit code scheme as defined in [ADR-008](adr/ADR-008-exit-codes.md).

### Exit Code Summary

| Code | Name | Meaning | Condition |
|------|------|---------|-----------|
| `0` | OK | Success | Pass, warn, or skip (unless `fail_on=warn`) |
| `1` | Tool/Runtime Error | Tool failed to run | Unexpected failure during execution (I/O error, parse failure, probe failure) |
| `2` | Policy Fail | Environment failed check | Environment does not meet requirements based on profile and `fail_on` settings |

### Exit Code 0: OK

The tool completed successfully and the environment is acceptable:
- All required tools present with correct versions
- Or warnings present but `fail_on` is not set to `warn`
- Or running in cockpit mode with successful receipt write

### Exit Code 1: Tool/Runtime Error

Something went wrong with the tool itself:
- Unrecoverable I/O error
- Parse failure in configuration
- Probe execution failure (unexpected)
- Any condition that prevents completing the check

This indicates "env-check failed to run" not "environment failed check".

### Exit Code 2: Policy Fail

The tool completed successfully but the environment fails policy:
- Missing required tools (in `team`/`strict` profiles)
- Version mismatches (in `strict` profile)
- Hash mismatches (in `team`/`strict` profiles)
- Warnings when `fail_on=warn`

This indicates "environment does not meet requirements".

### Exit Code Interaction with Mode

The `--mode` flag modifies exit code behavior:

| Mode | Success | Runtime Error | Policy Fail |
|------|---------|---------------|-------------|
| `default` | `0` | `1` | `2` |
| `cockpit` | `0` | `0`* | `0` |

*In cockpit mode, the exit code is always `0` as long as the receipt was written successfully. The receipt contains the verdict and findings, allowing the cockpit orchestrator to handle the result programmatically.

### Exit Code Interaction with Fail-On

The `--fail_on` flag determines which findings trigger exit code `2`:

| `fail_on` | Error Findings | Warning Findings | Exit Code |
|-----------|----------------|------------------|-----------|
| `error` | Present | Any | `2` |
| `warn` | Any | Any | `2` |
| `never` | Any | Any | `0` |

### Exit Code Decision Matrix

| Scenario | `--mode default` | `--mode cockpit` |
|----------|------------------|------------------|
| All tools pass | `0` | `0` |
| Warnings, `fail_on=error` | `0` | `0` |
| Warnings, `fail_on=warn` | `2` | `0` |
| Errors in findings | `2` | `0` |
| Runtime error during check | `1` | `0`* |
| Receipt write failure | `1` | `1` |

*In cockpit mode, runtime errors still write a receipt with error findings before exiting `0`.

---

## Environment Variables

### Configuration Variables

| Variable | Description |
|----------|-------------|
| `ENV_CHECK_DEBUG_LOG` | Path to debug log file. When set, enables debug logging and writes to the specified path. Equivalent to `--log_file` flag. CLI flag takes precedence if both are set. |

### CI Detection Variables

env-check automatically detects CI environments by reading these environment variables. These are **read-only** for metadata purposes and do not affect behavior:

#### GitHub Actions

| Variable | Purpose |
|----------|---------|
| `GITHUB_ACTIONS` | Detected as GitHub Actions when set |
| `GITHUB_JOB` | Job name (included in receipt metadata) |
| `GITHUB_RUN_ID` | Run ID (included in receipt metadata) |
| `GITHUB_WORKFLOW` | Workflow name (included in receipt metadata) |
| `GITHUB_REPOSITORY` | Repository (included in receipt metadata) |
| `GITHUB_REF` | Git reference (included in receipt metadata) |
| `GITHUB_SHA` | Commit SHA (included in receipt metadata) |
| `GITHUB_EVENT_PATH` | Path to event JSON file (parsed for PR metadata) |
| `GITHUB_BASE_REF` | Base branch for PRs |

#### GitLab CI

| Variable | Purpose |
|----------|---------|
| `GITLAB_CI` | Detected as GitLab CI when set |
| `CI_JOB_NAME` | Job name (included in receipt metadata) |
| `CI_JOB_ID` | Job ID (included in receipt metadata) |
| `CI_PIPELINE_NAME` | Pipeline name (included in receipt metadata) |
| `CI_PROJECT_PATH` | Project path (included in receipt metadata) |
| `CI_COMMIT_REF_NAME` | Branch name (included in receipt metadata) |
| `CI_COMMIT_SHA` | Commit SHA (included in receipt metadata) |

#### CircleCI

| Variable | Purpose |
|----------|---------|
| `CIRCLECI` | Detected as CircleCI when set |
| `CIRCLE_JOB` | Job name (included in receipt metadata) |
| `CIRCLE_BUILD_NUM` | Build number (included in receipt metadata) |
| `CIRCLE_WORKFLOW_ID` | Workflow ID (included in receipt metadata) |
| `CIRCLE_PROJECT_REPONAME` | Repository name (included in receipt metadata) |
| `CIRCLE_BRANCH` | Branch name (included in receipt metadata) |
| `CIRCLE_SHA1` | Commit SHA (included in receipt metadata) |

#### Azure Pipelines

| Variable | Purpose |
|----------|---------|
| `TF_BUILD` | Detected as Azure Pipelines when set |
| `SYSTEM_JOBDISPLAYNAME` | Job name (included in receipt metadata) |
| `BUILD_BUILDID` | Build ID (included in receipt metadata) |
| `BUILD_DEFINITIONNAME` | Pipeline name (included in receipt metadata) |
| `BUILD_REPOSITORY_NAME` | Repository name (included in receipt metadata) |
| `BUILD_SOURCEBRANCH` | Source branch (included in receipt metadata) |
| `BUILD_SOURCEVERSION` | Commit SHA (included in receipt metadata) |

#### Generic CI

| Variable | Purpose |
|----------|---------|
| `CI` | Fallback detection for any CI environment |

### Environment Variable Examples

```bash
# Enable debug logging via environment variable
ENV_CHECK_DEBUG_LOG=/tmp/debug.log env-check check

# Override with CLI flag (CLI takes precedence)
ENV_CHECK_DEBUG_LOG=/default/path.log env-check check --log_file /custom/path.log

# CI environment is automatically detected
# No configuration needed - metadata is captured when running in CI
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

See [contracts.md](contracts.md) for the complete schema specification.

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

### Debugging and Troubleshooting

```bash
# Enable verbose debug logging
env-check check --debug

# Custom debug log location
env-check check --log_file ./debug/env-check.log

# Explain a finding code seen in output
env-check explain env.missing_tool

# List all possible finding codes
env-check explain --list
```

---

## See Also

- [Configuration Reference](configuration.md) - Configuration file format
- [Finding Codes](finding-codes.md) - Complete list of finding codes
- [Architecture](architecture.md) - System architecture overview
- [Contracts](contracts.md) - Receipt schema specification
- [ADR-006: Profile-Based Severity Mapping](adr/ADR-006-profile-severity.md) - Profile design decisions
- [ADR-008: Exit Code Semantics](adr/ADR-008-exit-codes.md) - Exit code design decisions
- [CI Integration](ci-integration.md) - CI/CD integration guide
