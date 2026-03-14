# Configuration Reference

This document provides the normative reference for configuring env-check via `env-check.toml`. All documented fields reflect the actual implementation in `crates/env-check-config/src/lib.rs`.

## Configuration Sources and Precedence

env-check accepts configuration from multiple sources. The precedence order is:

| Priority | Source | Description |
|----------|--------|-------------|
| 1 (highest) | CLI flags | `--profile`, `--fail_on`, `--probe-timeout` |
| 2 | Config file | `env-check.toml` or path specified by `--config` |
| 3 (lowest) | Built-in defaults | Hardcoded defaults in the application |

### Precedence Rules

- **CLI flags always win**: If `--profile strict` is passed, it overrides `profile = "oss"` in the config file
- **Config file fills gaps**: If a CLI flag is not provided, the config file value is used
- **Defaults as fallback**: If neither CLI nor config specifies a value, built-in defaults apply

### Configuration File Location

| Priority | Location | Description |
|----------|----------|-------------|
| 1 | `--config <PATH>` | Explicit path via CLI flag |
| 2 | `<root>/env-check.toml` | Repository root directory |

The `<root>` directory defaults to the current working directory, or can be specified via `--root <PATH>`.

If no configuration file exists at the default location and none is specified via `--config`, env-check uses built-in defaults for all options.

---

## Configuration File Format

The configuration file uses TOML format with snake_case field names:

```toml
# env-check.toml
profile = "oss"
fail_on = "error"
probe_timeout_secs = 30

[sources]
enabled = ["node", "python"]
disabled = ["go"]

hash_manifests = ["scripts/tools.sha256"]
ignore_tools = ["java"]
force_required = ["rustc", "cargo"]
```

---

## Top-Level Options

### `profile`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Values** | `"oss"`, `"team"`, `"strict"` |
| **Required** | No |
| **Default** | `"oss"` |
| **CLI Flag** | `--profile` |
| **Config Field** | `AppConfig.profile` |

Determines the policy profile for severity mapping. Profiles control how findings are classified (error, warn, info).

| Profile | Missing Required Tool | Version Mismatch | Hash Mismatch |
|---------|----------------------|------------------|---------------|
| `oss` | warn | warn | warn |
| `team` | error | warn | error |
| `strict` | error | error | error |

**Semantics:**
- `oss`: Lenient profile for open-source projects. All issues produce warnings by default.
- `team`: Balanced profile for team projects. Missing tools and hash mismatches produce errors; version mismatches produce warnings.
- `strict`: Strictest profile for CI/CD pipelines. All issues produce errors.

**Example:**

```toml
profile = "team"
```

---

### `fail_on`

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Values** | `"error"`, `"warn"`, `"never"` |
| **Required** | No |
| **Default** | `"error"` |
| **CLI Flag** | `--fail_on` |
| **Config Field** | `AppConfig.fail_on` |

Controls the exit code behavior based on finding severities.

| Level | Exit Code Behavior |
|-------|-------------------|
| `error` | Exit with code `2` if any error-level findings exist |
| `warn` | Exit with code `2` if any warning or error findings exist |
| `never` | Always exit with code `0` (unless a runtime error occurs) |

**Semantics:**
- `error`: Only error-level findings trigger a failure exit code. Warnings are reported but don't fail the run.
- `warn`: Both warnings and errors trigger a failure exit code. Use for stricter CI gates.
- `never`: Never fail based on findings. Useful for reporting-only runs or during migration periods.

**Exit Code Summary:**

| Condition | `fail_on = "error"` | `fail_on = "warn"` | `fail_on = "never"` |
|-----------|---------------------|--------------------|---------------------|
| Errors present | Exit 2 | Exit 2 | Exit 0 |
| Warnings only | Exit 0 | Exit 2 | Exit 0 |
| Pass/Skip | Exit 0 | Exit 0 | Exit 0 |
| Runtime error | Exit 1 | Exit 1 | Exit 1 |

**Example:**

```toml
fail_on = "warn"
```

---

### `probe_timeout_secs`

| Property | Value |
|----------|-------|
| **Type** | `u64` (unsigned integer) |
| **Required** | No |
| **Default** | `30` |
| **CLI Flag** | `--probe-timeout` |
| **Config Field** | `AppConfig.probe_timeout_secs` |
| **Constant** | `DEFAULT_PROBE_TIMEOUT_SECS` in `env-check-config` |

Timeout in seconds for individual tool probing operations. Each invocation of a tool (e.g., `node --version`) must complete within this duration.

**Semantics:**
- Applies per-tool probe, not to the entire run
- If a tool probe times out, it is treated as a runtime error
- Increase for slow machines or network-mounted filesystems
- Decrease for faster feedback on unresponsive tools

**Example:**

```toml
probe_timeout_secs = 60
```

---

### `hash_manifests`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Required** | No |
| **Default** | `["scripts/tools.sha256"]` (if empty in config) |
| **CLI Flag** | None (config-only) |
| **Config Field** | `AppConfig.hash_manifests` |

Specifies paths to SHA256 hash manifest files for verifying tool integrity. Paths are relative to the repository root.

**Semantics:**
- If the config file specifies an empty array, the default `scripts/tools.sha256` is used
- Multiple manifests are supported; all are parsed and combined
- Files that don't exist are silently skipped
- Hash verification produces findings with severity determined by the profile

**Hash Manifest Format:**

```
# scripts/tools.sha256
a1b2c3d4e5f6...  scripts/mytool.sh
f6e5d4c3b2a1...  scripts/other-tool.sh
```

The format is compatible with `sha256sum` output: `<hex_hash>  <path>`.

**Example:**

```toml
hash_manifests = [
    "scripts/tools.sha256",
    "config/hashes.sha256"
]
```

---

### `ignore_tools`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Required** | No |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |
| **Config Field** | `AppConfig.ignore_tools` |

List of tool IDs to completely ignore during environment verification.

**Semantics:**
- Tools in this list are removed from requirements before probing
- Useful during migration periods or when certain tools are not relevant
- Tool IDs are normalized (e.g., `nodejs` → `node`, `golang` → `go`)
- Ignored tools produce no findings

**Example:**

```toml
ignore_tools = ["java", "dotnet", "ruby"]
```

---

### `force_required`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Required** | No |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |
| **Config Field** | `AppConfig.force_required` |

List of tool IDs to treat as required even if the source file marks them as optional.

**Semantics:**
- Overrides the `required` flag on requirements matching these tool IDs
- Useful for enforcing critical tool presence regardless of source configuration
- Tool IDs are normalized

**Example:**

```toml
force_required = ["rustc", "cargo", "node"]
```

---

## `[sources]` Section

The `[sources]` section controls which source file parsers are active. This is defined by the `SourcesConfig` struct.

```toml
[sources]
enabled = ["node", "python"]
disabled = ["go"]
```

### `sources.enabled`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Required** | No |
| **Default** | All available parsers |
| **CLI Flag** | None (config-only) |
| **Config Field** | `SourcesConfig.enabled` |

List of parser names to enable. If specified, only these parsers will be used. If empty or omitted, all available parsers are enabled (subject to `sources.disabled`).

**Supported Parser Names and Aliases:**

| Parser | Aliases | Source Files |
|--------|---------|--------------|
| `node` | `nodejs`, `node.js` | `.node-version`, `.nvmrc`, `package.json` |
| `python` | `py` | `.python-version`, `pyproject.toml` |
| `go` | `golang` | `go.mod` |

**Notes:**
- Parser names are case-insensitive
- Aliases are normalized to the canonical name
- Parsers may be unavailable if disabled at build time (feature flags)

**Example:**

```toml
[sources]
enabled = ["node", "python"]
```

---

### `sources.disabled`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Required** | No |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |
| **Config Field** | `SourcesConfig.disabled` |

List of parser names to disable. Useful for excluding specific source types without explicitly listing all enabled parsers.

**Semantics:**
- Applied after `enabled` logic
- A parser cannot appear in both `enabled` and `disabled` (error)
- Useful for excluding problematic parsers during migration

**Example:**

```toml
[sources]
disabled = ["go"]
```

---

## CLI Flag Precedence

When both CLI flags and configuration file options are present, CLI flags take precedence:

| Option | Config File | CLI Flag | Precedence |
|--------|-------------|----------|------------|
| Profile | `profile = "team"` | `--profile strict` | CLI flag wins |
| Fail-on | `fail_on = "warn"` | `--fail_on never` | CLI flag wins |
| Probe timeout | `probe_timeout_secs = 60` | `--probe-timeout 120` | CLI flag wins |
| Root directory | N/A | `--root ./path` | CLI only |
| Config file | N/A | `--config ./custom.toml` | CLI only |
| Output path | N/A | `--out report.json` | CLI only |
| Markdown output | N/A | `--md comment.md` | CLI only |
| Debug logging | N/A | `--debug` | CLI only |
| Parser filters | `sources.enabled` / `sources.disabled` | None | Config only |
| Hash manifests | `hash_manifests` | None | Config only |
| Ignore tools | `ignore_tools` | None | Config only |
| Force required | `force_required` | None | Config only |

### Precedence Example

Given this configuration file:

```toml
# env-check.toml
profile = "oss"
fail_on = "error"
probe_timeout_secs = 60
```

And this CLI command:

```bash
env-check check --profile strict
```

The effective settings will be:
- `profile`: `"strict"` (CLI flag overrides config)
- `fail_on`: `"error"` (from config, no CLI override)
- `probe_timeout_secs`: `60` (from config, no CLI override)

---

## Version Requirement Grammar

env-check supports multiple version constraint formats depending on the source file type. This section documents the grammar and semantics.

### Constraint Types

| Type | Sources | Semantics |
|------|---------|-----------|
| Exact | `.tool-versions`, `.mise.toml`, `.node-version`, `.nvmrc`, `.python-version`, `rust-toolchain.toml` | Version must match exactly |
| Minimum (>=) | `go.mod` | Version must be at or above the constraint |
| Semver Range | `package.json` | npm-style semver range |
| PEP 440 Range | `pyproject.toml` | Python PEP 440 specifier |

### Exact Match

The installed version must exactly match the constraint string after normalization.

**Examples:**
- `node 20.11.0` requires exactly `20.11.0`
- `python 3.12.0` requires exactly `3.12.0`

### Minimum Version (>=)

The installed version must be at or above the constraint. Used by `go.mod`.

**Examples:**
- `go 1.21` means `>=1.21.0`
- `go 1.21.5` means `>=1.21.5`

### Semver Range

Standard npm-style semver ranges are preserved and evaluated. Used by `package.json`.

**Examples:**
- `>=18.0.0 <20.0.0` - Between 18 and 20 (exclusive)
- `^18.0.0` - Compatible with 18.x.x
- `~18.0.0` - Approximately 18.0.x

### PEP 440 Range

Python PEP 440 constraints are preserved as-is. Used by `pyproject.toml`.

**Examples:**
- `>=3.8,<4.0` - Python 3.8 or higher, but less than 4.0
- `~=3.8.0` - Compatible with 3.8.x

### Version Normalization

| Input | Normalized |
|-------|------------|
| `20` | `20.0.0` |
| `20.11` | `20.11.0` |
| `v20.11.0` | `20.11.0` |
| `go1.21.5` | `1.21.5` |

### Tool ID Normalization

| Raw | Normalized |
|-----|------------|
| `nodejs` | `node` |
| `golang` | `go` |

### Presence-Only Constraints

The following constraints skip version checking and only verify presence:

- `latest`
- `system`
- `*`
- `default`

---

## Probe Timeout Semantics

The `probe_timeout_secs` option controls how long env-check waits for individual tool probes to complete.

### How It Works

1. **Per-probe timeout**: Each tool invocation (e.g., `node --version`, `go version`) has its own timeout
2. **Independent of total run**: The timeout applies to each probe, not the entire env-check run
3. **Timeout behavior**: If a probe exceeds the timeout, it's treated as a tool runtime error

### When to Adjust

**Increase the timeout if:**
- Running on slow CI runners
- Tools are on network-mounted filesystems
- Experiencing spurious timeout errors

**Decrease the timeout if:**
- You want faster feedback on hung tools
- Running on fast local machines

### Implementation Details

The timeout is implemented in `crates/env-check-probe/src/lib.rs` using the `Prober::with_timeout` constructor. The default value is defined as `DEFAULT_PROBE_TIMEOUT_SECS = 30` in `crates/env-check-config/src/lib.rs`.

---

## Output and CI Behavior

### Output Artifacts

env-check produces the following artifacts:

| Artifact | Path | Required | Description |
|----------|------|----------|-------------|
| Receipt | `artifacts/env-check/report.json` | Yes | JSON receipt with schema `sensor.report.v1` |
| Markdown | `artifacts/env-check/comment.md` | No | Human-readable summary (via `--md`) |
| Debug log | `artifacts/env-check/extras/raw.log` | No | Debug transcript (via `--debug`) |
| Annotations | `artifacts/env-check/extras/annotations.txt` | No | GitHub workflow annotations (via `--annotations`) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (pass, warn, or skip verdict) |
| 1 | Tool/runtime error (env-check itself failed) |
| 2 | Policy failure (verdict is fail based on `fail_on` setting) |

### Output Modes

The `--mode` flag (CLI only) controls exit code behavior:

| Mode | Description |
|------|-------------|
| `default` | Exit code reflects verdict per the table above |
| `cockpit` | Always exit 0 if receipt was written; orchestrator handles verdict |

---

## Configuration Validation

env-check validates the configuration file at startup. Common validation errors include:

### Invalid TOML Syntax

```
Error: parse env-check.toml: expected equals sign
```

**Solution**: Ensure valid TOML syntax. Use `#` for comments, quotes for strings.

### Invalid Profile Value

```
Error: unknown variant `invalid`, expected one of `oss`, `team`, `strict`
```

**Solution**: Use one of the valid profile values: `oss`, `team`, or `strict`.

### Invalid Fail-On Value

```
Error: unknown variant `invalid`, expected one of `error`, `warn`, `never`
```

**Solution**: Use one of the valid fail-on values: `error`, `warn`, or `never`.

### Parser Overlap

```
Error: parsers appear in both sources.enabled and sources.disabled: node
```

**Solution**: A parser cannot appear in both `enabled` and `disabled` lists. Remove it from one.

### Unknown Parser

```
Error: unsupported parser 'unknown'
```

**Solution**: Use a supported parser name: `node`, `python`, or `go` (or their aliases).

---

## Default Values Summary

| Option | Default Value | Source |
|--------|---------------|--------|
| `profile` | `"oss"` | CLI default |
| `fail_on` | `"error"` | CLI default |
| `probe_timeout_secs` | `30` | `DEFAULT_PROBE_TIMEOUT_SECS` |
| `hash_manifests` | `["scripts/tools.sha256"]` | App fallback if empty |
| `ignore_tools` | `[]` | `AppConfig::default()` |
| `force_required` | `[]` | `AppConfig::default()` |
| `sources.enabled` | All available parsers | `ParserFilters::all()` |
| `sources.disabled` | `[]` | `SourcesConfig::default()` |

---

## Example Configurations

### Minimal Configuration

The absolute minimum configuration (uses all defaults):

```toml
# env-check.toml - minimal
# All other options use built-in defaults
profile = "oss"
```

### Open Source Project (Default)

Minimal configuration suitable for open source projects with lenient requirements:

```toml
# env-check.toml
profile = "oss"
fail_on = "error"
```

### Team Project

Stricter configuration for team projects requiring critical tools:

```toml
# env-check.toml
profile = "team"
fail_on = "warn"

# Ensure these tools are always checked
force_required = ["node", "npm"]

# Ignore tools not used in this project
ignore_tools = ["go", "rust"]

# Hash manifests for verified binaries
hash_manifests = ["scripts/tools.sha256"]
```

### Strict CI/CD Pipeline

Maximum strictness for CI/CD pipelines:

```toml
# env-check.toml
profile = "strict"
fail_on = "warn"
probe_timeout_secs = 60

[sources]
# Only enable relevant parsers
enabled = ["node", "python"]

# All tools must be present
force_required = ["node", "npm", "python", "pip"]

# Verify binary integrity
hash_manifests = [
    "scripts/ci-tools.sha256",
    "scripts/validators.sha256"
]
```

### Legacy Project Migration

Configuration for projects migrating to env-check, ignoring problematic tools:

```toml
# env-check.toml
profile = "oss"
fail_on = "never"  # Don't fail during migration

# Ignore tools not yet properly configured
ignore_tools = ["java", "gradle", "maven"]

# Only check sources that are ready
[sources]
enabled = ["node"]
```

### Monorepo with Multiple Stacks

Configuration for monorepos with multiple technology stacks:

```toml
# env-check.toml
profile = "team"
fail_on = "error"

# Enable all parsers for polyglot repository
[sources]
disabled = []  # All parsers active

# Force required tools across all stacks
force_required = ["node", "python", "go"]

# Ignore tools not relevant to this monorepo
ignore_tools = ["ruby", "php"]
```

### Node.js Project

Focused configuration for Node.js projects:

```toml
# env-check.toml
profile = "team"
fail_on = "error"

[sources]
enabled = ["node"]

force_required = ["node", "npm"]
```

### Python Project

Focused configuration for Python projects:

```toml
# env-check.toml
profile = "team"
fail_on = "error"

[sources]
enabled = ["python"]

force_required = ["python", "pip"]
```

---

## See Also

- [CLI Reference](cli-reference.md) - Complete CLI command documentation
- [Parsers Reference](parsers.md) - Source file format details
- [Finding Codes](finding-codes.md) - Finding code explanations
- [ADR-006: Profile Severity](adr/ADR-006-profile-severity.md) - Profile design decisions
- [CI Integration](ci-integration.md) - GitHub Actions and CI/CD integration
