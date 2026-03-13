# Configuration Reference

This document provides a comprehensive reference for configuring env-check via `env-check.toml`.

## Configuration File Location

env-check looks for configuration in the following location:

| Priority | Location | Description |
|----------|----------|-------------|
| 1 | `--config <PATH>` | Explicit path via CLI flag |
| 2 | `<root>/env-check.toml` | Repository root directory |

The `<root>` directory defaults to the current working directory, or can be specified via `--root <PATH>`.

If no configuration file exists at the default location and none is specified via `--config`, env-check uses built-in defaults for all options.

## Configuration File Format

The configuration file uses TOML format:

```toml
# env-check.toml
profile = "oss"
fail_on = "error"

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
| **Default** | `"oss"` |
| **CLI Flag** | `--profile` |

Determines the policy profile for severity mapping. Profiles control how findings are classified (error, warn, info).

| Profile | Missing Required Tool | Version Mismatch | Hash Mismatch |
|---------|----------------------|------------------|---------------|
| `oss` | warn | warn | warn |
| `team` | error | warn | error |
| `strict` | error | error | error |

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
| **Default** | `"error"` |
| **CLI Flag** | `--fail_on` |

Controls the exit code behavior based on finding severities.

| Level | Behavior |
|-------|----------|
| `error` | Exit with code `2` if any error-level findings exist |
| `warn` | Exit with code `2` if any warning or error findings exist |
| `never` | Always exit with code `0` (unless a runtime error occurs) |

**Example:**

```toml
fail_on = "warn"
```

---

### `hash_manifests`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |

Specifies paths to SHA256 hash manifest files for verifying tool integrity. Paths are relative to the repository root.

**Example:**

```toml
hash_manifests = [
    "scripts/tools.sha256",
    "config/hashes.sha256"
]
```

**Hash Manifest Format:**

```
# scripts/tools.sha256
a1b2c3d4e5f6...  scripts/mytool.sh
f6e5d4c3b2a1...  scripts/other-tool.sh
```

---

### `ignore_tools`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |

List of tool IDs to completely ignore during environment verification. Useful during migration periods or when certain tools are not relevant to the check.

Tool IDs are normalized (e.g., `nodejs` → `node`, `golang` → `go`).

**Example:**

```toml
ignore_tools = ["java", "dotnet"]
```

---

### `force_required`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |

List of tool IDs to treat as required even if the source file marks them as optional. Useful for enforcing critical tool presence regardless of source configuration.

**Example:**

```toml
force_required = ["rustc", "cargo", "node"]
```

---

## `[sources]` Section

The `[sources]` section controls which source file parsers are active.

### `sources.enabled`

| Property | Value |
|----------|-------|
| **Type** | `array of strings` |
| **Default** | All available parsers |
| **CLI Flag** | None (config-only) |

List of parser names to enable. If specified, only these parsers will be used. If empty or omitted, all available parsers are enabled (subject to `sources.disabled`).

**Supported Parser Names:**

| Parser | Aliases | Source Files |
|--------|---------|--------------|
| `node` | `nodejs`, `node.js` | `.node-version`, `.nvmrc`, `package.json` |
| `python` | `py` | `.python-version`, `pyproject.toml` |
| `go` | `golang` | `go.mod` |

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
| **Default** | `[]` |
| **CLI Flag** | None (config-only) |

List of parser names to disable. Useful for excluding specific source types without explicitly listing all enabled parsers.

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
```

And this CLI command:

```bash
env-check check --profile strict
```

The effective settings will be:
- `profile`: `"strict"` (CLI flag overrides config)
- `fail_on`: `"error"` (from config, no CLI override)

---

## Example Configurations

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

## Configuration Validation

env-check validates the configuration file at startup. Common validation errors include:

### Invalid TOML Syntax

```
Error: parse env-check.toml: expected equals sign
```

Solution: Ensure valid TOML syntax. Use `#` for comments, quotes for strings.

### Invalid Profile Value

```
Error: unknown variant `invalid`, expected one of `oss`, `team`, `strict`
```

Solution: Use one of the valid profile values: `oss`, `team`, or `strict`.

### Invalid Fail-On Value

```
Error: unknown variant `invalid`, expected one of `error`, `warn`, `never`
```

Solution: Use one of the valid fail-on values: `error`, `warn`, or `never`.

### Parser Overlap

```
Error: parsers appear in both sources.enabled and sources.disabled: node
```

Solution: A parser cannot appear in both `enabled` and `disabled` lists. Remove it from one.

### Unknown Parser

```
Error: unsupported parser 'unknown'
```

Solution: Use a supported parser name: `node`, `python`, or `go` (or their aliases).

---

## Default Values Summary

| Option | Default Value |
|--------|---------------|
| `profile` | `"oss"` |
| `fail_on` | `"error"` |
| `hash_manifests` | `[]` |
| `ignore_tools` | `[]` |
| `force_required` | `[]` |
| `sources.enabled` | All available parsers |
| `sources.disabled` | `[]` |

---

## See Also

- [CLI Reference](cli-reference.md) - Complete CLI command documentation
- [Parsers Reference](parsers.md) - Source file format details
- [Finding Codes](finding-codes.md) - Finding code explanations
- [ADR-006: Profile Severity](adr/ADR-006-profile-severity.md) - Profile design decisions
