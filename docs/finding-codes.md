# Finding Codes Reference

This document describes all finding codes that env-check can produce, their severity mappings by profile, and remediation guidance.

## Finding Code Registry

| Code | Check ID | Description |
|------|----------|-------------|
| `env.missing_tool` | `env.presence` | Tool not found on PATH |
| `env.version_mismatch` | `env.version` | Version constraint not satisfied |
| `env.hash_mismatch` | `env.hash` | File hash verification failed |
| `env.toolchain_missing` | `env.presence` | Rust toolchain not installed |
| `env.source_parse_error` | `env.source_parse` | Source file parsing failed |
| `tool.runtime_error` | `tool.runtime` | Probe execution failed |

## Severity Mappings by Profile

### Profile: oss (Default)

| Code | Required | Optional |
|------|----------|----------|
| `env.missing_tool` | Warn | Info |
| `env.version_mismatch` | Warn | Info |
| `env.hash_mismatch` | Warn | Info |
| `env.toolchain_missing` | Warn | Info |
| `env.source_parse_error` | Error | Error |
| `tool.runtime_error` | Warn | Warn |

### Profile: team

| Code | Required | Optional |
|------|----------|----------|
| `env.missing_tool` | Error | Warn |
| `env.version_mismatch` | Error | Warn |
| `env.hash_mismatch` | Error | Warn |
| `env.toolchain_missing` | Error | Warn |
| `env.source_parse_error` | Error | Error |
| `tool.runtime_error` | Error | Error |

### Profile: strict

| Code | Required | Optional |
|------|----------|----------|
| `env.missing_tool` | Error | Error |
| `env.version_mismatch` | Error | Error |
| `env.hash_mismatch` | Error | Error |
| `env.toolchain_missing` | Error | Error |
| `env.source_parse_error` | Error | Error |
| `tool.runtime_error` | Error | Error |

## Verdict Reasons

Findings map to verdict reasons:

| Finding Code | Verdict Reason |
|--------------|----------------|
| `env.missing_tool` | `missing_tool` |
| `env.version_mismatch` | `version_mismatch` |
| `env.hash_mismatch` | `hash_mismatch` |
| `env.toolchain_missing` | `toolchain_missing` |
| `env.source_parse_error` | `source_parse_error` |
| `tool.runtime_error` | `tool_error` |

## Detailed Finding Descriptions

### env.missing_tool

**Triggered when:** A required tool is not found on the system PATH.

**Example message:** "Tool 'node' not found on PATH"

**Remediation:**
1. Install the missing tool using your preferred method (asdf, mise, brew, etc.)
2. Ensure the tool is in your PATH
3. Re-run env-check to verify

### env.version_mismatch

**Triggered when:** A tool's version doesn't satisfy the constraint.

**Example messages:**
- "Tool 'node' version 18.0.0 does not satisfy constraint >=20.0.0"
- "Could not parse version from tool 'custom-tool'"

**Remediation:**
1. Check the required version in your source file
2. Upgrade or downgrade the tool to match
3. For version parse failures, ensure the tool's `--version` output is parseable

### env.hash_mismatch

**Triggered when:** A file's SHA256 hash doesn't match the expected value.

**Example message:** "File 'scripts/deploy.sh' hash abc123... does not match expected def456..."

**Remediation:**
1. Verify the file contents haven't been modified
2. Update the hash in your manifest if the change was intentional
3. Re-generate the hash using `sha256sum <file>`

### env.toolchain_missing

**Triggered when:** A Rust toolchain channel is not installed.

**Example message:** "Rust toolchain '1.75.0' not found"

**Remediation:**
1. Run `rustup toolchain install 1.75.0`
2. For channels: `rustup toolchain install stable`

### env.source_parse_error

**Triggered when:** A source file cannot be parsed.

**Example message:** "Failed to parse .tool-versions at line 5: invalid version format"

**Remediation:**
1. Check the file syntax against the format specification
2. Fix syntax errors
3. Re-run env-check

### tool.runtime_error

**Triggered when:** A probe command fails to execute.

**Example message:** "Failed to execute 'node --version': permission denied"

**Remediation:**
1. Check tool execution permissions
2. Verify the tool is properly installed
3. Run with `--debug` for more details

## Presence-Only Constraints

The following constraints skip version checking and only verify presence:

| Constraint | Behavior |
|------------|----------|
| `latest` | Only checks if tool exists |
| `system` | Only checks if tool exists |
| `*` | Only checks if tool exists |
| `default` | Only checks if tool exists |

## See Also

- [ADR-006: Profile-Based Severity Mapping](adr/ADR-006-profile-severity.md)
- [ADR-008: Exit Code Semantics](adr/ADR-008-exit-codes.md)
- [Parsers Reference](parsers.md)
