# Source Parsers Reference

This document describes all supported source file formats, their syntax, and how env-check interprets version constraints.

## Supported Source Types

| Source | File(s) | Tools | Constraint Type |
|--------|---------|-------|-----------------|
| asdf | `.tool-versions` | Any | Exact |
| mise | `.mise.toml` | Any | Exact |
| Node.js | `.node-version`, `.nvmrc` | node | Exact |
| Node.js | `package.json` | node, npm | Range (semver) |
| Python | `.python-version` | python | Exact |
| Python | `pyproject.toml` | python | Range (PEP 440) |
| Go | `go.mod` | go | Minimum (>=) |
| Rust | `rust-toolchain.toml` | rust | Exact/Channel |
| Hash | `*.sha256` | file:* | Exact |

## Constraint Semantics

### Exact Match
The installed version must exactly match the constraint string.
- Example: `node 20.11.0` requires exactly `20.11.0`

### Minimum (>=)
The installed version must be at or above the constraint.
- Example: `go 1.21` means `>=1.21.0`

### Range (semver)
Standard npm-style semver ranges are preserved and evaluated.
- Example: `>=18.0.0 <20.0.0`

### Range (PEP 440)
Python PEP 440 constraints are preserved as-is.
- Example: `>=3.8,<4.0`

## Format Details

### .tool-versions (asdf)

```
nodejs 20.11.0
python 3.12.0
go 1.21.5
```

**Notes:**
- Tool ID normalization: `nodejs` → `node`, `golang` → `go`
- Comments with `#` are supported
- Multiple versions can be specified (first is used)

### .mise.toml

```toml
[tools]
node = "20.11.0"
python = "3.12.0"
```

**Notes:**
- Supports string, integer, or array values
- Complex table shapes use `version` field

### .node-version / .nvmrc

```
20.11.0
lts/*
```

**Notes:**
- `v` prefix is stripped automatically
- LTS aliases (`lts/*`, `node`, `stable`) are preserved

### package.json

```json
{
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=9.0.0"
  },
  "packageManager": "pnpm@8.15.0+sha256.abc123"
}
```

**Notes:**
- `packageManager` hash suffix is stripped
- `packageManager` takes precedence over `engines.npm` for npm

### .python-version

```
3.12.0
pypy3.9-7.3.9
```

**Notes:**
- PyPy versions preserved verbatim
- No version coercion applied

### pyproject.toml

```toml
[project]
requires-python = ">=3.8,<4.0"
```

**Notes:**
- PEP 440 constraint syntax
- Complex constraints preserved as-is

### go.mod

```go
module example.com/myapp

go 1.21

toolchain go1.21.5
```

**Notes:**
- `go` directive specifies minimum version
- `toolchain` directive can override (stricter wins)
- `toolchain default` is ignored

### rust-toolchain.toml

```toml
[toolchain]
channel = "1.75.0"
```

**Notes:**
- Channel can be version, `stable`, `beta`, `nightly`
- Substring matching for installed toolchains

### Hash Manifests

```
abc123...  scripts/tool.sh
def456...  bin/myapp
```

**Notes:**
- sha256sum compatible format
- Only SHA256 supported
- Absolute paths rejected for security
- Tools prefixed with `file:`

## Version Normalization

env-check normalizes version strings from CLI output to enable consistent semver comparison.

### Normalization Pipeline

1. **Trim whitespace** - Remove leading/trailing whitespace
2. **Extract version token** - Parse version from common CLI output patterns
3. **Strip 'v' prefix** - Remove optional leading 'v' or 'V'
4. **Zero-fill missing components** - `1` → `1.0.0`, `1.2` → `1.2.0`
5. **Preserve prerelease/build metadata** - Keep `-rc.1`, `+build.5` suffixes

### Version Parsing Fixture Matrix

The following table defines the canonical version parsing behavior. These cases are
tested in `crates/env-check-domain/src/version_norm.rs` as part of the behavioral contract.
Regressions are detected when these mappings fail.

#### Plain Semver

| Input | Normalized | Description |
|-------|------------|-------------|
| `1.2.3` | `1.2.3` | Standard semver |
| `20.11.0` | `20.11.0` | Large major version |
| `0.0.0` | `0.0.0` | Zero versions |

#### Prefixed Semver (v-prefix)

| Input | Normalized | Description |
|-------|------------|-------------|
| `v1.2.3` | `1.2.3` | Lowercase v prefix |
| `V1.2.3` | `1.2.3` | Uppercase V prefix |
| `v20.11.0` | `20.11.0` | v-prefix with large version |

#### Text-Wrapped Versions (CLI Output)

| Input | Normalized | Description |
|-------|------------|-------------|
| `git version 2.43.0` | `2.43.0` | Git version output |
| `git version 2.43.0.windows.1` | `2.43.0` | Git with platform suffix |
| `Python 3.11.8` | `3.11.8` | Python version output |
| `Terraform v1.7.5` | `1.7.5` | Terraform with v-prefix |
| `go1.22.1` | `1.22.1` | Go version output |
| `node v20.11.0 (LTS)` | `20.11.0` | Node with LTS marker |

#### Partial Versions (Zero-Fill)

| Input | Normalized | Description |
|-------|------------|-------------|
| `1` | `1.0.0` | Major only |
| `1.2` | `1.2.0` | Major.minor only |
| `20` | `20.0.0` | Large major only |
| `0` | `0.0.0` | Zero major |

#### Prerelease Versions

| Input | Normalized | Description |
|-------|------------|-------------|
| `1.2.3-rc.1` | `1.2.3-rc.1` | RC prerelease |
| `1.2.3-alpha.1` | `1.2.3-alpha.1` | Alpha prerelease |
| `1.2.3-beta.2` | `1.2.3-beta.2` | Beta prerelease |
| `1-rc.1` | `1.0.0-rc.1` | Prerelease with zero-fill |

#### Build Metadata

| Input | Normalized | Description |
|-------|------------|-------------|
| `1.2.3+build.5` | `1.2.3+build.5` | Build metadata only |
| `1.2.3-rc.1+build.5` | `1.2.3-rc.1+build.5` | Prerelease + build |

#### Whitespace Handling

| Input | Normalized | Description |
|-------|------------|-------------|
| `  1.2.3` | `1.2.3` | Leading whitespace |
| `1.2.3  ` | `1.2.3` | Trailing whitespace |
| `  1.2.3  ` | `1.2.3` | Surrounding whitespace |

### Rejected Inputs

The following inputs are **not** valid version strings and will cause a parse error:

| Input | Error | Description |
|-------|-------|-------------|
| `` (empty) | `EmptyInput` | Empty string |
| `   ` | `EmptyInput` | Whitespace only |
| `latest` | `NoVersionFound` | Marketing label |
| `system` | `NoVersionFound` | Presence-only constraint |
| `*` | `NoVersionFound` | Wildcard constraint |
| `default` | `NoVersionFound` | Presence-only constraint |
| `lts/*` | `NoVersionFound` | LTS alias |
| `node` | `NoVersionFound` | Node alias |
| `stable` | `NoVersionFound` | Stable alias |

> **Note:** These rejected inputs are intentionally not parsed as versions. They represent
> special constraint types or aliases that require different handling in the source parsers.

### Comparison Semantics

Normalized versions are compared using standard semver rules:

- `>=20.0.0` matches `20.11.0`, `21.0.0`, etc.
- `^20.0.0` matches `20.x.y` but not `21.0.0`
- `~20.11.0` matches `20.11.z` but not `20.12.0`

## Tool ID Normalization

| Raw | Normalized |
|-----|------------|
| `nodejs` | `node` |
| `golang` | `go` |

## Presence-Only Constraints

The following constraints skip version checking:
- `latest`
- `system`
- `*`
- `default`

## See Also

- [ADR-003: Feature-Gated Parsers](adr/ADR-003-feature-gated-parsers.md)
- [Architecture](architecture.md)
