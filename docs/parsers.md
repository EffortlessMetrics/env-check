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

| Input | Normalized |
|-------|------------|
| `20` | `20.0.0` |
| `20.11` | `20.11.0` |
| `v20.11.0` | `20.11.0` |
| `go1.21.5` | `1.21.5` |

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
