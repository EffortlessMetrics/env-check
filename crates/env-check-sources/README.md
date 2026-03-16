# env-check-sources

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Deterministic source discovery and parsing for repo-declared tool requirements.

## What This Crate Does

- Discovers supported source files in a fixed order via `parse_all`.
- Parses source files into normalized `Requirement` entries.
- Emits parse findings (`env.source_parse_error`) instead of crashing on malformed input.
- Preserves source-specific structured data where needed (for receipt `data.source_data`).

## Supported Sources

- `.tool-versions`
- `.mise.toml`
- `rust-toolchain.toml` / `rust-toolchain`
- `.node-version`
- `.nvmrc`
- `package.json` (`engines`, `packageManager`)
- `.python-version`
- `pyproject.toml`
- `go.mod`
- Hash manifests (for file hash requirements)

## Public API Highlights

- `parse_all(root, hash_manifests) -> ParsedSources`
- `parse_all_with_filters(root, hash_manifests, &ParserFilters) -> ParsedSources`
- `parse_tool_versions(_str)`
- `parse_mise_toml(_str)`
- `parse_rust_toolchain(_str)`
- `parse_hash_manifest(_str)`
- Node/Python/Go parser modules and their `_str` helpers

## Parser filtering

- Parser-specific crates:
  `env-check-sources-node`, `env-check-sources-python`, `env-check-sources-go`, `env-check-sources-hash`.
- Node/Python/Go crates are optional and enabled with crate features
  (`parser-node`, `parser-python`, `parser-go`).
- Hash manifest parsing is always available via `env-check-sources-hash`.
- `ParserFilters` is derived from config with precedence:
  - `sources.enabled` explicit set (optional, defaults to all available parsers)
  - `sources.disabled` removes parsers from that set
- Use `parse_all_with_filters` when caller-supplied filters are available.

## Boundaries

- No probing of installed tools.
- No policy evaluation.
- Focused on deterministic parsing and normalized requirements.
