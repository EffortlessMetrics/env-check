# env-check-sources

Discover and parse repository tool requirements from multiple configuration formats.

## Purpose

This crate handles all source file discovery and parsing, converting various configuration formats into normalized `Requirement` structs that the domain layer can evaluate.

## Supported Sources

| Source | File | Parser Function |
|--------|------|-----------------|
| asdf | `.tool-versions` | `parse_tool_versions()` / `parse_tool_versions_str()` |
| mise | `.mise.toml` | `parse_mise_toml()` / `parse_mise_toml_str()` |
| Rust | `rust-toolchain.toml` / `rust-toolchain` | `parse_rust_toolchain()` / `parse_rust_toolchain_str()` |
| Node.js | `.node-version` | `parse_node_version()` |
| nvm | `.nvmrc` | `parse_nvmrc()` |
| npm | `package.json` | `parse_package_json()` |
| Python | `.python-version` | `parse_python_version()` |
| Python | `pyproject.toml` | `parse_pyproject_toml()` |
| Go | `go.mod` | `parse_go_mod()` |
| Hashes | `scripts/tools.sha256` | `parse_hash_manifest()` / `parse_hash_manifest_str()` |

## Key Functions

- `parse_all(repo_root)`: Main entry point. Discovers and parses all supported sources under repo root. Returns `ParsedSources` with discovered sources, requirements, and any parse error findings.

## Module Structure

- `lib.rs`: Core discovery engine and parsers for `.tool-versions`, `.mise.toml`, `rust-toolchain.toml`, hash manifests
- `node.rs`: Node.js version sources (`.node-version`, `.nvmrc`, `package.json`)
- `python.rs`: Python version sources (`.python-version`, `pyproject.toml`)
- `go_mod.rs`: Go module support (`go.mod`)

## Working Agreements

- **New parser requires**: fixtures, fuzz target, proptest case
- Parsers must never panic on arbitrary input (fuzz-tested)
- All parsers have `_str` variants for testing without filesystem
- Parse errors emit findings with code `env.source_parse_error` rather than failing
- Discovery order must be deterministic (sorted paths)
- Each parser returns `Vec<Requirement>` with proper `SourceRef` provenance

## Testing

```bash
# Run unit tests
cargo test -p env-check-sources

# Run property tests
cargo test -p env-check-sources proptest

# Run fuzzing (requires nightly)
cargo fuzz run parse_tool_versions
cargo fuzz run fuzz_node_version
cargo fuzz run fuzz_nvmrc
cargo fuzz run fuzz_package_json
cargo fuzz run fuzz_python_version
cargo fuzz run fuzz_pyproject_toml
cargo fuzz run fuzz_go_mod
```

## Fixtures

Test fixtures live in `tests/fixtures/`:
- Each fixture directory contains sample source files
- Fixtures are used by both unit tests and fuzz seed corpora
- When adding a new source type, add representative fixtures

## Adding a New Source

1. Create parser function with both file and `_str` variants
2. Add `SourceKind` variant in `env-check-types`
3. Integrate into `parse_all()` discovery
4. Add fixtures in `tests/fixtures/`
5. Add fuzz target in `fuzz/fuzz_targets/`
6. Add proptest cases
7. Update root CLAUDE.md with new fuzz target
