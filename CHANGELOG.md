# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Documentation for performance benchmarks (`docs/performance.md`)
- Troubleshooting guide (`docs/troubleshooting.md`)
- Security policy (`SECURITY.md`)
- Code of Conduct (`CODE_OF_CONDUCT.md`)

## [0.2.0] - 2026-03-13

### Added

#### Shell Completions

- Bash shell completion support with automatic installation
- Zsh shell completion support with automatic installation
- Fish shell completion support with automatic installation
- PowerShell completion support for Windows users
- `env-check completions <shell>` command to generate completion scripts
- Completion files distributed with release assets

#### Probe Timeout Support

- `--probe-timeout` CLI flag for configurable probe command timeouts
- Default 30-second timeout for all probe commands
- Per-tool timeout configuration in `env-check.toml`
- Timeout error handling with graceful degradation

#### CI Integration Guidance

- Expanded `docs/ci-integration.md` with multi-provider examples:
  - GitHub Actions (complete workflow examples)
  - GitLab CI (pipeline configuration)
  - CircleCI (job configuration)
  - Azure Pipelines (task configuration)
- Best practices for CI environment setup
- Artifact handling across different CI providers

#### Configuration Documentation

- Complete configuration reference in `docs/configuration.md`
- Example configurations for common use cases:
  - `examples/config/ci-strict.toml` - Strict CI profile
  - `examples/config/local-dev.toml` - Local development profile
  - `examples/config/minimal.toml` - Minimal configuration
- All configuration options documented with examples

#### Version Parsing Hardening

- Version normalization improvements for edge cases
- Additional test fixtures for non-standard version formats
- Parser robustness improvements for:
  - Windows tools with non-standard `--version` output
  - Legacy tool versions with unusual formatting
  - Tools with version prefixes/suffixes
- Expanded fuzz corpus for version parsing

### Changed

- Improved error messages for common failure modes
- Better path handling on Windows platforms

### Fixed

- Version parsing edge cases for tools with non-standard output
- Path normalization issues on Windows

## [0.1.0] - 2026-03-13

### Added

#### Core Functionality

- Initial release of env-check machine-truth sensor
- Source discovery and parsing for multiple formats:
  - `.tool-versions` (asdf format) - parses tool name and version pairs
  - `.mise.toml` (mise format) - parses tools section with version specifications
  - `.node-version` - parses Node.js version requirements
  - `.nvmrc` - parses nvm configuration with LTS alias support
  - `package.json` engines field - parses Node.js and npm version constraints
  - `.python-version` - parses pyenv-style Python version requirements
  - `pyproject.toml` requires-python - parses Python version constraints
  - `go.mod` toolchain directive - parses Go toolchain version
  - `rust-toolchain.toml` - parses Rust channel and components
  - Hash manifests (SHA256 checksums) - verifies tool binary integrity

#### Runtime Probing

- Tool presence detection via `which`/`where` lookups
- Version probing via allowlisted commands:
  - `node --version`
  - `npm --version`
  - `go version`
  - `python --version` / `python3 --version`
  - `rustc --version`
  - Custom tool version commands
- Hash verification for tool binaries (SHA256)
- Timeout protection for all probe commands (30-second default)

#### Domain Evaluation

- Semver constraint matching engine
- Version comparison operators: `=`, `>`, `>=`, `<`, `<=`, `~`, `^`
- Pre-release version handling
- Version range parsing (e.g., `>=1.0.0 <2.0.0`)
- Profile-based severity mapping:
  - `oss` profile: missing tools are warnings
  - `team` profile: missing tools are errors
  - `strict` profile: all findings are errors
- `fail-on` configuration for granular control

#### CLI Interface

- `env-check` command with comprehensive options:
  - `--profile <PROFILE>`: select evaluation profile
  - `--fail-on <LEVEL>`: set failure threshold
  - `--sources <SOURCES>`: filter which sources to check
  - `--output <PATH>`: specify output directory
  - `--format <FORMAT>`: output format (json, markdown)
  - `--debug`: enable debug logging
  - `--quiet`: suppress non-essential output
  - `--help`: display help information
  - `--version`: display version information

#### Output Formats

- JSON receipt to `artifacts/env-check/report.json`:
  - Schema version `sensor.report.v1`
  - Deterministic ordering of findings
  - CI metadata inclusion (GitHub Actions support)
  - Tool error handling with graceful degradation
- Markdown summary to `artifacts/env-check/comment.md`:
  - Human-readable findings table
  - Severity-based formatting
  - Truncation for large finding sets
- GitHub Actions annotations:
  - Error-level findings as error annotations
  - Warning-level findings as warning annotations
- Debug logs to `artifacts/env-check/extras/raw.log`

#### GitHub Actions Integration

- `action.yml` for GitHub Actions workflow integration
- Automatic detection of GitHub Actions environment
- PR comment generation with markdown summary
- Job summary support
- Exit code semantics:
  - `0`: pass (all requirements satisfied)
  - `1`: fail (requirements not met or tool error)
  - `2`: skip (no sources found)

#### Architecture

- Microcrate architecture with 15+ crates:
  - `env-check-types`: core types and finding codes
  - `env-check-config`: configuration parsing
  - `env-check-sources`: source discovery and parsing
  - `env-check-sources-go`: Go-specific parsers
  - `env-check-sources-node`: Node.js-specific parsers
  - `env-check-sources-python`: Python-specific parsers
  - `env-check-probe`: runtime probing
  - `env-check-domain`: evaluation engine
  - `env-check-evidence`: evidence collection
  - `env-check-render`: output rendering
  - `env-check-app`: application orchestration
  - `env-check-cli`: command-line interface
- Hexagonal architecture with ports and adapters
- Feature-gated parsers for minimal builds

#### Testing

- BDD test suite with 551 lines of scenarios (`features/env_check.feature`)
- Integration tests for CLI end-to-end behavior
- Unit tests for parsing, evaluation, and rendering
- Property-based testing with proptest:
  - Version parsing properties
  - Whitespace handling properties
  - Path normalization properties
- Fuzz testing for all parsers:
  - `fuzz_go_mod`
  - `fuzz_node_version`
  - `fuzz_nvmrc`
  - `fuzz_package_json`
  - `fuzz_pyproject_toml`
  - `fuzz_python_version`
  - `parse_hash_manifest`
  - `parse_mise_toml`
  - `parse_rust_toolchain`
  - `parse_tool_versions`
- Snapshot testing for output rendering

#### Documentation

- Architecture documentation (`docs/architecture.md`)
- CI integration guide (`docs/ci-integration.md`)
- CLI reference (`docs/cli-reference.md`)
- Configuration guide (`docs/configuration.md`)
- Contracts specification (`docs/contracts.md`)
- Design document (`docs/design.md`)
- Finding codes reference (`docs/finding-codes.md`)
- Implementation plan (`docs/implementation-plan.md`)
- Parser documentation (`docs/parsers.md`)
- Release guide (`docs/release.md`)
- Requirements specification (`docs/requirements.md`)
- Signals documentation (`docs/signals.md`)
- Testing guide (`docs/testing.md`)
- Architecture Decision Records (ADRs):
  - ADR-001: Microcrate Architecture
  - ADR-002: Hexagonal Architecture
  - ADR-003: Feature-Gated Parsers
  - ADR-004: Receipt Schema
  - ADR-005: Determinism
  - ADR-006: Profile Severity
  - ADR-007: No Network Default
  - ADR-008: Exit Codes
  - ADR-009: Testing Strategy
  - ADR-010: Dependencies
  - ADR-011: Parser Output Contract
  - ADR-012: Tool ID Normalization

#### Configuration

- `env-check.toml` configuration file support:
  - Profile selection
  - Fail-on threshold
  - Sources filter
  - Parser enable/disable flags
  - Debug logging control
- Environment variable overrides:
  - `ENV_CHECK_PROFILE`
  - `ENV_CHECK_FAIL_ON`
  - `ENV_CHECK_SOURCES`
  - `ENV_CHECK_OUTPUT`
  - `ENV_CHECK_DEBUG`

### Changed

- N/A (initial release)

### Deprecated

- N/A (initial release)

### Removed

- N/A (initial release)

### Fixed

- N/A (initial release)

### Security

- **No network access by default** (offline-first design):
  - No HTTP requests during normal operation
  - No telemetry or analytics
  - All operations are local
- **Allowlisted probe commands only**:
  - Only predefined version commands can be executed
  - No arbitrary command execution
  - No shell interpolation
- **Fuzz-tested parsers**:
  - All parsers handle malformed input gracefully
  - No panics on arbitrary input
  - Memory-safe parsing
- **Path traversal protection**:
  - File paths are normalized
  - Directory traversal attempts are blocked
- **Timeout protection**:
  - All probe commands have timeouts
  - No indefinite hangs on broken tools

---

## Release Notes Template

For future releases, use this template:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing features

### Deprecated
- Features to be removed in future releases

### Removed
- Features removed in this release

### Fixed
- Bug fixes

### Security
- Security improvements
```

---

## Version History Summary

| Version | Date       | Highlights                                                    |
| ------- | ---------- | ------------------------------------------------------------- |
| 0.2.0   | 2026-03-13 | Shell completions, probe timeout, expanded CI docs, config ref |
| 0.1.0   | 2026-03-13 | Initial release with core functionality                       |
