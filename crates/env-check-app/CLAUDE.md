# env-check-app

Composition root that wires all adapters and orchestrates the pipeline.

## Purpose

This crate is the application layer that connects all the pieces: sources, probes, domain logic, and rendering. It handles configuration loading, artifact writing, and CI environment detection.

## Key Functions

### Entry Points

```rust
pub fn run_check(
    repo_root: &Path,
    config_path: Option<&Path>,
    policy: &PolicyConfig,
    report_path: &Path,
) -> Result<(ReceiptEnvelope, Option<String>)>

pub fn run_check_with_options(
    repo_root: &Path,
    config_path: Option<&Path>,
    policy: &PolicyConfig,
    report_path: &Path,
    options: &CheckOptions,
) -> Result<(ReceiptEnvelope, Option<String>)>
```

### Pipeline Steps

1. `load_config()`: Read optional `env-check.toml`
2. `parse_all()`: Discover and parse source files
3. `normalize_requirements()`: Dedupe, filter ignores, apply force-required
4. `probe_requirements()`: Run probes (with optional debug logging)
5. `evaluate()`: Apply domain logic
6. `build_receipt()`: Construct receipt envelope with metadata
7. `write_atomic()`: Write JSON artifact
8. `render_markdown()`: Generate optional markdown

## Configuration (env-check.toml)

```toml
profile = "team"          # Override default profile
fail_on = "error"         # Override fail_on behavior
hash_manifest = "custom/path.sha256"

[tools]
ignore = ["optional-tool"]
force_required = ["critical-tool"]
```

## Environment Detection

- `detect_host()`: OS, arch, hostname
- `detect_ci()`: GitHub Actions, GitLab CI, CircleCI, Azure Pipelines
- `detect_git()`: Repo URL, branch, commit, PR number, merge-base
- `parse_github_event_json()`: Extract PR metadata from `$GITHUB_EVENT_PATH`

## Atomic Writes

Uses temp file + rename pattern to prevent partial artifacts in CI:
```rust
write_atomic(path, content)?; // Never leaves partial file
```

## Debug Logging

When `CheckOptions::debug_log_path` is set:
- Wraps `CommandRunner` with `LoggingCommandRunner`
- Writes all probe commands and outputs to log file
- Log is a side artifact; doesn't affect receipt

## Working Agreements

- This is the only crate that performs real I/O
- All other crates are pure/testable
- Atomic writes prevent CI artifact corruption
- Debug logs are optional side effects
- Config errors should produce helpful messages
- Deduplication uses (tool, probe_kind) as key

## Testing

```bash
# Run unit tests
cargo test -p env-check-app

# Tests focus on:
# - GitHub event JSON parsing
# - Config loading edge cases
# - Requirement normalization
# - Default behavior
```

## Adding a New CI Environment

1. Add detection logic in `detect_ci()`
2. Add environment variable mappings
3. Add tests for the new CI environment
4. Update documentation
