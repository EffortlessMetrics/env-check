# env-check-cli

Clap-based CLI entry point for env-check.

## Purpose

This crate provides the command-line interface, parsing arguments and delegating to the app layer.

## Commands

### check (default)

Main command that runs the full pipeline.

```bash
env-check check [OPTIONS]
env-check [OPTIONS]  # 'check' is implicit
```

| Flag | Default | Description |
|------|---------|-------------|
| `--root <PATH>` | `.` | Repository root |
| `--config <PATH>` | - | Optional env-check.toml |
| `--profile <PROFILE>` | `oss` | Policy profile (oss/team/strict) |
| `--fail-on <LEVEL>` | `error` | Verdict escalation (error/warn/never) |
| `--out <PATH>` | `artifacts/env-check/report.json` | Receipt output path |
| `--md <PATH>` | - | Optional markdown output |
| `--annotations <PATH>` | - | Optional GitHub annotations output |
| `--annotations-max <N>` | `20` | Max findings in annotations output |
| `--debug` | false | Enable debug logging |
| `--log-file <PATH>` | `artifacts/env-check/extras/raw.log` | Debug log path |

Environment: `ENV_CHECK_DEBUG_LOG` overrides `--log-file`

### md

Render markdown from an existing report.

```bash
env-check md <REPORT> [--out <PATH>]
env-check md --report <REPORT> [--out <PATH>]
```

| Flag | Default | Description |
|------|---------|-------------|
| `REPORT` / `--report` | - | Path to report.json |
| `--out <PATH>` | `artifacts/env-check/comment.md` | Markdown output path |

### explain

Print details about a finding code or check ID.

```bash
env-check explain <CODE_OR_CHECK_ID>
env-check explain --list
```

Explain entries are sourced from the shared registry in `env-check-types`.

## Exit Codes

- `0`: Pass or Warn (unless fail_on=warn)
- `2`: Policy Fail
- `1`: Tool/runtime error (receipt still written when possible)

## Working Agreements

- CLI is thin; all logic in app layer
- Use clap derive macros for argument parsing
- Exit codes must be stable (CI depends on them)
- Error messages should be helpful and actionable
- `--debug` flag is for troubleshooting probe issues

## Testing

```bash
# Run CLI integration tests
cargo test -p env-check-cli

# Run BDD tests
cargo test -p env-check-cli --test bdd
```

## Integration Tests

Uses `assert_cmd` for CLI testing:
- Tests live in `tests/cli.rs`
- BDD tests in `tests/bdd.rs` use cucumber
- Test fixtures provide reproducible environments

## Adding a New Subcommand

1. Add subcommand enum variant in clap Args struct
2. Implement handler function
3. Add CLI integration tests
4. Update this README with usage
