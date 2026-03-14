# ADR-008: Exit Code Semantics

## Status

Accepted

## Context

Command-line tools communicate results through exit codes. Different tools use different conventions:

- Unix tradition: `0` = success, non-zero = failure
- Some tools use multiple non-zero codes for different failure modes
- CI systems interpret exit codes to determine pass/fail status
- Scripts may need to distinguish between "policy failed" and "tool broke"

env-check needs exit codes that:
- Work correctly in CI pipelines
- Allow scripts to distinguish between different outcomes
- Follow Unix conventions for compatibility
- Don't conflict with shell special values

## Decision

env-check uses a **three-tier exit code scheme**:

| Exit Code | Meaning | Condition |
|-----------|---------|-----------|
| `0` | OK | Pass or warn (unless `fail_on=warn`) |
| `1` | Tool/Runtime Error | Unexpected failure during execution |
| `2` | Policy Fail | Environment does not meet requirements |

### Exit Code 0: OK

The tool completed successfully and the environment is acceptable:
- All required tools present with correct versions
- Or warnings present but `fail_on` is not set to `warn`

### Exit Code 1: Tool/Runtime Error

Something went wrong with the tool itself:
- Unrecoverable I/O error
- Parse failure in configuration
- Probe execution failure (unexpected)
- Any condition that prevents completing the check

This indicates "env-check failed to run" not "environment failed check".

### Exit Code 2: Policy Fail

The tool completed successfully but the environment fails policy:
- Missing required tools (in `team`/`strict` profiles)
- Version mismatches (in `strict` profile)
- Hash mismatches (in `team`/`strict` profiles)
- Warnings when `fail_on=warn`

This indicates "environment does not meet requirements".

### What About 127 and Other Codes?

- `127` (command not found) is handled by the shell, not env-check
- `130` (SIGINT) and similar signal-derived codes are not used
- We avoid `>2` to keep the scheme simple

## Consequences

### Positive

- **CI integration**: Most CI systems treat non-zero as failure automatically
- **Scripting compatibility**: Scripts can distinguish "tool broke" from "policy failed"
- **Unix convention**: `0` = success follows standard practice
- **Clear signals**: Each code has unambiguous meaning

### Negative

- **Limited granularity**: Cannot distinguish between different failure types without parsing output
- **Not universally known**: Users may not be aware of the `1` vs `2` distinction

### Neutral

- This scheme is similar to `grep` (0=found, 1=not found, 2=error)
- The `fail_on` setting can promote warnings to exit code 2

## References

- [docs/requirements.md:127-134](../requirements.md) - Exit code specification
- [docs/architecture.md:97-102](../architecture.md) - Verdict semantics
- [POSIX Exit Codes](https://www.gnu.org/software/libc/manual/html_node/Exit-Status.html)
