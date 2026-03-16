# Troubleshooting Guide

This guide covers common issues and solutions when using env-check.

## Quick Diagnostics

Before diving into specific issues, run these diagnostic steps:

1. **Check env-check version**:
   ```bash
   env-check --version
   ```

2. **Run with debug logging**:
   ```bash
   env-check --debug
   ```

3. **Check the output artifacts**:
   ```bash
   cat artifacts/env-check/report.json
   cat artifacts/env-check/extras/raw.log
   ```

## Common Issues

### No Sources Found

**Symptom**: env-check exits with code 2 (skip) and reports "no sources found".

**Causes and Solutions**:

1. **No source files in the project**:
   - Create a `.tool-versions` file or other supported source file
   - See [parsers.md](parsers.md) for supported formats

2. **Running from wrong directory**:
   - Ensure you're running env-check from the project root
   - Use `cd` to navigate to the correct directory first

3. **Source files filtered out**:
   - Check your `env-check.toml` for `sources` filters
   - Check command-line `--sources` argument

4. **Parser disabled**:
   - Check `env-check.toml` for disabled parsers:
     ```toml
     [parsers]
     node = false  # This disables .node-version and .nvmrc parsing
     ```

### Tool Not Found

**Symptom**: Finding with code `tool.not_found` for a tool.

**Causes and Solutions**:

1. **Tool not installed**:
   - Install the tool using your preferred method (asdf, mise, brew, etc.)
   - Verify with `which <tool>` or `where <tool>` (Windows)

2. **Tool not in PATH**:
   - Add the tool to your PATH environment variable
   - Restart your shell or terminal after PATH changes

3. **Tool has different name**:
   - Some tools have different binary names (e.g., `nodejs` vs `node`)
   - Use the standard binary name in your source files

4. **CI environment issue**:
   - Ensure tools are installed in CI before running env-check
   - Use caching to speed up tool installation

### Version Mismatch

**Symptom**: Finding with code `version.mismatch` or `version.constraint_failed`.

**Causes and Solutions**:

1. **Wrong version installed**:
   - Check installed version: `<tool> --version`
   - Install the required version

2. **Version constraint too strict**:
   - Review the version constraint in your source file
   - Consider using looser constraints (e.g., `>=18.0.0` instead of `18.19.0`)

3. **Pre-release version issues**:
   - Pre-release versions (e.g., `18.0.0-beta.1`) may not match constraints
   - Use explicit pre-release constraints if needed

4. **Version parsing differences**:
   - Some tools output versions in non-standard formats
   - Check debug output to see how env-check parsed the version

### Version Parse Errors

**Symptom**: Finding with code `version.parse_error` or unexpected version comparisons.

**Common Causes**:

1. **Unsupported version format**:
   - env-check normalizes common CLI output formats
   - See [Version Parsing Fixture Matrix](parsers.md#version-parsing-fixture-matrix) for supported formats
   - If your tool outputs an unsupported format, report it as an issue

2. **Marketing labels instead of versions**:
   - Inputs like `latest`, `system`, `default` are not valid versions
   - These are intentionally rejected to prevent ambiguous comparisons
   - Use explicit version numbers in source files

3. **Ambiguous multi-version output**:
   - If a tool outputs multiple version numbers, env-check extracts the first
   - This may not always be the correct version
   - Check debug output to see what was extracted

**Supported Version Formats**:

| Category | Examples | Behavior |
|----------|----------|----------|
| Plain semver | `1.2.3`, `20.11.0` | Parsed as-is |
| v-prefixed | `v1.2.3`, `V20.11.0` | Prefix stripped |
| CLI output | `git version 2.43.0`, `Python 3.11.8` | Version extracted |
| Partial | `1`, `1.2` | Zero-filled to `1.0.0`, `1.2.0` |
| Prerelease | `1.2.3-rc.1`, `1.2.3-alpha.1` | Prerelease preserved |
| Build metadata | `1.2.3+build.5` | Build metadata preserved |

**Rejected Inputs**:

| Input | Reason |
|-------|--------|
| `latest` | Marketing label, not a version |
| `system` | Presence-only constraint |
| `*` | Wildcard constraint |
| `lts/*`, `node`, `stable` | Aliases, not versions |

**Debugging Version Parsing**:

```bash
# Run with debug to see parsed versions
env-check --debug 2>&1 | grep -i "version"

# Check the raw probe output in the report
cat artifacts/env-check/report.json | jq '.data.findings[] | select(.code == "version.parse_error")'
```

**Adding Support for New Formats**:

If you encounter a tool with an unsupported version format:

1. Check the [fixture matrix](parsers.md#version-parsing-fixture-matrix) to confirm it's not supported
2. Run with `--debug` to capture the raw output
3. Open an issue with:
   - Tool name and version
   - Raw output from `<tool> --version`
   - Expected parsed version

### Hash Verification Failed

**Symptom**: Finding with code `hash.mismatch` or `hash.error`.

**Causes and Solutions**:

1. **Binary changed or updated**:
   - The tool binary was updated since the hash was recorded
   - Update the hash in your manifest file

2. **Different binary source**:
   - Binary installed from different source (brew vs npm vs direct download)
   - Different sources may produce different binaries
   - Use consistent installation methods

3. **Platform differences**:
   - Hashes are platform-specific
   - Ensure your hash manifest matches your platform

4. **Corrupted binary**:
   - Reinstall the tool if the binary might be corrupted

### Parse Errors

**Symptom**: Finding with code `parse.error` or tool runtime error.

**Causes and Solutions**:

1. **Malformed source file**:
   - Check the syntax of your source file
   - Validate JSON with a linter for `package.json`
   - Validate TOML with a linter for `mise.toml` or `rust-toolchain.toml`

2. **Unsupported format**:
   - Some parsers only support specific formats
   - Check [parsers.md](parsers.md) for supported syntax

3. **Encoding issues**:
   - Ensure files use UTF-8 encoding
   - Check for BOM markers or invisible characters

4. **File permissions**:
   - Ensure env-check has read permissions for source files
   - Check file permissions with `ls -la` (Unix) or file properties (Windows)

### Permission Denied

**Symptom**: Error running probe commands or reading files.

**Causes and Solutions**:

1. **File read permissions**:
   - Check file permissions on source files
   - Run `chmod +r <file>` if needed (Unix)

2. **Tool execution permissions**:
   - Ensure tool binaries are executable
   - Run `chmod +x <tool>` if needed (Unix)

3. **CI permissions**:
   - In GitHub Actions, ensure the workflow has appropriate permissions
   - Check repository settings for Actions permissions

### Exit Code Issues

**Symptom**: Unexpected exit code from env-check.

**Exit Code Reference**:

| Code | Meaning | Common Causes |
|------|---------|---------------|
| 0 | Pass | All requirements satisfied |
| 1 | Fail | Requirements not met, or tool error |
| 2 | Skip | No sources found |

**Troubleshooting**:

1. **Exit code 1 with no findings**:
   - Check for tool runtime errors in debug output
   - Look for `tool.runtime_error` in the report

2. **Exit code 1 in CI but not locally**:
   - Check CI environment differences
   - Ensure tools are installed in CI
   - Check PATH configuration in CI

3. **Unexpected exit code 2**:
   - Verify source files exist
   - Check `--sources` filter

### Configuration Not Loading

**Symptom**: Configuration options not being applied.

**Causes and Solutions**:

1. **Wrong configuration file name**:
   - File must be named `env-check.toml` (not `.env-check.toml`)
   - Must be in the working directory

2. **Configuration syntax error**:
   - Validate TOML syntax
   - Check for typos in field names

3. **Command-line overrides**:
   - Command-line arguments override configuration file
   - Check for conflicting arguments

4. **Environment variable overrides**:
   - Environment variables override configuration file
   - Check for `ENV_CHECK_*` environment variables

### GitHub Actions Issues

**Symptom**: Problems when running in GitHub Actions.

**Causes and Solutions**:

1. **Action not found**:
   - Ensure you're using the correct action reference
   - Check the action version

2. **No PR comment created**:
   - PR comments require `pull-requests: write` permission
   - Ensure the workflow has appropriate permissions:
     ```yaml
     permissions:
       pull-requests: write
     ```

3. **Annotations not appearing**:
   - Annotations are only created for error/warning findings
   - Check the report for findings

4. **Wrong working directory**:
   - Use `working-directory` if your project is in a subdirectory:
     ```yaml
     - uses: your-org/env-check@v1
       with:
         working-directory: ./subdir
     ```

### Performance Issues

**Symptom**: env-check running slowly.

**See [performance.md](performance.md) for detailed performance troubleshooting.**

Quick checks:

1. **Many tools**: More tools = more probe commands
2. **Slow tool startup**: Some tools start slowly
3. **Network filesystem**: Use local storage for better performance
4. **Debug logging**: Disable debug logging in production

## Finding Codes Reference

Common finding codes and their meanings:

| Code | Severity | Description |
|------|----------|-------------|
| `tool.not_found` | Error/Warning | Tool binary not found in PATH |
| `tool.error` | Error | Error executing tool version command |
| `version.mismatch` | Error/Warning | Installed version doesn't match requirement |
| `version.constraint_failed` | Error/Warning | Version doesn't satisfy constraint |
| `version.parse_error` | Error | Could not parse version string |
| `hash.mismatch` | Error | Binary hash doesn't match expected |
| `hash.error` | Error | Error computing binary hash |
| `parse.error` | Error | Error parsing source file |
| `source.error` | Warning | Error reading source file |
| `tool.runtime_error` | Error | Internal tool error (one per run max) |

## Debugging Techniques

### Enable Debug Logging

```bash
env-check --debug
```

Debug output includes:
- Source discovery details
- Parsing results
- Probe command outputs
- Evaluation decisions
- Timing information

### Check Raw Output

```bash
# View the JSON report
cat artifacts/env-check/report.json | jq

# View debug log
cat artifacts/env-check/extras/raw.log
```

### Verbose Probe Output

To see exactly what probe commands are executed:

```bash
env-check --debug 2>&1 | grep -i probe
```

### Test Individual Parsers

Create a minimal test file and run env-check:

```bash
# Create test source
echo "node 20.0.0" > .tool-versions

# Run env-check
env-check --debug

# Clean up
rm .tool-versions
```

### Isolate the Problem

1. **Minimal reproduction**:
   - Create a new directory with minimal source files
   - Run env-check to see if the issue persists

2. **Check without configuration**:
   ```bash
   mv env-check.toml env-check.toml.bak
   env-check --debug
   mv env-check.toml.bak env-check.toml
   ```

3. **Test with single source**:
   ```bash
   env-check --sources tool-versions
   ```

## Getting Help

If you can't resolve an issue:

1. **Search existing issues**: Check the repository issues for similar problems

2. **Gather information**:
   - env-check version (`env-check --version`)
   - Operating system and version
   - Debug output (`env-check --debug`)
   - Contents of `artifacts/env-check/report.json`
   - Contents of relevant source files

3. **Create an issue**:
   - Use the issue template if available
   - Include all gathered information
   - Describe steps to reproduce

4. **Security issues**:
   - Do not open public issues for security vulnerabilities
   - See [SECURITY.md](../SECURITY.md) for responsible disclosure

## FAQ

### Q: Why does env-check exit with code 1 even when tools are installed?

A: Check for version mismatches or constraint failures. The exit code 1 indicates
requirements are not met, which includes version mismatches, not just missing tools.

### Q: Can I use env-check with asdf/mise/volta/etc.?

A: Yes! env-check reads source files created by these tools. It doesn't manage
installations, but it verifies the tools are available and meet requirements.

### Q: Why is my `.nvmrc` LTS alias not working?

A: env-check supports `lts/*` aliases but requires network access to resolve
them to specific versions. Since env-check is offline by default, use explicit
versions in CI environments.

### Q: How do I ignore a specific tool?

A: Remove it from your source files, or use `--sources` to filter which sources
are checked. There's currently no per-tool ignore feature.

### Q: Can env-check install missing tools?

A: No. env-check is a verification tool only. It reports what's missing but
doesn't modify your environment. Use asdf, mise, or your preferred tool manager
for installations.

### Q: Why is the report different between runs?

A: Reports should be deterministic for the same inputs. If you see differences:
- Check for changes in source files
- Check for changes in installed tools
- Check for environment variable differences
- Report a bug if the issue persists

---

For performance-related issues, see [performance.md](performance.md).
For security concerns, see [SECURITY.md](../SECURITY.md).
