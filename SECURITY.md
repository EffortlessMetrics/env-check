# Security Policy

## Supported Versions

env-check is currently in active development. Security updates are provided for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in env-check, please report it responsibly.

### How to Report

**Preferred Method**: Open a private security advisory on GitHub

1. Navigate to the [Security Advisories](https://github.com/example/env-check/security/advisories) page
2. Click "Report a vulnerability"
3. Fill in the details of the vulnerability

**Alternative Method**: Email the maintainers directly if GitHub Security Advisories are not available.

### What to Include

Please include the following information in your report:

- **Description**: A clear description of the vulnerability
- **Impact**: What an attacker could achieve by exploiting this vulnerability
- **Reproduction**: Step-by-step instructions to reproduce the issue
- **Proof of Concept**: Code or commands that demonstrate the vulnerability (if applicable)
- **Suggested Fix**: If you have ideas for how to fix the issue (optional)
- **Affected Versions**: Which versions of env-check are affected

### Response Timeline

| Stage | Target Timeframe |
|-------|-----------------|
| Initial Response | Within 48 hours |
| Vulnerability Confirmation | Within 5 business days |
| Fix Development | Depends on severity and complexity |
| Security Advisory Published | After fix is released |

### Disclosure Policy

- We follow **coordinated disclosure**
- We will work with you to understand and fix the issue
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- Please do not disclose the vulnerability publicly until a fix is available

## Security Best Practices

When using env-check, follow these security best practices:

### 1. Verify Tool Integrity

env-check supports hash verification for tool binaries. Use this feature to ensure tools haven't been tampered with:

```toml
# env-check.toml
[hash]
manifest = ".hash-manifest"
```

Create a hash manifest with expected SHA256 checksums:
```
node:abc123def456...
npm:xyz789...
```

### 2. Review Source Files

Source files (`.tool-versions`, `.mise.toml`, etc.) can declare arbitrary tool requirements. Always review these files in projects you're checking:

```bash
# Review source files before running env-check
cat .tool-versions
cat .mise.toml
```

### 3. Secure CI/CD Integration

When using env-check in CI/CD pipelines:

- Use pinned versions of env-check (not `@latest`)
- Pin tool versions explicitly in your source files
- Review changes to source files in pull requests
- Use GitHub Actions' `hashFiles()` for caching integrity

```yaml
# Example: Pinning env-check version in GitHub Actions
- uses: example/env-check@v0.1.0  # Pinned version
  with:
    profile: team
```

### 4. Limit Network Exposure

env-check does not make network requests by default. This is a security feature:

- No telemetry is sent to external servers
- No automatic updates are performed
- Tool downloads are not handled by env-check

If you need tool installation, use dedicated tools like asdf, mise, or package managers.

### 5. Protect Output Artifacts

The output artifacts may contain information about your environment:

```bash
# Protect artifacts directory
chmod 700 artifacts/env-check/
```

In CI environments, ensure artifact access is appropriately restricted.

## Security Features

env-check includes several security-conscious design decisions:

### No Network Requests by Default

env-check operates entirely offline unless explicitly configured otherwise. This prevents:
- Data exfiltration through network channels
- Supply chain attacks from compromised servers
- Information leakage to third parties

See [ADR-007: No Network Default](docs/adr/ADR-007-no-network-default.md) for the full rationale.

### Deterministic Output

All output is deterministic for the same inputs:
- Findings are sorted consistently
- No timestamps or random values in output
- Reproducible results across runs

This prevents timing attacks and ensures verifiable results.

### Safe Parsing

All parsers are designed to handle malicious input safely:
- Fuzz testing for all parsers
- No arbitrary code execution from parsed files
- Memory-safe implementation in Rust

### Timeout Protection

All external commands have timeout protection:
- Default 30-second timeout for tool probing
- Prevents hanging on misbehaving tools
- Configurable timeout values

## Known Security Considerations

### Tool Execution

env-check executes external tools to probe versions. While the command list is restricted:

```bash
# Allowlisted commands only
node --version
npm --version
go version
python --version
python3 --version
rustc --version
```

**Consideration**: A compromised tool binary could potentially execute arbitrary code when invoked.

**Mitigation**: Use hash verification to ensure tool integrity.

### PATH Injection

env-check uses the system PATH to locate tools. A malicious entry in PATH could cause the wrong binary to be executed.

**Mitigation**: 
- Ensure your PATH is properly configured
- Use absolute paths in tool configurations where possible
- Review PATH in CI environments

### Symlink Attacks

Source files and tool binaries could be replaced by symlinks pointing to sensitive files.

**Mitigation**:
- env-check follows symlinks for source files
- Use hash verification for critical tools
- Run with appropriate file system permissions

## Security Architecture

For a detailed understanding of env-check's security architecture, see:

- [ADR-007: No Network Default](docs/adr/ADR-007-no-network-default.md) - Network isolation design
- [ADR-008: Exit Codes](docs/adr/ADR-008-exit-codes.md) - Exit code semantics for CI security
- [Architecture Documentation](docs/architecture.md) - Overall system design

## Security Updates

Security updates will be announced through:

1. GitHub Security Advisories
2. Release notes with `security` label
3. CHANGELOG.md entries marked with `[Security]`

Subscribe to repository notifications to receive security updates.

## Contact

For security-related questions (non-vulnerability reports):

- Open a GitHub Discussion with the `security` label
- Email maintainers for sensitive inquiries

---

Thank you for helping keep env-check and its users safe!
