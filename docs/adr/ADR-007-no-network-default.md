# ADR-007: No Network Access by Default

## Status

Accepted

## Context

Environment checking tools might be tempted to fetch data from the network:
- Checking for tool updates
- Downloading latest version definitions
- Querying package registries for version information
- Fetching configuration from remote sources

However, network access introduces several concerns:

- **Security**: Network requests can leak information about the repository
- **Reproducibility**: Results depend on network state and external service availability
- **CI reliability**: Network failures cause spurious build failures
- **Speed**: Network latency is unpredictable
- **Air-gapped environments**: Some CI environments have no network access

## Decision

env-check operates **offline by default**. It does not make network requests.

### What This Means

- **No version lookups**: Tool versions come from local probes (`node --version`), not registries
- **No update checks**: The tool does not check for newer versions of itself
- **No remote config**: Configuration is read from local files only
- **No telemetry**: No usage data is sent anywhere

### Future Network Features

If network features are ever added, they will:
- Be opt-in via explicit flag (e.g., `--network`)
- Document exactly what data is sent/received
- Fail gracefully when network is unavailable
- Not affect core functionality when disabled

### Security Posture

env-check does execute external commands for probing. Constraints:
- Commands are fixed argv vectors (no shell parsing)
- Probes are allowlisted by tool name
- No "run arbitrary command from config" capability

## Consequences

### Positive

- **Security**: No data exfiltration risk
- **Reproducibility**: Same inputs always produce same outputs
- **CI reliability**: No network-dependent failures
- **Speed**: No network latency
- **Air-gapped compatible**: Works in restricted environments
- **Trust**: Users can verify the tool doesn't "phone home"

### Negative

- **Limited currency**: Cannot check if tools are "latest available"
- **Manual updates**: Users must update version knowledge manually
- **No remote config**: Cannot centralize configuration

### Neutral

- This aligns with the project's "machine truth" scope
- Network features could be added as optional extensions without breaking this guarantee

## References

- [docs/architecture.md:147-153](../architecture.md) - Security posture
- [docs/architecture.md:32-39](../architecture.md) - Hard boundaries (what env-check does not do)
- [AGENTS.md](../../AGENTS.md) - Scope limitations
