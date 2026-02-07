# env-check-probe

Probe the local machine for tool presence, versions, and file hashes via injectable adapter traits.

## Purpose

This crate implements the "probe" side of the hexagonal architecture, executing actual system commands to determine what tools are installed and their versions. All I/O is abstracted behind traits for testability.

## Key Abstractions (Ports)

### CommandRunner
Executes commands and returns exit code + stdout/stderr.
- `OsCommandRunner`: Real OS implementation using `std::process::Command`

### PathResolver
Resolves tool names to paths on PATH.
- `OsPathResolver`: Uses `which` crate

### Hasher
Computes file hashes.
- `Sha256Hasher`: Real SHA256 implementation using `sha2` crate

## Main Struct

```rust
pub struct Prober<R, P, H> {
    runner: R,
    resolver: P,
    hasher: H,
}
```

### Methods

- `probe(&self, req: &Requirement) -> Observation`: Routes to appropriate probe method based on `ProbeKind`
- `probe_path_tool()`: Runs `<tool> --version` and extracts version with regex
- `probe_rustup_toolchain()`: Runs `rustup toolchain list` and checks for required channel
- `probe_file_hash()`: Computes SHA256 of repo-local file and compares to expected

## Decorators

- `LoggingCommandRunner<R, W>`: Wraps any `CommandRunner` to write debug logs
- Debug logs are side artifacts that don't affect the receipt

## Test Fakes

For testing without OS:
- `FakePathResolver`: Returns configured path mappings
- `FakeCommandRunner`: Returns configured command outputs
- `FakeHasher`: Returns configured hash values

## Version Extraction

Uses conservative semver-like regex: `(\d+)(?:\.(\d+))?(?:\.(\d+))?`

This extracts the first numeric version found in command output, handling various formats:
- `node v20.10.0` → `20.10.0`
- `Python 3.11.4` → `3.11.4`
- `rustc 1.75.0 (82e1608df 2023-12-21)` → `1.75.0`

## Working Agreements

- Probes use fixed argv vectors (no shell parsing)
- No "run arbitrary command from config" - security boundary
- All I/O goes through trait abstractions
- Fakes must be provided for all production adapters
- Probe errors should produce `Observation` with error info, not panic
- Version extraction is best-effort; unparseable output is still captured in transcript

## Testing

```bash
# Run unit tests (uses fakes, no real I/O)
cargo test -p env-check-probe

# Integration test with real probes requires tools installed
```

## Adding a New Probe Kind

1. Add `ProbeKind` variant in `env-check-types`
2. Add routing case in `Prober::probe()`
3. Implement `probe_<kind>()` method
4. Add fake behavior in test fakes
5. Add domain evaluation logic in `env-check-domain`
