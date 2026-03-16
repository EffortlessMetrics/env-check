# ADR-002: Hexagonal Ports/Adapters Architecture

## Status

Accepted

## Context

The env-check project needs to interact with the operating system to:
- Execute external commands (version probes like `node --version`, `python --version`)
- Resolve executables in PATH (which `node` is being used)
- Compute file hashes for binary verification
- Generate timestamps for receipts

These operations are inherently side-effectful and environment-dependent. This creates several testing challenges:

- **Non-deterministic tests**: Results depend on what's installed on the developer's machine
- **Hard to simulate failures**: Cannot easily test behavior when commands fail or return unexpected output
- **CI flakiness**: Tests may pass locally but fail in CI due to different tool versions
- **Slow tests**: Real command execution adds overhead
- **Untestable edge cases**: Cannot easily test malformed output or edge cases

## Decision

We adopt a **hexagonal (ports/adapters) architecture** for all I/O operations in `env-check-probe`. The core domain logic remains pure and depends only on abstractions (traits).

### Ports (Traits)

```rust
// In env-check-probe
trait CommandRunner {
    fn run(&self, argv: &[&str]) -> CommandResult;
}

trait PathResolver {
    fn resolve(&self, name: &str) -> Option<PathBuf>;
}

trait Hasher {
    fn hash(&self, path: &Path) -> Result<String>;
}

trait Clock {
    fn now(&self) -> DateTime<Utc>;
}
```

### Production Adapters

- `OsCommandRunner` - Uses `std::process::Command` for real command execution
- `OsPathResolver` - Uses the `which` crate for PATH resolution
- `Sha256Hasher` - Uses the `sha2` crate for hash computation
- `SystemClock` - Uses `chrono::Utc` for timestamps

### Test Adapters (Fakes)

- `FakeCommandRunner` - Pre-programmed outputs for deterministic testing
- `FakePathResolver` - Configurable PATH resolution results
- `FakeClock` - Fixed timestamps for reproducible receipts

## Consequences

### Positive

- **Pure domain logic**: The `env-check-domain` crate has zero OS dependencies
- **Deterministic testing**: All domain behavior can be tested with fakes
- **Easy failure simulation**: Fakes can be configured to return errors or malformed data
- **Fast tests**: No real command execution in unit tests
- **CI reliability**: Tests pass regardless of what tools are installed
- **Future extensibility**: New adapters can be added without changing domain code
  - Example: A Docker-based runner could implement `CommandRunner`
  - Example: A remote execution adapter for distributed probing

### Negative

- **Abstraction overhead**: Additional traits and structs to maintain
- **Indirection**: Debugging requires tracing through trait implementations
- **Adapter boilerplate**: Each new I/O operation needs both port and adapter(s)

### Neutral

- The composition root (`env-check-app`) is responsible for wiring real adapters
- Test code must construct fakes explicitly

## References

- [docs/design.md:104-130](../design.md) - Ports and adapters definition
- [crates/env-check-probe/src/lib.rs](../../crates/env-check-probe/src/lib.rs) - Port trait definitions
- [Hexagonal Architecture (Alistair Cockburn)](https://alistair.cockburn.us/hexagonal-architecture/)
