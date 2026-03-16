# Release and publishing

## Publishing to crates.io

All 19 crates are published to crates.io in dependency order using the xtask publish command.

### Prerequisites

Set your crates.io token:

```bash
export CARGO_REGISTRY_TOKEN=<your-token>
# Or: cargo login
```

### Publish order (19 crates)

1. env-check-types
2. env-check-config
3. env-check-parser-flags
4. env-check-requirement-normalizer
5. env-check-runtime-metadata
6. env-check-sources-node
7. env-check-sources-python
8. env-check-sources-go
9. env-check-sources-hash
10. env-check-sources
11. env-check-probe
12. env-check-runtime
13. env-check-domain
14. env-check-evidence
15. env-check-reporting
16. env-check-render
17. env-check-app
18. env-check-cli
19. env-check (public facade)

### Using xtask publish

```bash
# Dry run — validates all crates can be packaged without uploading
cargo run -p xtask -- publish --dry-run

# Publish for real (65-second sleep between crates for crates.io indexing)
cargo run -p xtask -- publish
```

### Manual publish (single crate)

```bash
cargo publish -p env-check-types
# Wait ~65 seconds for crates.io to index before publishing dependents
cargo publish -p env-check-config
```

## Release binaries

Release binaries are produced via cargo-dist with configuration in `Cargo.toml` under
`[workspace.metadata.dist]`.

Current release targets:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-apple-darwin`

Installers: `shell` + `powershell` (`env-check-installer.sh` / `env-check-installer.ps1`).

## Release workflow

1. Ensure all tests pass: `cargo test --workspace && cargo test -p env-check-cli --test bdd`
2. Verify conformance: `cargo run -p xtask -- conform`
3. Dry-run publish: `cargo run -p xtask -- publish --dry-run`
4. Publish to crates.io: `cargo run -p xtask -- publish`
5. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`
6. The release workflow builds binaries and creates a GitHub release automatically.

## Compatibility and versioning

Schema and finding codes are public APIs. Changes must follow semver:

- **Patch**: no schema or code changes.
- **Minor**: additive changes only under `data` or `finding.data`.
- **Major**: any breaking change to schema, codes, or their semantics.

Deprecation policy:

- Mark deprecated codes/fields in docs first.
- Keep them emitted for at least one minor release.
- Remove only in the next major release.
