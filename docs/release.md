# Release and publishing

This workspace publishes all microcrates. Publish in dependency order:

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

Release binaries are produced via cargo-dist with configuration in `Cargo.toml` under
`[workspace.metadata.dist]`.

Current release targets:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-apple-darwin`

Installers: `shell` + `powershell` (`env-check-installer.sh` / `env-check-installer.ps1`).
Tag releases as `vX.Y.Z` and let the release workflow build and upload assets.

## Compatibility and versioning

Schema and finding codes are public APIs. Changes must follow semver:

- **Patch**: no schema or code changes.
- **Minor**: additive changes only under `data` or `finding.data`.
- **Major**: any breaking change to schema, codes, or their semantics.

Deprecation policy:

- Mark deprecated codes/fields in docs first.
- Keep them emitted for at least one minor release.
- Remove only in the next major release.
