# Release and publishing

This workspace publishes all microcrates. Publish in dependency order:

1. env-check-types
2. env-check-sources
3. env-check-probe
4. env-check-domain
5. env-check-render
6. env-check-app
7. env-check-cli

Release binaries are produced via cargo-dist with configuration in `Cargo.toml` under
`[workspace.metadata.dist]`.

Current release targets:
- `x86_64-unknown-linux-gnu`
- `x86_64-pc-windows-msvc`
- `aarch64-apple-darwin`

Installers: `shell` + `powershell` (`env-check-installer.sh` / `env-check-installer.ps1`).
Tag releases as `vX.Y.Z` and let the release workflow build and upload assets.
