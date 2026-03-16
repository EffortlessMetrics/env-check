# env-check-config

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Shared, stable configuration parsing for env-check.

- `AppConfig` and `SourcesConfig` mirror CLI/API config keys.
- `load_config()` loads `env-check.toml` from root when no explicit path is provided.
- `[sources] enabled` / `[sources] disabled` are parsed as parser allowlist/denylist inputs.
