# env-check-config

Shared, stable configuration parsing for env-check.

- `AppConfig` and `SourcesConfig` mirror CLI/API config keys.
- `load_config()` loads `env-check.toml` from root when no explicit path is provided.
- `[sources] enabled` / `[sources] disabled` are parsed as parser allowlist/denylist inputs.
