//! Configuration parsing for env-check.
//!
//! The app layer imports this crate to keep configuration semantics stable and
//! independent from orchestration/probing logic.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{FailOn, Profile};
use serde::Deserialize;

/// Default probe timeout in seconds.
pub const DEFAULT_PROBE_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub fail_on: Option<FailOn>,
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub hash_manifests: Vec<String>,
    #[serde(default)]
    pub ignore_tools: Vec<String>,
    #[serde(default)]
    pub force_required: Vec<String>,
    /// Timeout in seconds for individual tool probing operations.
    /// Defaults to 30 seconds if not specified.
    #[serde(default)]
    pub probe_timeout_secs: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct SourcesConfig {
    #[serde(default)]
    pub enabled: Vec<String>,
    #[serde(default)]
    pub disabled: Vec<String>,
}

/// Load env-check configuration from a specific file or from `${root}/env-check.toml`.
///
/// If the config file does not exist (for default path lookup), this returns
/// `AppConfig::default()` and does not fail.
pub fn load_config(root: &Path, config_path: Option<&Path>) -> anyhow::Result<AppConfig> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            let candidate = root.join("env-check.toml");
            if candidate.exists() {
                candidate
            } else {
                return Ok(AppConfig::default());
            }
        }
    };

    let text =
        fs::read_to_string(&path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: AppConfig = toml::from_str(&text).with_context(|| "parse env-check.toml")?;
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn write_file(dir: &Path, rel: &str, text: &str) {
        let path = dir.join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create fixture dir");
        }
        fs::write(path, text).expect("write fixture file");
    }

    #[test]
    fn load_config_returns_default_when_missing() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path();

        let cfg = load_config(root, None).expect("load missing config");
        assert_eq!(cfg.profile, None);
        assert!(cfg.hash_manifests.is_empty());
        assert!(cfg.sources.enabled.is_empty());
        assert!(cfg.sources.disabled.is_empty());
    }

    #[test]
    fn load_config_reads_sources_filters_from_custom_path() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path();
        let cfg_path = root.join("env-check-custom.toml");

        write_file(
            root,
            "env-check-custom.toml",
            r#"
            [sources]
            enabled = ["node", "python"]
            disabled = ["go"]
"#,
        );
        let cfg = load_config(root, Some(&cfg_path)).expect("load config");

        assert_eq!(cfg.sources.enabled, vec!["node", "python"]);
        assert_eq!(cfg.sources.disabled, vec!["go"]);
    }

    #[test]
    fn load_config_rejects_invalid_toml() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path();
        write_file(root, "env-check.toml", "this is not toml = [");
        let err = load_config(root, None).unwrap_err();
        assert!(err.to_string().contains("parse env-check.toml"));
    }
}
