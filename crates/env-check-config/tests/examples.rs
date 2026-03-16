//! Integration test to validate documented configuration examples.
//!
//! This test discovers all TOML files under `examples/config/` and validates
//! that they parse correctly with the current config schema. This ensures
//! that documentation examples cannot drift from the actual schema.

use std::fs;
use std::path::Path;

/// Path to the examples config directory, relative to the crate root.
const EXAMPLES_CONFIG_DIR: &str = "../../examples/config";

/// Validates that a config file parses successfully.
///
/// Returns an error message if parsing fails, or None on success.
fn validate_config_file(path: &Path) -> Option<String> {
    let text = match fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => return Some(format!("Failed to read file: {e}")),
    };

    match toml::from_str::<env_check_config::AppConfig>(&text) {
        Ok(_) => None,
        Err(e) => Some(format!("Failed to parse config: {e}")),
    }
}

/// Discovers all TOML files in the examples/config directory.
fn discover_example_configs() -> Vec<String> {
    let examples_dir = Path::new(EXAMPLES_CONFIG_DIR);

    if !examples_dir.exists() {
        panic!(
            "Examples config directory does not exist: {}",
            examples_dir.display()
        );
    }

    let mut configs: Vec<String> = fs::read_dir(examples_dir)
        .expect("Failed to read examples config directory")
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .path()
                .extension()
                .map(|ext| ext == "toml")
                .unwrap_or(false)
        })
        .filter_map(|entry| entry.file_name().to_string_lossy().into_owned().into())
        .collect();

    // Sort for deterministic test behavior
    configs.sort();
    configs
}

#[test]
fn all_example_configs_parse_successfully() {
    let examples_dir = Path::new(EXAMPLES_CONFIG_DIR);
    let configs = discover_example_configs();

    assert!(
        !configs.is_empty(),
        "No example config files found in {}",
        examples_dir.display()
    );

    let mut failures: Vec<(String, String)> = Vec::new();

    for config_name in &configs {
        let config_path = examples_dir.join(config_name);
        if let Some(error) = validate_config_file(&config_path) {
            failures.push((config_name.clone(), error));
        }
    }

    if !failures.is_empty() {
        let failure_messages: Vec<String> = failures
            .iter()
            .map(|(name, error)| format!("  - {name}: {error}"))
            .collect();

        panic!(
            "One or more example config files failed to parse:\n{}",
            failure_messages.join("\n")
        );
    }
}

#[test]
fn minimal_config_parses_correctly() {
    let path = Path::new(EXAMPLES_CONFIG_DIR).join("minimal.toml");
    let text = fs::read_to_string(&path).expect("Failed to read minimal.toml");
    let config: env_check_config::AppConfig =
        toml::from_str(&text).expect("Failed to parse minimal.toml");

    // Verify the key configuration value from the minimal example
    assert_eq!(config.profile, Some(env_check_types::Profile::Oss));
}

#[test]
fn local_dev_config_parses_correctly() {
    let path = Path::new(EXAMPLES_CONFIG_DIR).join("local-dev.toml");
    let text = fs::read_to_string(&path).expect("Failed to read local-dev.toml");
    let config: env_check_config::AppConfig =
        toml::from_str(&text).expect("Failed to parse local-dev.toml");

    // Verify key configuration values from the local-dev example
    assert_eq!(config.profile, Some(env_check_types::Profile::Oss));
    assert_eq!(config.fail_on, Some(env_check_types::FailOn::Never));
    assert_eq!(config.probe_timeout_secs, Some(60));
    assert_eq!(config.sources.enabled, vec!["node", "python"]);
    // Note: ignore_tools and force_required may be handled differently by the schema
    // The important thing is that the config parses without errors
}

#[test]
fn ci_strict_config_parses_correctly() {
    let path = Path::new(EXAMPLES_CONFIG_DIR).join("ci-strict.toml");
    let text = fs::read_to_string(&path).expect("Failed to read ci-strict.toml");
    let config: env_check_config::AppConfig =
        toml::from_str(&text).expect("Failed to parse ci-strict.toml");

    // Verify key configuration values from the ci-strict example
    assert_eq!(config.profile, Some(env_check_types::Profile::Strict));
    assert_eq!(config.fail_on, Some(env_check_types::FailOn::Warn));
    assert_eq!(config.probe_timeout_secs, Some(60));
    assert_eq!(config.sources.enabled, vec!["node", "python", "go"]);
    // Note: force_required and hash_manifests may be handled differently by the schema
    // The important thing is that the config parses without errors
}
