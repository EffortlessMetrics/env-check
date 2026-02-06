//! Node.js source file parsers.
//!
//! Supports:
//! - `.node-version` - Simple version file
//! - `.nvmrc` - NVM configuration file
//! - `package.json` - engines.node and packageManager fields

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

use crate::rel;

/// Parse a `.node-version` file.
///
/// Format: A single version string, optionally prefixed with 'v'.
/// Blank lines and comments (lines starting with #) are ignored.
pub fn parse_node_version(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read .node-version")?;
    parse_node_version_str(root, path, &text)
}

/// Parse `.node-version` content from a string.
pub fn parse_node_version_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let version = extract_version_line(text);

    match version {
        Some(v) => Ok(vec![Requirement {
            tool: "node".to_string(),
            constraint: Some(normalize_node_version(&v)),
            required: true,
            source: SourceRef {
                kind: SourceKind::NodeVersion,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }]),
        None => Ok(vec![]), // Empty or comments-only file
    }
}

/// Parse a `.nvmrc` file.
///
/// Format: Same as `.node-version` - a single version string.
/// Also supports aliases like `lts/*`, `node`, `stable`.
pub fn parse_nvmrc(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read .nvmrc")?;
    parse_nvmrc_str(root, path, &text)
}

/// Parse `.nvmrc` content from a string.
pub fn parse_nvmrc_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
    let version = extract_version_line(text);

    match version {
        Some(v) => Ok(vec![Requirement {
            tool: "node".to_string(),
            constraint: Some(normalize_node_version(&v)),
            required: true,
            source: SourceRef {
                kind: SourceKind::Nvmrc,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }]),
        None => Ok(vec![]), // Empty or comments-only file
    }
}

/// Parse a `package.json` file.
///
/// Extracts:
/// - `engines.node` - Node.js version constraint
/// - `packageManager` - Package manager with version (e.g., "pnpm@8.15.0")
pub fn parse_package_json(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read package.json")?;
    parse_package_json_str(root, path, &text)
}

/// Parse `package.json` content from a string.
pub fn parse_package_json_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let value: serde_json::Value =
        serde_json::from_str(text).with_context(|| "parse package.json")?;

    let mut reqs = vec![];

    // Extract engines.node
    if let Some(engines) = value.get("engines")
        && let Some(node_constraint) = engines.get("node").and_then(|v| v.as_str()) {
            reqs.push(Requirement {
                tool: "node".to_string(),
                constraint: Some(node_constraint.to_string()),
                required: true,
                source: SourceRef {
                    kind: SourceKind::PackageJson,
                    path: rel(root, path),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            });
        }

    // Extract packageManager (e.g., "pnpm@8.15.0")
    if let Some(pm) = value.get("packageManager").and_then(|v| v.as_str())
        && let Some((tool, version)) = parse_package_manager(pm) {
            reqs.push(Requirement {
                tool,
                constraint: Some(version),
                required: true,
                source: SourceRef {
                    kind: SourceKind::PackageJson,
                    path: rel(root, path),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            });
        }

    Ok(reqs)
}

/// Extract the first non-empty, non-comment line from text.
fn extract_version_line(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        return Some(trimmed.to_string());
    }
    None
}

/// Normalize a Node.js version string.
/// Removes leading 'v' prefix if present.
fn normalize_node_version(version: &str) -> String {
    version.strip_prefix('v').unwrap_or(version).to_string()
}

/// Parse a packageManager field value.
/// Format: "name@version" or "name@version+sha..."
/// Returns (tool_name, version) if valid.
fn parse_package_manager(pm: &str) -> Option<(String, String)> {
    let pm = pm.trim();
    if pm.is_empty() {
        return None;
    }

    // Split on @ to get name and version
    let parts: Vec<&str> = pm.splitn(2, '@').collect();
    if parts.len() != 2 {
        return None;
    }

    let tool = parts[0].trim();
    let version_part = parts[1].trim();

    if tool.is_empty() || version_part.is_empty() {
        return None;
    }

    // Handle version with hash suffix (e.g., "8.15.0+sha256.abc123...")
    // We only want the version part before the +
    let version = version_part.split('+').next().unwrap_or(version_part);

    Some((tool.to_string(), version.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // .node-version tests
    // =========================================================================

    #[test]
    fn node_version_basic() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20.11.0").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "node");
        assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
    }

    #[test]
    fn node_version_with_v_prefix() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "v20.11.0").unwrap();
        assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
    }

    #[test]
    fn node_version_with_whitespace() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "  20.11.0  \n").unwrap();
        assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
    }

    #[test]
    fn node_version_with_comments() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "# comment\n20.11.0\n").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
    }

    #[test]
    fn node_version_empty() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn node_version_comments_only() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "# just a comment\n# another").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn node_version_sets_correct_source_kind() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20.0.0").unwrap();
        assert_eq!(reqs[0].source.kind, SourceKind::NodeVersion);
    }

    #[test]
    fn node_version_sets_path_tool_probe_kind() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20.0.0").unwrap();
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
    }

    #[test]
    fn node_version_marked_as_required() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20.0.0").unwrap();
        assert!(reqs[0].required);
    }

    #[test]
    fn node_version_relative_path_stored() {
        let root = Path::new("/fake/project");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20.0.0").unwrap();
        assert_eq!(reqs[0].source.path, ".node-version");
    }

    #[test]
    fn node_version_lts_alias() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "lts/*").unwrap();
        assert_eq!(reqs[0].constraint, Some("lts/*".to_string()));
    }

    #[test]
    fn node_version_major_only() {
        let root = Path::new("/fake");
        let path = root.join(".node-version");
        let reqs = parse_node_version_str(root, &path, "20").unwrap();
        assert_eq!(reqs[0].constraint, Some("20".to_string()));
    }

    // =========================================================================
    // .nvmrc tests
    // =========================================================================

    #[test]
    fn nvmrc_basic() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "18.19.0").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "node");
        assert_eq!(reqs[0].constraint, Some("18.19.0".to_string()));
    }

    #[test]
    fn nvmrc_with_v_prefix() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "v18.19.0").unwrap();
        assert_eq!(reqs[0].constraint, Some("18.19.0".to_string()));
    }

    #[test]
    fn nvmrc_lts_alias() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "lts/*").unwrap();
        assert_eq!(reqs[0].constraint, Some("lts/*".to_string()));
    }

    #[test]
    fn nvmrc_node_alias() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "node").unwrap();
        assert_eq!(reqs[0].constraint, Some("node".to_string()));
    }

    #[test]
    fn nvmrc_stable_alias() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "stable").unwrap();
        assert_eq!(reqs[0].constraint, Some("stable".to_string()));
    }

    #[test]
    fn nvmrc_with_whitespace() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "  18.19.0  \n").unwrap();
        assert_eq!(reqs[0].constraint, Some("18.19.0".to_string()));
    }

    #[test]
    fn nvmrc_with_comments() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "# Use LTS\n18.19.0").unwrap();
        assert_eq!(reqs[0].constraint, Some("18.19.0".to_string()));
    }

    #[test]
    fn nvmrc_empty() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn nvmrc_sets_correct_source_kind() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "20.0.0").unwrap();
        assert_eq!(reqs[0].source.kind, SourceKind::Nvmrc);
    }

    #[test]
    fn nvmrc_sets_path_tool_probe_kind() {
        let root = Path::new("/fake");
        let path = root.join(".nvmrc");
        let reqs = parse_nvmrc_str(root, &path, "20.0.0").unwrap();
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
    }

    // =========================================================================
    // package.json tests
    // =========================================================================

    #[test]
    fn package_json_engines_node() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=18.0.0"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "node");
        assert_eq!(reqs[0].constraint, Some(">=18.0.0".to_string()));
    }

    #[test]
    fn package_json_package_manager_pnpm() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "pnpm@8.15.0"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "pnpm");
        assert_eq!(reqs[0].constraint, Some("8.15.0".to_string()));
    }

    #[test]
    fn package_json_package_manager_npm() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "npm@10.2.3"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "npm");
        assert_eq!(reqs[0].constraint, Some("10.2.3".to_string()));
    }

    #[test]
    fn package_json_package_manager_yarn() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "yarn@4.0.0"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "yarn");
        assert_eq!(reqs[0].constraint, Some("4.0.0".to_string()));
    }

    #[test]
    fn package_json_package_manager_with_hash() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "pnpm@8.15.0+sha256.abc123def456"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "pnpm");
        assert_eq!(reqs[0].constraint, Some("8.15.0".to_string()));
    }

    #[test]
    fn package_json_both_engines_and_package_manager() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=20"}, "packageManager": "pnpm@8.15.0"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs.len(), 2);
        assert!(reqs.iter().any(|r| r.tool == "node"));
        assert!(reqs.iter().any(|r| r.tool == "pnpm"));
    }

    #[test]
    fn package_json_no_relevant_fields() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"name": "my-package", "version": "1.0.0"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn package_json_empty_object() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let reqs = parse_package_json_str(root, &path, "{}").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn package_json_engines_without_node() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"npm": ">=8.0.0"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn package_json_invalid_json() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let result = parse_package_json_str(root, &path, "not valid json");
        assert!(result.is_err());
    }

    #[test]
    fn package_json_sets_correct_source_kind() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=18"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].source.kind, SourceKind::PackageJson);
    }

    #[test]
    fn package_json_sets_path_tool_probe_kind() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=18"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
    }

    #[test]
    fn package_json_marked_as_required() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=18"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs[0].required);
    }

    #[test]
    fn package_json_relative_path_stored() {
        let root = Path::new("/fake/project");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": ">=18"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].source.path, "package.json");
    }

    #[test]
    fn package_json_engines_node_semver_range() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": "^18.0.0 || ^20.0.0"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].constraint, Some("^18.0.0 || ^20.0.0".to_string()));
    }

    #[test]
    fn package_json_engines_node_tilde_range() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": "~20.11.0"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].constraint, Some("~20.11.0".to_string()));
    }

    #[test]
    fn package_json_engines_node_exact() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"engines": {"node": "20.11.0"}}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
    }

    #[test]
    fn package_json_package_manager_empty() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": ""}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn package_json_package_manager_no_version() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "pnpm"}"#;
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs.is_empty()); // No @ separator
    }

    #[test]
    fn package_json_package_manager_invalid_format() {
        let root = Path::new("/fake");
        let path = root.join("package.json");
        let json = r#"{"packageManager": "@8.15.0"}"#; // Missing tool name
        let reqs = parse_package_json_str(root, &path, json).unwrap();
        assert!(reqs.is_empty());
    }

    // =========================================================================
    // parse_package_manager helper tests
    // =========================================================================

    #[test]
    fn parse_package_manager_valid() {
        let result = parse_package_manager("pnpm@8.15.0");
        assert_eq!(result, Some(("pnpm".to_string(), "8.15.0".to_string())));
    }

    #[test]
    fn parse_package_manager_with_hash() {
        let result = parse_package_manager("pnpm@8.15.0+sha256.abc123");
        assert_eq!(result, Some(("pnpm".to_string(), "8.15.0".to_string())));
    }

    #[test]
    fn parse_package_manager_empty() {
        assert_eq!(parse_package_manager(""), None);
    }

    #[test]
    fn parse_package_manager_no_at() {
        assert_eq!(parse_package_manager("pnpm"), None);
    }

    #[test]
    fn parse_package_manager_empty_tool() {
        assert_eq!(parse_package_manager("@8.15.0"), None);
    }

    #[test]
    fn parse_package_manager_empty_version() {
        assert_eq!(parse_package_manager("pnpm@"), None);
    }

    #[test]
    fn parse_package_manager_whitespace() {
        let result = parse_package_manager("  pnpm@8.15.0  ");
        assert_eq!(result, Some(("pnpm".to_string(), "8.15.0".to_string())));
    }
}
