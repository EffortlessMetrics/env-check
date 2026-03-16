//! Node.js source parser microcrate.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

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
        None => Ok(vec![]),
    }
}

/// Parse a `.nvmrc` file.
///
/// Format: Same as `.node-version` - a single version string.
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
        None => Ok(vec![]),
    }
}

/// Parse a `package.json` file.
///
/// Extracts:
/// - `engines.node` - Node.js version constraint
/// - `engines.npm` - npm version constraint
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
    let engines = value.get("engines");

    // Extract engines.node
    if let Some(node_constraint) = engines.and_then(|v| v.get("node")).and_then(|v| v.as_str()) {
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

    // Extract engines.npm
    let engines_npm = engines
        .and_then(|v| v.get("npm"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // Parse packageManager first so we can resolve npm precedence deterministically.
    let package_manager = value
        .get("packageManager")
        .and_then(|v| v.as_str())
        .and_then(parse_package_manager);

    if let Some(npm_constraint) = engines_npm {
        let package_manager_is_npm = package_manager
            .as_ref()
            .is_some_and(|(tool, _)| tool == "npm");

        if !package_manager_is_npm {
            reqs.push(Requirement {
                tool: "npm".to_string(),
                constraint: Some(npm_constraint),
                required: true,
                source: SourceRef {
                    kind: SourceKind::PackageJson,
                    path: rel(root, path),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            });
        }
    }

    // packageManager
    if let Some((tool, version)) = package_manager {
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

fn normalize_node_version(version: &str) -> String {
    version.strip_prefix('v').unwrap_or(version).to_string()
}

fn parse_package_manager(pm: &str) -> Option<(String, String)> {
    let pm = pm.trim();
    if pm.is_empty() {
        return None;
    }

    let parts: Vec<&str> = pm.splitn(2, '@').collect();
    if parts.len() != 2 {
        return None;
    }

    let tool = parts[0].trim();
    let version_part = parts[1].trim();

    if tool.is_empty() || version_part.is_empty() {
        return None;
    }

    let version = version_part.split('+').next().unwrap_or(version_part);
    Some((tool.to_string(), version.to_string()))
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
