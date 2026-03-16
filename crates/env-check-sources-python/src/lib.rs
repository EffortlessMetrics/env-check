//! Python source parser microcrate.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

/// Parse `.python-version` file.
///
/// The file format is simple: a single line with the Python version.
pub fn parse_python_version(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read .python-version")?;
    parse_python_version_str(root, path, &text)
}

/// Parse `.python-version` content from a string.
pub fn parse_python_version_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        return Ok(vec![Requirement {
            tool: "python".to_string(),
            constraint: Some(line.to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::PythonVersion,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }]);
    }

    Ok(vec![])
}

/// Parse `pyproject.toml` file to extract `requires-python` from `[project]` table.
pub fn parse_pyproject_toml(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read pyproject.toml")?;
    parse_pyproject_toml_str(root, path, &text)
}

/// Parse `pyproject.toml` content from a string.
pub fn parse_pyproject_toml_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let value: toml::Value = toml::from_str(text).with_context(|| "parse pyproject.toml")?;

    let requires_python = value
        .get("project")
        .and_then(|p| p.get("requires-python"))
        .and_then(|v| v.as_str());

    match requires_python {
        Some(constraint) => Ok(vec![Requirement {
            tool: "python".to_string(),
            constraint: Some(constraint.to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::PyprojectToml,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }]),
        None => Ok(vec![]),
    }
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
