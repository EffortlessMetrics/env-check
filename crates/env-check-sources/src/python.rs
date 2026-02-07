//! Python source file parsers.
//!
//! Parses `.python-version` and `pyproject.toml` files to extract Python version requirements.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

/// Parse `.python-version` file.
///
/// The file format is simple: a single line with the Python version.
/// Lines starting with `#` are comments. Whitespace is trimmed.
/// May contain just "3.11" or "3.11.4" or "pypy3.9-7.3.9".
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
    // Find first non-empty, non-comment line
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // The version is the entire line (trimmed)
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

    // Empty file or only comments - valid but no requirements
    Ok(vec![])
}

/// Parse `pyproject.toml` file to extract `requires-python` from `[project]` table.
///
/// Example:
/// ```toml
/// [project]
/// requires-python = ">=3.8"
/// ```
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

    // Look for [project].requires-python
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
        None => {
            // No requires-python specified - valid but no Python requirements
            Ok(vec![])
        }
    }
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // .python-version tests
    // =========================================================================

    #[test]
    fn python_version_simple() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "python");
        assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
    }

    #[test]
    fn python_version_full_semver() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11.4").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("3.11.4".to_string()));
    }

    #[test]
    fn python_version_pypy() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "pypy3.9-7.3.9").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("pypy3.9-7.3.9".to_string()));
    }

    #[test]
    fn python_version_with_whitespace() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "  3.11  \n").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
    }

    #[test]
    fn python_version_with_comments() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "# Use Python 3.11\n3.11\n").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
    }

    #[test]
    fn python_version_empty() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn python_version_only_comments() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "# comment\n# another\n").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn python_version_only_whitespace() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "   \n\t\n  ").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn python_version_multiple_lines_takes_first() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11\n3.12\n").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
    }

    #[test]
    fn python_version_sets_correct_source_kind() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11").unwrap();
        assert_eq!(reqs[0].source.kind, SourceKind::PythonVersion);
    }

    #[test]
    fn python_version_sets_path_tool_probe_kind() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11").unwrap();
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
    }

    #[test]
    fn python_version_marked_as_required() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11").unwrap();
        assert!(reqs[0].required);
    }

    #[test]
    fn python_version_relative_path_stored() {
        let root = Path::new("/fake/project");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11").unwrap();
        assert_eq!(reqs[0].source.path, ".python-version");
    }

    #[test]
    fn python_version_crlf_line_endings() {
        let root = Path::new("/fake");
        let path = root.join(".python-version");
        let reqs = parse_python_version_str(root, &path, "3.11\r\n").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
    }

    // =========================================================================
    // pyproject.toml tests
    // =========================================================================

    #[test]
    fn pyproject_requires_python_basic() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
name = "myproject"
requires-python = ">=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "python");
        assert_eq!(reqs[0].constraint, Some(">=3.8".to_string()));
    }

    #[test]
    fn pyproject_requires_python_exact() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = "==3.11.4"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some("==3.11.4".to_string()));
    }

    #[test]
    fn pyproject_requires_python_range() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8,<4.0"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some(">=3.8,<4.0".to_string()));
    }

    #[test]
    fn pyproject_no_requires_python() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
name = "myproject"
version = "1.0.0"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn pyproject_no_project_table() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[tool.pytest]
testpaths = ["tests"]
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn pyproject_empty_file() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let reqs = parse_pyproject_toml_str(root, &path, "").unwrap();
        assert!(reqs.is_empty());
    }

    #[test]
    fn pyproject_invalid_toml_is_error() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let result = parse_pyproject_toml_str(root, &path, "this is not valid toml [[[");
        assert!(result.is_err());
    }

    #[test]
    fn pyproject_sets_correct_source_kind() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs[0].source.kind, SourceKind::PyprojectToml);
    }

    #[test]
    fn pyproject_sets_path_tool_probe_kind() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
    }

    #[test]
    fn pyproject_marked_as_required() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert!(reqs[0].required);
    }

    #[test]
    fn pyproject_relative_path_stored() {
        let root = Path::new("/fake/project");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs[0].source.path, "pyproject.toml");
    }

    #[test]
    fn pyproject_with_other_sections() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[project]
name = "myproject"
requires-python = ">=3.9"

[tool.black]
line-length = 88
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some(">=3.9".to_string()));
    }

    #[test]
    fn pyproject_tilde_constraint() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = "~=3.8"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs[0].constraint, Some("~=3.8".to_string()));
    }

    #[test]
    fn pyproject_complex_constraint() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = ">=3.8,!=3.9.0,<4"
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        assert_eq!(reqs[0].constraint, Some(">=3.8,!=3.9.0,<4".to_string()));
    }

    #[test]
    fn pyproject_requires_python_not_string_is_ignored() {
        let root = Path::new("/fake");
        let path = root.join("pyproject.toml");
        let content = r#"
[project]
requires-python = 3
"#;
        let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
        // Non-string values are ignored (returns None from as_str)
        assert!(reqs.is_empty());
    }
}
