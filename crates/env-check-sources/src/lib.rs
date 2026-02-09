//! Parse repo sources into normalized Requirements.

pub mod go_mod;
pub mod node;
pub mod python;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use env_check_types::{
    Finding, Location, ProbeKind, Requirement, Severity, SourceKind, SourceRef, checks, codes,
};

pub use go_mod::{parse_go_mod, parse_go_mod_str};
pub use node::{
    parse_node_version, parse_node_version_str, parse_nvmrc, parse_nvmrc_str, parse_package_json,
    parse_package_json_str,
};
pub use python::{
    parse_pyproject_toml, parse_pyproject_toml_str, parse_python_version, parse_python_version_str,
};

#[derive(Debug, Clone)]
pub struct ParsedSources {
    pub sources_used: Vec<SourceRef>,
    pub requirements: Vec<Requirement>,
    pub findings: Vec<Finding>, // parse errors etc.
}

impl ParsedSources {
    pub fn empty() -> Self {
        Self {
            sources_used: vec![],
            requirements: vec![],
            findings: vec![],
        }
    }
}

/// Discover and parse all supported sources under `root`.
pub fn parse_all(root: &Path, hash_manifests: &[PathBuf]) -> ParsedSources {
    let mut out = ParsedSources::empty();

    // Deterministic discovery order.
    let candidates: Vec<(SourceKind, PathBuf)> = vec![
        (SourceKind::RustToolchain, root.join("rust-toolchain.toml")),
        (SourceKind::RustToolchain, root.join("rust-toolchain")),
        (SourceKind::MiseToml, root.join(".mise.toml")),
        (SourceKind::ToolVersions, root.join(".tool-versions")),
        (SourceKind::NodeVersion, root.join(".node-version")),
        (SourceKind::Nvmrc, root.join(".nvmrc")),
        (SourceKind::PackageJson, root.join("package.json")),
        (SourceKind::PythonVersion, root.join(".python-version")),
        (SourceKind::PyprojectToml, root.join("pyproject.toml")),
        (SourceKind::GoMod, root.join("go.mod")),
    ];

    for (kind, path) in candidates {
        if path.exists() {
            out.sources_used.push(SourceRef {
                kind: kind.clone(),
                path: rel(root, &path),
            });
            match kind {
                SourceKind::ToolVersions => match parse_tool_versions(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::MiseToml => match parse_mise_toml(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::RustToolchain => match parse_rust_toolchain(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::NodeVersion => match node::parse_node_version(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::Nvmrc => match node::parse_nvmrc(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::PackageJson => match node::parse_package_json(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::PythonVersion => match python::parse_python_version(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::PyprojectToml => match python::parse_pyproject_toml(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::GoMod => match go_mod::parse_go_mod(root, &path) {
                    Ok(reqs) => out.requirements.extend(reqs),
                    Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
                },
                SourceKind::HashManifest => { /* not discovered here */ }
            }
        }
    }

    // Hash manifests are configurable; include defaults if present.
    for rel_path in hash_manifests {
        let path = root.join(rel_path);
        if path.exists() {
            out.sources_used.push(SourceRef {
                kind: SourceKind::HashManifest,
                path: rel(root, &path),
            });
            match parse_hash_manifest(root, &path) {
                Ok(reqs) => out.requirements.extend(reqs),
                Err(e) => out.findings.push(parse_error_finding(root, &path, e)),
            }
        }
    }

    // Normalize ordering for determinism.
    out.requirements
        .sort_by(|a, b| a.tool.cmp(&b.tool).then(a.source.path.cmp(&b.source.path)));

    out
}

fn parse_error_finding(root: &Path, path: &Path, err: anyhow::Error) -> Finding {
    Finding {
        severity: Severity::Warn,
        check_id: Some(checks::SOURCE_PARSE.to_string()),
        code: codes::ENV_SOURCE_PARSE_ERROR.to_string(),
        message: format!("Failed to parse {}: {}", rel(root, path), err),
        location: Some(Location {
            path: rel(root, path),
            line: None,
            col: None,
        }),
        help: Some("Fix the file format or temporarily remove the source. env-check treats malformed sources as warnings under oss profile by default.".to_string()),
        url: None,
        fingerprint: None,
        data: None,
    }
}

/// `.tool-versions` (asdf) format: `tool version`
pub fn parse_tool_versions(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read .tool-versions")?;
    parse_tool_versions_str(root, path, &text)
}

pub fn parse_tool_versions_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let mut out = vec![];

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let mut parts = line.split_whitespace();
        let tool = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing tool at line {}", idx + 1))?;
        let ver = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing version at line {}", idx + 1))?;

        let tool = normalize_tool_id(tool);

        out.push(Requirement {
            tool,
            constraint: Some(ver.to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        });
    }

    Ok(out)
}

/// `.mise.toml` format: `[tools] node = "20"`.
pub fn parse_mise_toml(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read .mise.toml")?;
    parse_mise_toml_str(root, path, &text)
}

pub fn parse_mise_toml_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let value: toml::Value = toml::from_str(text).with_context(|| "parse toml")?;

    let tools = value
        .get("tools")
        .ok_or_else(|| anyhow::anyhow!("missing [tools] table"))?;

    let table = tools
        .as_table()
        .ok_or_else(|| anyhow::anyhow!("[tools] must be a table"))?;

    let mut out = vec![];
    for (tool, v) in table.iter() {
        let tool_id = normalize_tool_id(tool);

        let constraint = match v {
            toml::Value::String(s) => Some(s.to_string()),
            toml::Value::Integer(i) => Some(i.to_string()),
            toml::Value::Array(arr) => {
                // Keep the first entry as the constraint, capture the full shape in data later.
                arr.first().and_then(|x| x.as_str()).map(|s| s.to_string())
            }
            _ => None,
        };

        out.push(Requirement {
            tool: tool_id,
            constraint,
            required: true,
            source: SourceRef {
                kind: SourceKind::MiseToml,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        });
    }

    Ok(out)
}

/// `rust-toolchain.toml` or legacy `rust-toolchain` file.
pub fn parse_rust_toolchain(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read rust toolchain")?;
    parse_rust_toolchain_str(root, path, &text)
}

pub fn parse_rust_toolchain_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    if path.file_name().and_then(|n| n.to_str()) == Some("rust-toolchain")
        && !text.trim_start().starts_with('[')
    {
        // Legacy format: single string channel/version.
        let channel = text.trim().to_string();
        return Ok(vec![Requirement {
            tool: "rust".to_string(),
            constraint: Some(channel),
            required: true,
            source: SourceRef {
                kind: SourceKind::RustToolchain,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::RustupToolchain,
            hash: None,
        }]);
    }

    let value: toml::Value = toml::from_str(text).with_context(|| "parse rust-toolchain.toml")?;
    let toolchain = value
        .get("toolchain")
        .ok_or_else(|| anyhow::anyhow!("missing [toolchain] table"))?;

    let channel = toolchain
        .get("channel")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing toolchain.channel"))?;

    Ok(vec![Requirement {
        tool: "rust".to_string(),
        constraint: Some(channel.to_string()),
        required: true,
        source: SourceRef {
            kind: SourceKind::RustToolchain,
            path: rel(root, path),
        },
        probe_kind: ProbeKind::RustupToolchain,
        hash: None,
    }])
}

/// Hash manifest format: `<sha256>  <path>`
pub fn parse_hash_manifest(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read hash manifest")?;
    parse_hash_manifest_str(root, path, &text)
}

pub fn parse_hash_manifest_str(
    root: &Path,
    path: &Path,
    text: &str,
) -> anyhow::Result<Vec<Requirement>> {
    let mut out = vec![];

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Support either one or two spaces; sha256sum commonly uses two.
        let mut parts = line.split_whitespace();
        let hash = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing hash at line {}", idx + 1))?;
        let rel_path = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("missing path at line {}", idx + 1))?;

        // Keep it repo-relative; don't allow absolute paths.
        if rel_path.starts_with('/') || rel_path.contains(':') {
            return Err(anyhow::anyhow!(
                "hash manifest path must be repo-relative: {}",
                rel_path
            ));
        }

        out.push(Requirement {
            tool: format!("file:{}", rel_path),
            constraint: None,
            required: true,
            source: SourceRef {
                kind: SourceKind::HashManifest,
                path: rel(root, path),
            },
            probe_kind: ProbeKind::FileHash,
            hash: Some(env_check_types::HashSpec {
                algo: env_check_types::HashAlgo::Sha256,
                hex: hash.to_string(),
                path: rel_path.to_string(),
            }),
        });
    }

    Ok(out)
}

fn normalize_tool_id(raw: &str) -> String {
    match raw {
        "nodejs" => "node",
        "golang" => "go",
        other => other,
    }
    .to_string()
}

pub(crate) fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_all_collects_sources_and_sorts_requirements() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path();

        fs::write(root.join(".tool-versions"), "python 3.11\nnode 20\n")
            .expect("write .tool-versions");
        fs::write(root.join(".node-version"), "18.0.0\n").expect("write .node-version");

        let scripts_dir = root.join("scripts");
        fs::create_dir_all(&scripts_dir).expect("create scripts dir");
        fs::write(
            scripts_dir.join("tools.sha256"),
            "deadbeef  scripts/tool.sh\n",
        )
        .expect("write tools.sha256");

        let parsed = parse_all(root, &[PathBuf::from("scripts/tools.sha256")]);

        let sources: Vec<String> = parsed.sources_used.iter().map(|s| s.path.clone()).collect();
        assert_eq!(
            sources,
            vec![".tool-versions", ".node-version", "scripts/tools.sha256"]
        );

        let tools: Vec<String> = parsed.requirements.iter().map(|r| r.tool.clone()).collect();
        assert_eq!(
            tools,
            vec![
                "file:scripts/tool.sh",
                "node",
                "node",
                "python",
            ]
        );

        let node_paths: Vec<String> = parsed
            .requirements
            .iter()
            .filter(|r| r.tool == "node")
            .map(|r| r.source.path.clone())
            .collect();
        assert_eq!(node_paths, vec![".node-version", ".tool-versions"]);

        assert!(parsed.findings.is_empty());
    }

    #[test]
    fn parse_all_emits_parse_error_finding() {
        let dir = tempdir().expect("temp dir");
        let root = dir.path();

        fs::write(root.join(".mise.toml"), "this is not toml {{{\n")
            .expect("write invalid .mise.toml");

        let parsed = parse_all(root, &[]);
        assert_eq!(parsed.findings.len(), 1);
        let finding = &parsed.findings[0];
        assert_eq!(finding.code, codes::ENV_SOURCE_PARSE_ERROR);
        assert_eq!(finding.check_id.as_deref(), Some(checks::SOURCE_PARSE));
        assert!(finding.message.contains(".mise.toml"));
        assert_eq!(
            finding.location.as_ref().map(|l| l.path.as_str()),
            Some(".mise.toml")
        );
    }

    #[test]
    fn tool_versions_missing_version_is_error() {
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, "node");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing version"));
    }

    #[test]
    fn mise_toml_missing_tools_table_is_error() {
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, "[settings]\nexperimental = true\n");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing [tools] table"));
    }

    #[test]
    fn mise_toml_tools_not_table_is_error() {
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, "tools = \"node\"");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("[tools] must be a table"));
    }

    #[test]
    fn rust_toolchain_legacy_format_parses_channel() {
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain");
        let reqs = parse_rust_toolchain_str(root, &path, "stable").unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "rust");
        assert_eq!(reqs[0].constraint.as_deref(), Some("stable"));
        assert_eq!(reqs[0].probe_kind, ProbeKind::RustupToolchain);
    }

    #[test]
    fn rust_toolchain_missing_table_is_error() {
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, "[not_toolchain]\nfoo = \"bar\"");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing [toolchain] table"));
    }

    #[test]
    fn rust_toolchain_missing_channel_is_error() {
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, "[toolchain]\nprofile = \"default\"");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("missing toolchain.channel"));
    }
}
