//! Parse repo sources into normalized Requirements.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use env_check_types::{
    checks, codes, Finding, Location, ProbeKind, Requirement, Severity, SourceKind, SourceRef,
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
    out.requirements.sort_by(|a, b| a.tool.cmp(&b.tool).then(a.source.path.cmp(&b.source.path)));

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

pub fn parse_tool_versions_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
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

pub fn parse_mise_toml_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
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
                arr.get(0).and_then(|x| x.as_str()).map(|s| s.to_string())
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

pub fn parse_rust_toolchain_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
    if path.file_name().and_then(|n| n.to_str()) == Some("rust-toolchain") && !text.trim_start().starts_with('[') {
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

pub fn parse_hash_manifest_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
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
            return Err(anyhow::anyhow!("hash manifest path must be repo-relative: {}", rel_path));
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

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
