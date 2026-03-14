//! go.mod parser microcrate.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

/// Parse a `go.mod` file and extract the Go version requirement.
pub fn parse_go_mod(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read go.mod")?;
    parse_go_mod_str(root, path, &text)
}

/// Parse go.mod content from a string.
pub fn parse_go_mod_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
    // Parse the go/toolchain directives from go.mod.
    let mut go_version: Option<String> = None;
    let mut toolchain_version: Option<String> = None;

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and full-line comments
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Handle `go` directive.
        if line == "go" || line.starts_with("go ") || line.starts_with("go\t") {
            let version = if line == "go" {
                ""
            } else {
                line[2..].trim().split("//").next().unwrap_or("").trim()
            };

            if version.is_empty() {
                return Err(anyhow::anyhow!(
                    "go directive has no version at line {}",
                    idx + 1
                ));
            }

            if !is_valid_go_version(version) {
                return Err(anyhow::anyhow!(
                    "invalid go version format '{}' at line {}",
                    version,
                    idx + 1
                ));
            }

            if go_version.is_none() {
                go_version = Some(version.to_string());
            }
            continue;
        }

        // Handle optional `toolchain` directive.
        if line == "toolchain" || line.starts_with("toolchain ") || line.starts_with("toolchain\t")
        {
            let raw = if line == "toolchain" {
                ""
            } else {
                line["toolchain".len()..]
                    .trim()
                    .split("//")
                    .next()
                    .unwrap_or("")
                    .trim()
            };

            if raw.is_empty() {
                return Err(anyhow::anyhow!(
                    "toolchain directive has no value at line {}",
                    idx + 1
                ));
            }

            // `default` means no extra constraint.
            if raw != "default" {
                let normalized = raw.strip_prefix("go").unwrap_or(raw);
                if !is_valid_go_version(normalized) {
                    return Err(anyhow::anyhow!(
                        "invalid toolchain version format '{}' at line {}",
                        raw,
                        idx + 1
                    ));
                }
                if toolchain_version.is_none() {
                    toolchain_version = Some(normalized.to_string());
                }
            }
        }
    }

    let go_version = go_version.ok_or_else(|| anyhow::anyhow!("missing go directive in go.mod"))?;

    let effective = match toolchain_version {
        Some(toolchain) => stricter_go_version(&go_version, &toolchain),
        None => go_version,
    };

    Ok(vec![Requirement {
        tool: "go".to_string(),
        constraint: Some(format!(">={}", effective)),
        required: true,
        source: SourceRef {
            kind: SourceKind::GoMod,
            path: rel(root, path),
        },
        probe_kind: ProbeKind::PathTool,
        hash: None,
    }])
}

fn is_valid_go_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();

    if parts.len() < 2 || parts.len() > 3 {
        return false;
    }

    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

fn parse_go_version_parts(version: &str) -> Option<(u32, u32, u32)> {
    if !is_valid_go_version(version) {
        return None;
    }

    let mut it = version.split('.');
    let major = it.next()?.parse::<u32>().ok()?;
    let minor = it.next()?.parse::<u32>().ok()?;
    let patch = it
        .next()
        .map(|p| p.parse::<u32>().ok())
        .unwrap_or(Some(0))?;

    Some((major, minor, patch))
}

fn stricter_go_version(go: &str, toolchain: &str) -> String {
    let go_parts = parse_go_version_parts(go).unwrap_or((0, 0, 0));
    let toolchain_parts = parse_go_version_parts(toolchain).unwrap_or((0, 0, 0));

    if toolchain_parts > go_parts {
        toolchain.to_string()
    } else {
        go.to_string()
    }
}

fn rel(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
