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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn root() -> PathBuf {
        PathBuf::from("/repo")
    }

    fn path() -> PathBuf {
        PathBuf::from("/repo/go.mod")
    }

    #[test]
    fn parse_basic_go_mod() {
        let text = "module example.com/foo\n\ngo 1.22\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "go");
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22"));
    }

    #[test]
    fn parse_go_mod_with_comment() {
        let text = "module example.com/foo\n\n// a comment\ngo 1.22 // inline\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22"));
    }

    #[test]
    fn parse_go_mod_with_toolchain() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain go1.22.5\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22.5"));
    }

    #[test]
    fn parse_go_mod_toolchain_default_ignored() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain default\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22"));
    }

    #[test]
    fn parse_go_mod_empty_go_directive() {
        let text = "module example.com/foo\n\ngo\n";
        let err = parse_go_mod_str(&root(), &path(), text).unwrap_err();
        assert!(err.to_string().contains("no version"));
    }

    #[test]
    fn parse_go_mod_invalid_version() {
        let text = "module example.com/foo\n\ngo abc\n";
        let err = parse_go_mod_str(&root(), &path(), text).unwrap_err();
        assert!(err.to_string().contains("invalid go version"));
    }

    #[test]
    fn parse_go_mod_missing_go_directive() {
        let text = "module example.com/foo\n";
        let err = parse_go_mod_str(&root(), &path(), text).unwrap_err();
        assert!(err.to_string().contains("missing go directive"));
    }

    #[test]
    fn parse_go_mod_tab_separator() {
        let text = "module example.com/foo\n\ngo\t1.22\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22"));
    }

    #[test]
    fn parse_go_mod_empty_toolchain_directive() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain\n";
        let err = parse_go_mod_str(&root(), &path(), text).unwrap_err();
        assert!(err.to_string().contains("toolchain directive has no value"));
    }

    #[test]
    fn parse_go_mod_invalid_toolchain_version() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain goabc\n";
        let err = parse_go_mod_str(&root(), &path(), text).unwrap_err();
        assert!(err.to_string().contains("invalid toolchain version"));
    }

    #[test]
    fn parse_go_mod_toolchain_tab_separator() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain\tgo1.22.5\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22.5"));
    }

    #[test]
    fn parse_go_mod_toolchain_lower_than_go_uses_go() {
        let text = "module example.com/foo\n\ngo 1.23\ntoolchain go1.22.0\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        // go directive is stricter
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.23"));
    }

    #[test]
    fn parse_go_mod_three_part_version() {
        let text = "module example.com/foo\n\ngo 1.22.1\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22.1"));
    }

    #[test]
    fn parse_go_mod_skips_blank_and_comment_lines() {
        let text = "\n// comment\n\nmodule example.com/foo\n\ngo 1.22\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs.len(), 1);
    }

    #[test]
    fn parse_go_mod_duplicate_go_directive_uses_first() {
        let text = "module example.com/foo\n\ngo 1.22\ngo 1.23\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22"));
    }

    #[test]
    fn parse_go_mod_toolchain_with_comment() {
        let text = "module example.com/foo\n\ngo 1.22\ntoolchain go1.22.5 // inline\n";
        let reqs = parse_go_mod_str(&root(), &path(), text).unwrap();
        assert_eq!(reqs[0].constraint.as_deref(), Some(">=1.22.5"));
    }

    #[test]
    fn is_valid_go_version_rejects_single_part() {
        assert!(!is_valid_go_version("1"));
    }

    #[test]
    fn is_valid_go_version_rejects_four_parts() {
        assert!(!is_valid_go_version("1.2.3.4"));
    }

    #[test]
    fn is_valid_go_version_rejects_non_numeric() {
        assert!(!is_valid_go_version("1.x"));
    }

    #[test]
    fn is_valid_go_version_accepts_two_parts() {
        assert!(is_valid_go_version("1.22"));
    }

    #[test]
    fn is_valid_go_version_accepts_three_parts() {
        assert!(is_valid_go_version("1.22.1"));
    }
}
