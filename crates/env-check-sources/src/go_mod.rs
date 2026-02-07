//! Parser for go.mod files.
//!
//! Extracts the `go` directive which specifies the minimum Go version required.
//! The directive appears as: `go 1.21` or `go 1.21.5`

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

use crate::rel;

/// Parse a `go.mod` file and extract the Go version requirement.
pub fn parse_go_mod(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read go.mod")?;
    parse_go_mod_str(root, path, &text)
}

/// Parse go.mod content from a string.
///
/// The go directive specifies the minimum Go version for the module.
/// Format examples:
/// - `go 1.21`
/// - `go 1.21.5`
/// - `go 1.21 // comment`
pub fn parse_go_mod_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
    // Parse the go directive from go.mod
    // The directive appears as: go 1.21 or go 1.21.5
    // May have trailing comments (// style)

    for (idx, line) in text.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and full-line comments
        if line.is_empty() || line.starts_with("//") {
            continue;
        }

        // Check for go directive
        // Handle both "go 1.21" and malformed "go" with no version
        if line == "go" || line.starts_with("go ") || line.starts_with("go\t") {
            let version = if line == "go" {
                ""
            } else {
                // Extract version, handling potential inline comments
                line[2..].trim().split("//").next().unwrap_or("").trim()
            };

            if version.is_empty() {
                return Err(anyhow::anyhow!(
                    "go directive has no version at line {}",
                    idx + 1
                ));
            }

            // Validate version format (should be like 1.21 or 1.21.5)
            if !is_valid_go_version(version) {
                return Err(anyhow::anyhow!(
                    "invalid go version format '{}' at line {}",
                    version,
                    idx + 1
                ));
            }

            return Ok(vec![Requirement {
                tool: "go".to_string(),
                // go directive means minimum version, prefix with >= for clarity
                constraint: Some(format!(">={}", version)),
                required: true,
                source: SourceRef {
                    kind: SourceKind::GoMod,
                    path: rel(root, path),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            }]);
        }
    }

    // No go directive found
    Err(anyhow::anyhow!("missing go directive in go.mod"))
}

/// Validate that a string looks like a valid Go version (e.g., 1.21 or 1.21.5)
fn is_valid_go_version(version: &str) -> bool {
    let parts: Vec<&str> = version.split('.').collect();

    // Must have at least major.minor
    if parts.len() < 2 || parts.len() > 3 {
        return false;
    }

    // All parts must be numeric
    parts
        .iter()
        .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_go_version() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.21\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "go");
        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
        assert_eq!(reqs[0].source.kind, SourceKind::GoMod);
        assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
        assert!(reqs[0].required);
    }

    #[test]
    fn parses_patch_version() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.21.5\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].constraint, Some(">=1.21.5".to_string()));
    }

    #[test]
    fn handles_inline_comment() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.22 // minimum version\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].constraint, Some(">=1.22".to_string()));
    }

    #[test]
    fn skips_full_line_comments() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "// This is a comment\nmodule example.com/mymod\n\ngo 1.21\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
    }

    #[test]
    fn missing_go_directive_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\nrequire (\n    golang.org/x/text v0.3.0\n)\n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("missing go directive"));
    }

    #[test]
    fn empty_go_version_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo \n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("no version"));
    }

    #[test]
    fn invalid_version_format_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo invalid\n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid go version format"));
    }

    #[test]
    fn version_with_too_many_parts_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.21.5.0\n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("invalid go version format"));
    }

    #[test]
    fn version_with_non_numeric_parts_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.21rc1\n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
    }

    #[test]
    fn parses_complex_go_mod() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = r#"module github.com/example/myproject

go 1.21

require (
    github.com/pkg/errors v0.9.1
    golang.org/x/text v0.3.7
)

replace github.com/old/pkg => github.com/new/pkg v1.0.0
"#;
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "go");
        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
    }

    #[test]
    fn handles_toolchain_directive_separately() {
        // The toolchain directive (go 1.21 vs toolchain go1.21.5) is a separate concern
        // We only extract the go directive, not toolchain
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = r#"module example.com/mymod

go 1.21

toolchain go1.21.5
"#;
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        // Should only get the go directive, not toolchain
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
    }

    #[test]
    fn whitespace_handling() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "  module example.com/mymod  \n\n  go   1.21  \n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
    }

    #[test]
    fn go_directive_at_start() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "go 1.21\nmodule example.com/mymod\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
    }

    #[test]
    fn empty_file_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("missing go directive"));
    }

    #[test]
    fn only_comments_is_error() {
        let root = Path::new("/fake");
        let path = root.join("go.mod");
        let text = "// just a comment\n// another comment\n";
        let result = parse_go_mod_str(root, &path, text);

        assert!(result.is_err());
    }

    #[test]
    fn relative_path_stored() {
        let root = Path::new("/fake/project");
        let path = root.join("go.mod");
        let text = "module example.com/mymod\n\ngo 1.21\n";
        let reqs = parse_go_mod_str(root, &path, text).unwrap();

        assert_eq!(reqs[0].source.path, "go.mod");
    }

    #[test]
    fn is_valid_go_version_basic() {
        assert!(is_valid_go_version("1.21"));
        assert!(is_valid_go_version("1.21.5"));
        assert!(is_valid_go_version("1.0"));
        assert!(is_valid_go_version("2.0.0"));
    }

    #[test]
    fn is_valid_go_version_invalid() {
        assert!(!is_valid_go_version("1"));
        assert!(!is_valid_go_version("1.21.5.0"));
        assert!(!is_valid_go_version("1.21rc1"));
        assert!(!is_valid_go_version("latest"));
        assert!(!is_valid_go_version(""));
        assert!(!is_valid_go_version(".21"));
        assert!(!is_valid_go_version("1."));
    }
}
