//! Hash manifest parser microcrate.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{HashAlgo, HashSpec, ProbeKind, Requirement, SourceKind, SourceRef};

/// Hash manifest format: `<sha256>  <path>`.
pub fn parse_hash_manifest(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read hash manifest")?;
    parse_hash_manifest_str(root, path, &text)
}

/// Parse hash manifest content from a string.
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

        // Keep it repo-relative; do not allow absolute paths.
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
            hash: Some(HashSpec {
                algo: HashAlgo::Sha256,
                hex: hash.to_string(),
                path: rel_path.to_string(),
            }),
        });
    }

    Ok(out)
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
    use std::path::Path;

    #[test]
    fn parses_basic_manifest() {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let reqs = parse_hash_manifest_str(root, &path, "abc123  scripts/mytool.sh").unwrap();

        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "file:scripts/mytool.sh");
        assert_eq!(reqs[0].source.kind, SourceKind::HashManifest);
        assert_eq!(reqs[0].source.path, "scripts/tools.sha256");
        assert_eq!(reqs[0].probe_kind, ProbeKind::FileHash);

        let hash = reqs[0].hash.as_ref().expect("hash spec");
        assert_eq!(hash.algo, HashAlgo::Sha256);
        assert_eq!(hash.hex, "abc123");
        assert_eq!(hash.path, "scripts/mytool.sh");
    }

    #[test]
    fn skips_comments_and_blank_lines() {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let reqs = parse_hash_manifest_str(
            root,
            &path,
            "# comment\n\nabc123  scripts/a.sh\n# trailing\n",
        )
        .unwrap();

        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].tool, "file:scripts/a.sh");
    }

    #[test]
    fn rejects_absolute_unix_path() {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let err = parse_hash_manifest_str(root, &path, "abc123 /etc/passwd").unwrap_err();
        assert!(err.to_string().contains("repo-relative"));
    }

    #[test]
    fn rejects_windows_drive_path() {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let err = parse_hash_manifest_str(root, &path, "abc123 C:\\tools\\bin.exe").unwrap_err();
        assert!(err.to_string().contains("repo-relative"));
    }

    #[test]
    fn missing_path_is_error() {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let err = parse_hash_manifest_str(root, &path, "abc123").unwrap_err();
        assert!(err.to_string().contains("missing path"));
    }
}
