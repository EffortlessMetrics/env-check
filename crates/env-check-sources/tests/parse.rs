use std::path::Path;

use env_check_sources::{
    parse_all, parse_go_mod, parse_go_mod_str, parse_hash_manifest, parse_mise_toml,
    parse_mise_toml_str, parse_node_version, parse_node_version_str, parse_nvmrc, parse_nvmrc_str,
    parse_package_json, parse_package_json_str, parse_pyproject_toml, parse_pyproject_toml_str,
    parse_python_version, parse_python_version_str, parse_rust_toolchain, parse_tool_versions,
    parse_tool_versions_str,
};
use env_check_types::{ProbeKind, SourceKind};

// =============================================================================
// Tool versions tests
// =============================================================================

#[test]
fn parses_tool_versions_basic() {
    let root = Path::new("tests/fixtures/tool_versions_basic");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions(root, &path).unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[1].tool, "rust");
}

#[test]
fn tool_versions_with_comments() {
    let root = Path::new("tests/fixtures/tool_versions_comments");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions(root, &path).unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[1].tool, "rust");
}

#[test]
fn tool_versions_normalizes_nodejs() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "nodejs 20.0.0").unwrap();
    assert_eq!(reqs[0].tool, "node");
}

#[test]
fn tool_versions_normalizes_golang() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "golang 1.21.0").unwrap();
    assert_eq!(reqs[0].tool, "go");
}

#[test]
fn tool_versions_empty_file() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn tool_versions_only_comments() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "# comment\n# another").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn tool_versions_missing_version_is_error() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let result = parse_tool_versions_str(root, &path, "node\n");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("missing version"));
}

#[test]
fn tool_versions_whitespace_only_lines() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "   \n\t\nnode 20.0.0\n   \n").unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
}

#[test]
fn tool_versions_multiple_spaces_between_tool_and_version() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node    20.0.0").unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[0].constraint, Some("20.0.0".to_string()));
}

#[test]
fn tool_versions_tabs_as_delimiter() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node\t20.0.0").unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[0].constraint, Some("20.0.0".to_string()));
}

#[test]
fn tool_versions_extra_fields_ignored() {
    // asdf allows multiple versions, we take the first
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0 18.0.0").unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].constraint, Some("20.0.0".to_string()));
}

#[test]
fn tool_versions_inline_comment_not_supported() {
    // Inline comments are not standard in .tool-versions, the # becomes part of version
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0 # comment").unwrap();
    // The parser takes version as-is, extra parts are ignored
    assert_eq!(reqs[0].constraint, Some("20.0.0".to_string()));
}

#[test]
fn tool_versions_sets_correct_source_kind() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0").unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::ToolVersions);
}

#[test]
fn tool_versions_sets_path_tool_probe_kind() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0").unwrap();
    assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
}

#[test]
fn tool_versions_marked_as_required() {
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0").unwrap();
    assert!(reqs[0].required);
}

#[test]
fn tool_versions_relative_path_stored() {
    let root = Path::new("/fake/project");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "node 20.0.0").unwrap();
    assert_eq!(reqs[0].source.path, ".tool-versions");
}

#[test]
fn tool_versions_preserves_tool_case() {
    // Tools not in normalization list should preserve their case
    let root = Path::new("/fake");
    let path = root.join(".tool-versions");
    let reqs = parse_tool_versions_str(root, &path, "MyTool 1.0.0").unwrap();
    assert_eq!(reqs[0].tool, "MyTool");
}

// =============================================================================
// Mise.toml tests
// =============================================================================

#[test]
fn parses_mise_tools_basic() {
    let root = Path::new("tests/fixtures/mise_basic");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml(root, &path).unwrap();
    assert!(reqs.iter().any(|r| r.tool == "node"));
}

#[test]
fn mise_integer_version() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = 20").unwrap();
    assert_eq!(reqs[0].constraint, Some("20".to_string()));
}

#[test]
fn mise_array_version_takes_first() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = [\"20\", \"18\"]").unwrap();
    assert_eq!(reqs[0].constraint, Some("20".to_string()));
}

#[test]
fn mise_missing_tools_table_is_error() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let result = parse_mise_toml_str(root, &path, "[other]\nfoo = \"bar\"");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("[tools]"));
}

#[test]
fn mise_empty_tools_table() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\n").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn mise_normalizes_nodejs() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnodejs = \"20\"").unwrap();
    assert_eq!(reqs[0].tool, "node");
}

#[test]
fn mise_normalizes_golang() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\ngolang = \"1.21\"").unwrap();
    assert_eq!(reqs[0].tool, "go");
}

#[test]
fn mise_float_version() {
    // TOML can have float-like versions, test that we handle integer only
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\npython = \"3.12\"").unwrap();
    assert_eq!(reqs[0].constraint, Some("3.12".to_string()));
}

#[test]
fn mise_multiple_tools() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(
        root,
        &path,
        "[tools]\nnode = \"20\"\npython = \"3.12\"\nrust = \"1.75\"",
    )
    .unwrap();
    assert_eq!(reqs.len(), 3);
}

#[test]
fn mise_sets_correct_source_kind() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = \"20\"").unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::MiseToml);
}

#[test]
fn mise_sets_path_tool_probe_kind() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = \"20\"").unwrap();
    assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
}

#[test]
fn mise_marked_as_required() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = \"20\"").unwrap();
    assert!(reqs[0].required);
}

#[test]
fn mise_invalid_toml_is_error() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let result = parse_mise_toml_str(root, &path, "this is not valid toml [[[");
    assert!(result.is_err());
}

#[test]
fn mise_tools_not_a_table_is_error() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let result = parse_mise_toml_str(root, &path, "tools = \"not a table\"");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("table"));
}

#[test]
fn mise_empty_array_version() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = []").unwrap();
    // Empty array means no constraint
    assert_eq!(reqs[0].constraint, None);
}

#[test]
fn mise_boolean_version_becomes_none() {
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(root, &path, "[tools]\nnode = true").unwrap();
    // Unsupported types result in None constraint
    assert_eq!(reqs[0].constraint, None);
}

#[test]
fn mise_with_other_tables() {
    // mise.toml can have other sections like [settings]
    let root = Path::new("/fake");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml_str(
        root,
        &path,
        "[settings]\nexperimental = true\n\n[tools]\nnode = \"20\"",
    )
    .unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
}

// =============================================================================
// Rust toolchain tests
// =============================================================================

#[test]
fn rust_toolchain_toml_parses() {
    let root = Path::new("tests/fixtures/rust_toolchain");
    let path = root.join("rust-toolchain.toml");
    let reqs = parse_rust_toolchain(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "rust");
    assert_eq!(reqs[0].constraint, Some("1.75.0".to_string()));
    assert_eq!(reqs[0].probe_kind, ProbeKind::RustupToolchain);
}

#[test]
fn rust_toolchain_sets_correct_source_kind() {
    let root = Path::new("tests/fixtures/rust_toolchain");
    let path = root.join("rust-toolchain.toml");
    let reqs = parse_rust_toolchain(root, &path).unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::RustToolchain);
}

#[test]
fn rust_toolchain_marked_as_required() {
    let root = Path::new("tests/fixtures/rust_toolchain");
    let path = root.join("rust-toolchain.toml");
    let reqs = parse_rust_toolchain(root, &path).unwrap();
    assert!(reqs[0].required);
}

// =============================================================================
// Hash manifest tests
// =============================================================================

#[test]
fn hash_manifest_parses() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].probe_kind, ProbeKind::FileHash);
    assert!(reqs[0].hash.is_some());
}

#[test]
fn hash_manifest_sets_correct_source_kind() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(root, &path).unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::HashManifest);
}

#[test]
fn hash_manifest_marked_as_required() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(root, &path).unwrap();
    assert!(reqs[0].required);
}

#[test]
fn hash_manifest_extracts_hash_spec() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(root, &path).unwrap();
    let hash = reqs[0].hash.as_ref().unwrap();
    assert_eq!(hash.algo, env_check_types::HashAlgo::Sha256);
    assert_eq!(hash.hex, "abc123def456");
    assert_eq!(hash.path, "scripts/mytool.sh");
}

#[test]
fn hash_manifest_tool_name_is_file_prefixed() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(root, &path).unwrap();
    assert!(reqs[0].tool.starts_with("file:"));
    assert_eq!(reqs[0].tool, "file:scripts/mytool.sh");
}

// =============================================================================
// parse_all tests
// =============================================================================

#[test]
fn parse_all_discovers_sources() {
    let root = Path::new("tests/fixtures/tool_versions_basic");
    let parsed = parse_all(root, &[]);
    assert!(!parsed.sources_used.is_empty());
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::ToolVersions));
}

#[test]
fn parse_all_no_sources_is_empty() {
    // Create a temporary empty directory for this test
    let tmp = tempfile::tempdir().unwrap();
    let parsed = parse_all(tmp.path(), &[]);
    assert!(parsed.sources_used.is_empty());
    assert!(parsed.requirements.is_empty());
}

#[test]
fn parse_all_sorts_requirements() {
    let root = Path::new("tests/fixtures/tool_versions_basic");
    let parsed = parse_all(root, &[]);
    // Requirements should be sorted by tool name
    for window in parsed.requirements.windows(2) {
        assert!(
            window[0].tool <= window[1].tool,
            "Requirements not sorted: {} > {}",
            window[0].tool,
            window[1].tool
        );
    }
}

#[test]
fn parse_all_returns_empty_findings_on_success() {
    let root = Path::new("tests/fixtures/tool_versions_basic");
    let parsed = parse_all(root, &[]);
    assert!(
        parsed.findings.is_empty(),
        "Expected no parse errors for valid fixtures"
    );
}

#[test]
fn parse_all_records_parse_errors_as_findings() {
    let root = Path::new("tests/fixtures/malformed_tool_versions");
    let parsed = parse_all(root, &[]);
    // Should have a finding for parse error
    assert!(
        !parsed.findings.is_empty(),
        "Expected parse error finding for malformed fixture"
    );
}

#[test]
fn parse_all_includes_hash_manifests() {
    let root = Path::new("tests/fixtures/hash_manifest");
    let hash_manifests = vec![std::path::PathBuf::from("scripts/tools.sha256")];
    let parsed = parse_all(root, &hash_manifests);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::HashManifest));
    assert!(parsed.requirements.iter().any(|r| r.tool.starts_with("file:")));
}

#[test]
fn parse_all_skips_nonexistent_hash_manifest() {
    let tmp = tempfile::tempdir().unwrap();
    let hash_manifests = vec![std::path::PathBuf::from("nonexistent.sha256")];
    let parsed = parse_all(tmp.path(), &hash_manifests);
    // Should not error, just skip the manifest
    assert!(parsed.sources_used.is_empty());
    assert!(parsed.requirements.is_empty());
}

#[test]
fn parse_all_discovers_mise_toml() {
    let root = Path::new("tests/fixtures/mise_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::MiseToml));
}

#[test]
fn parse_all_discovers_rust_toolchain() {
    let root = Path::new("tests/fixtures/rust_toolchain");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::RustToolchain));
}

// =============================================================================
// Python version tests
// =============================================================================

#[test]
fn python_version_parses_basic() {
    let root = Path::new("tests/fixtures/python_version_basic");
    let path = root.join(".python-version");
    let reqs = parse_python_version(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "python");
    assert_eq!(reqs[0].constraint, Some("3.11.4".to_string()));
}

#[test]
fn python_version_parses_pypy() {
    let root = Path::new("tests/fixtures/python_version_pypy");
    let path = root.join(".python-version");
    let reqs = parse_python_version(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "python");
    assert_eq!(reqs[0].constraint, Some("pypy3.9-7.3.9".to_string()));
}

#[test]
fn python_version_with_comments() {
    let root = Path::new("tests/fixtures/python_version_comments");
    let path = root.join(".python-version");
    let reqs = parse_python_version(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].constraint, Some("3.12.0".to_string()));
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
fn python_version_empty_file() {
    let root = Path::new("/fake");
    let path = root.join(".python-version");
    let reqs = parse_python_version_str(root, &path, "").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn python_version_whitespace_only() {
    let root = Path::new("/fake");
    let path = root.join(".python-version");
    let reqs = parse_python_version_str(root, &path, "  \n  \t  ").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn python_version_trims_whitespace() {
    let root = Path::new("/fake");
    let path = root.join(".python-version");
    let reqs = parse_python_version_str(root, &path, "  3.11  \n").unwrap();
    assert_eq!(reqs[0].constraint, Some("3.11".to_string()));
}

// =============================================================================
// pyproject.toml tests
// =============================================================================

#[test]
fn pyproject_toml_parses_basic() {
    let root = Path::new("tests/fixtures/pyproject_basic");
    let path = root.join("pyproject.toml");
    let reqs = parse_pyproject_toml(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "python");
    assert_eq!(reqs[0].constraint, Some(">=3.8".to_string()));
}

#[test]
fn pyproject_toml_no_requires_python() {
    let root = Path::new("tests/fixtures/pyproject_no_requires");
    let path = root.join("pyproject.toml");
    let reqs = parse_pyproject_toml(root, &path).unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn pyproject_toml_invalid_is_error() {
    let root = Path::new("tests/fixtures/pyproject_invalid");
    let path = root.join("pyproject.toml");
    let result = parse_pyproject_toml(root, &path);
    assert!(result.is_err());
}

#[test]
fn pyproject_toml_sets_correct_source_kind() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let content = "[project]\nrequires-python = \">=3.8\"";
    let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::PyprojectToml);
}

#[test]
fn pyproject_toml_sets_path_tool_probe_kind() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let content = "[project]\nrequires-python = \">=3.8\"";
    let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
    assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
}

#[test]
fn pyproject_toml_marked_as_required() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let content = "[project]\nrequires-python = \">=3.8\"";
    let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
    assert!(reqs[0].required);
}

#[test]
fn pyproject_toml_preserves_pep440_constraint() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let content = "[project]\nrequires-python = \">=3.8,<4.0,!=3.9.0\"";
    let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
    assert_eq!(reqs[0].constraint, Some(">=3.8,<4.0,!=3.9.0".to_string()));
}

#[test]
fn pyproject_toml_no_project_section() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let content = "[tool.pytest]\ntestpaths = [\"tests\"]";
    let reqs = parse_pyproject_toml_str(root, &path, content).unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn pyproject_toml_empty_file() {
    let root = Path::new("/fake");
    let path = root.join("pyproject.toml");
    let reqs = parse_pyproject_toml_str(root, &path, "").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn parse_all_discovers_python_version() {
    let root = Path::new("tests/fixtures/python_version_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::PythonVersion));
}

#[test]
fn parse_all_discovers_pyproject_toml() {
    let root = Path::new("tests/fixtures/pyproject_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::PyprojectToml));
}

#[test]
fn parse_all_records_pyproject_parse_error() {
    let root = Path::new("tests/fixtures/pyproject_invalid");
    let parsed = parse_all(root, &[]);
    assert!(
        !parsed.findings.is_empty(),
        "Expected parse error finding for invalid pyproject.toml"
    );
}

// =============================================================================
// go.mod tests
// =============================================================================

#[test]
fn go_mod_parses_basic() {
    let root = Path::new("tests/fixtures/go_mod_basic");
    let path = root.join("go.mod");
    let reqs = parse_go_mod(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "go");
    assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
}

#[test]
fn go_mod_parses_complex() {
    let root = Path::new("tests/fixtures/go_mod_complex");
    let path = root.join("go.mod");
    let reqs = parse_go_mod(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "go");
    assert_eq!(reqs[0].constraint, Some(">=1.21.5".to_string()));
}

#[test]
fn go_mod_with_comments() {
    let root = Path::new("tests/fixtures/go_mod_comments");
    let path = root.join("go.mod");
    let reqs = parse_go_mod(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].constraint, Some(">=1.22".to_string()));
}

#[test]
fn go_mod_missing_directive_is_error() {
    let root = Path::new("tests/fixtures/go_mod_missing_directive");
    let path = root.join("go.mod");
    let result = parse_go_mod(root, &path);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("missing go directive"));
}

#[test]
fn go_mod_with_toolchain() {
    // Should extract the go directive, ignore toolchain directive
    let root = Path::new("tests/fixtures/go_mod_with_toolchain");
    let path = root.join("go.mod");
    let reqs = parse_go_mod(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].constraint, Some(">=1.21".to_string()));
}

#[test]
fn go_mod_sets_correct_source_kind() {
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let reqs = parse_go_mod_str(root, &path, "module example.com/test\n\ngo 1.21\n").unwrap();
    assert_eq!(reqs[0].source.kind, SourceKind::GoMod);
}

#[test]
fn go_mod_sets_path_tool_probe_kind() {
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let reqs = parse_go_mod_str(root, &path, "module example.com/test\n\ngo 1.21\n").unwrap();
    assert_eq!(reqs[0].probe_kind, ProbeKind::PathTool);
}

#[test]
fn go_mod_marked_as_required() {
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let reqs = parse_go_mod_str(root, &path, "module example.com/test\n\ngo 1.21\n").unwrap();
    assert!(reqs[0].required);
}

#[test]
fn go_mod_empty_file_is_error() {
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let result = parse_go_mod_str(root, &path, "");
    assert!(result.is_err());
}

#[test]
fn go_mod_invalid_version_is_error() {
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let result = parse_go_mod_str(root, &path, "module example.com/test\n\ngo invalid\n");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(err_msg.contains("invalid go version format"));
}

#[test]
fn go_mod_constraint_is_minimum_version() {
    // The go directive specifies minimum version, so constraint should be >=
    let root = Path::new("/fake");
    let path = root.join("go.mod");
    let reqs = parse_go_mod_str(root, &path, "go 1.21\n").unwrap();
    assert!(reqs[0].constraint.as_ref().unwrap().starts_with(">="));
}

#[test]
fn go_mod_relative_path_stored() {
    let root = Path::new("/fake/project");
    let path = root.join("go.mod");
    let reqs = parse_go_mod_str(root, &path, "go 1.21\n").unwrap();
    assert_eq!(reqs[0].source.path, "go.mod");
}

#[test]
fn parse_all_discovers_go_mod() {
    let root = Path::new("tests/fixtures/go_mod_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::GoMod));
}

#[test]
fn parse_all_records_go_mod_parse_error() {
    let root = Path::new("tests/fixtures/go_mod_missing_directive");
    let parsed = parse_all(root, &[]);
    assert!(
        !parsed.findings.is_empty(),
        "Expected parse error finding for go.mod without go directive"
    );
}

// =============================================================================
// .node-version tests
// =============================================================================

#[test]
fn node_version_parses_basic() {
    let root = Path::new("tests/fixtures/node_version_basic");
    let path = root.join(".node-version");
    let reqs = parse_node_version(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
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
fn node_version_strips_v_prefix() {
    let root = Path::new("/fake");
    let path = root.join(".node-version");
    let reqs = parse_node_version_str(root, &path, "v20.0.0").unwrap();
    assert_eq!(reqs[0].constraint, Some("20.0.0".to_string()));
}

#[test]
fn node_version_empty_file() {
    let root = Path::new("/fake");
    let path = root.join(".node-version");
    let reqs = parse_node_version_str(root, &path, "").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn node_version_comments_only() {
    let root = Path::new("/fake");
    let path = root.join(".node-version");
    let reqs = parse_node_version_str(root, &path, "# comment\n# another").unwrap();
    assert!(reqs.is_empty());
}

#[test]
fn node_version_trims_whitespace() {
    let root = Path::new("/fake");
    let path = root.join(".node-version");
    let reqs = parse_node_version_str(root, &path, "  20.11.0  \n").unwrap();
    assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
}

#[test]
fn node_version_with_comments() {
    let root = Path::new("/fake");
    let path = root.join(".node-version");
    let reqs = parse_node_version_str(root, &path, "# Node version\n20.11.0\n").unwrap();
    assert_eq!(reqs[0].constraint, Some("20.11.0".to_string()));
}

// =============================================================================
// .nvmrc tests
// =============================================================================

#[test]
fn nvmrc_parses_basic() {
    let root = Path::new("tests/fixtures/nvmrc_basic");
    let path = root.join(".nvmrc");
    let reqs = parse_nvmrc(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[0].constraint, Some("18.19.0".to_string()));
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

#[test]
fn nvmrc_marked_as_required() {
    let root = Path::new("/fake");
    let path = root.join(".nvmrc");
    let reqs = parse_nvmrc_str(root, &path, "20.0.0").unwrap();
    assert!(reqs[0].required);
}

#[test]
fn nvmrc_strips_v_prefix() {
    let root = Path::new("/fake");
    let path = root.join(".nvmrc");
    let reqs = parse_nvmrc_str(root, &path, "v18.0.0").unwrap();
    assert_eq!(reqs[0].constraint, Some("18.0.0".to_string()));
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
fn nvmrc_empty_file() {
    let root = Path::new("/fake");
    let path = root.join(".nvmrc");
    let reqs = parse_nvmrc_str(root, &path, "").unwrap();
    assert!(reqs.is_empty());
}

// =============================================================================
// package.json tests
// =============================================================================

#[test]
fn package_json_parses_engines_node() {
    let root = Path::new("tests/fixtures/package_json_basic");
    let path = root.join("package.json");
    let reqs = parse_package_json(root, &path).unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "node");
    assert_eq!(reqs[0].constraint, Some(">=18.0.0".to_string()));
}

#[test]
fn package_json_parses_full() {
    let root = Path::new("tests/fixtures/package_json_full");
    let path = root.join("package.json");
    let reqs = parse_package_json(root, &path).unwrap();
    assert_eq!(reqs.len(), 2);
    assert!(reqs.iter().any(|r| r.tool == "node"));
    assert!(reqs.iter().any(|r| r.tool == "pnpm"));
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
fn package_json_package_manager_pnpm() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"packageManager": "pnpm@8.15.0"}"#;
    let reqs = parse_package_json_str(root, &path, json).unwrap();
    assert_eq!(reqs[0].tool, "pnpm");
    assert_eq!(reqs[0].constraint, Some("8.15.0".to_string()));
}

#[test]
fn package_json_package_manager_npm() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"packageManager": "npm@10.2.3"}"#;
    let reqs = parse_package_json_str(root, &path, json).unwrap();
    assert_eq!(reqs[0].tool, "npm");
    assert_eq!(reqs[0].constraint, Some("10.2.3".to_string()));
}

#[test]
fn package_json_package_manager_yarn() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"packageManager": "yarn@4.0.0"}"#;
    let reqs = parse_package_json_str(root, &path, json).unwrap();
    assert_eq!(reqs[0].tool, "yarn");
    assert_eq!(reqs[0].constraint, Some("4.0.0".to_string()));
}

#[test]
fn package_json_package_manager_with_hash() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"packageManager": "pnpm@8.15.0+sha256.abc123"}"#;
    let reqs = parse_package_json_str(root, &path, json).unwrap();
    assert_eq!(reqs[0].constraint, Some("8.15.0".to_string()));
}

#[test]
fn package_json_no_relevant_fields() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"name": "test", "version": "1.0.0"}"#;
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
fn package_json_invalid_json_is_error() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let result = parse_package_json_str(root, &path, "not valid json");
    assert!(result.is_err());
}

#[test]
fn package_json_engines_semver_range() {
    let root = Path::new("/fake");
    let path = root.join("package.json");
    let json = r#"{"engines": {"node": "^18.0.0 || ^20.0.0"}}"#;
    let reqs = parse_package_json_str(root, &path, json).unwrap();
    assert_eq!(reqs[0].constraint, Some("^18.0.0 || ^20.0.0".to_string()));
}

#[test]
fn parse_all_discovers_node_version() {
    let root = Path::new("tests/fixtures/node_version_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::NodeVersion));
}

#[test]
fn parse_all_discovers_nvmrc() {
    let root = Path::new("tests/fixtures/nvmrc_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::Nvmrc));
}

#[test]
fn parse_all_discovers_package_json() {
    let root = Path::new("tests/fixtures/package_json_basic");
    let parsed = parse_all(root, &[]);
    assert!(parsed
        .sources_used
        .iter()
        .any(|s| s.kind == SourceKind::PackageJson));
}

#[test]
fn parse_all_records_package_json_parse_error() {
    let root = Path::new("tests/fixtures/malformed_package_json");
    let parsed = parse_all(root, &[]);
    assert!(
        !parsed.findings.is_empty(),
        "Expected parse error finding for malformed package.json"
    );
}
