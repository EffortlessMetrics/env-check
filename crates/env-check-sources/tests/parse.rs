use std::path::Path;

use env_check_sources::{parse_mise_toml, parse_tool_versions};

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
fn parses_mise_tools_basic() {
    let root = Path::new("tests/fixtures/mise_basic");
    let path = root.join(".mise.toml");
    let reqs = parse_mise_toml(root, &path).unwrap();
    assert!(reqs.iter().any(|r| r.tool == "node"));
}
