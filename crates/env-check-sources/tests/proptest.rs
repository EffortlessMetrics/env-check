use proptest::prelude::*;
use std::path::Path;
use env_check_sources::{
    parse_tool_versions_str,
    parse_mise_toml_str,
    parse_rust_toolchain_str,
    parse_hash_manifest_str,
};

// =============================================================================
// .tool-versions Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// .tool-versions parser never panics on arbitrary input
    #[test]
    fn tool_versions_never_panics(s in ".*") {
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let _ = parse_tool_versions_str(root, &path, &s);
    }

    /// .tool-versions parser handles whitespace variations
    #[test]
    fn tool_versions_whitespace_tolerance(
        tool in "[a-z][a-z0-9_-]{0,20}",
        version in "[0-9]{1,3}(\\.[0-9]{1,3}){0,2}",
        leading_ws in "[ \t]{0,5}",
        middle_ws in "[ \t]{1,5}",
        trailing_ws in "[ \t]{0,5}",
    ) {
        let line = format!("{}{}{}{}{}", leading_ws, tool, middle_ws, version, trailing_ws);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &line);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version.as_str()));
    }

    /// .tool-versions parser handles comments correctly
    #[test]
    fn tool_versions_comments_ignored(
        comment in "# [^\n]{0,50}",
        tool in "[a-z][a-z0-9_-]{0,10}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("{}\n{} {}\n", comment, tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// .tool-versions parser handles blank lines
    #[test]
    fn tool_versions_blank_lines(
        blank_count in 0usize..5,
        tool in "[a-z]{3,10}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let blanks = "\n".repeat(blank_count);
        let content = format!("{}{} {}\n{}", blanks, tool, version, blanks);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// Tool ID normalization is consistent
    #[test]
    fn tool_id_normalization(
        raw in "(nodejs|golang|node|go|python|rust)",
    ) {
        let content = format!("{} 1.0.0", raw);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        // nodejs -> node, golang -> go
        let expected = match raw.as_str() {
            "nodejs" => "node",
            "golang" => "go",
            other => other,
        };
        prop_assert_eq!(reqs[0].tool.as_str(), expected);
    }

    /// .tool-versions parser handles random tool names (ASCII)
    #[test]
    fn tool_versions_random_tool_names(
        tool in "[a-zA-Z][a-zA-Z0-9_-]{0,30}",
        version in "[0-9]{1,4}(\\.[0-9]{1,4}){0,3}(-[a-z0-9]+)?",
    ) {
        let content = format!("{} {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version.as_str()));
    }

    /// .tool-versions parser handles Unicode tool names (doesn't crash)
    #[test]
    fn tool_versions_unicode_tool_names(
        tool in "[\\p{L}][\\p{L}0-9_-]{0,20}",
        version in "[0-9]{1,3}\\.[0-9]{1,3}",
    ) {
        let content = format!("{} {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        // Should not panic; may succeed or fail gracefully
        let _ = parse_tool_versions_str(root, &path, &content);
    }

    /// .tool-versions parser handles multiple tools per file
    #[test]
    fn tool_versions_multiple_entries(
        tools in prop::collection::vec(
            ("[a-z]{3,10}", "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}"),
            1..10
        ),
    ) {
        let content: String = tools.iter()
            .map(|(tool, ver)| format!("{} {}\n", tool, ver))
            .collect();
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), tools.len());
    }

    /// .tool-versions parser handles interleaved comments and blanks
    #[test]
    fn tool_versions_interleaved_comments(
        tool1 in "[a-z]{3,8}",
        ver1 in "[0-9]{1,2}\\.[0-9]{1,2}",
        comment in "[^\\n]{0,30}",
        tool2 in "[a-z]{3,8}",
        ver2 in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!(
            "# header\n\n{} {}\n# {}\n\n{} {}\n# footer\n",
            tool1, ver1, comment, tool2, ver2
        );
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 2);
    }

    /// .tool-versions parser handles extra version fields (asdf style)
    #[test]
    fn tool_versions_extra_version_fields(
        tool in "[a-z]{3,10}",
        ver1 in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
        ver2 in "[0-9]{1,2}\\.[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("{} {} {}", tool, ver1, ver2);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        // Should take the first version only
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(ver1.as_str()));
    }

    /// .tool-versions parser handles version with prerelease tags
    #[test]
    fn tool_versions_prerelease_versions(
        tool in "[a-z]{3,10}",
        major in 0u32..100,
        minor in 0u32..100,
        patch in 0u32..100,
        prerelease in "(alpha|beta|rc|dev|nightly|canary)[0-9]{0,3}",
    ) {
        let version = format!("{}.{}.{}-{}", major, minor, patch, prerelease);
        let content = format!("{} {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version.as_str()));
    }

    /// .tool-versions handles lines with only whitespace
    #[test]
    fn tool_versions_whitespace_only_lines(
        ws1 in "[ \t]{0,10}",
        ws2 in "[ \t]{0,10}",
        tool in "[a-z]{3,10}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("{}\n{} {}\n{}\n", ws1, tool, version, ws2);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// .tool-versions handles CR+LF line endings
    #[test]
    fn tool_versions_crlf_line_endings(
        tool in "[a-z]{3,10}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("{} {}\r\n", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// .tool-versions handles tool names with hyphens and underscores
    #[test]
    fn tool_versions_hyphen_underscore_names(
        prefix in "[a-z]{2,5}",
        sep in "[-_]",
        suffix in "[a-z]{2,5}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let tool = format!("{}{}{}", prefix, sep, suffix);
        let content = format!("{} {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".tool-versions");
        let result = parse_tool_versions_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }
}

// =============================================================================
// .mise.toml Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// mise.toml parser never panics on arbitrary input
    #[test]
    fn mise_toml_never_panics(s in ".*") {
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let _ = parse_mise_toml_str(root, &path, &s);
    }

    /// mise.toml parser handles valid tool entries with string versions
    #[test]
    fn mise_toml_valid_tools(
        tool in "[a-z][a-z0-9_]{0,10}",
        version in "[0-9]{1,2}(\\.[0-9]{1,2})?",
    ) {
        let content = format!("[tools]\n{} = \"{}\"", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// mise.toml parser handles integer version values
    #[test]
    fn mise_toml_integer_versions(
        tool in "[a-z][a-z0-9_]{0,10}",
        version in 0i64..1000,
    ) {
        let content = format!("[tools]\n{} = {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        let version_str = version.to_string();
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version_str.as_str()));
    }

    /// mise.toml parser handles array version values (takes first)
    #[test]
    fn mise_toml_array_versions(
        tool in "[a-z][a-z0-9_]{0,10}",
        first in "[0-9]{1,2}\\.[0-9]{1,2}",
        second in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("[tools]\n{} = [\"{}\", \"{}\"]", tool, first, second);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(first.as_str()));
    }

    /// mise.toml parser handles multiple tools
    #[test]
    fn mise_toml_multiple_tools(
        tools in prop::collection::vec(
            ("[a-z]{3,10}", "[0-9]{1,2}\\.[0-9]{1,2}"),
            1..5
        ),
    ) {
        // Generate unique tool names
        let mut tool_entries: Vec<(String, String)> = Vec::new();
        for (i, (tool, ver)) in tools.iter().enumerate() {
            tool_entries.push((format!("{}_{}", tool, i), ver.clone()));
        }

        let entries: String = tool_entries.iter()
            .map(|(tool, ver)| format!("{} = \"{}\"", tool, ver))
            .collect::<Vec<_>>()
            .join("\n");
        let content = format!("[tools]\n{}", entries);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), tool_entries.len());
    }

    /// mise.toml parser handles various unsupported types gracefully (constraint becomes None)
    #[test]
    fn mise_toml_boolean_becomes_none(
        tool in "[a-z][a-z0-9_]{0,10}",
        b in prop::bool::ANY,
    ) {
        let content = format!("[tools]\n{} = {}", tool, b);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert!(reqs[0].constraint.is_none());
    }

    /// mise.toml handles empty array (constraint becomes None)
    #[test]
    fn mise_toml_empty_array(
        tool in "[a-z][a-z0-9_]{0,10}",
    ) {
        let content = format!("[tools]\n{} = []", tool);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert!(reqs[0].constraint.is_none());
    }

    /// mise.toml with other sections is still valid
    #[test]
    fn mise_toml_with_settings(
        tool in "[a-z][a-z0-9_]{0,10}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
        setting_val in prop::bool::ANY,
    ) {
        let content = format!(
            "[settings]\nexperimental = {}\n\n[tools]\n{} = \"{}\"",
            setting_val, tool, version
        );
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// mise.toml normalizes nodejs and golang
    #[test]
    fn mise_toml_normalizes_tool_names(
        raw in "(nodejs|golang)",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let content = format!("[tools]\n{} = \"{}\"", raw, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        let expected = match raw.as_str() {
            "nodejs" => "node",
            "golang" => "go",
            other => other,
        };
        prop_assert_eq!(reqs[0].tool.as_str(), expected);
    }

    /// mise.toml handles quoted tool names with special chars
    #[test]
    fn mise_toml_quoted_tool_names(
        prefix in "[a-z]{2,5}",
        suffix in "[a-z]{2,5}",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        // Tool names with dashes need quoting in TOML
        let tool = format!("{}-{}", prefix, suffix);
        let content = format!("[tools]\n\"{}\" = \"{}\"", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// mise.toml handles semver-style version strings
    #[test]
    fn mise_toml_semver_versions(
        tool in "[a-z]{3,10}",
        major in 0u32..100,
        minor in 0u32..100,
        patch in 0u32..100,
    ) {
        let version = format!("{}.{}.{}", major, minor, patch);
        let content = format!("[tools]\n{} = \"{}\"", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version.as_str()));
    }

    /// mise.toml handles negative integers gracefully
    #[test]
    fn mise_toml_negative_integers(
        tool in "[a-z]{3,10}",
        version in -100i64..0,
    ) {
        let content = format!("[tools]\n{} = {}", tool, version);
        let root = Path::new("/fake");
        let path = root.join(".mise.toml");
        let result = parse_mise_toml_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        // Negative version should still be parsed as string
        let version_str = version.to_string();
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(version_str.as_str()));
    }
}

// =============================================================================
// rust-toolchain.toml Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// rust-toolchain.toml parser never panics on arbitrary input
    #[test]
    fn rust_toolchain_never_panics(s in ".*") {
        let root = Path::new("/fake");
        // Test TOML format
        let path_toml = root.join("rust-toolchain.toml");
        let _ = parse_rust_toolchain_str(root, &path_toml, &s);
        // Test legacy format
        let path_legacy = root.join("rust-toolchain");
        let _ = parse_rust_toolchain_str(root, &path_legacy, &s);
    }

    /// rust-toolchain.toml handles valid TOML format
    #[test]
    fn rust_toolchain_toml_format(
        channel in "(stable|beta|nightly|[0-9]{1,2}\\.[0-9]{1,2}(\\.[0-9]{1,2})?)",
    ) {
        let content = format!("[toolchain]\nchannel = \"{}\"", channel);
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].tool.as_str(), "rust");
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.as_str()));
    }

    /// rust-toolchain (legacy) handles plain text channel
    #[test]
    fn rust_toolchain_legacy_format(
        channel in "(stable|beta|nightly|[0-9]{1,2}\\.[0-9]{1,2}(\\.[0-9]{1,2})?)",
    ) {
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain");  // No .toml extension
        let result = parse_rust_toolchain_str(root, &path, &channel);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].tool.as_str(), "rust");
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.trim()));
    }

    /// rust-toolchain legacy handles whitespace around channel
    #[test]
    fn rust_toolchain_legacy_whitespace(
        leading in "[ \t\n]{0,5}",
        channel in "(stable|beta|nightly)",
        trailing in "[ \t\n]{0,5}",
    ) {
        let content = format!("{}{}{}", leading, channel, trailing);
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.as_str()));
    }

    /// rust-toolchain.toml handles nightly with date
    #[test]
    fn rust_toolchain_nightly_with_date(
        year in 2020u32..2030,
        month in 1u32..13,
        day in 1u32..29,
    ) {
        let channel = format!("nightly-{:04}-{:02}-{:02}", year, month, day);
        let content = format!("[toolchain]\nchannel = \"{}\"", channel);
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.as_str()));
    }

    /// rust-toolchain.toml with extra fields is still valid
    #[test]
    fn rust_toolchain_with_components(
        channel in "(stable|beta|nightly)",
        component in "(rustfmt|clippy|rust-src)",
    ) {
        let content = format!(
            "[toolchain]\nchannel = \"{}\"\ncomponents = [\"{}\"]",
            channel, component
        );
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// rust-toolchain.toml with targets is still valid
    #[test]
    fn rust_toolchain_with_targets(
        channel in "(stable|beta|nightly)",
        target in "(x86_64-unknown-linux-gnu|x86_64-pc-windows-msvc|aarch64-apple-darwin)",
    ) {
        let content = format!(
            "[toolchain]\nchannel = \"{}\"\ntargets = [\"{}\"]",
            channel, target
        );
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
    }

    /// rust-toolchain.toml handles version strings like "1.75.0"
    #[test]
    fn rust_toolchain_version_channel(
        major in 1u32..2,
        minor in 0u32..100,
        patch in 0u32..10,
    ) {
        let channel = format!("{}.{}.{}", major, minor, patch);
        let content = format!("[toolchain]\nchannel = \"{}\"", channel);
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain.toml");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.as_str()));
    }

    /// Legacy rust-toolchain file detects TOML content and parses as TOML
    #[test]
    fn rust_toolchain_legacy_with_toml_content(
        channel in "(stable|beta|nightly)",
    ) {
        // If the legacy file contains TOML (starts with [), it's parsed as TOML
        let content = format!("[toolchain]\nchannel = \"{}\"", channel);
        let root = Path::new("/fake");
        let path = root.join("rust-toolchain");
        let result = parse_rust_toolchain_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs[0].constraint.as_deref(), Some(channel.as_str()));
    }
}

// =============================================================================
// Hash Manifest Property Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// Hash manifest parser never panics on arbitrary input
    #[test]
    fn hash_manifest_never_panics(s in ".*") {
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let _ = parse_hash_manifest_str(root, &path, &s);
    }

    /// Hash manifest handles valid SHA256 hex strings (64 chars)
    #[test]
    fn hash_manifest_valid_sha256(
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/.-]{0,30}",
    ) {
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
        let hash_spec = reqs[0].hash.as_ref().unwrap();
        prop_assert_eq!(hash_spec.hex.as_str(), hash.as_str());
        prop_assert_eq!(hash_spec.path.as_str(), rel_path.as_str());
    }

    /// Hash manifest handles uppercase hex characters
    #[test]
    fn hash_manifest_uppercase_hex(
        hash in "[0-9A-F]{64}",
        rel_path in "[a-z][a-z0-9_/.-]{0,30}",
    ) {
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
    }

    /// Hash manifest handles mixed case hex characters
    #[test]
    fn hash_manifest_mixed_case_hex(
        hash in "[0-9a-fA-F]{64}",
        rel_path in "[a-z][a-z0-9_/.-]{0,30}",
    ) {
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
    }

    /// Hash manifest handles short hash strings (invalid length but doesn't panic)
    #[test]
    fn hash_manifest_short_hash(
        hash_len in 1usize..64,
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let hash = "a".repeat(hash_len);
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        // Should not panic - may parse successfully or fail gracefully
        let _ = parse_hash_manifest_str(root, &path, &content);
    }

    /// Hash manifest handles long hash strings (invalid but doesn't panic)
    #[test]
    fn hash_manifest_long_hash(
        extra in 1usize..20,
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let hash = "a".repeat(64 + extra);
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        // Should not panic - may parse successfully or fail gracefully
        let _ = parse_hash_manifest_str(root, &path, &content);
    }

    /// Hash manifest handles various whitespace between hash and path
    #[test]
    fn hash_manifest_whitespace_variations(
        hash in "[0-9a-f]{64}",
        ws in "[ \t]{1,10}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let content = format!("{}{}{}", hash, ws, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// Hash manifest handles comments
    #[test]
    fn hash_manifest_with_comments(
        comment in "[^\\n]{0,50}",
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let content = format!("# {}\n{}  {}\n", comment, hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// Hash manifest handles blank lines
    #[test]
    fn hash_manifest_blank_lines(
        blank_count in 0usize..5,
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let blanks = "\n".repeat(blank_count);
        let content = format!("{}{}  {}\n{}", blanks, hash, rel_path, blanks);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), 1);
    }

    /// Hash manifest handles multiple entries
    #[test]
    fn hash_manifest_multiple_entries(
        entries in prop::collection::vec(
            ("[0-9a-f]{64}", "[a-z][a-z0-9_/-]{1,20}"),
            1..10
        ),
    ) {
        let content: String = entries.iter()
            .map(|(hash, path)| format!("{}  {}\n", hash, path))
            .collect();
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs.len(), entries.len());
    }

    /// Hash manifest rejects absolute paths (starts with /)
    #[test]
    fn hash_manifest_absolute_path_rejected(
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let abs_path = format!("/{}", rel_path);
        let content = format!("{}  {}", hash, abs_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        prop_assert!(err.contains("repo-relative"));
    }

    /// Hash manifest rejects Windows-style paths with drive letters
    #[test]
    fn hash_manifest_windows_path_rejected(
        hash in "[0-9a-f]{64}",
        drive in "[A-Z]",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let win_path = format!("{}:{}", drive, rel_path);
        let content = format!("{}  {}", hash, win_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        prop_assert!(err.contains("repo-relative"));
    }

    /// Hash manifest handles paths with subdirectories
    #[test]
    fn hash_manifest_nested_paths(
        hash in "[0-9a-f]{64}",
        dir1 in "[a-z]{2,5}",
        dir2 in "[a-z]{2,5}",
        file in "[a-z]{2,8}\\.[a-z]{2,4}",
    ) {
        let rel_path = format!("{}/{}/{}", dir1, dir2, file);
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert_eq!(reqs[0].hash.as_ref().unwrap().path.as_str(), rel_path.as_str());
    }

    /// Hash manifest sets tool name with file: prefix
    #[test]
    fn hash_manifest_tool_name_prefix(
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        let expected_tool = format!("file:{}", rel_path);
        prop_assert_eq!(reqs[0].tool.as_str(), expected_tool.as_str());
    }

    /// Hash manifest handles invalid hex characters (doesn't panic)
    #[test]
    fn hash_manifest_invalid_hex_chars(
        invalid in "[g-z]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let content = format!("{}  {}", invalid, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        // Should not panic - currently accepts any string as hash
        let _ = parse_hash_manifest_str(root, &path, &content);
    }

    /// Hash manifest handles paths with dots and dashes
    #[test]
    fn hash_manifest_special_path_chars(
        hash in "[0-9a-f]{64}",
        dir in "[a-z]{2,5}",
        base in "[a-z]{2,8}",
        ext in "[a-z]{2,4}",
    ) {
        let rel_path = format!("{}/my-tool.{}.{}", dir, base, ext);
        let content = format!("{}  {}", hash, rel_path);
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
    }

    /// Hash manifest handles empty file
    #[test]
    fn hash_manifest_empty_file(_dummy in 0..1i32) {
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, "");
        prop_assert!(result.is_ok());
        let reqs = result.unwrap();
        prop_assert!(reqs.is_empty());
    }

    /// Hash manifest handles single space separator (sha256sum uses two)
    #[test]
    fn hash_manifest_single_space(
        hash in "[0-9a-f]{64}",
        rel_path in "[a-z][a-z0-9_/-]{0,20}",
    ) {
        let content = format!("{} {}", hash, rel_path);  // Single space
        let root = Path::new("/fake");
        let path = root.join("tools.sha256");
        let result = parse_hash_manifest_str(root, &path, &content);
        prop_assert!(result.is_ok());
    }
}

// =============================================================================
// Cross-Parser Consistency Tests
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Parsing the same tool in different formats yields same normalized name
    #[test]
    fn cross_parser_tool_normalization(
        raw in "(nodejs|golang)",
        version in "[0-9]{1,2}\\.[0-9]{1,2}",
    ) {
        let root = Path::new("/fake");

        // Parse in .tool-versions
        let tv_path = root.join(".tool-versions");
        let tv_content = format!("{} {}", raw, version);
        let tv_result = parse_tool_versions_str(root, &tv_path, &tv_content).unwrap();

        // Parse in .mise.toml
        let mise_path = root.join(".mise.toml");
        let mise_content = format!("[tools]\n{} = \"{}\"", raw, version);
        let mise_result = parse_mise_toml_str(root, &mise_path, &mise_content).unwrap();

        // Both should normalize to the same tool name
        prop_assert_eq!(tv_result[0].tool.as_str(), mise_result[0].tool.as_str());
    }

    /// Empty input yields empty requirements for all parsers
    #[test]
    fn all_parsers_handle_empty(_dummy in 0..1i32) {
        let root = Path::new("/fake");

        // .tool-versions
        let tv_path = root.join(".tool-versions");
        let tv_result = parse_tool_versions_str(root, &tv_path, "");
        prop_assert!(tv_result.is_ok());
        prop_assert!(tv_result.unwrap().is_empty());

        // hash manifest
        let hash_path = root.join("tools.sha256");
        let hash_result = parse_hash_manifest_str(root, &hash_path, "");
        prop_assert!(hash_result.is_ok());
        prop_assert!(hash_result.unwrap().is_empty());
    }

    /// Comments-only input yields empty requirements for tool-versions and hash manifest
    #[test]
    fn comments_only_yields_empty(
        comment in "[^\\n]{0,50}",
    ) {
        let root = Path::new("/fake");
        let content = format!("# {}\n# another comment", comment);

        // .tool-versions
        let tv_path = root.join(".tool-versions");
        let tv_result = parse_tool_versions_str(root, &tv_path, &content);
        prop_assert!(tv_result.is_ok());
        prop_assert!(tv_result.unwrap().is_empty());

        // hash manifest
        let hash_path = root.join("tools.sha256");
        let hash_result = parse_hash_manifest_str(root, &hash_path, &content);
        prop_assert!(hash_result.is_ok());
        prop_assert!(hash_result.unwrap().is_empty());
    }
}
