use env_check_sources_hash::parse_hash_manifest_str;
use proptest::prelude::*;
use std::path::Path;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn hash_manifest_never_panics(s in ".*") {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let _ = parse_hash_manifest_str(root, &path, &s);
    }

    #[test]
    fn hash_manifest_parses_valid_entries(
        hash in "[0-9a-fA-F]{6,128}",
        dir in "[a-z][a-z0-9_-]{1,12}",
        file in "[a-z][a-z0-9_.-]{1,16}",
    ) {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let rel_path = format!("{}/{}", dir, file);
        let text = format!("{}  {}", hash, rel_path);
        let reqs = parse_hash_manifest_str(root, &path, &text).expect("valid hash manifest entry should parse");

        prop_assert_eq!(reqs.len(), 1);
        prop_assert_eq!(reqs[0].tool.as_str(), format!("file:{}", rel_path));
        prop_assert_eq!(reqs[0].hash.as_ref().map(|h| h.path.as_str()), Some(rel_path.as_str()));
    }

    #[test]
    fn hash_manifest_rejects_absolute_paths(
        hash in "[0-9a-fA-F]{6,128}",
        tail in "[a-z0-9_/.-]{1,32}",
    ) {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let text = format!("{} /{}", hash, tail);
        let result = parse_hash_manifest_str(root, &path, &text);

        prop_assert!(result.is_err());
        prop_assert!(result.unwrap_err().to_string().contains("repo-relative"));
    }

    #[test]
    fn hash_manifest_rejects_windows_drive_paths(
        hash in "[0-9a-fA-F]{6,128}",
        drive in "(C|D|E)",
        tail in "[a-z0-9_./-]{1,32}",
    ) {
        let root = Path::new("/fake");
        let path = root.join("scripts/tools.sha256");
        let text = format!("{} {}:\\{}", hash, drive, tail);
        let result = parse_hash_manifest_str(root, &path, &text);

        prop_assert!(result.is_err());
        prop_assert!(result.unwrap_err().to_string().contains("repo-relative"));
    }
}
