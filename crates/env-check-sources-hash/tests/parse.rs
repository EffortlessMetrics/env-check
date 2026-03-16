use std::path::Path;

use env_check_sources_hash::{parse_hash_manifest, parse_hash_manifest_str};
use env_check_types::{HashAlgo, ProbeKind, SourceKind};

fn fixtures_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

#[test]
fn parses_fixture_manifest() {
    let root = fixtures_dir().join("hash_manifest_basic");
    let path = root.join("scripts/tools.sha256");
    let reqs = parse_hash_manifest(&root, &path).expect("parse fixture hash manifest");

    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].tool, "file:scripts/mytool.sh");
    assert_eq!(reqs[0].probe_kind, ProbeKind::FileHash);
    assert_eq!(reqs[0].source.kind, SourceKind::HashManifest);
    assert_eq!(reqs[0].source.path, "scripts/tools.sha256");
    assert!(reqs[0].required);

    let hash = reqs[0].hash.as_ref().expect("hash spec should exist");
    assert_eq!(hash.algo, HashAlgo::Sha256);
    assert_eq!(hash.hex, "abc123def456");
    assert_eq!(hash.path, "scripts/mytool.sh");
}

#[test]
fn parse_str_handles_multiple_entries() {
    let root = Path::new("/fake");
    let path = root.join("scripts/tools.sha256");
    let text = "abc123  scripts/a.sh\ndef456 scripts/b.sh\n";
    let reqs = parse_hash_manifest_str(root, &path, text).expect("parse manifest text");

    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].tool, "file:scripts/a.sh");
    assert_eq!(reqs[1].tool, "file:scripts/b.sh");
}
