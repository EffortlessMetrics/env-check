#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let root = Path::new("/fuzz");
        let path = root.join("tools.sha256");
        let _ = env_check_sources::parse_hash_manifest_str(root, &path, text);
    }
});
