#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let root = Path::new("/fuzz");
        let path = root.join(".node-version");
        let _ = env_check_sources::parse_node_version_str(root, &path, text);
    }
});
