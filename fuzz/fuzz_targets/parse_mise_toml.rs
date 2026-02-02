#![no_main]
use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let root = Path::new(".");
        let path = Path::new(".mise.toml");
        let _ = env_check_sources::parse_mise_toml_str(root, path, s);
    }
});
