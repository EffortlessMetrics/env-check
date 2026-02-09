#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let root = Path::new("/fuzz");

        // Test TOML format (rust-toolchain.toml)
        let path_toml = root.join("rust-toolchain.toml");
        let _ = env_check_sources::parse_rust_toolchain_str(root, &path_toml, text);

        // Test legacy format (rust-toolchain without extension)
        let path_legacy = root.join("rust-toolchain");
        let _ = env_check_sources::parse_rust_toolchain_str(root, &path_legacy, text);
    }
});
