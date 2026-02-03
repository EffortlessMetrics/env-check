//! Probe the local machine for tool presence, versions, and hashes.
//!
//! This crate is written as an adapter boundary: OS interaction lives behind small traits
//! so we can run BDD/integration tests without depending on the host environment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use env_check_types::{EnvCheckError, HashAlgo, Observation, ProbeKind, ProbeRecord, Requirement, VersionObservation};
use regex::Regex;

pub trait CommandRunner: Send + Sync {
    fn run(&self, cwd: &Path, argv: &[String]) -> Result<CmdOutput, EnvCheckError>;
}

#[derive(Debug, Clone)]
pub struct CmdOutput {
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub struct OsCommandRunner;

impl CommandRunner for OsCommandRunner {
    fn run(&self, cwd: &Path, argv: &[String]) -> Result<CmdOutput, EnvCheckError> {
        if argv.is_empty() {
            return Err(EnvCheckError::Runtime("empty argv".into()));
        }

        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..]);
        cmd.current_dir(cwd);

        let out = cmd.output().map_err(|e| EnvCheckError::Runtime(e.to_string()))?;
        Ok(CmdOutput {
            exit: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        })
    }
}

pub trait PathResolver: Send + Sync {
    fn resolve(&self, tool: &str) -> Option<PathBuf>;
}

pub struct OsPathResolver;

impl PathResolver for OsPathResolver {
    fn resolve(&self, tool: &str) -> Option<PathBuf> {
        which::which(tool).ok()
    }
}

pub trait Hasher: Send + Sync {
    fn sha256_hex(&self, path: &Path) -> Result<String, EnvCheckError>;
}

pub struct Sha256Hasher;

impl Hasher for Sha256Hasher {
    fn sha256_hex(&self, path: &Path) -> Result<String, EnvCheckError> {
        use sha2::{Digest, Sha256};

        let bytes = fs::read(path).map_err(|e| EnvCheckError::Io(e.to_string()))?;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }
}

#[derive(Clone)]
pub struct Prober<R: CommandRunner, P: PathResolver, H: Hasher> {
    runner: R,
    path: P,
    hasher: H,
    version_re: Regex,
}

impl<R: CommandRunner, P: PathResolver, H: Hasher> Prober<R, P, H> {
    pub fn new(runner: R, path: P, hasher: H) -> anyhow::Result<Self> {
        // Conservative semver-ish matcher. We intentionally don't parse prerelease/build.
        let version_re = Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").context("compile version regex")?;
        Ok(Self { runner, path, hasher, version_re })
    }

    pub fn probe(&self, root: &Path, req: &Requirement) -> Observation {
        match req.probe_kind {
            ProbeKind::PathTool => self.probe_path_tool(root, req),
            ProbeKind::RustupToolchain => self.probe_rustup_toolchain(root, req),
            ProbeKind::FileHash => self.probe_file_hash(root, req),
        }
    }

    fn probe_path_tool(&self, root: &Path, req: &Requirement) -> Observation {
        let present = self.path.resolve(&req.tool).is_some();
        let mut record = ProbeRecord {
            cmd: vec![],
            exit: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let version = if present {
            let argv = vec![req.tool.clone(), "--version".to_string()];
            record.cmd = argv.clone();
            match self.runner.run(root, &argv) {
                Ok(out) => {
                    record.exit = out.exit;
                    record.stdout = out.stdout.clone();
                    record.stderr = out.stderr.clone();
                    Some(VersionObservation {
                        parsed: extract_version(&self.version_re, &out.stdout)
                            .or_else(|| extract_version(&self.version_re, &out.stderr)),
                        raw: format!("{}{}", out.stdout, out.stderr),
                    })
                }
                Err(e) => {
                    record.stderr = e.to_string();
                    Some(VersionObservation { parsed: None, raw: e.to_string() })
                }
            }
        } else {
            None
        };

        Observation {
            tool: req.tool.clone(),
            present,
            version,
            hash_ok: None,
            probe: record,
        }
    }

    fn probe_rustup_toolchain(&self, root: &Path, req: &Requirement) -> Observation {
        // We treat rustup itself as the transport. If rustup isn't available, present=false.
        let present = self.path.resolve("rustup").is_some();

        let argv = vec!["rustup".to_string(), "toolchain".to_string(), "list".to_string()];
        let mut record = ProbeRecord {
            cmd: argv.clone(),
            exit: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let version = if present {
            match self.runner.run(root, &argv) {
                Ok(out) => {
                    record.exit = out.exit;
                    record.stdout = out.stdout.clone();
                    record.stderr = out.stderr.clone();

                    // The "version" here is the declared toolchain channel we saw (if present).
                    // Actual satisfaction checking happens in the domain layer.
                    Some(VersionObservation {
                        parsed: req.constraint.clone(),
                        raw: out.stdout,
                    })
                }
                Err(e) => {
                    record.stderr = e.to_string();
                    Some(VersionObservation { parsed: req.constraint.clone(), raw: e.to_string() })
                }
            }
        } else {
            None
        };

        Observation {
            tool: req.tool.clone(),
            present,
            version,
            hash_ok: None,
            probe: record,
        }
    }

    fn probe_file_hash(&self, root: &Path, req: &Requirement) -> Observation {
        let mut record = ProbeRecord {
            cmd: vec![],
            exit: None,
            stdout: String::new(),
            stderr: String::new(),
        };

        let Some(spec) = &req.hash else {
            return Observation {
                tool: req.tool.clone(),
                present: false,
                version: None,
                hash_ok: None,
                probe: record,
            };
        };

        let path = root.join(&spec.path);
        let present = path.exists();

        let hash_ok = if present {
            match spec.algo {
                HashAlgo::Sha256 => match self.hasher.sha256_hex(&path) {
                    Ok(hex) => {
                        record.stdout = format!("sha256 {} = {}", spec.path, hex);
                        Some(normalize_hex(&hex) == normalize_hex(&spec.hex))
                    }
                    Err(e) => {
                        record.stderr = e.to_string();
                        None
                    }
                },
            }
        } else {
            Some(false)
        };

        Observation {
            tool: req.tool.clone(),
            present,
            version: None,
            hash_ok,
            probe: record,
        }
    }
}

fn normalize_hex(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

fn extract_version(re: &Regex, text: &str) -> Option<String> {
    re.find(text).map(|m| m.as_str().to_string())
}

/// Fake/test adapters for use in other crates' tests.
pub mod fakes {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// A fake PathResolver that returns a synthetic path for tools in its "present" set.
    pub struct FakePathResolver {
        present: HashSet<String>,
    }

    impl FakePathResolver {
        pub fn new(tools: impl IntoIterator<Item = impl Into<String>>) -> Self {
            Self {
                present: tools.into_iter().map(|t| t.into()).collect(),
            }
        }
    }

    impl PathResolver for FakePathResolver {
        fn resolve(&self, tool: &str) -> Option<PathBuf> {
            if self.present.contains(tool) {
                Some(PathBuf::from(format!("/fake/bin/{}", tool)))
            } else {
                None
            }
        }
    }

    /// A fake CommandRunner that returns pre-configured responses based on argv[0].
    pub struct FakeCommandRunner {
        responses: HashMap<String, CmdOutput>,
    }

    impl FakeCommandRunner {
        pub fn new() -> Self {
            Self {
                responses: HashMap::new(),
            }
        }

        pub fn with_response(mut self, cmd: impl Into<String>, output: CmdOutput) -> Self {
            self.responses.insert(cmd.into(), output);
            self
        }
    }

    impl Default for FakeCommandRunner {
        fn default() -> Self {
            Self::new()
        }
    }

    impl CommandRunner for FakeCommandRunner {
        fn run(&self, _cwd: &Path, argv: &[String]) -> Result<CmdOutput, EnvCheckError> {
            if argv.is_empty() {
                return Err(EnvCheckError::Runtime("empty argv".into()));
            }
            Ok(self
                .responses
                .get(&argv[0])
                .cloned()
                .unwrap_or(CmdOutput {
                    exit: Some(127),
                    stdout: String::new(),
                    stderr: format!("command not found: {}", argv[0]),
                }))
        }
    }

    /// A fake Hasher that returns pre-configured hashes for specific paths.
    pub struct FakeHasher {
        hashes: HashMap<PathBuf, String>,
    }

    impl FakeHasher {
        pub fn new() -> Self {
            Self {
                hashes: HashMap::new(),
            }
        }

        pub fn with_hash(mut self, path: impl Into<PathBuf>, hex: impl Into<String>) -> Self {
            self.hashes.insert(path.into(), hex.into());
            self
        }
    }

    impl Default for FakeHasher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Hasher for FakeHasher {
        fn sha256_hex(&self, path: &Path) -> Result<String, EnvCheckError> {
            self.hashes
                .get(path)
                .cloned()
                .ok_or_else(|| EnvCheckError::Io(format!("file not found: {}", path.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::fakes::*;
    use env_check_types::{HashAlgo, HashSpec, ProbeKind, Requirement, SourceKind, SourceRef};
    use proptest::prelude::*;

    fn make_req(tool: &str, probe_kind: ProbeKind) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: Some("1.0.0".to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".to_string(),
            },
            probe_kind,
            hash: None,
        }
    }

    fn make_hash_req(tool: &str, path: &str, hash: &str) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: None,
            required: true,
            source: SourceRef {
                kind: SourceKind::HashManifest,
                path: "tools.sha256".to_string(),
            },
            probe_kind: ProbeKind::FileHash,
            hash: Some(HashSpec {
                algo: HashAlgo::Sha256,
                hex: hash.to_string(),
                path: path.to_string(),
            }),
        }
    }

    #[test]
    fn version_extraction_picks_first_numeric() {
        let re = Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").unwrap();
        assert_eq!(extract_version(&re, "node v20.11.0 (foo)"), Some("20.11.0".into()));
        assert_eq!(extract_version(&re, "no digits here"), None);
    }

    #[test]
    fn probe_path_tool_present() {
        let path_resolver = FakePathResolver::new(["node"]);
        let cmd_runner = FakeCommandRunner::new()
            .with_response("node", CmdOutput {
                exit: Some(0),
                stdout: "v20.11.0".to_string(),
                stderr: String::new(),
            });
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_req("node", ProbeKind::PathTool);
        let obs = prober.probe(Path::new("/repo"), &req);

        assert!(obs.present);
        assert!(obs.version.is_some());
        assert_eq!(obs.version.as_ref().unwrap().parsed, Some("20.11.0".to_string()));
    }

    #[test]
    fn probe_path_tool_missing() {
        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_req("node", ProbeKind::PathTool);
        let obs = prober.probe(Path::new("/repo"), &req);

        assert!(!obs.present);
        assert!(obs.version.is_none());
    }

    #[test]
    fn probe_extracts_version_from_stdout() {
        let path_resolver = FakePathResolver::new(["node"]);
        let cmd_runner = FakeCommandRunner::new()
            .with_response("node", CmdOutput {
                exit: Some(0),
                stdout: "node v20.11.0 (LTS)".to_string(),
                stderr: String::new(),
            });
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_req("node", ProbeKind::PathTool);
        let obs = prober.probe(Path::new("/repo"), &req);

        assert_eq!(obs.version.as_ref().unwrap().parsed, Some("20.11.0".to_string()));
    }

    #[test]
    fn probe_extracts_version_from_stderr() {
        // Some tools print version to stderr
        let path_resolver = FakePathResolver::new(["java"]);
        let cmd_runner = FakeCommandRunner::new()
            .with_response("java", CmdOutput {
                exit: Some(0),
                stdout: String::new(),
                stderr: "openjdk version \"17.0.1\" 2021-10-19".to_string(),
            });
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_req("java", ProbeKind::PathTool);
        let obs = prober.probe(Path::new("/repo"), &req);

        assert_eq!(obs.version.as_ref().unwrap().parsed, Some("17.0.1".to_string()));
    }

    #[test]
    fn probe_rustup_toolchain_present() {
        let path_resolver = FakePathResolver::new(["rustup"]);
        let cmd_runner = FakeCommandRunner::new()
            .with_response("rustup", CmdOutput {
                exit: Some(0),
                stdout: "stable-x86_64-unknown-linux-gnu (default)\n1.75.0-x86_64-unknown-linux-gnu\nnightly-x86_64-unknown-linux-gnu".to_string(),
                stderr: String::new(),
            });
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let mut req = make_req("rust", ProbeKind::RustupToolchain);
        req.constraint = Some("1.75.0".to_string());
        let obs = prober.probe(Path::new("/repo"), &req);

        assert!(obs.present);
        assert!(obs.version.as_ref().unwrap().raw.contains("1.75.0"));
    }

    #[test]
    fn probe_rustup_missing() {
        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = FakeHasher::new();

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_req("rust", ProbeKind::RustupToolchain);
        let obs = prober.probe(Path::new("/repo"), &req);

        assert!(!obs.present);
    }

    #[test]
    fn probe_file_hash_matches() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let scripts_dir = temp_dir.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();

        let file_path = scripts_dir.join("tool.sh");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"#!/bin/bash\necho hello").unwrap();

        // Calculate expected hash
        let expected_hash = Sha256Hasher.sha256_hex(&file_path).unwrap();

        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = Sha256Hasher;

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_hash_req("file:scripts/tool.sh", "scripts/tool.sh", &expected_hash);
        let obs = prober.probe(temp_dir.path(), &req);

        assert!(obs.present);
        assert_eq!(obs.hash_ok, Some(true));
    }

    #[test]
    fn probe_file_hash_mismatch() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let scripts_dir = temp_dir.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();

        let file_path = scripts_dir.join("tool.sh");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"#!/bin/bash\necho hello").unwrap();

        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = Sha256Hasher;

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        // Use a wrong hash
        let req = make_hash_req("file:scripts/tool.sh", "scripts/tool.sh", "0000000000000000000000000000000000000000000000000000000000000000");
        let obs = prober.probe(temp_dir.path(), &req);

        assert!(obs.present);
        assert_eq!(obs.hash_ok, Some(false));
    }

    #[test]
    fn probe_file_hash_case_insensitive() {
        use std::io::Write;

        let temp_dir = tempfile::tempdir().unwrap();
        let scripts_dir = temp_dir.path().join("scripts");
        std::fs::create_dir_all(&scripts_dir).unwrap();

        let file_path = scripts_dir.join("tool.sh");
        let mut file = std::fs::File::create(&file_path).unwrap();
        file.write_all(b"#!/bin/bash\necho hello").unwrap();

        // Calculate expected hash and convert to uppercase
        let expected_hash = Sha256Hasher.sha256_hex(&file_path).unwrap();
        let uppercase_hash = expected_hash.to_uppercase();

        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = Sha256Hasher;

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        // Use uppercase hash in requirement, hasher returns lowercase
        let req = make_hash_req("file:scripts/tool.sh", "scripts/tool.sh", &uppercase_hash);
        let obs = prober.probe(temp_dir.path(), &req);

        assert_eq!(obs.hash_ok, Some(true));
    }

    #[test]
    fn probe_file_hash_file_missing() {
        let temp_dir = tempfile::tempdir().unwrap();

        let path_resolver = FakePathResolver::new(Vec::<String>::new());
        let cmd_runner = FakeCommandRunner::new();
        let hasher = Sha256Hasher;

        let prober = Prober::new(cmd_runner, path_resolver, hasher).unwrap();
        let req = make_hash_req("file:scripts/tool.sh", "scripts/tool.sh", "abc123");
        let obs = prober.probe(temp_dir.path(), &req);

        assert!(!obs.present);
        assert_eq!(obs.hash_ok, Some(false));
    }

    proptest! {
        #[test]
        fn version_extraction_never_panics(s in ".*") {
            let re = Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").unwrap();
            let _ = extract_version(&re, &s);
        }
    }
}
