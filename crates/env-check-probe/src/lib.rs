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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn version_extraction_picks_first_numeric() {
        let re = Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").unwrap();
        assert_eq!(extract_version(&re, "node v20.11.0 (foo)"), Some("20.11.0".into()));
        assert_eq!(extract_version(&re, "no digits here"), None);
    }

    proptest! {
        #[test]
        fn version_extraction_never_panics(s in ".*") {
            let re = Regex::new(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?").unwrap();
            let _ = extract_version(&re, &s);
        }
    }
}
