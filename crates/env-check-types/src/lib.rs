//! Shared DTOs and stable codes for env-check.
//!
//! This crate is deliberately boring: it should be safe to depend on from
//! any layer (domain, renderers, adapters).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const TOOL_NAME: &str = "env-check";
pub const SCHEMA_ID: &str = "env-check.report.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Error => 3,
            Severity::Warn => 2,
            Severity::Info => 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Pass,
    Warn,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Counts {
    pub info: u32,
    pub warn: u32,
    pub error: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolMeta {
    pub name: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunMeta {
    pub started_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci: Option<CiMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git: Option<GitMeta>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostMeta {
    pub os: String,
    pub arch: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CiMeta {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitMeta {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub head_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub merge_base: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Verdict {
    pub status: VerdictStatus,
    pub counts: Counts,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_id: Option<String>,
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<Location>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptEnvelope {
    pub schema: String,
    pub tool: ToolMeta,
    pub run: RunMeta,
    pub verdict: Verdict,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

/// A single normalized tool requirement derived from repo sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    pub tool: String,
    pub constraint: Option<String>,
    pub required: bool,
    pub source: SourceRef,
    pub probe_kind: ProbeKind,
    pub hash: Option<HashSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceRef {
    pub kind: SourceKind,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    ToolVersions,
    MiseToml,
    RustToolchain,
    HashManifest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    PathTool,         // `<tool> --version`
    RustupToolchain,  // `rustup toolchain list` + rust-toolchain
    FileHash,         // sha256 on repo-local file
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashSpec {
    pub algo: HashAlgo,
    pub hex: String,
    pub path: String, // repo-relative path
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
}

/// Observation produced by probing the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub tool: String,
    pub present: bool,
    pub version: Option<VersionObservation>,
    pub hash_ok: Option<bool>,
    pub probe: ProbeRecord,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionObservation {
    pub parsed: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRecord {
    pub cmd: Vec<String>,
    pub exit: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Oss,
    Team,
    Strict,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailOn {
    Error,
    Warn,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyConfig {
    pub profile: Profile,
    pub fail_on: FailOn,
    #[serde(default)]
    pub max_findings: Option<usize>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EnvCheckError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

pub mod codes {
    // Keep these stable. This is the external API.
    pub const ENV_MISSING_TOOL: &str = "env.missing_tool";
    pub const ENV_VERSION_MISMATCH: &str = "env.version_mismatch";
    pub const ENV_HASH_MISMATCH: &str = "env.hash_mismatch";
    pub const ENV_TOOLCHAIN_MISSING: &str = "env.toolchain_missing";
    pub const ENV_SOURCE_PARSE_ERROR: &str = "env.source_parse_error";

    pub const TOOL_RUNTIME_ERROR: &str = "tool.runtime_error";
}

pub mod checks {
    // Stable producer IDs. Also part of the API.
    pub const PRESENCE: &str = "env.presence";
    pub const VERSION: &str = "env.version";
    pub const HASH: &str = "env.hash";
    pub const SOURCE_PARSE: &str = "env.source_parse";
}

/// Sorting key used to ensure deterministic findings order.
pub fn finding_sort_key(f: &Finding) -> (u8, String, String, String, String) {
    let sev = f.severity.rank();
    let path = f.location.as_ref().map(|l| l.path.clone()).unwrap_or_default();
    let check_id = f.check_id.clone().unwrap_or_default();
    (sev, path, check_id, f.code.clone(), f.message.clone())
}
