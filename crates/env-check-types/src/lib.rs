//! Shared DTOs and stable codes for env-check.
//!
//! This crate is deliberately boring: it should be safe to depend on from
//! any layer (domain, renderers, adapters).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const TOOL_NAME: &str = "env-check";
pub const SCHEMA_ID: &str = "sensor.report.v1";

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

/// Status of a single sensor capability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityStatus {
    Available,
    Unavailable,
    Skipped,
}

/// A single capability entry with status and optional reason.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEntry {
    pub status: CapabilityStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Declares what the sensor actually checked ("No Green By Omission").
///
/// This allows downstream consumers to distinguish between:
/// - "We checked for X and found nothing wrong" (capability available, no findings)
/// - "We didn't check for X at all" (capability unavailable/skipped)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Capabilities {
    /// Whether git metadata was detected and used.
    pub git: CapabilityEntry,
    /// Whether baseline comparison was performed.
    pub baseline: CapabilityEntry,
    /// Whether input source files were discovered and parsed.
    pub inputs: CapabilityEntry,
    /// Whether the probe engine ran checks.
    pub engine: CapabilityEntry,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workflow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pr_number: Option<u64>,
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

/// A pointer to a depth artifact produced alongside the receipt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    /// Relative path from the receipt file to the artifact.
    pub path: String,
    /// Machine-readable kind (e.g. `"debug_log"`).
    pub kind: String,
    /// Optional human description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ArtifactRef {
    /// Returns `true` if the artifact path is safe to embed in a receipt.
    ///
    /// A safe path is:
    /// - Not empty
    /// - Not absolute (no leading `/`, no Windows drive letter like `C:/`)
    /// - Forward-slash only (no backslashes)
    /// - No `..` traversal components
    pub fn is_safe(&self) -> bool {
        let p = &self.path;
        if p.is_empty() {
            return false;
        }
        // No backslashes
        if p.contains('\\') {
            return false;
        }
        // No absolute unix paths
        if p.starts_with('/') {
            return false;
        }
        // No Windows drive letters (e.g. C:/ or D:\)
        if p.len() >= 2 && p.as_bytes()[1] == b':' && p.as_bytes()[0].is_ascii_alphabetic() {
            return false;
        }
        // No .. traversal components
        for component in p.split('/') {
            if component == ".." {
                return false;
            }
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReceiptEnvelope {
    pub schema: String,
    pub tool: ToolMeta,
    pub run: RunMeta,
    pub verdict: Verdict,
    #[serde(default)]
    pub findings: Vec<Finding>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactRef>,
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
    NodeVersion,
    Nvmrc,
    PackageJson,
    PythonVersion,
    PyprojectToml,
    GoMod,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeKind {
    PathTool,        // `<tool> --version`
    RustupToolchain, // `rustup toolchain list` + rust-toolchain
    FileHash,        // sha256 on repo-local file
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
pub fn finding_sort_key(f: &Finding) -> (std::cmp::Reverse<u8>, String, String, String, String) {
    let sev = std::cmp::Reverse(f.severity.rank());
    let path = f
        .location
        .as_ref()
        .map(|l| l.path.clone())
        .unwrap_or_default();
    let check_id = f.check_id.clone().unwrap_or_default();
    (sev, path, check_id, f.code.clone(), f.message.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_status_serializes_to_snake_case() {
        let json = serde_json::to_string(&CapabilityStatus::Available).unwrap();
        assert_eq!(json, "\"available\"");
        let json = serde_json::to_string(&CapabilityStatus::Unavailable).unwrap();
        assert_eq!(json, "\"unavailable\"");
        let json = serde_json::to_string(&CapabilityStatus::Skipped).unwrap();
        assert_eq!(json, "\"skipped\"");
    }

    #[test]
    fn capability_entry_serialization_round_trip() {
        let entry = CapabilityEntry {
            status: CapabilityStatus::Available,
            reason: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: CapabilityEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
        // reason=None should be omitted
        assert!(!json.contains("reason"));
    }

    #[test]
    fn capability_entry_with_reason() {
        let entry = CapabilityEntry {
            status: CapabilityStatus::Unavailable,
            reason: Some("no git repository detected".into()),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["status"], "unavailable");
        assert_eq!(value["reason"], "no git repository detected");
    }

    #[test]
    fn capabilities_serialization_round_trip() {
        let caps = Capabilities {
            git: CapabilityEntry {
                status: CapabilityStatus::Available,
                reason: None,
            },
            baseline: CapabilityEntry {
                status: CapabilityStatus::Skipped,
                reason: Some("env-check does not use baseline comparison".into()),
            },
            inputs: CapabilityEntry {
                status: CapabilityStatus::Available,
                reason: None,
            },
            engine: CapabilityEntry {
                status: CapabilityStatus::Available,
                reason: None,
            },
        };

        let json = serde_json::to_string(&caps).unwrap();
        let parsed: Capabilities = serde_json::from_str(&json).unwrap();

        assert_eq!(caps, parsed);
    }

    #[test]
    fn run_meta_with_capabilities() {
        use chrono::TimeZone;

        let run = RunMeta {
            started_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
            ended_at: None,
            duration_ms: None,
            host: None,
            ci: None,
            git: None,
            capabilities: Some(Capabilities {
                git: CapabilityEntry {
                    status: CapabilityStatus::Available,
                    reason: None,
                },
                baseline: CapabilityEntry {
                    status: CapabilityStatus::Skipped,
                    reason: Some("not supported".into()),
                },
                inputs: CapabilityEntry {
                    status: CapabilityStatus::Available,
                    reason: None,
                },
                engine: CapabilityEntry {
                    status: CapabilityStatus::Available,
                    reason: None,
                },
            }),
        };

        let json = serde_json::to_string(&run).unwrap();
        let parsed: RunMeta = serde_json::from_str(&json).unwrap();

        assert_eq!(run, parsed);
        assert!(parsed.capabilities.is_some());
        assert_eq!(
            parsed.capabilities.as_ref().unwrap().git.status,
            CapabilityStatus::Available
        );
    }

    #[test]
    fn run_meta_without_capabilities_backward_compatible() {
        // JSON without capabilities field should deserialize successfully
        let json = r#"{"started_at":"2024-01-01T00:00:00Z"}"#;
        let parsed: RunMeta = serde_json::from_str(json).unwrap();

        assert!(parsed.capabilities.is_none());
    }

    #[test]
    fn artifact_ref_serialization_round_trip() {
        let artifact = ArtifactRef {
            path: "extras/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: Some("Probe debug transcript".to_string()),
        };
        let json = serde_json::to_string(&artifact).unwrap();
        let parsed: ArtifactRef = serde_json::from_str(&json).unwrap();
        assert_eq!(artifact, parsed);
    }

    #[test]
    fn artifact_ref_omits_none_description() {
        let artifact = ArtifactRef {
            path: "extras/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        let json = serde_json::to_string(&artifact).unwrap();
        assert!(!json.contains("description"));
    }

    #[test]
    fn receipt_envelope_omits_empty_artifacts() {
        use chrono::TimeZone;
        let receipt = ReceiptEnvelope {
            schema: "sensor.report.v1".to_string(),
            tool: ToolMeta {
                name: "env-check".to_string(),
                version: "0.1.0".to_string(),
                commit: None,
            },
            run: RunMeta {
                started_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
                ended_at: None,
                duration_ms: None,
                host: None,
                ci: None,
                git: None,
                capabilities: None,
            },
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: Counts::default(),
                reasons: vec![],
            },
            findings: vec![],
            artifacts: vec![],
            data: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(!json.contains("artifacts"), "empty artifacts should be omitted");
    }

    #[test]
    fn receipt_envelope_includes_nonempty_artifacts() {
        use chrono::TimeZone;
        let receipt = ReceiptEnvelope {
            schema: "sensor.report.v1".to_string(),
            tool: ToolMeta {
                name: "env-check".to_string(),
                version: "0.1.0".to_string(),
                commit: None,
            },
            run: RunMeta {
                started_at: Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap(),
                ended_at: None,
                duration_ms: None,
                host: None,
                ci: None,
                git: None,
                capabilities: None,
            },
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: Counts::default(),
                reasons: vec![],
            },
            findings: vec![],
            artifacts: vec![ArtifactRef {
                path: "extras/raw.log".to_string(),
                kind: "debug_log".to_string(),
                description: Some("Probe debug transcript".to_string()),
            }],
            data: None,
        };
        let json = serde_json::to_string(&receipt).unwrap();
        assert!(json.contains("artifacts"), "non-empty artifacts should be serialized");
        assert!(json.contains("extras/raw.log"));
    }

    #[test]
    fn receipt_envelope_without_artifacts_field_deserializes() {
        // Backward compatibility: JSON without artifacts field should deserialize
        let json = r#"{
            "schema": "sensor.report.v1",
            "tool": {"name": "env-check", "version": "0.1.0"},
            "run": {"started_at": "2024-01-01T00:00:00Z"},
            "verdict": {"status": "pass", "counts": {"info": 0, "warn": 0, "error": 0}},
            "findings": []
        }"#;
        let parsed: ReceiptEnvelope = serde_json::from_str(json).unwrap();
        assert!(parsed.artifacts.is_empty());
    }

    // =========================================================================
    // Serde + defaults
    // =========================================================================

    #[test]
    fn severity_serializes_to_snake_case() {
        assert_eq!(serde_json::to_string(&Severity::Info).unwrap(), "\"info\"");
        assert_eq!(serde_json::to_string(&Severity::Warn).unwrap(), "\"warn\"");
        assert_eq!(serde_json::to_string(&Severity::Error).unwrap(), "\"error\"");
    }

    #[test]
    fn verdict_status_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Pass).unwrap(),
            "\"pass\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Warn).unwrap(),
            "\"warn\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Fail).unwrap(),
            "\"fail\""
        );
        assert_eq!(
            serde_json::to_string(&VerdictStatus::Skip).unwrap(),
            "\"skip\""
        );
    }

    #[test]
    fn profile_and_fail_on_serialization() {
        assert_eq!(serde_json::to_string(&Profile::Oss).unwrap(), "\"oss\"");
        assert_eq!(serde_json::to_string(&Profile::Team).unwrap(), "\"team\"");
        assert_eq!(serde_json::to_string(&Profile::Strict).unwrap(), "\"strict\"");
        assert_eq!(serde_json::to_string(&FailOn::Error).unwrap(), "\"error\"");
        assert_eq!(serde_json::to_string(&FailOn::Warn).unwrap(), "\"warn\"");
        assert_eq!(serde_json::to_string(&FailOn::Never).unwrap(), "\"never\"");
    }

    #[test]
    fn policy_config_default_values() {
        let cfg = PolicyConfig::default();
        assert!(matches!(cfg.profile, Profile::Oss));
        assert!(matches!(cfg.fail_on, FailOn::Error));
        assert_eq!(cfg.max_findings, Some(100));
    }

    // =========================================================================
    // ArtifactRef::is_safe() tests
    // =========================================================================

    #[test]
    fn artifact_ref_is_safe_valid_relative_path() {
        let a = ArtifactRef {
            path: "extras/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_empty() {
        let a = ArtifactRef {
            path: "".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_absolute_unix() {
        let a = ArtifactRef {
            path: "/tmp/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_absolute_windows() {
        let a = ArtifactRef {
            path: "C:/Users/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_backslash() {
        let a = ArtifactRef {
            path: "extras\\raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_dotdot_at_start() {
        let a = ArtifactRef {
            path: "../secret/raw.log".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn artifact_ref_is_safe_rejects_dotdot_mid_path() {
        let a = ArtifactRef {
            path: "extras/../../../etc/passwd".to_string(),
            kind: "debug_log".to_string(),
            description: None,
        };
        assert!(!a.is_safe());
    }

    #[test]
    fn severity_rank_orders_correctly() {
        assert!(Severity::Error.rank() > Severity::Warn.rank());
        assert!(Severity::Warn.rank() > Severity::Info.rank());
    }

    #[test]
    fn finding_sort_key_orders_by_severity_and_path() {
        let mut findings = [
            Finding {
                severity: Severity::Info,
                check_id: Some("b".into()),
                code: "code_b".into(),
                message: "msg_b".into(),
                location: Some(Location {
                    path: "b.txt".into(),
                    line: None,
                    col: None,
                }),
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Error,
                check_id: Some("a".into()),
                code: "code_a".into(),
                message: "msg_a".into(),
                location: Some(Location {
                    path: "a.txt".into(),
                    line: None,
                    col: None,
                }),
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Warn,
                check_id: Some("c".into()),
                code: "code_c".into(),
                message: "msg_c".into(),
                location: None, // empty path should sort before "z.txt" if same severity
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Warn,
                check_id: Some("d".into()),
                code: "code_d".into(),
                message: "msg_d".into(),
                location: Some(Location {
                    path: "z.txt".into(),
                    line: None,
                    col: None,
                }),
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
        ];

        findings.sort_by_key(finding_sort_key);

        assert_eq!(findings[0].severity, Severity::Error);
        assert_eq!(findings[1].severity, Severity::Warn);
        assert_eq!(findings[2].severity, Severity::Warn);
        assert_eq!(findings[3].severity, Severity::Info);

        // For equal severity (warn), empty path sorts before "z.txt"
        assert!(findings[1].location.is_none());
        assert_eq!(findings[2].location.as_ref().unwrap().path, "z.txt");
    }
}
