//! Deterministic receipt report assembly helpers.

use env_check_domain::DomainOutcome;
use env_check_evidence::{dependency_graph, probe_kinds, source_kinds, summarize_probes};
use env_check_sources::ParsedSources;
use env_check_types::{
    Capabilities, CapabilityEntry, CapabilityStatus, GitMeta, Observation, PolicyConfig,
    Requirement,
};

/// Build the `data` envelope portion for a receipt.
pub fn build_data(
    policy: &PolicyConfig,
    parsed: &ParsedSources,
    requirements: &[Requirement],
    observations: &[Observation],
    outcome: &DomainOutcome,
) -> serde_json::Value {
    use serde_json::json;

    let observed_source_kinds = source_kinds(&parsed.sources_used);
    let observed_probe_kinds = probe_kinds(requirements);
    let probes = summarize_probes(requirements, observations);
    let dependencies = dependency_graph(requirements);

    let mut data = json!({
        "profile": match policy.profile {
            env_check_types::Profile::Oss => "oss",
            env_check_types::Profile::Team => "team",
            env_check_types::Profile::Strict => "strict",
        },
        "fail_on": match policy.fail_on {
            env_check_types::FailOn::Error => "error",
            env_check_types::FailOn::Warn => "warn",
            env_check_types::FailOn::Never => "never",
        },
        "sources_used": parsed.sources_used.iter().map(|s| s.path.clone()).collect::<Vec<_>>(),
        "requirements_total": outcome.requirements_total,
        "requirements_failed": outcome.requirements_failed,
        "probes": probes,
        "dependencies": dependencies,
        "truncated": outcome.truncated,
        "observed": {
            "source_kinds": observed_source_kinds,
            "probe_kinds": observed_probe_kinds,
        },
    });

    if !parsed.source_data.is_empty() {
        if let Some(data_obj) = data.as_object_mut() {
            let mut source_data_obj = serde_json::Map::new();
            for (path, value) in &parsed.source_data {
                source_data_obj.insert(path.clone(), value.clone());
            }
            data_obj.insert(
                "source_data".to_string(),
                serde_json::Value::Object(source_data_obj),
            );
        }
    }

    data
}

/// Build capabilities block declaring what the sensor actually checked.
///
/// This enables "No Green By Omission" - consumers can distinguish between
/// "we checked and found nothing wrong" vs "we didn't check at all".
pub fn build_capabilities(
    parsed: &ParsedSources,
    requirements: &[Requirement],
    git: Option<&GitMeta>,
) -> Capabilities {
    Capabilities {
        git: CapabilityEntry {
            status: if git.is_some() {
                CapabilityStatus::Available
            } else {
                CapabilityStatus::Unavailable
            },
            reason: if git.is_none() {
                Some("not_a_git_repo".into())
            } else {
                None
            },
        },
        baseline: CapabilityEntry {
            status: CapabilityStatus::Skipped,
            reason: Some("not_applicable".into()),
        },
        inputs: CapabilityEntry {
            status: if parsed.sources_used.is_empty() {
                CapabilityStatus::Unavailable
            } else {
                CapabilityStatus::Available
            },
            reason: if parsed.sources_used.is_empty() {
                Some("no_sources_found".into())
            } else {
                None
            },
        },
        engine: CapabilityEntry {
            status: if requirements.is_empty() {
                CapabilityStatus::Skipped
            } else {
                CapabilityStatus::Available
            },
            reason: if requirements.is_empty() {
                Some("no_requirements".into())
            } else {
                None
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_check_types::{
        Counts, FailOn, Observation, PolicyConfig, ProbeKind, ProbeRecord, Profile, SourceKind,
        SourceRef, Verdict, VerdictStatus, VersionObservation,
    };
    use std::collections::BTreeMap;

    fn make_req(
        tool: &str,
        ver: &str,
        required: bool,
        probe_kind: ProbeKind,
    ) -> env_check_types::Requirement {
        env_check_types::Requirement {
            tool: tool.to_string(),
            constraint: Some(ver.to_string()),
            required,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: "test".to_string(),
            },
            probe_kind,
            hash: None,
        }
    }

    #[test]
    fn build_data_adds_required_fields() {
        let parsed = ParsedSources {
            sources_used: vec![
                SourceRef {
                    kind: SourceKind::ToolVersions,
                    path: "a".into(),
                },
                SourceRef {
                    kind: SourceKind::ToolVersions,
                    path: "b".into(),
                },
            ],
            requirements: vec![],
            findings: vec![],
            source_data: BTreeMap::new(),
        };

        let reqs = vec![make_req("node", "20", true, ProbeKind::PathTool)];
        let outcome = DomainOutcome {
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: Counts::default(),
                reasons: vec![],
            },
            truncated: false,
            requirements_total: 1,
            requirements_failed: 0,
        };
        let obs = vec![Observation {
            tool: "node".into(),
            present: true,
            version: Some(VersionObservation {
                parsed: Some("20.0.0".into()),
                raw: "20".into(),
            }),
            hash_ok: None,
            probe: ProbeRecord {
                cmd: vec!["node".into()],
                exit: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            },
        }];
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };

        let data = build_data(&policy, &parsed, &reqs, &obs, &outcome);
        assert_eq!(data["profile"], "oss");
        assert_eq!(data["fail_on"], "error");
        assert!(data.get("probes").and_then(|v| v.as_array()).is_some());
        assert!(
            data.get("dependencies")
                .and_then(|v| v.as_object())
                .is_some()
        );
    }

    #[test]
    fn build_capabilities_reflect_inputs_and_engine() {
        let parsed_empty = ParsedSources {
            sources_used: vec![],
            requirements: vec![],
            findings: vec![],
            source_data: BTreeMap::new(),
        };

        let caps = build_capabilities(&parsed_empty, &[], None);
        assert_eq!(caps.inputs.status, CapabilityStatus::Unavailable);
        assert_eq!(caps.engine.status, CapabilityStatus::Skipped);

        let parsed = ParsedSources {
            sources_used: vec![SourceRef {
                kind: SourceKind::ToolVersions,
                path: "x".into(),
            }],
            requirements: vec![make_req("node", "20", true, ProbeKind::PathTool)],
            findings: vec![],
            source_data: BTreeMap::new(),
        };
        let caps = build_capabilities(&parsed, &parsed.requirements, None);
        assert_eq!(caps.inputs.status, CapabilityStatus::Available);
        assert_eq!(caps.engine.status, CapabilityStatus::Available);
    }
}
