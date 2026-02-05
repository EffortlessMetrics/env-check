//! Pure evaluation logic: map requirements + observations + policy into findings + verdict.

use std::collections::BTreeSet;

use env_check_types::{
    checks, codes, Counts, FailOn, Finding, Location, Observation, PolicyConfig, ProbeKind,
    Requirement, Severity, Verdict, VerdictStatus,
};
use semver::{Version, VersionReq};

#[derive(Debug, Clone)]
pub struct DomainOutcome {
    pub findings: Vec<Finding>,
    pub verdict: Verdict,
    pub truncated: bool,
    pub requirements_total: usize,
    pub requirements_failed: usize,
}

/// Evaluate the environment given normalized requirements and probe observations.
///
/// This function is pure (no IO). Determinism is enforced by explicit sorting.
pub fn evaluate(
    requirements: &[Requirement],
    observations: &[Observation],
    policy: &PolicyConfig,
    sources_used: &[String],
) -> DomainOutcome {
    evaluate_with_extras(requirements, observations, policy, sources_used, &[])
}

pub fn evaluate_with_extras(
    requirements: &[Requirement],
    observations: &[Observation],
    policy: &PolicyConfig,
    sources_used: &[String],
    extra_findings: &[Finding],
) -> DomainOutcome {
    // One observation per requirement is expected. If callers dedupe requirements,
    // this also dedupes probes.
    let mut findings: Vec<Finding> = vec![];
    let mut failed = 0usize;

    for (req, obs) in requirements.iter().zip(observations.iter()) {
        let mut local = eval_one(req, obs, policy);
        if local.iter().any(|f| matches!(f.severity, Severity::Error)) {
            failed += 1;
        }
        findings.append(&mut local);
    }

    // Extra findings (e.g., source parse errors) are evaluated here so policy and truncation apply uniformly.
    findings.extend(extra_findings.iter().cloned());

    // Stable ordering.
    findings.sort_by(|a, b| {
        env_check_types::finding_sort_key(a).cmp(&env_check_types::finding_sort_key(b))
    });

    let max = policy.max_findings.unwrap_or(usize::MAX);
    let mut truncated = false;
    if findings.len() > max {
        findings.truncate(max);
        truncated = true;
    }

    let counts = count(&findings);
    let mut reasons = reasons(&findings);

    if truncated {
        reasons.push("truncated".to_string());
    }

    let status = compute_status(&counts, &policy.fail_on, sources_used.is_empty());

    DomainOutcome {
        findings,
        verdict: Verdict {
            status,
            counts,
            reasons,
        },
        truncated,
        requirements_total: requirements.len(),
        requirements_failed: failed,
    }
}

fn eval_one(req: &Requirement, obs: &Observation, policy: &PolicyConfig) -> Vec<Finding> {
    let mut out = vec![];

    // Probe runtime errors: present tool but probe crashed/failed to execute.
    if obs.present
        && !obs.probe.cmd.is_empty()
        && obs.probe.exit.is_none()
        && !obs.probe.stderr.trim().is_empty()
    {
        out.push(Finding {
            severity: severity_for(policy, req.required, "runtime"),
            check_id: Some("tool.runtime".into()),
            code: codes::TOOL_RUNTIME_ERROR.into(),
            message: format!("Failed to probe {}: {}", req.tool, obs.probe.stderr.trim()),
            location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
            help: Some("Ensure the tool is executable on this runner and that PATH is configured correctly.".into()),
            url: None,
            fingerprint: None,
            data: None,
        });
        // Continue; we may still produce a missing/version finding depending on what we know.
    }

    match req.probe_kind {
        ProbeKind::PathTool => {
            if !obs.present {
                out.push(Finding {
                    severity: severity_for(policy, req.required, "missing"),
                    check_id: Some(checks::PRESENCE.into()),
                    code: codes::ENV_MISSING_TOOL.into(),
                    message: format!("Missing tool on PATH: {}", req.tool),
                    location: Some(Location {
                        path: req.source.path.clone(),
                        line: None,
                        col: None,
                    }),
                    help: Some(format!("Install {} and ensure it is on PATH.", req.tool)),
                    url: None,
                    fingerprint: None,
                    data: None,
                });
                return out;
            }

            // Version check.
            if let Some(constraint) = req.constraint.as_deref() {
                if is_presence_only_constraint(constraint) {
                    return out;
                }

                let Some(vo) = &obs.version else {
                    return out;
                };
                let Some(parsed) = vo.parsed.as_deref() else {
                    out.push(Finding {
                        severity: Severity::Warn,
                        check_id: Some(checks::VERSION.into()),
                        code: codes::ENV_VERSION_MISMATCH.into(),
                        message: format!(
                            "Could not parse version for {} (constraint {})",
                            req.tool, constraint
                        ),
                        location: Some(Location {
                            path: req.source.path.clone(),
                            line: None,
                            col: None,
                        }),
                        help: Some(
                            "Ensure the tool prints a standard version string with `--version`."
                                .into(),
                        ),
                        url: None,
                        fingerprint: None,
                        data: None,
                    });
                    return out;
                };

                let ok = satisfies_semverish(constraint, parsed);
                if !ok {
                    out.push(Finding {
                        severity: severity_for(policy, req.required, "version"),
                        check_id: Some(checks::VERSION.into()),
                        code: codes::ENV_VERSION_MISMATCH.into(),
                        message: format!("Version mismatch for {}: have {}, want {}", req.tool, parsed, constraint),
                        location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
                        help: Some("Install a compatible version or update the repo's declared constraint.".into()),
                        url: None,
                        fingerprint: None,
                        data: None,
                    });
                }
            }
        }
        ProbeKind::RustupToolchain => {
            if !obs.present {
                out.push(Finding {
                    severity: severity_for(policy, req.required, "missing"),
                    check_id: Some(checks::PRESENCE.into()),
                    code: codes::ENV_TOOLCHAIN_MISSING.into(),
                    message: "rustup not found; cannot satisfy rust toolchain requirement".into(),
                    location: Some(Location {
                        path: req.source.path.clone(),
                        line: None,
                        col: None,
                    }),
                    help: Some("Install rustup and re-run env-check.".into()),
                    url: None,
                    fingerprint: None,
                    data: None,
                });
                return out;
            }

            if let Some(constraint) = req.constraint.as_deref() {
                // rustup output is stored in obs.version.raw (best-effort)
                let raw = obs.version.as_ref().map(|v| v.raw.as_str()).unwrap_or("");
                if !raw.contains(constraint) {
                    out.push(Finding {
                        severity: severity_for(policy, req.required, "toolchain"),
                        check_id: Some(checks::PRESENCE.into()),
                        code: codes::ENV_TOOLCHAIN_MISSING.into(),
                        message: format!("Rust toolchain not installed: {}", constraint),
                        location: Some(Location {
                            path: req.source.path.clone(),
                            line: None,
                            col: None,
                        }),
                        help: Some(format!("Run: rustup toolchain install {}", constraint)),
                        url: None,
                        fingerprint: None,
                        data: None,
                    });
                }
            }
        }
        ProbeKind::FileHash => {
            // A missing file is a presence issue (hash can't match).
            if !obs.present {
                out.push(Finding {
                    severity: severity_for(policy, req.required, "missing"),
                    check_id: Some(checks::PRESENCE.into()),
                    code: codes::ENV_MISSING_TOOL.into(),
                    message: format!(
                        "Missing repo-local file for hash verification: {}",
                        req.tool
                    ),
                    location: Some(Location {
                        path: req.source.path.clone(),
                        line: None,
                        col: None,
                    }),
                    help: Some(
                        "Ensure the file exists (did you fetch LFS artifacts or submodules?)."
                            .into(),
                    ),
                    url: None,
                    fingerprint: None,
                    data: None,
                });
                return out;
            }

            if let Some(false) = obs.hash_ok {
                out.push(Finding {
                    severity: severity_for(policy, req.required, "hash"),
                    check_id: Some(checks::HASH.into()),
                    code: codes::ENV_HASH_MISMATCH.into(),
                    message: format!("Hash mismatch for {}", req.tool),
                    location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
                    help: Some("Re-fetch the binary or clean the tool cache; the repo hash manifest is the source of truth.".into()),
                    url: None,
                    fingerprint: None,
                    data: None,
                });
            }
        }
    }

    out
}

fn is_presence_only_constraint(c: &str) -> bool {
    matches!(c.trim(), "latest" | "system" | "*" | "default")
}

fn severity_for(policy: &PolicyConfig, required: bool, kind: &str) -> Severity {
    use env_check_types::Profile;

    match policy.profile {
        Profile::Oss => match kind {
            "missing" | "version" | "hash" | "toolchain" => {
                if required {
                    Severity::Warn
                } else {
                    Severity::Info
                }
            }
            "runtime" => Severity::Warn,
            _ => Severity::Warn,
        },
        Profile::Team => match kind {
            "missing" | "toolchain" => {
                if required {
                    Severity::Error
                } else {
                    Severity::Warn
                }
            }
            "version" | "hash" => {
                if required {
                    Severity::Error
                } else {
                    Severity::Warn
                }
            }
            "runtime" => Severity::Error,
            _ => Severity::Warn,
        },
        Profile::Strict => match kind {
            "missing" | "version" | "hash" | "toolchain" | "runtime" => Severity::Error,
            _ => Severity::Error,
        },
    }
}

fn coerce_version(raw: &str) -> Option<Version> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    // semver requires major.minor.patch.
    let parts: Vec<&str> = s.split('.').collect();
    let coerced = match parts.len() {
        1 => format!("{}.0.0", s),
        2 => format!("{}.0", s),
        _ => s.to_string(),
    };

    Version::parse(&coerced).ok()
}

fn satisfies_semverish(constraint: &str, have: &str) -> bool {
    let Some(v) = coerce_version(have) else {
        return false;
    };

    // If constraint is an exact version, semver also accepts it as a requirement.
    let req = match VersionReq::parse(constraint.trim()) {
        Ok(r) => r,
        Err(_) => {
            // Fallback: exact match (string containment) for non-semver constraints.
            return have.trim() == constraint.trim();
        }
    };

    req.matches(&v)
}

fn count(findings: &[Finding]) -> Counts {
    let mut c = Counts::default();
    for f in findings {
        match f.severity {
            Severity::Info => c.info += 1,
            Severity::Warn => c.warn += 1,
            Severity::Error => c.error += 1,
        }
    }
    c
}

fn reasons(findings: &[Finding]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for f in findings {
        match f.code.as_str() {
            codes::ENV_MISSING_TOOL => {
                set.insert("missing_tool".to_string());
            }
            codes::ENV_VERSION_MISMATCH => {
                set.insert("version_mismatch".to_string());
            }
            codes::ENV_HASH_MISMATCH => {
                set.insert("hash_mismatch".to_string());
            }
            codes::ENV_TOOLCHAIN_MISSING => {
                set.insert("toolchain_missing".to_string());
            }
            codes::ENV_SOURCE_PARSE_ERROR => {
                set.insert("source_parse_error".to_string());
            }
            codes::TOOL_RUNTIME_ERROR => {
                set.insert("tool_error".to_string());
            }
            _ => {}
        }
    }
    set.into_iter().collect()
}

fn compute_status(counts: &Counts, fail_on: &FailOn, no_sources: bool) -> VerdictStatus {
    if no_sources {
        return VerdictStatus::Skip;
    }

    if counts.error > 0 {
        return match fail_on {
            FailOn::Never => VerdictStatus::Warn,
            _ => VerdictStatus::Fail,
        };
    }

    if counts.warn > 0 {
        return match fail_on {
            FailOn::Warn => VerdictStatus::Fail,
            _ => VerdictStatus::Warn,
        };
    }

    VerdictStatus::Pass
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_check_types::{
        FailOn, Observation, ProbeKind, ProbeRecord, Profile, Requirement, SourceKind, SourceRef,
    };

    fn req(tool: &str, constraint: Option<&str>) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: constraint.map(|s| s.to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".into(),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }
    }

    fn req_optional(tool: &str, constraint: Option<&str>) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: constraint.map(|s| s.to_string()),
            required: false,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".into(),
            },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }
    }

    fn obs(tool: &str, present: bool, ver: Option<&str>) -> Observation {
        Observation {
            tool: tool.to_string(),
            present,
            version: ver.map(|v| env_check_types::VersionObservation {
                parsed: Some(v.into()),
                raw: v.into(),
            }),
            hash_ok: None,
            probe: ProbeRecord {
                cmd: vec![tool.into(), "--version".into()],
                exit: Some(0),
                stdout: "".into(),
                stderr: "".into(),
            },
        }
    }

    fn obs_missing(tool: &str) -> Observation {
        Observation {
            tool: tool.to_string(),
            present: false,
            version: None,
            hash_ok: None,
            probe: ProbeRecord {
                cmd: vec![],
                exit: None,
                stdout: "".into(),
                stderr: "".into(),
            },
        }
    }

    // ==================== Presence checks by profile ====================

    #[test]
    fn mismatch_is_warn_in_oss() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
        assert_eq!(out.verdict.counts.warn, 1);
    }

    #[test]
    fn missing_tool_is_warn_in_oss() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
        assert_eq!(out.verdict.counts.warn, 1);
    }

    #[test]
    fn missing_tool_is_error_in_team() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
        assert_eq!(out.verdict.counts.error, 1);
    }

    #[test]
    fn missing_tool_is_error_in_strict() {
        let policy = PolicyConfig {
            profile: Profile::Strict,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
        assert_eq!(out.verdict.counts.error, 1);
    }

    #[test]
    fn missing_optional_tool_is_info_in_oss() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req_optional("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.verdict.counts.info, 1);
    }

    #[test]
    fn missing_optional_tool_is_warn_in_team() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req_optional("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
        assert_eq!(out.verdict.counts.warn, 1);
    }

    // ==================== Version matching ====================

    #[test]
    fn exact_version_match_passes() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("20.11.0"))];
        let obs = vec![obs("node", true, Some("20.11.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.findings.len(), 0);
    }

    #[test]
    fn semver_range_satisfied() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("20.11.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.findings.len(), 0);
    }

    #[test]
    fn semver_range_not_satisfied() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
        assert_eq!(out.findings.len(), 1);
        assert!(out.findings[0].message.contains("Version mismatch"));
    }

    #[test]
    fn major_version_constraint_satisfied() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("^20"))];
        let obs = vec![obs("node", true, Some("20.5.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn tilde_version_constraint_satisfied() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("~20.11"))];
        let obs = vec![obs("node", true, Some("20.11.5"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn version_mismatch_is_error_in_strict() {
        let policy = PolicyConfig {
            profile: Profile::Strict,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
        assert_eq!(out.verdict.counts.error, 1);
    }

    #[test]
    fn presence_only_constraint_latest_passes() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("latest"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.findings.len(), 0);
    }

    #[test]
    fn presence_only_constraint_system_passes() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("system"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn presence_only_constraint_star_passes() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("*"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn no_constraint_passes_when_present() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", None)];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.findings.len(), 0);
    }

    // ==================== No sources => skip ====================

    #[test]
    fn no_sources_yields_skip() {
        let policy = PolicyConfig::default();
        let out = evaluate(&[], &[], &policy, &[]);
        assert_eq!(out.verdict.status, VerdictStatus::Skip);
    }

    #[test]
    fn no_sources_but_requirements_still_skips() {
        // Even if there are requirements, empty sources means skip
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs("node", true, Some("20.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[]);
        assert_eq!(out.verdict.status, VerdictStatus::Skip);
    }

    // ==================== Verdict computation with fail_on ====================

    #[test]
    fn fail_on_warn_triggers_fail() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Warn,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        // Oss profile gives warn for mismatch, fail_on=Warn escalates to fail
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
    }

    #[test]
    fn fail_on_warn_passes_without_warnings() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Warn,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("20.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn fail_on_never_never_fails_with_errors() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Never,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        // Team profile gives error for missing, but fail_on=Never downgrades
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
    }

    #[test]
    fn fail_on_never_keeps_warn_status() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Never,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        // Oss profile gives warn for mismatch, fail_on=Never keeps as warn
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
    }

    #[test]
    fn fail_on_error_with_only_warnings_is_warn() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
    }

    #[test]
    fn fail_on_error_with_errors_fails() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
    }

    // ==================== Truncation ====================

    #[test]
    fn truncation_caps_findings() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(2),
        };
        let reqs = vec![
            req("a", Some("1")),
            req("b", Some("1")),
            req("c", Some("1")),
        ];
        let obs = vec![obs_missing("a"), obs_missing("b"), obs_missing("c")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.findings.len(), 2);
        assert!(out.truncated);
        assert!(out.verdict.reasons.contains(&"truncated".to_string()));
    }

    #[test]
    fn no_truncation_when_under_limit() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(10),
        };
        let reqs = vec![req("a", Some("1")), req("b", Some("1"))];
        let obs = vec![obs_missing("a"), obs_missing("b")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.findings.len(), 2);
        assert!(!out.truncated);
        assert!(!out.verdict.reasons.contains(&"truncated".to_string()));
    }

    #[test]
    fn no_truncation_when_exactly_at_limit() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(2),
        };
        let reqs = vec![req("a", Some("1")), req("b", Some("1"))];
        let obs = vec![obs_missing("a"), obs_missing("b")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.findings.len(), 2);
        assert!(!out.truncated);
    }

    #[test]
    fn unlimited_findings_when_max_is_none() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: None,
        };
        let reqs = vec![
            req("a", Some("1")),
            req("b", Some("1")),
            req("c", Some("1")),
            req("d", Some("1")),
            req("e", Some("1")),
        ];
        let obs = vec![
            obs_missing("a"),
            obs_missing("b"),
            obs_missing("c"),
            obs_missing("d"),
            obs_missing("e"),
        ];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.findings.len(), 5);
        assert!(!out.truncated);
    }

    // ==================== Reasons tracking ====================

    #[test]
    fn reasons_include_missing_tool() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("20"))];
        let obs = vec![obs_missing("node")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert!(out.verdict.reasons.contains(&"missing_tool".to_string()));
    }

    #[test]
    fn reasons_include_version_mismatch() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert!(out
            .verdict
            .reasons
            .contains(&"version_mismatch".to_string()));
    }

    #[test]
    fn reasons_are_deduplicated() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some("20")), req("npm", Some("10"))];
        let obs = vec![obs_missing("node"), obs_missing("npm")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        let missing_count = out
            .verdict
            .reasons
            .iter()
            .filter(|r| *r == "missing_tool")
            .count();
        assert_eq!(missing_count, 1);
    }

    // ==================== Requirements counts ====================

    #[test]
    fn requirements_total_is_tracked() {
        let policy = PolicyConfig::default();
        let reqs = vec![
            req("node", Some("20")),
            req("npm", Some("10")),
            req("go", Some("1.21")),
        ];
        let obs = vec![
            obs("node", true, Some("20.0.0")),
            obs("npm", true, Some("10.0.0")),
            obs("go", true, Some("1.21.0")),
        ];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.requirements_total, 3);
    }

    #[test]
    fn requirements_failed_counts_errors() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![
            req("node", Some("20")),
            req("npm", Some("10")),
            req("go", Some("1.21")),
        ];
        let obs = vec![
            obs_missing("node"),
            obs("npm", true, Some("10.0.0")),
            obs_missing("go"),
        ];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.requirements_total, 3);
        assert_eq!(out.requirements_failed, 2);
    }

    // ==================== Sorting ====================

    #[test]
    fn findings_are_sorted_deterministically() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![
            req_optional("opt", Some("1")), // will be warn
            req("required", Some("1")),     // will be error
        ];
        let obs = vec![obs_missing("opt"), obs_missing("required")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        // Findings are sorted by severity rank ascending (Info=1, Warn=2, Error=3), then by path, check_id, code, message
        // So Warn (rank 2) comes before Error (rank 3)
        assert_eq!(out.findings[0].severity, Severity::Warn);
        assert_eq!(out.findings[1].severity, Severity::Error);
    }

    #[test]
    fn findings_sorted_by_path_within_same_severity() {
        let policy = PolicyConfig {
            profile: Profile::Oss,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![
            Requirement {
                tool: "z_tool".to_string(),
                constraint: Some("1".to_string()),
                required: true,
                source: SourceRef {
                    kind: SourceKind::ToolVersions,
                    path: "a_path".into(),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            },
            Requirement {
                tool: "a_tool".to_string(),
                constraint: Some("1".to_string()),
                required: true,
                source: SourceRef {
                    kind: SourceKind::ToolVersions,
                    path: "z_path".into(),
                },
                probe_kind: ProbeKind::PathTool,
                hash: None,
            },
        ];
        let obs = vec![obs_missing("z_tool"), obs_missing("a_tool")];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        // Both are warn, sorted by path: a_path should come before z_path
        assert!(
            out.findings[0].location.as_ref().unwrap().path
                < out.findings[1].location.as_ref().unwrap().path
        );
    }

    // ==================== Multiple tools ====================

    #[test]
    fn multiple_tools_all_pass() {
        let policy = PolicyConfig::default();
        let reqs = vec![
            req("node", Some("20")),
            req("npm", Some("10")),
            req("go", Some("1.21")),
        ];
        let obs = vec![
            obs("node", true, Some("20.0.0")),
            obs("npm", true, Some("10.0.0")),
            obs("go", true, Some("1.21.0")),
        ];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
        assert_eq!(out.findings.len(), 0);
    }

    #[test]
    fn mixed_pass_warn_fail() {
        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Error,
            max_findings: Some(100),
        };
        let reqs = vec![
            req("node", Some("20")),  // will pass
            req("npm", Some(">=10")), // will fail version
            req("go", Some("1.21")),  // will be missing
        ];
        let obs = vec![
            obs("node", true, Some("20.0.0")),
            obs("npm", true, Some("9.0.0")),
            obs_missing("go"),
        ];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Fail);
        assert_eq!(out.verdict.counts.error, 2); // version mismatch + missing
    }

    // ==================== Edge cases ====================

    #[test]
    fn empty_requirements_with_sources_passes() {
        let policy = PolicyConfig::default();
        let out = evaluate(&[], &[], &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn coerce_version_handles_single_number() {
        // Version "20" should be coerced to "20.0.0"
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("21"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }

    #[test]
    fn coerce_version_handles_two_numbers() {
        // Version "20.11" should be coerced to "20.11.0"
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20.10"))];
        let obs = vec![obs("node", true, Some("20.11"))];
        let out = evaluate(&reqs, &obs, &policy, &[".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Pass);
    }
}
