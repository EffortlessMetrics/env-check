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
pub fn evaluate(requirements: &[Requirement], observations: &[Observation], policy: &PolicyConfig, sources_used: &[String]) -> DomainOutcome {
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
    findings.sort_by(|a, b| env_check_types::finding_sort_key(a).cmp(&env_check_types::finding_sort_key(b)));

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
        verdict: Verdict { status, counts, reasons },
        truncated,
        requirements_total: requirements.len(),
        requirements_failed: failed,
    }
}

fn eval_one(req: &Requirement, obs: &Observation, policy: &PolicyConfig) -> Vec<Finding> {
    let mut out = vec![];

    // Probe runtime errors: present tool but probe crashed/failed to execute.
    if obs.present && !obs.probe.cmd.is_empty() && obs.probe.exit.is_none() && !obs.probe.stderr.trim().is_empty() {
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
                    location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
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

                let Some(vo) = &obs.version else { return out; };
                let Some(parsed) = vo.parsed.as_deref() else {
                    out.push(Finding {
                        severity: Severity::Warn,
                        check_id: Some(checks::VERSION.into()),
                        code: codes::ENV_VERSION_MISMATCH.into(),
                        message: format!("Could not parse version for {} (constraint {})", req.tool, constraint),
                        location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
                        help: Some("Ensure the tool prints a standard version string with `--version`.".into()),
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
                    location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
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
                        location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
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
                    message: format!("Missing repo-local file for hash verification: {}", req.tool),
                    location: Some(Location { path: req.source.path.clone(), line: None, col: None }),
                    help: Some("Ensure the file exists (did you fetch LFS artifacts or submodules?).".into()),
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
                if required { Severity::Warn } else { Severity::Info }
            }
            "runtime" => Severity::Warn,
            _ => Severity::Warn,
        },
        Profile::Team => match kind {
            "missing" | "toolchain" => if required { Severity::Error } else { Severity::Warn },
            "version" | "hash" => if required { Severity::Error } else { Severity::Warn },
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
    let Some(v) = coerce_version(have) else { return false; };

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
            codes::ENV_MISSING_TOOL => { set.insert("missing_tool".to_string()); }
            codes::ENV_VERSION_MISMATCH => { set.insert("version_mismatch".to_string()); }
            codes::ENV_HASH_MISMATCH => { set.insert("hash_mismatch".to_string()); }
            codes::ENV_TOOLCHAIN_MISSING => { set.insert("toolchain_missing".to_string()); }
            codes::ENV_SOURCE_PARSE_ERROR => { set.insert("source_parse_error".to_string()); }
            codes::TOOL_RUNTIME_ERROR => { set.insert("tool_error".to_string()); }
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
    use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef, Observation, ProbeRecord};

    fn req(tool: &str, constraint: Option<&str>) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: constraint.map(|s| s.to_string()),
            required: true,
            source: SourceRef { kind: SourceKind::ToolVersions, path: ".tool-versions".into() },
            probe_kind: ProbeKind::PathTool,
            hash: None,
        }
    }

    fn obs(tool: &str, present: bool, ver: Option<&str>) -> Observation {
        Observation {
            tool: tool.to_string(),
            present,
            version: ver.map(|v| env_check_types::VersionObservation { parsed: Some(v.into()), raw: v.into() }),
            hash_ok: None,
            probe: ProbeRecord { cmd: vec![tool.into(), "--version".into()], exit: Some(0), stdout: "".into(), stderr: "".into() },
        }
    }

    #[test]
    fn mismatch_is_warn_in_oss() {
        let policy = PolicyConfig::default();
        let reqs = vec![req("node", Some(">=20"))];
        let obs = vec![obs("node", true, Some("18.0.0"))];
        let out = evaluate(&reqs, &obs, &policy, &vec![".tool-versions".into()]);
        assert_eq!(out.verdict.status, VerdictStatus::Warn);
        assert_eq!(out.verdict.counts.warn, 1);
    }
}
