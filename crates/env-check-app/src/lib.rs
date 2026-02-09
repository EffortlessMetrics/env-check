//! Composition root for env-check.
//!
//! This crate wires sources + probes + domain evaluation and writes artifacts.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use env_check_domain::DomainOutcome;
use env_check_probe::{
    Clock, FileLogWriter, LoggingCommandRunner, OsCommandRunner, OsPathResolver, Prober,
    Sha256Hasher, SystemClock,
};
use env_check_sources::ParsedSources;
use env_check_types::{
    Capabilities, CapabilityEntry, CapabilityStatus, CiMeta, Counts, FailOn, Finding, GitMeta,
    HostMeta, Observation, PolicyConfig, Profile, ReceiptEnvelope, Requirement, RunMeta, SCHEMA_ID,
    Severity, SourceKind, TOOL_NAME, ToolMeta, Verdict, VerdictStatus, codes,
};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub profile: Option<Profile>,
    #[serde(default)]
    pub fail_on: Option<FailOn>,
    #[serde(default)]
    pub hash_manifests: Vec<String>,
    #[serde(default)]
    pub ignore_tools: Vec<String>,
    #[serde(default)]
    pub force_required: Vec<String>,
}

pub struct CheckOutput {
    pub receipt: ReceiptEnvelope,
    pub markdown: String,
    pub exit_code: i32,
}

/// Options for running env-check with additional configuration.
#[derive(Debug, Clone, Default)]
pub struct CheckOptions {
    /// Optional path to write debug log output.
    /// This is a side artifact and does NOT affect receipt determinism.
    pub debug_log_path: Option<PathBuf>,
}

/// Run env-check end-to-end (backwards compatible wrapper).
pub fn run_check(
    root: &Path,
    config_path: Option<&Path>,
    profile: Profile,
    fail_on: FailOn,
) -> anyhow::Result<CheckOutput> {
    run_check_with_options(root, config_path, profile, fail_on, CheckOptions::default())
}

/// Run env-check end-to-end with additional options.
pub fn run_check_with_options(
    root: &Path,
    config_path: Option<&Path>,
    profile: Profile,
    fail_on: FailOn,
    options: CheckOptions,
) -> anyhow::Result<CheckOutput> {
    run_check_with_clock(root, config_path, profile, fail_on, options, &SystemClock)
}

/// Run env-check end-to-end with a custom clock (for deterministic testing).
pub fn run_check_with_clock(
    root: &Path,
    config_path: Option<&Path>,
    profile: Profile,
    fail_on: FailOn,
    options: CheckOptions,
    clock: &dyn Clock,
) -> anyhow::Result<CheckOutput> {
    let started = clock.now();

    let mut cfg = load_config(root, config_path)?;
    if cfg.hash_manifests.is_empty() {
        cfg.hash_manifests.push("scripts/tools.sha256".into());
    }

    let effective_profile = cfg.profile.clone().unwrap_or(profile);
    let effective_fail_on = cfg.fail_on.clone().unwrap_or(fail_on);
    let policy = PolicyConfig {
        profile: effective_profile,
        fail_on: effective_fail_on,
        max_findings: Some(100),
    };

    let manifests: Vec<PathBuf> = cfg.hash_manifests.iter().map(PathBuf::from).collect();

    let parsed = env_check_sources::parse_all(root, &manifests);
    let sources_used: Vec<String> = parsed.sources_used.iter().map(|s| s.path.clone()).collect();

    // Normalize requirements for determinism and policy overrides.
    let requirements = normalize_requirements(parsed.requirements.clone(), &cfg);

    // Probe with optional debug logging.
    let observations = probe_requirements(root, &requirements, &options)?;

    // Evaluate.
    let outcome = env_check_domain::evaluate_with_extras(
        &requirements,
        &observations,
        &policy,
        &sources_used,
        &parsed.findings,
    );

    let ended = clock.now();
    let duration_ms = ended
        .signed_duration_since(started)
        .num_milliseconds()
        .max(0) as u64;

    // Build receipt envelope.
    let data = build_data(&policy, &parsed, &requirements, &outcome);
    let git = detect_git(root);
    let capabilities = build_capabilities(&parsed, &requirements, git.as_ref());

    let receipt = ReceiptEnvelope {
        schema: SCHEMA_ID.to_string(),
        tool: ToolMeta {
            name: TOOL_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: None,
        },
        run: RunMeta {
            started_at: started,
            ended_at: Some(ended),
            duration_ms: Some(duration_ms),
            host: detect_host(),
            ci: detect_ci(),
            git,
            capabilities: Some(capabilities),
        },
        verdict: outcome.verdict.clone(),
        findings: outcome.findings.clone(),
        artifacts: vec![],
        data: Some(data),
    };

    // Render markdown.
    let markdown = env_check_render::render_markdown(&receipt);

    // Exit code mapping: policy semantics are already reflected in verdict.status.
    let exit_code = match receipt.verdict.status {
        env_check_types::VerdictStatus::Pass
        | env_check_types::VerdictStatus::Warn
        | env_check_types::VerdictStatus::Skip => 0,
        env_check_types::VerdictStatus::Fail => 2,
    };

    Ok(CheckOutput {
        receipt,
        markdown,
        exit_code,
    })
}

/// Probe requirements, optionally with debug logging.
fn probe_requirements(
    root: &Path,
    requirements: &[Requirement],
    options: &CheckOptions,
) -> anyhow::Result<Vec<Observation>> {
    if let Some(log_path) = &options.debug_log_path {
        // Use logging command runner
        let log_writer = FileLogWriter::new(log_path)
            .with_context(|| format!("create debug log at {}", log_path.display()))?;
        let logging_runner = LoggingCommandRunner::new(OsCommandRunner, log_writer);
        let prober =
            Prober::new(logging_runner, OsPathResolver, Sha256Hasher).context("init prober")?;
        Ok(requirements.iter().map(|r| prober.probe(root, r)).collect())
    } else {
        // Use regular command runner (no logging)
        let prober =
            Prober::new(OsCommandRunner, OsPathResolver, Sha256Hasher).context("init prober")?;
        Ok(requirements.iter().map(|r| prober.probe(root, r)).collect())
    }
}

fn load_config(root: &Path, config_path: Option<&Path>) -> anyhow::Result<AppConfig> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            let p = root.join("env-check.toml");
            if p.exists() {
                p
            } else {
                return Ok(AppConfig::default());
            }
        }
    };

    let text =
        fs::read_to_string(&path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: AppConfig = toml::from_str(&text).with_context(|| "parse env-check.toml")?;
    Ok(cfg)
}

fn normalize_requirements(
    mut reqs: Vec<env_check_types::Requirement>,
    cfg: &AppConfig,
) -> Vec<env_check_types::Requirement> {
    // ignore tools
    reqs.retain(|r| !cfg.ignore_tools.iter().any(|t| t == &r.tool));

    // force required
    for r in &mut reqs {
        if cfg.force_required.iter().any(|t| t == &r.tool) {
            r.required = true;
        }
    }

    // Deduplicate by (tool, probe_kind). Keep first occurrence (sources are already in deterministic order).
    let mut out: Vec<env_check_types::Requirement> = vec![];
    for r in reqs {
        if out
            .iter()
            .any(|x| x.tool == r.tool && x.probe_kind == r.probe_kind)
        {
            continue;
        }
        out.push(r);
    }
    out
}

fn build_data(
    policy: &PolicyConfig,
    parsed: &ParsedSources,
    requirements: &[Requirement],
    outcome: &DomainOutcome,
) -> serde_json::Value {
    use serde_json::json;
    use std::collections::BTreeSet;

    let source_kinds: Vec<String> = parsed
        .sources_used
        .iter()
        .map(|s| source_kind_to_string(&s.kind))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    let probe_kinds: Vec<String> = requirements
        .iter()
        .map(|r| probe_kind_to_string(&r.probe_kind))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();

    json!({
        "profile": match policy.profile { Profile::Oss => "oss", Profile::Team => "team", Profile::Strict => "strict" },
        "fail_on": match policy.fail_on { FailOn::Error => "error", FailOn::Warn => "warn", FailOn::Never => "never" },
        "sources_used": parsed.sources_used.iter().map(|s| s.path.clone()).collect::<Vec<_>>(),
        "requirements_total": outcome.requirements_total,
        "requirements_failed": outcome.requirements_failed,
        "truncated": outcome.truncated,
        "observed": {
            "source_kinds": source_kinds,
            "probe_kinds": probe_kinds,
        },
    })
}

/// Build capabilities block declaring what the sensor actually checked.
///
/// This enables "No Green By Omission" - consumers can distinguish between
/// "we checked and found nothing wrong" vs "we didn't check at all".
fn build_capabilities(
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

/// Map SourceKind enum to stable string identifier for capabilities.
fn source_kind_to_string(kind: &SourceKind) -> String {
    match kind {
        SourceKind::ToolVersions => "tool-versions".to_string(),
        SourceKind::MiseToml => "mise".to_string(),
        SourceKind::RustToolchain => "rust-toolchain".to_string(),
        SourceKind::HashManifest => "hash-manifest".to_string(),
        SourceKind::NodeVersion => "node-version".to_string(),
        SourceKind::Nvmrc => "nvmrc".to_string(),
        SourceKind::PackageJson => "package-json".to_string(),
        SourceKind::PythonVersion => "python-version".to_string(),
        SourceKind::PyprojectToml => "pyproject".to_string(),
        SourceKind::GoMod => "go-mod".to_string(),
    }
}

/// Map ProbeKind enum to stable string identifier for capabilities.
fn probe_kind_to_string(kind: &env_check_types::ProbeKind) -> String {
    match kind {
        env_check_types::ProbeKind::PathTool => "path".to_string(),
        env_check_types::ProbeKind::RustupToolchain => "rustup".to_string(),
        env_check_types::ProbeKind::FileHash => "hash".to_string(),
    }
}

/// Build a minimal receipt for tool/runtime errors.
///
/// This is used when env-check fails before producing a normal receipt.
pub fn runtime_error_receipt(message: &str) -> ReceiptEnvelope {
    runtime_error_receipt_with_clock(message, &SystemClock)
}

/// Build a minimal receipt for tool/runtime errors with a custom clock.
///
/// This is used when env-check fails before producing a normal receipt.
/// The clock parameter enables deterministic testing.
pub fn runtime_error_receipt_with_clock(message: &str, clock: &dyn Clock) -> ReceiptEnvelope {
    let started = clock.now();
    ReceiptEnvelope {
        schema: SCHEMA_ID.to_string(),
        tool: ToolMeta {
            name: TOOL_NAME.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            commit: None,
        },
        run: RunMeta {
            started_at: started,
            ended_at: None,
            duration_ms: None,
            host: None,
            ci: None,
            git: None,
            capabilities: None,
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: Counts {
                info: 0,
                warn: 0,
                error: 1,
            },
            reasons: vec!["tool_error".to_string()],
        },
        findings: vec![Finding {
            severity: Severity::Error,
            check_id: Some("tool.runtime".into()),
            code: codes::TOOL_RUNTIME_ERROR.into(),
            message: message.to_string(),
            location: None,
            help: None,
            url: None,
            fingerprint: None,
            data: None,
        }],
        artifacts: vec![],
        data: None,
    }
}

/// Write a file atomically: write temp + rename.
///
/// This avoids partial artifacts in CI.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let parent = path.parent().context("no parent dir")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;

    let tmp = path.with_extension("tmp");
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Detect host metadata (OS, arch, hostname).
fn detect_host() -> Option<HostMeta> {
    Some(HostMeta {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
    })
}

/// Detect CI provider metadata via environment variables.
fn detect_ci() -> Option<CiMeta> {
    detect_ci_from_env(|key| std::env::var(key).ok())
}

/// Inner implementation that accepts an env-lookup closure for testability.
fn detect_ci_from_env(env: impl Fn(&str) -> Option<String>) -> Option<CiMeta> {
    // GitHub Actions
    if env("GITHUB_ACTIONS").is_some() {
        return Some(CiMeta {
            provider: "github".to_string(),
            job: env("GITHUB_JOB"),
            run_id: env("GITHUB_RUN_ID"),
            workflow: env("GITHUB_WORKFLOW").filter(|s| !s.is_empty()),
            repository: env("GITHUB_REPOSITORY").filter(|s| !s.is_empty()),
            git_ref: env("GITHUB_REF").filter(|s| !s.is_empty()),
            sha: env("GITHUB_SHA").filter(|s| !s.is_empty()),
        });
    }
    // GitLab CI
    if env("GITLAB_CI").is_some() {
        return Some(CiMeta {
            provider: "gitlab".to_string(),
            job: env("CI_JOB_NAME"),
            run_id: env("CI_JOB_ID"),
            workflow: env("CI_PIPELINE_NAME").filter(|s| !s.is_empty()),
            repository: env("CI_PROJECT_PATH").filter(|s| !s.is_empty()),
            git_ref: env("CI_COMMIT_REF_NAME").filter(|s| !s.is_empty()),
            sha: env("CI_COMMIT_SHA").filter(|s| !s.is_empty()),
        });
    }
    // CircleCI
    if env("CIRCLECI").is_some() {
        return Some(CiMeta {
            provider: "circleci".to_string(),
            job: env("CIRCLE_JOB"),
            run_id: env("CIRCLE_BUILD_NUM"),
            workflow: env("CIRCLE_WORKFLOW_ID").filter(|s| !s.is_empty()),
            repository: env("CIRCLE_PROJECT_REPONAME").filter(|s| !s.is_empty()),
            git_ref: env("CIRCLE_BRANCH").filter(|s| !s.is_empty()),
            sha: env("CIRCLE_SHA1").filter(|s| !s.is_empty()),
        });
    }
    // Azure Pipelines
    if env("TF_BUILD").is_some() {
        return Some(CiMeta {
            provider: "azure".to_string(),
            job: env("SYSTEM_JOBDISPLAYNAME"),
            run_id: env("BUILD_BUILDID"),
            workflow: env("BUILD_DEFINITIONNAME").filter(|s| !s.is_empty()),
            repository: env("BUILD_REPOSITORY_NAME").filter(|s| !s.is_empty()),
            git_ref: env("BUILD_SOURCEBRANCH").filter(|s| !s.is_empty()),
            sha: env("BUILD_SOURCEVERSION").filter(|s| !s.is_empty()),
        });
    }
    // Generic CI detection
    if env("CI").is_some() {
        return Some(CiMeta {
            provider: "unknown".to_string(),
            job: None,
            run_id: None,
            workflow: None,
            repository: None,
            git_ref: None,
            sha: None,
        });
    }
    None
}

/// Metadata extracted from a GitHub pull_request event.
#[derive(Debug, Default)]
struct GitHubPrEvent {
    base_sha: Option<String>,
    head_sha: Option<String>,
    pr_number: Option<u64>,
    base_ref: Option<String>,
}

/// Parse GITHUB_EVENT_PATH JSON when it exists and is a pull_request event.
/// Returns None fields gracefully if file doesn't exist, isn't PR event, or is malformed.
fn parse_github_event() -> GitHubPrEvent {
    parse_github_event_from_env(std::env::var("GITHUB_EVENT_PATH").ok())
}

/// Internal helper that takes the path as argument for testability.
fn parse_github_event_from_env(event_path: Option<String>) -> GitHubPrEvent {
    let path = match event_path {
        Some(p) if !p.is_empty() => p,
        _ => return GitHubPrEvent::default(),
    };

    parse_github_event_file(&path)
}

/// Parse the GitHub event JSON file at the given path.
fn parse_github_event_file(path: &str) -> GitHubPrEvent {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return GitHubPrEvent::default(),
    };

    parse_github_event_json(&content)
}

/// Parse GitHub event JSON content and extract PR metadata.
fn parse_github_event_json(content: &str) -> GitHubPrEvent {
    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return GitHubPrEvent::default(),
    };

    // Only extract PR metadata if this is a pull_request event
    let pr = match json.get("pull_request") {
        Some(pr) => pr,
        None => return GitHubPrEvent::default(),
    };

    GitHubPrEvent {
        base_sha: pr
            .get("base")
            .and_then(|b| b.get("sha"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        head_sha: pr
            .get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        pr_number: pr.get("number").and_then(|v| v.as_u64()),
        base_ref: pr
            .get("base")
            .and_then(|b| b.get("ref"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

/// Compute merge-base between HEAD and the base branch.
/// Returns None if git command fails (doesn't fail the whole run).
fn compute_merge_base(root: &Path, base_ref: Option<&str>) -> Option<String> {
    use std::process::Command;

    fn ref_exists(root: &Path, reference: &str) -> bool {
        Command::new("git")
            .args(["rev-parse", "--verify", reference])
            .current_dir(root)
            .output()
            .ok()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    let base_name = base_ref.unwrap_or("main");
    let candidates = [format!("origin/{}", base_name), base_name.to_string()];
    let base_branch = candidates
        .iter()
        .find(|r| ref_exists(root, r))
        .map(|r| r.as_str())?;

    Command::new("git")
        .args(["merge-base", "HEAD", base_branch])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Detect git repository metadata by shelling out to git.
fn detect_git(root: &Path) -> Option<GitMeta> {
    use std::process::Command;

    fn git(root: &Path, args: &[&str]) -> Option<String> {
        Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
    }

    // Check if in a git repo
    let _ = git(root, &["rev-parse", "--git-dir"])?;

    // Parse GitHub event for PR metadata
    let gh_event = parse_github_event();

    // Determine base_ref from multiple sources (prefer GitHub event, then env vars)
    let base_ref = gh_event
        .base_ref
        .clone()
        .or_else(|| {
            std::env::var("GITHUB_BASE_REF")
                .ok()
                .filter(|s| !s.is_empty())
        })
        .or_else(|| {
            std::env::var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
                .ok()
                .filter(|s| !s.is_empty())
        });

    // Compute merge-base if git is available
    let merge_base = compute_merge_base(root, base_ref.as_deref());

    // Use GitHub event SHA if available, otherwise query git
    let head_sha = gh_event
        .head_sha
        .clone()
        .or_else(|| std::env::var("GITHUB_SHA").ok().filter(|s| !s.is_empty()))
        .or_else(|| git(root, &["rev-parse", "HEAD"]));

    // Use GitHub event PR number if available, otherwise try env vars
    Some(GitMeta {
        repo: git(root, &["config", "--get", "remote.origin.url"]),
        base_ref,
        head_ref: git(root, &["rev-parse", "--abbrev-ref", "HEAD"]),
        base_sha: gh_event.base_sha,
        head_sha,
        merge_base,
        pr_number: gh_event.pr_number,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_check_types::{ProbeKind, SourceRef};

    /// Get the path to a test fixture file.
    fn fixture_path(name: &str) -> String {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        format!("{}/tests/fixtures/{}", manifest_dir, name)
    }

    // =========================================================================
    // GitHub Event JSON Parsing Tests
    // =========================================================================

    #[test]
    fn test_parse_github_event_json_valid_pr() {
        let json = r#"{
            "action": "opened",
            "number": 42,
            "pull_request": {
                "number": 42,
                "base": {
                    "ref": "main",
                    "sha": "abc123def456789012345678901234567890abcd"
                },
                "head": {
                    "ref": "feature/x",
                    "sha": "def456abc789012345678901234567890abcdef12"
                }
            }
        }"#;

        let result = parse_github_event_json(json);

        assert_eq!(result.pr_number, Some(42));
        assert_eq!(result.base_ref, Some("main".to_string()));
        assert_eq!(
            result.base_sha,
            Some("abc123def456789012345678901234567890abcd".to_string())
        );
        assert_eq!(
            result.head_sha,
            Some("def456abc789012345678901234567890abcdef12".to_string())
        );
    }

    #[test]
    fn test_parse_github_event_json_push_event_returns_none() {
        let json = r#"{
            "ref": "refs/heads/main",
            "before": "abc123",
            "after": "def456"
        }"#;

        let result = parse_github_event_json(json);

        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
        assert_eq!(result.base_sha, None);
        assert_eq!(result.head_sha, None);
    }

    #[test]
    fn test_parse_github_event_json_malformed_returns_none() {
        let json = r#"{ this is not valid json "#;

        let result = parse_github_event_json(json);

        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
        assert_eq!(result.base_sha, None);
        assert_eq!(result.head_sha, None);
    }

    #[test]
    fn test_parse_github_event_json_empty_returns_none() {
        let result = parse_github_event_json("");

        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
    }

    #[test]
    fn test_parse_github_event_json_partial_pr_data() {
        // PR with missing base sha
        let json = r#"{
            "pull_request": {
                "number": 123,
                "base": {
                    "ref": "develop"
                },
                "head": {
                    "sha": "partial123456789"
                }
            }
        }"#;

        let result = parse_github_event_json(json);

        assert_eq!(result.pr_number, Some(123));
        assert_eq!(result.base_ref, Some("develop".to_string()));
        assert_eq!(result.base_sha, None); // Missing
        assert_eq!(result.head_sha, Some("partial123456789".to_string()));
    }

    #[test]
    fn test_parse_github_event_from_env_none_path() {
        let result = parse_github_event_from_env(None);

        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
    }

    #[test]
    fn test_parse_github_event_from_env_empty_path() {
        let result = parse_github_event_from_env(Some(String::new()));

        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
    }

    #[test]
    fn test_parse_github_event_from_env_valid_path() {
        let path = fixture_path("github_event_pull_request.json");
        let result = parse_github_event_from_env(Some(path));

        assert_eq!(result.pr_number, Some(42));
        assert_eq!(result.base_ref, Some("main".to_string()));
        assert_eq!(
            result.base_sha,
            Some("abc123def456789012345678901234567890abcd".to_string())
        );
        assert_eq!(
            result.head_sha,
            Some("def456abc789012345678901234567890abcdef12".to_string())
        );
    }

    #[test]
    fn test_parse_github_event_matches_env_helper() {
        let direct = parse_github_event();
        let via = parse_github_event_from_env(std::env::var("GITHUB_EVENT_PATH").ok());

        assert_eq!(direct.pr_number, via.pr_number);
        assert_eq!(direct.base_ref, via.base_ref);
        assert_eq!(direct.base_sha, via.base_sha);
        assert_eq!(direct.head_sha, via.head_sha);
    }

    #[test]
    fn test_parse_github_event_file_valid_pr() {
        let path = fixture_path("github_event_pull_request.json");
        let result = parse_github_event_file(&path);

        assert_eq!(result.pr_number, Some(42));
        assert_eq!(result.base_ref, Some("main".to_string()));
        assert_eq!(
            result.base_sha,
            Some("abc123def456789012345678901234567890abcd".to_string())
        );
        assert_eq!(
            result.head_sha,
            Some("def456abc789012345678901234567890abcdef12".to_string())
        );
    }

    #[test]
    fn test_parse_github_event_file_push_event() {
        let path = fixture_path("github_event_push.json");
        let result = parse_github_event_file(&path);

        // Push events don't have pull_request, so all fields should be None
        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
        assert_eq!(result.base_sha, None);
        assert_eq!(result.head_sha, None);
    }

    #[test]
    fn test_parse_github_event_file_malformed() {
        let path = fixture_path("github_event_malformed.json");
        let result = parse_github_event_file(&path);

        // Malformed JSON should gracefully return defaults
        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
    }

    #[test]
    fn test_parse_github_event_file_partial_pr() {
        let path = fixture_path("github_event_partial_pr.json");
        let result = parse_github_event_file(&path);

        assert_eq!(result.pr_number, Some(123));
        assert_eq!(result.base_ref, Some("develop".to_string()));
        assert_eq!(result.base_sha, None); // Missing in fixture
        assert_eq!(
            result.head_sha,
            Some("partial123456789012345678901234567890abcd".to_string())
        );
    }

    #[test]
    fn test_parse_github_event_file_nonexistent() {
        let result = parse_github_event_file("/nonexistent/path/to/file.json");

        // Nonexistent file should gracefully return defaults
        assert_eq!(result.pr_number, None);
        assert_eq!(result.base_ref, None);
    }

    // =========================================================================
    // GitHubPrEvent Default Tests
    // =========================================================================

    #[test]
    fn test_github_pr_event_default() {
        let event = GitHubPrEvent::default();

        assert_eq!(event.base_sha, None);
        assert_eq!(event.head_sha, None);
        assert_eq!(event.pr_number, None);
        assert_eq!(event.base_ref, None);
    }

    #[test]
    fn compute_merge_base_missing_base_ref_returns_none() {
        use std::process::Command;

        fn git(root: &Path, args: &[&str]) {
            let status = Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .expect("run git");
            assert!(status.success(), "git {:?} failed", args);
        }

        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let temp_root = std::env::temp_dir().join(format!("env-check-merge-base-{unique}"));

        fs::create_dir_all(&temp_root).expect("create temp repo dir");
        git(&temp_root, &["init"]);
        git(
            &temp_root,
            &[
                "-c",
                "user.name=env-check",
                "-c",
                "user.email=env-check@example.com",
                "commit",
                "--allow-empty",
                "-m",
                "init",
            ],
        );

        let merge_base = compute_merge_base(&temp_root, Some("missing-base-ref"));
        assert!(
            merge_base.is_none(),
            "expected None when base ref does not exist"
        );

        let _ = fs::remove_dir_all(&temp_root);
    }

    #[test]
    fn detect_host_returns_os_and_arch() {
        let host = detect_host().expect("host metadata");
        assert!(!host.os.trim().is_empty());
        assert!(!host.arch.trim().is_empty());
    }

    // =========================================================================
    // Clock Integration Tests
    // =========================================================================

    #[test]
    fn runtime_error_receipt_with_clock_uses_fixed_time() {
        use chrono::TimeZone;
        use env_check_probe::fakes::FakeClock;

        let fixed_time = chrono::Utc
            .with_ymd_and_hms(2024, 6, 15, 10, 30, 0)
            .unwrap();
        let clock = FakeClock::new(fixed_time);

        let receipt = runtime_error_receipt_with_clock("test error", &clock);

        assert_eq!(receipt.run.started_at, fixed_time);
    }

    #[test]
    fn runtime_error_receipt_deterministic_with_same_clock() {
        use env_check_probe::fakes::FakeClock;

        let clock = FakeClock::default();

        let receipt1 = runtime_error_receipt_with_clock("error 1", &clock);
        let receipt2 = runtime_error_receipt_with_clock("error 2", &clock);

        // Same clock produces same timestamps
        assert_eq!(receipt1.run.started_at, receipt2.run.started_at);
    }

    // =========================================================================
    // CI Detection Tests
    // =========================================================================

    fn env_from_map<'a>(
        map: &'a std::collections::HashMap<&'a str, &'a str>,
    ) -> impl Fn(&str) -> Option<String> + 'a {
        move |key| map.get(key).map(|v| v.to_string())
    }

    // =========================================================================
    // Config + normalization tests
    // =========================================================================

    fn temp_root_dir(prefix: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("env-check-{prefix}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn make_req(tool: &str, constraint: &str, required: bool, probe_kind: ProbeKind) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: Some(constraint.to_string()),
            required,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".into(),
            },
            probe_kind,
            hash: None,
        }
    }

    #[test]
    fn load_config_missing_returns_default() {
        let root = temp_root_dir("config-missing");
        let cfg = load_config(&root, None).expect("load config");
        assert!(cfg.profile.is_none());
        assert!(cfg.fail_on.is_none());
        assert!(cfg.hash_manifests.is_empty());
        assert!(cfg.ignore_tools.is_empty());
        assert!(cfg.force_required.is_empty());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn load_config_parses_file() {
        let root = temp_root_dir("config-parse");
        let path = root.join("env-check.toml");
        let text = r#"
profile = "team"
fail_on = "warn"
hash_manifests = ["a.sha256", "b.sha256"]
ignore_tools = ["python"]
force_required = ["go"]
"#;
        fs::write(&path, text).expect("write config");

        let cfg = load_config(&root, None).expect("load config");
        assert_eq!(cfg.profile, Some(Profile::Team));
        assert_eq!(cfg.fail_on, Some(FailOn::Warn));
        assert_eq!(cfg.hash_manifests, vec!["a.sha256", "b.sha256"]);
        assert_eq!(cfg.ignore_tools, vec!["python"]);
        assert_eq!(cfg.force_required, vec!["go"]);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normalize_requirements_applies_ignore_force_and_dedupe() {
        let cfg = AppConfig {
            profile: None,
            fail_on: None,
            hash_manifests: vec![],
            ignore_tools: vec!["python".into()],
            force_required: vec!["go".into()],
        };

        let reqs = vec![
            make_req("node", "20", false, ProbeKind::PathTool),
            make_req("node", "18", true, ProbeKind::PathTool), // duplicate tool+probe_kind
            make_req("go", "1.22", false, ProbeKind::PathTool),
            make_req("python", "3.12", true, ProbeKind::PathTool),
        ];

        let out = normalize_requirements(reqs, &cfg);
        assert_eq!(out.len(), 2, "python ignored, node deduped");
        assert_eq!(out[0].tool, "node");
        assert_eq!(out[0].constraint.as_deref(), Some("20"));
        assert_eq!(out[1].tool, "go");
        assert!(out[1].required, "force_required should flip required");
    }

    // =========================================================================
    // Data + capabilities tests
    // =========================================================================

    #[test]
    fn build_data_sorts_kinds_and_reports_counts() {
        let parsed = ParsedSources {
            sources_used: vec![
                SourceRef {
                    kind: SourceKind::GoMod,
                    path: "go.mod".into(),
                },
                SourceRef {
                    kind: SourceKind::ToolVersions,
                    path: ".tool-versions".into(),
                },
                SourceRef {
                    kind: SourceKind::GoMod,
                    path: "go.mod".into(),
                },
            ],
            requirements: vec![],
            findings: vec![],
        };

        let requirements = vec![
            make_req("node", "20", true, ProbeKind::PathTool),
            Requirement {
                tool: "file:scripts/tool.sh".into(),
                constraint: None,
                required: true,
                source: SourceRef {
                    kind: SourceKind::HashManifest,
                    path: "scripts/tools.sha256".into(),
                },
                probe_kind: ProbeKind::FileHash,
                hash: None,
            },
        ];

        let outcome = DomainOutcome {
            findings: vec![],
            verdict: Verdict {
                status: VerdictStatus::Pass,
                counts: Counts::default(),
                reasons: vec![],
            },
            truncated: false,
            requirements_total: 2,
            requirements_failed: 0,
        };

        let policy = PolicyConfig {
            profile: Profile::Team,
            fail_on: FailOn::Warn,
            max_findings: Some(100),
        };

        let data = build_data(&policy, &parsed, &requirements, &outcome);
        let observed = data.get("observed").expect("observed block");

        let source_kinds = observed["source_kinds"]
            .as_array()
            .expect("source_kinds");
        let probe_kinds = observed["probe_kinds"].as_array().expect("probe_kinds");

        let source_list: Vec<String> = source_kinds
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        let probe_list: Vec<String> = probe_kinds
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();

        assert_eq!(source_list, vec!["go-mod", "tool-versions"]);
        assert_eq!(probe_list, vec!["hash", "path"]);
        assert_eq!(data["profile"], "team");
        assert_eq!(data["fail_on"], "warn");
        assert_eq!(data["requirements_total"], 2);
        assert_eq!(data["requirements_failed"], 0);
    }

    #[test]
    fn build_capabilities_reports_statuses() {
        let parsed_empty = ParsedSources::empty();
        let caps = build_capabilities(&parsed_empty, &[], None);
        assert_eq!(caps.git.status, CapabilityStatus::Unavailable);
        assert_eq!(caps.git.reason.as_deref(), Some("not_a_git_repo"));
        assert_eq!(caps.inputs.status, CapabilityStatus::Unavailable);
        assert_eq!(caps.inputs.reason.as_deref(), Some("no_sources_found"));
        assert_eq!(caps.engine.status, CapabilityStatus::Skipped);
        assert_eq!(caps.engine.reason.as_deref(), Some("no_requirements"));
        assert_eq!(caps.baseline.status, CapabilityStatus::Skipped);

        let parsed = ParsedSources {
            sources_used: vec![SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".into(),
            }],
            requirements: vec![],
            findings: vec![],
        };
        let reqs = vec![make_req("node", "20", true, ProbeKind::PathTool)];
        let git = GitMeta {
            repo: Some("git@example.com:repo.git".into()),
            base_ref: None,
            head_ref: None,
            base_sha: None,
            head_sha: None,
            merge_base: None,
            pr_number: None,
        };
        let caps = build_capabilities(&parsed, &reqs, Some(&git));
        assert_eq!(caps.git.status, CapabilityStatus::Available);
        assert_eq!(caps.inputs.status, CapabilityStatus::Available);
        assert_eq!(caps.engine.status, CapabilityStatus::Available);
    }

    #[test]
    fn source_kind_to_string_all_variants() {
        let variants = vec![
            (SourceKind::ToolVersions, "tool-versions"),
            (SourceKind::MiseToml, "mise"),
            (SourceKind::RustToolchain, "rust-toolchain"),
            (SourceKind::HashManifest, "hash-manifest"),
            (SourceKind::NodeVersion, "node-version"),
            (SourceKind::Nvmrc, "nvmrc"),
            (SourceKind::PackageJson, "package-json"),
            (SourceKind::PythonVersion, "python-version"),
            (SourceKind::PyprojectToml, "pyproject"),
            (SourceKind::GoMod, "go-mod"),
        ];

        for (kind, expected) in variants {
            assert_eq!(source_kind_to_string(&kind), expected);
        }
    }

    #[test]
    fn probe_kind_to_string_all_variants() {
        let variants = vec![
            (ProbeKind::PathTool, "path"),
            (ProbeKind::RustupToolchain, "rustup"),
            (ProbeKind::FileHash, "hash"),
        ];

        for (kind, expected) in variants {
            assert_eq!(probe_kind_to_string(&kind), expected);
        }
    }

    // =========================================================================
    // Atomic write tests
    // =========================================================================

    #[test]
    fn write_atomic_creates_parent_and_writes_content() {
        let root = temp_root_dir("write-atomic");
        let path = root.join("artifacts").join("env-check").join("report.json");
        let bytes = b"{\"ok\":true}";

        write_atomic(&path, bytes).expect("write atomic");

        let on_disk = fs::read(&path).expect("read back");
        assert_eq!(on_disk, bytes);

        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "temp file should be renamed away");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn probe_requirements_with_debug_log_writes_header_even_when_empty() {
        let root = temp_root_dir("probe-debug");
        let log_path = root.join("artifacts").join("env-check").join("extras").join("raw.log");
        let options = CheckOptions {
            debug_log_path: Some(log_path.clone()),
        };

        let observations = probe_requirements(&root, &[], &options).expect("probe");
        assert!(observations.is_empty());

        let log_content = fs::read_to_string(&log_path).expect("read log");
        assert!(log_content.contains("# env-check probe debug log"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_detect_ci_github_actions_all_fields() {
        let vars: std::collections::HashMap<&str, &str> = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_JOB", "build"),
            ("GITHUB_RUN_ID", "12345"),
            ("GITHUB_WORKFLOW", "CI"),
            ("GITHUB_REPOSITORY", "owner/repo"),
            ("GITHUB_REF", "refs/heads/main"),
            ("GITHUB_SHA", "abc123"),
        ]
        .into_iter()
        .collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "github");
        assert_eq!(ci.job.as_deref(), Some("build"));
        assert_eq!(ci.run_id.as_deref(), Some("12345"));
        assert_eq!(ci.workflow.as_deref(), Some("CI"));
        assert_eq!(ci.repository.as_deref(), Some("owner/repo"));
        assert_eq!(ci.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(ci.sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_detect_ci_gitlab() {
        let vars: std::collections::HashMap<&str, &str> = [
            ("GITLAB_CI", "true"),
            ("CI_JOB_NAME", "test"),
            ("CI_JOB_ID", "999"),
            ("CI_PROJECT_PATH", "group/project"),
            ("CI_COMMIT_REF_NAME", "develop"),
            ("CI_COMMIT_SHA", "def456"),
        ]
        .into_iter()
        .collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "gitlab");
        assert_eq!(ci.job.as_deref(), Some("test"));
        assert_eq!(ci.run_id.as_deref(), Some("999"));
        assert_eq!(ci.repository.as_deref(), Some("group/project"));
        assert_eq!(ci.git_ref.as_deref(), Some("develop"));
        assert_eq!(ci.sha.as_deref(), Some("def456"));
        assert_eq!(ci.workflow, None); // CI_PIPELINE_NAME not set
    }

    #[test]
    fn test_detect_ci_circleci() {
        let vars: std::collections::HashMap<&str, &str> = [
            ("CIRCLECI", "true"),
            ("CIRCLE_JOB", "build"),
            ("CIRCLE_BUILD_NUM", "321"),
            ("CIRCLE_WORKFLOW_ID", "wf-123"),
            ("CIRCLE_PROJECT_REPONAME", "repo"),
            ("CIRCLE_BRANCH", "main"),
            ("CIRCLE_SHA1", "abc123"),
        ]
        .into_iter()
        .collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "circleci");
        assert_eq!(ci.job.as_deref(), Some("build"));
        assert_eq!(ci.run_id.as_deref(), Some("321"));
        assert_eq!(ci.workflow.as_deref(), Some("wf-123"));
        assert_eq!(ci.repository.as_deref(), Some("repo"));
        assert_eq!(ci.git_ref.as_deref(), Some("main"));
        assert_eq!(ci.sha.as_deref(), Some("abc123"));
    }

    #[test]
    fn test_detect_ci_azure() {
        let vars: std::collections::HashMap<&str, &str> = [
            ("TF_BUILD", "true"),
            ("SYSTEM_JOBDISPLAYNAME", "job"),
            ("BUILD_BUILDID", "456"),
            ("BUILD_DEFINITIONNAME", "pipeline"),
            ("BUILD_REPOSITORY_NAME", "repo"),
            ("BUILD_SOURCEBRANCH", "refs/heads/main"),
            ("BUILD_SOURCEVERSION", "def456"),
        ]
        .into_iter()
        .collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "azure");
        assert_eq!(ci.job.as_deref(), Some("job"));
        assert_eq!(ci.run_id.as_deref(), Some("456"));
        assert_eq!(ci.workflow.as_deref(), Some("pipeline"));
        assert_eq!(ci.repository.as_deref(), Some("repo"));
        assert_eq!(ci.git_ref.as_deref(), Some("refs/heads/main"));
        assert_eq!(ci.sha.as_deref(), Some("def456"));
    }

    #[test]
    fn test_detect_ci_none_when_no_vars() {
        let vars: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
        assert!(detect_ci_from_env(env_from_map(&vars)).is_none());
    }

    #[test]
    fn test_detect_ci_empty_strings_filtered() {
        let vars: std::collections::HashMap<&str, &str> = [
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_WORKFLOW", ""),
            ("GITHUB_SHA", ""),
            ("GITHUB_REF", ""),
            ("GITHUB_REPOSITORY", ""),
        ]
        .into_iter()
        .collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "github");
        assert_eq!(ci.workflow, None);
        assert_eq!(ci.sha, None);
        assert_eq!(ci.git_ref, None);
        assert_eq!(ci.repository, None);
    }

    #[test]
    fn test_detect_ci_generic_fallback() {
        let vars: std::collections::HashMap<&str, &str> = [("CI", "true")].into_iter().collect();

        let ci = detect_ci_from_env(env_from_map(&vars)).unwrap();
        assert_eq!(ci.provider, "unknown");
        assert!(ci.job.is_none());
        assert!(ci.run_id.is_none());
    }
}
