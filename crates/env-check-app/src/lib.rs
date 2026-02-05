//! Composition root for env-check.
//!
//! This crate wires sources + probes + domain evaluation and writes artifacts.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::Utc;
use env_check_domain::DomainOutcome;
use env_check_probe::{
    FileLogWriter, LoggingCommandRunner, OsCommandRunner, OsPathResolver, Prober, Sha256Hasher,
};
use env_check_sources::ParsedSources;
use env_check_types::{
    codes, CiMeta, Counts, FailOn, Finding, GitMeta, HostMeta, Observation, PolicyConfig, Profile,
    ReceiptEnvelope, Requirement, RunMeta, Severity, ToolMeta, Verdict, VerdictStatus, SCHEMA_ID,
    TOOL_NAME,
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
    let started = Utc::now();

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

    let ended = Utc::now();
    let duration_ms = ended.signed_duration_since(started).num_milliseconds().max(0) as u64;

    // Build receipt envelope.
    let data = build_data(&policy, &parsed, &outcome);

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
            git: detect_git(root),
        },
        verdict: outcome.verdict.clone(),
        findings: outcome.findings.clone(),
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
        let log_writer =
            FileLogWriter::new(log_path).with_context(|| format!("create debug log at {}", log_path.display()))?;
        let logging_runner = LoggingCommandRunner::new(OsCommandRunner, log_writer);
        let prober = Prober::new(logging_runner, OsPathResolver, Sha256Hasher).context("init prober")?;
        Ok(requirements.iter().map(|r| prober.probe(root, r)).collect())
    } else {
        // Use regular command runner (no logging)
        let prober = Prober::new(OsCommandRunner, OsPathResolver, Sha256Hasher).context("init prober")?;
        Ok(requirements.iter().map(|r| prober.probe(root, r)).collect())
    }
}

fn load_config(root: &Path, config_path: Option<&Path>) -> anyhow::Result<AppConfig> {
    let path = match config_path {
        Some(p) => p.to_path_buf(),
        None => {
            let p = root.join("env-check.toml");
            if p.exists() { p } else { return Ok(AppConfig::default()); }
        }
    };

    let text = fs::read_to_string(&path).with_context(|| format!("read config {}", path.display()))?;
    let cfg: AppConfig = toml::from_str(&text).with_context(|| "parse env-check.toml")?;
    Ok(cfg)
}

fn normalize_requirements(mut reqs: Vec<env_check_types::Requirement>, cfg: &AppConfig) -> Vec<env_check_types::Requirement> {
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
        if out.iter().any(|x| x.tool == r.tool && x.probe_kind == r.probe_kind) {
            continue;
        }
        out.push(r);
    }
    out
}

fn build_data(policy: &PolicyConfig, parsed: &ParsedSources, outcome: &DomainOutcome) -> serde_json::Value {
    use serde_json::json;

    json!({
        "profile": match policy.profile { Profile::Oss => "oss", Profile::Team => "team", Profile::Strict => "strict" },
        "fail_on": match policy.fail_on { FailOn::Error => "error", FailOn::Warn => "warn", FailOn::Never => "never" },
        "sources_used": parsed.sources_used.iter().map(|s| s.path.clone()).collect::<Vec<_>>(),
        "requirements_total": outcome.requirements_total,
        "requirements_failed": outcome.requirements_failed,
        "truncated": outcome.truncated,
    })
}

/// Build a minimal receipt for tool/runtime errors.
///
/// This is used when env-check fails before producing a normal receipt.
pub fn runtime_error_receipt(message: &str) -> ReceiptEnvelope {
    let started = Utc::now();
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
        },
        verdict: Verdict {
            status: VerdictStatus::Fail,
            counts: Counts { info: 0, warn: 0, error: 1 },
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
    fs::rename(&tmp, path).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
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
    // GitHub Actions
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        return Some(CiMeta {
            provider: "github".to_string(),
            job: std::env::var("GITHUB_JOB").ok(),
            run_id: std::env::var("GITHUB_RUN_ID").ok(),
            workflow: None,
            repository: None,
            git_ref: None,
            sha: None,
        });
    }
    // GitLab CI
    if std::env::var("GITLAB_CI").is_ok() {
        return Some(CiMeta {
            provider: "gitlab".to_string(),
            job: std::env::var("CI_JOB_NAME").ok(),
            run_id: std::env::var("CI_JOB_ID").ok(),
            workflow: None,
            repository: None,
            git_ref: None,
            sha: None,
        });
    }
    // CircleCI
    if std::env::var("CIRCLECI").is_ok() {
        return Some(CiMeta {
            provider: "circleci".to_string(),
            job: std::env::var("CIRCLE_JOB").ok(),
            run_id: std::env::var("CIRCLE_BUILD_NUM").ok(),
            workflow: None,
            repository: None,
            git_ref: None,
            sha: None,
        });
    }
    // Azure Pipelines
    if std::env::var("TF_BUILD").is_ok() {
        return Some(CiMeta {
            provider: "azure".to_string(),
            job: std::env::var("SYSTEM_JOBDISPLAYNAME").ok(),
            run_id: std::env::var("BUILD_BUILDID").ok(),
            workflow: None,
            repository: None,
            git_ref: None,
            sha: None,
        });
    }
    // Generic CI detection
    if std::env::var("CI").is_ok() {
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
    #[allow(dead_code)]
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
        base_sha: pr.get("base")
            .and_then(|b| b.get("sha"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        head_sha: pr.get("head")
            .and_then(|h| h.get("sha"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        pr_number: pr.get("number")
            .and_then(|v| v.as_u64()),
        base_ref: pr.get("base")
            .and_then(|b| b.get("ref"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    }
}

/// Compute merge-base between HEAD and the base branch.
/// Returns None if git command fails (doesn't fail the whole run).
fn compute_merge_base(root: &Path, base_ref: Option<&str>) -> Option<String> {
    use std::process::Command;

    // Use detected base_ref, or fall back to origin/main
    let base_branch = base_ref
        .map(|r| format!("origin/{}", r))
        .unwrap_or_else(|| "origin/main".to_string());

    // First, try to fetch the base branch to ensure we have it
    // (This is best-effort; if it fails, we'll try merge-base anyway)
    let _ = Command::new("git")
        .args(["fetch", "origin", base_ref.unwrap_or("main"), "--depth=1"])
        .current_dir(root)
        .output();

    // Compute merge-base
    Command::new("git")
        .args(["merge-base", "HEAD", &base_branch])
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
    let base_ref = gh_event.base_ref.clone()
        .or_else(|| std::env::var("GITHUB_BASE_REF").ok().filter(|s| !s.is_empty()))
        .or_else(|| std::env::var("CI_MERGE_REQUEST_TARGET_BRANCH_NAME").ok().filter(|s| !s.is_empty()));

    // Compute merge-base if git is available
    let merge_base = compute_merge_base(root, base_ref.as_deref());

    // Use GitHub event SHA if available, otherwise query git
    let head_sha = gh_event.head_sha.clone()
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
        pr_number: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(result.base_sha, Some("abc123def456789012345678901234567890abcd".to_string()));
        assert_eq!(result.head_sha, Some("def456abc789012345678901234567890abcdef12".to_string()));
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
    fn test_parse_github_event_file_valid_pr() {
        let path = fixture_path("github_event_pull_request.json");
        let result = parse_github_event_file(&path);

        assert_eq!(result.pr_number, Some(42));
        assert_eq!(result.base_ref, Some("main".to_string()));
        assert_eq!(result.base_sha, Some("abc123def456789012345678901234567890abcd".to_string()));
        assert_eq!(result.head_sha, Some("def456abc789012345678901234567890abcdef12".to_string()));
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
        assert_eq!(result.head_sha, Some("partial123456789012345678901234567890abcd".to_string()));
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
}
