//! Runtime metadata helpers shared by env-check composition boundaries and adapters.

use env_check_types::{CiMeta, GitMeta, HostMeta};
use std::fs;
use std::path::Path;

/// Parse a GitHub pull request event extracted from `$GITHUB_EVENT_PATH`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GitHubPrEvent {
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub pr_number: Option<u64>,
    pub base_ref: Option<String>,
}

/// Detect host metadata (OS, arch, hostname).
pub fn detect_host() -> Option<HostMeta> {
    Some(HostMeta {
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        hostname: hostname::get().ok().and_then(|h| h.into_string().ok()),
    })
}

/// Detect CI provider metadata via environment variables.
pub fn detect_ci() -> Option<CiMeta> {
    detect_ci_from_env(|key| std::env::var(key).ok())
}

/// Inner CI parser that accepts an env accessor.
pub fn detect_ci_from_env(env: impl Fn(&str) -> Option<String>) -> Option<CiMeta> {
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

/// Parse `$GITHUB_EVENT_PATH` when it exists and is a pull request event.
pub fn parse_github_event() -> GitHubPrEvent {
    parse_github_event_from_env(std::env::var("GITHUB_EVENT_PATH").ok())
}

/// Internal helper that takes the path as argument for testability.
pub fn parse_github_event_from_env(event_path: Option<String>) -> GitHubPrEvent {
    let path = match event_path {
        Some(p) if !p.is_empty() => p,
        _ => return GitHubPrEvent::default(),
    };

    parse_github_event_file(&path)
}

/// Parse the GitHub event JSON file at the given path.
pub fn parse_github_event_file(path: &str) -> GitHubPrEvent {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return GitHubPrEvent::default(),
    };

    parse_github_event_json(&content)
}

/// Parse GitHub event JSON and extract pull-request metadata.
pub fn parse_github_event_json(content: &str) -> GitHubPrEvent {
    let json: serde_json::Value = match serde_json::from_str(content) {
        Ok(v) => v,
        Err(_) => return GitHubPrEvent::default(),
    };

    // Only extract PR metadata if this is a pull_request event.
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
///
/// Returns None if the git commands fail.
pub fn compute_merge_base(root: &Path, base_ref: Option<&str>) -> Option<String> {
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

/// Detect git metadata by shelling out to git.
pub fn detect_git(root: &Path) -> Option<GitMeta> {
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

    // Check if in a git repo.
    let _ = git(root, &["rev-parse", "--git-dir"])?;

    // Parse GitHub event for PR metadata.
    let gh_event = parse_github_event();

    // Determine base_ref from multiple sources.
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

    // Compute merge-base if possible.
    let merge_base = compute_merge_base(root, base_ref.as_deref());

    // Prefer event-provided head SHA when available.
    let head_sha = gh_event
        .head_sha
        .clone()
        .or_else(|| std::env::var("GITHUB_SHA").ok().filter(|s| !s.is_empty()))
        .or_else(|| git(root, &["rev-parse", "HEAD"]));

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
