//! Runtime utility crate for env-check.
//!
//! The IO boundary (`write_atomic`) stays here for compatibility with the existing
//! app/cli contracts. Metadata helpers are delegated to
//! `env-check-runtime-metadata` behind the `metadata` feature.

use std::fs;
use std::path::Path;

#[cfg(feature = "metadata")]
pub use env_check_runtime_metadata::{
    GitHubPrEvent, compute_merge_base, detect_ci, detect_ci_from_env, detect_git, detect_host,
    parse_github_event, parse_github_event_file, parse_github_event_from_env,
    parse_github_event_json,
};

#[cfg(not(feature = "metadata"))]
pub use env_check_types::{CiMeta, GitMeta, HostMeta};

use anyhow::Context;

#[cfg(not(feature = "metadata"))]
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GitHubPrEvent {
    pub base_sha: Option<String>,
    pub head_sha: Option<String>,
    pub pr_number: Option<u64>,
    pub base_ref: Option<String>,
}

#[cfg(not(feature = "metadata"))]
pub fn detect_host() -> Option<HostMeta> {
    None
}

#[cfg(not(feature = "metadata"))]
pub fn detect_ci() -> Option<CiMeta> {
    None
}

#[cfg(not(feature = "metadata"))]
pub fn detect_ci_from_env(_env: impl Fn(&str) -> Option<String>) -> Option<CiMeta> {
    None
}

#[cfg(not(feature = "metadata"))]
pub fn parse_github_event() -> GitHubPrEvent {
    GitHubPrEvent::default()
}

#[cfg(not(feature = "metadata"))]
pub fn parse_github_event_from_env(_event_path: Option<String>) -> GitHubPrEvent {
    GitHubPrEvent::default()
}

#[cfg(not(feature = "metadata"))]
pub fn parse_github_event_file(_path: &str) -> GitHubPrEvent {
    GitHubPrEvent::default()
}

#[cfg(not(feature = "metadata"))]
pub fn parse_github_event_json(_content: &str) -> GitHubPrEvent {
    GitHubPrEvent::default()
}

#[cfg(not(feature = "metadata"))]
pub fn compute_merge_base(_root: &Path, _base_ref: Option<&str>) -> Option<String> {
    None
}

#[cfg(not(feature = "metadata"))]
pub fn detect_git(_root: &Path) -> Option<GitMeta> {
    None
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
