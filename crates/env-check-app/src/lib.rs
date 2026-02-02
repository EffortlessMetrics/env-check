//! Composition root for env-check.
//!
//! This crate wires sources + probes + domain evaluation and writes artifacts.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use chrono::Utc;
use env_check_domain::DomainOutcome;
use env_check_probe::{OsCommandRunner, OsPathResolver, Prober, Sha256Hasher};
use env_check_sources::ParsedSources;
use env_check_types::{
    FailOn, PolicyConfig, Profile, ReceiptEnvelope, RunMeta, ToolMeta, TOOL_NAME, SCHEMA_ID,
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

/// Run env-check end-to-end.
pub fn run_check(root: &Path, config_path: Option<&Path>, profile: Profile, fail_on: FailOn) -> anyhow::Result<CheckOutput> {
    let started = Utc::now();

    let mut cfg = load_config(root, config_path)?;
    if cfg.hash_manifests.is_empty() {
        cfg.hash_manifests.push("scripts/tools.sha256".into());
    }

    let policy = PolicyConfig {
        profile: cfg.profile.unwrap_or(profile),
        fail_on: cfg.fail_on.unwrap_or(fail_on),
        max_findings: Some(100),
    };

    let manifests: Vec<PathBuf> = cfg.hash_manifests.iter().map(PathBuf::from).collect();

    let parsed = env_check_sources::parse_all(root, &manifests);
    let sources_used: Vec<String> = parsed.sources_used.iter().map(|s| s.path.clone()).collect();

    // Normalize requirements for determinism and policy overrides.
    let mut requirements = normalize_requirements(parsed.requirements, &cfg);

    // Probe.
    let prober = Prober::new(OsCommandRunner, OsPathResolver, Sha256Hasher)
        .context("init prober")?;

    let observations: Vec<_> = requirements
        .iter()
        .map(|r| prober.probe(root, r))
        .collect();

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
            host: None,
            ci: None,
            git: None,
        },
        verdict: outcome.verdict.clone(),
        findings: outcome.findings.clone(),
        data: Some(data),
    };

    // Render markdown.
    let markdown = env_check_render::render_markdown(&receipt);

    // Exit code mapping: policy semantics are already reflected in verdict.status.
    let exit_code = match receipt.verdict.status {
        env_check_types::VerdictStatus::Pass | env_check_types::VerdictStatus::Warn | env_check_types::VerdictStatus::Skip => 0,
        env_check_types::VerdictStatus::Fail => 2,
    };

    Ok(CheckOutput { receipt, markdown, exit_code })
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
