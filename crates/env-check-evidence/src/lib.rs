//! Deterministic evidence-shaping helpers for env-check receipts.
//!
//! This crate is pure by design: it transforms requirements/observations into
//! stable, serializable evidence payloads for `data{}`.

use std::collections::BTreeSet;

use env_check_types::{Observation, ProbeKind, Requirement, SourceKind, SourceRef};
use semver::{Version, VersionReq};
use serde::Serialize;

const MAX_RAW_CHARS: usize = 240;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeResult {
    Ok,
    NotFound,
    VersionMismatch,
    HashMismatch,
    Error,
    Skipped,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeSummary {
    pub tool: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cmd: Vec<String>,
    pub result: ProbeResult,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyGraph {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub edges: Vec<DependencyEdge>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DependencyEdge {
    pub from: String,
    pub to: String,
    pub reason: String,
}

/// Stable external name for a source kind.
pub fn source_kind_id(kind: &SourceKind) -> &'static str {
    match kind {
        SourceKind::ToolVersions => "tool-versions",
        SourceKind::MiseToml => "mise",
        SourceKind::RustToolchain => "rust-toolchain",
        SourceKind::HashManifest => "hash-manifest",
        SourceKind::NodeVersion => "node-version",
        SourceKind::Nvmrc => "nvmrc",
        SourceKind::PackageJson => "package-json",
        SourceKind::PythonVersion => "python-version",
        SourceKind::PyprojectToml => "pyproject",
        SourceKind::GoMod => "go-mod",
    }
}

/// Stable external name for a probe kind.
pub fn probe_kind_id(kind: &ProbeKind) -> &'static str {
    match kind {
        ProbeKind::PathTool => "path",
        ProbeKind::RustupToolchain => "rustup",
        ProbeKind::FileHash => "hash",
    }
}

/// Unique, sorted source-kind list for `data.observed.source_kinds`.
pub fn source_kinds(sources: &[SourceRef]) -> Vec<String> {
    sources
        .iter()
        .map(|s| source_kind_id(&s.kind).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Unique, sorted probe-kind list for `data.observed.probe_kinds`.
pub fn probe_kinds(requirements: &[Requirement]) -> Vec<String> {
    requirements
        .iter()
        .map(|r| probe_kind_id(&r.probe_kind).to_string())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Condense probe observations into deterministic `data.probes` rows.
pub fn summarize_probes(
    requirements: &[Requirement],
    observations: &[Observation],
) -> Vec<ProbeSummary> {
    let mut out = Vec::with_capacity(requirements.len());

    for (idx, req) in requirements.iter().enumerate() {
        match observations.get(idx) {
            Some(obs) => {
                out.push(ProbeSummary {
                    tool: req.tool.clone(),
                    cmd: obs.probe.cmd.clone(),
                    result: classify_probe(req, obs),
                    raw: condensed_raw(obs),
                });
            }
            None => {
                out.push(ProbeSummary {
                    tool: req.tool.clone(),
                    cmd: vec![],
                    result: ProbeResult::Skipped,
                    raw: "observation missing".to_string(),
                });
            }
        }
    }

    out.sort_by(|a, b| {
        a.tool
            .cmp(&b.tool)
            .then(a.cmd.cmp(&b.cmd))
            .then(result_rank(&a.result).cmp(&result_rank(&b.result)))
            .then(a.raw.cmp(&b.raw))
    });
    out
}

/// Build a deterministic dependency graph for declared tools.
///
/// The graph is intentionally conservative and only includes stable, known
/// relationships where one tool runtime is required to run another.
pub fn dependency_graph(requirements: &[Requirement]) -> DependencyGraph {
    let mut nodes: BTreeSet<String> = BTreeSet::new();
    let mut edges: BTreeSet<(String, String, String)> = BTreeSet::new();

    for req in requirements {
        if req.tool.trim().is_empty() {
            continue;
        }
        nodes.insert(req.tool.clone());

        for (to, reason) in inferred_dependencies(&req.tool) {
            if req.tool == *to {
                continue;
            }
            nodes.insert((*to).to_string());
            edges.insert((req.tool.clone(), (*to).to_string(), (*reason).to_string()));
        }
    }

    DependencyGraph {
        nodes: nodes.into_iter().collect(),
        edges: edges
            .into_iter()
            .map(|(from, to, reason)| DependencyEdge { from, to, reason })
            .collect(),
    }
}

fn inferred_dependencies(tool: &str) -> &'static [(&'static str, &'static str)] {
    const NODE_DEPS_NPM: &[(&str, &str)] = &[("node", "npm_requires_node")];
    const NODE_DEPS_PNPM: &[(&str, &str)] = &[("node", "pnpm_requires_node")];
    const NODE_DEPS_YARN: &[(&str, &str)] = &[("node", "yarn_requires_node")];
    const PYTHON_DEPS_PIP: &[(&str, &str)] = &[("python", "pip_requires_python")];
    const PYTHON_DEPS_PIP3: &[(&str, &str)] = &[("python", "pip3_requires_python")];
    const PYTHON_DEPS_PIPX: &[(&str, &str)] = &[("python", "pipx_requires_python")];
    const PYTHON_DEPS_POETRY: &[(&str, &str)] = &[("python", "poetry_requires_python")];
    const RUST_DEPS_CARGO: &[(&str, &str)] = &[("rust", "cargo_requires_rust_toolchain")];
    const RUST_DEPS_RUSTC: &[(&str, &str)] = &[("rust", "rustc_requires_rust_toolchain")];
    const RUST_DEPS_RUSTFMT: &[(&str, &str)] = &[("rust", "rustfmt_requires_rust_toolchain")];
    const RUST_DEPS_CLIPPY: &[(&str, &str)] = &[("rust", "clippy_requires_rust_toolchain")];
    const RUST_DEPS_ANALYZER: &[(&str, &str)] =
        &[("rust", "rust_analyzer_requires_rust_toolchain")];
    const RUST_DEPS_RUSTDOC: &[(&str, &str)] = &[("rust", "rustdoc_requires_rust_toolchain")];

    match tool {
        "npm" => NODE_DEPS_NPM,
        "pnpm" => NODE_DEPS_PNPM,
        "yarn" => NODE_DEPS_YARN,
        "pip" => PYTHON_DEPS_PIP,
        "pip3" => PYTHON_DEPS_PIP3,
        "pipx" => PYTHON_DEPS_PIPX,
        "poetry" => PYTHON_DEPS_POETRY,
        "cargo" => RUST_DEPS_CARGO,
        "rustc" => RUST_DEPS_RUSTC,
        "rustfmt" => RUST_DEPS_RUSTFMT,
        "clippy" => RUST_DEPS_CLIPPY,
        "rust-analyzer" => RUST_DEPS_ANALYZER,
        "rustdoc" => RUST_DEPS_RUSTDOC,
        _ => &[],
    }
}

fn classify_probe(req: &Requirement, obs: &Observation) -> ProbeResult {
    if is_runtime_error(obs) {
        return ProbeResult::Error;
    }

    match req.probe_kind {
        ProbeKind::PathTool => classify_path_probe(req, obs),
        ProbeKind::RustupToolchain => classify_rustup_probe(req, obs),
        ProbeKind::FileHash => classify_hash_probe(obs),
    }
}

fn classify_path_probe(req: &Requirement, obs: &Observation) -> ProbeResult {
    if !obs.present {
        return ProbeResult::NotFound;
    }

    let Some(constraint) = req.constraint.as_deref() else {
        return ProbeResult::Ok;
    };

    if is_presence_only_constraint(constraint) {
        return ProbeResult::Ok;
    }

    let Some(version) = obs.version.as_ref() else {
        return classify_from_probe_record(obs);
    };

    let Some(parsed) = version.parsed.as_deref() else {
        return ProbeResult::VersionMismatch;
    };

    if satisfies_semverish(constraint, parsed) {
        ProbeResult::Ok
    } else {
        ProbeResult::VersionMismatch
    }
}

fn classify_rustup_probe(req: &Requirement, obs: &Observation) -> ProbeResult {
    if !obs.present {
        return ProbeResult::NotFound;
    }

    let Some(constraint) = req.constraint.as_deref() else {
        return ProbeResult::Ok;
    };

    let raw = obs
        .version
        .as_ref()
        .map(|v| v.raw.as_str())
        .unwrap_or_default();
    if raw.contains(constraint) {
        ProbeResult::Ok
    } else {
        ProbeResult::VersionMismatch
    }
}

fn classify_hash_probe(obs: &Observation) -> ProbeResult {
    if !obs.present {
        return ProbeResult::NotFound;
    }

    match obs.hash_ok {
        Some(true) => ProbeResult::Ok,
        Some(false) => ProbeResult::HashMismatch,
        None => classify_from_probe_record(obs),
    }
}

fn classify_from_probe_record(obs: &Observation) -> ProbeResult {
    if !obs.probe.stderr.trim().is_empty() {
        return ProbeResult::Error;
    }

    match obs.probe.exit {
        Some(0) => ProbeResult::Skipped,
        Some(_) => ProbeResult::Error,
        None => ProbeResult::Skipped,
    }
}

fn is_runtime_error(obs: &Observation) -> bool {
    obs.present
        && !obs.probe.cmd.is_empty()
        && obs.probe.exit.is_none()
        && !obs.probe.stderr.trim().is_empty()
}

fn is_presence_only_constraint(c: &str) -> bool {
    matches!(c.trim(), "latest" | "system" | "*" | "default")
}

fn coerce_version(raw: &str) -> Option<Version> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }

    let parts: Vec<&str> = s.split('.').collect();
    let coerced = match parts.len() {
        1 => format!("{}.0.0", s),
        2 => format!("{}.0", s),
        _ => s.to_string(),
    };
    Version::parse(&coerced).ok()
}

fn satisfies_semverish(constraint: &str, have: &str) -> bool {
    if let Some(v) = coerce_version(have) {
        if let Ok(req) = VersionReq::parse(constraint.trim()) {
            return req.matches(&v);
        }
    }
    have.trim() == constraint.trim()
}

fn condensed_raw(obs: &Observation) -> String {
    let base = obs
        .version
        .as_ref()
        .map(|v| v.raw.as_str())
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| {
            [obs.probe.stdout.as_str(), obs.probe.stderr.as_str()]
                .into_iter()
                .filter(|s| !s.trim().is_empty())
                .collect::<Vec<_>>()
                .join(" ")
        });

    let cleaned = normalize_whitespace(&base);
    truncate_chars(&cleaned, MAX_RAW_CHARS)
}

fn normalize_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn truncate_chars(s: &str, limit: usize) -> String {
    let mut out = String::new();
    let mut count = 0usize;
    for ch in s.chars() {
        if count >= limit {
            break;
        }
        out.push(ch);
        count += 1;
    }
    if s.chars().count() > limit {
        out.push_str("...");
    }
    out
}

fn result_rank(result: &ProbeResult) -> u8 {
    match result {
        ProbeResult::Ok => 1,
        ProbeResult::NotFound => 2,
        ProbeResult::VersionMismatch => 3,
        ProbeResult::HashMismatch => 4,
        ProbeResult::Error => 5,
        ProbeResult::Skipped => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use env_check_types::{ProbeRecord, SourceRef, VersionObservation};

    fn req(tool: &str, constraint: Option<&str>, probe_kind: ProbeKind) -> Requirement {
        Requirement {
            tool: tool.to_string(),
            constraint: constraint.map(|s| s.to_string()),
            required: true,
            source: SourceRef {
                kind: SourceKind::ToolVersions,
                path: ".tool-versions".to_string(),
            },
            probe_kind,
            hash: None,
        }
    }

    fn obs(
        tool: &str,
        present: bool,
        parsed: Option<&str>,
        raw: &str,
        exit: Option<i32>,
        stderr: &str,
    ) -> Observation {
        Observation {
            tool: tool.to_string(),
            present,
            version: Some(VersionObservation {
                parsed: parsed.map(|s| s.to_string()),
                raw: raw.to_string(),
            }),
            hash_ok: None,
            probe: ProbeRecord {
                cmd: vec![tool.to_string(), "--version".to_string()],
                exit,
                stdout: raw.to_string(),
                stderr: stderr.to_string(),
            },
        }
    }

    #[test]
    fn source_and_probe_kind_ids_are_stable() {
        assert_eq!(source_kind_id(&SourceKind::ToolVersions), "tool-versions");
        assert_eq!(source_kind_id(&SourceKind::GoMod), "go-mod");
        assert_eq!(probe_kind_id(&ProbeKind::PathTool), "path");
        assert_eq!(probe_kind_id(&ProbeKind::FileHash), "hash");
    }

    #[test]
    fn kinds_are_deduped_and_sorted() {
        let kinds = source_kinds(&[
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
        ]);
        assert_eq!(kinds, vec!["go-mod", "tool-versions"]);
    }

    #[test]
    fn summarizes_not_found_version_and_ok_states() {
        let requirements = vec![
            req("node", Some(">=20"), ProbeKind::PathTool),
            req("python", Some("3.13"), ProbeKind::PathTool),
            req("go", Some("latest"), ProbeKind::PathTool),
        ];
        let observations = vec![
            Observation {
                tool: "node".into(),
                present: false,
                version: None,
                hash_ok: None,
                probe: ProbeRecord {
                    cmd: vec![],
                    exit: None,
                    stdout: String::new(),
                    stderr: String::new(),
                },
            },
            obs("python", true, Some("3.12.0"), "Python 3.12.0", Some(0), ""),
            obs(
                "go",
                true,
                Some("1.23.1"),
                "go version go1.23.1",
                Some(0),
                "",
            ),
        ];

        let probes = summarize_probes(&requirements, &observations);
        let by_tool: std::collections::BTreeMap<String, ProbeResult> =
            probes.into_iter().map(|p| (p.tool, p.result)).collect();

        assert_eq!(by_tool["node"], ProbeResult::NotFound);
        assert_eq!(by_tool["python"], ProbeResult::VersionMismatch);
        assert_eq!(by_tool["go"], ProbeResult::Ok);
    }

    #[test]
    fn summarizes_hash_mismatch_and_runtime_error() {
        let mut hash_req = req("file:scripts/tool.sh", None, ProbeKind::FileHash);
        hash_req.source.kind = SourceKind::HashManifest;
        let requirements = vec![hash_req, req("node", Some(">=20"), ProbeKind::PathTool)];

        let observations = vec![
            Observation {
                tool: "file:scripts/tool.sh".into(),
                present: true,
                version: None,
                hash_ok: Some(false),
                probe: ProbeRecord {
                    cmd: vec![],
                    exit: Some(0),
                    stdout: "sha256 scripts/tool.sh = abc".into(),
                    stderr: String::new(),
                },
            },
            Observation {
                tool: "node".into(),
                present: true,
                version: None,
                hash_ok: None,
                probe: ProbeRecord {
                    cmd: vec!["node".into(), "--version".into()],
                    exit: None,
                    stdout: String::new(),
                    stderr: "runtime error".into(),
                },
            },
        ];

        let probes = summarize_probes(&requirements, &observations);
        let by_tool: std::collections::BTreeMap<String, ProbeResult> =
            probes.into_iter().map(|p| (p.tool, p.result)).collect();

        assert_eq!(by_tool["file:scripts/tool.sh"], ProbeResult::HashMismatch);
        assert_eq!(by_tool["node"], ProbeResult::Error);
    }

    #[test]
    fn raw_is_normalized_and_truncated() {
        let requirements = vec![req("node", Some(">=20"), ProbeKind::PathTool)];
        let long = format!("node    v20.11.0 \n\t {}", "x".repeat(300));
        let observations = vec![obs("node", true, Some("20.11.0"), &long, Some(0), "")];

        let probes = summarize_probes(&requirements, &observations);
        assert_eq!(probes.len(), 1);
        assert!(!probes[0].raw.contains('\n'));
        assert!(probes[0].raw.len() <= MAX_RAW_CHARS + 3);
        assert!(probes[0].raw.ends_with("..."));
    }

    #[test]
    fn summaries_are_stably_sorted() {
        let requirements = vec![
            req("ztool", Some("1"), ProbeKind::PathTool),
            req("atool", Some("1"), ProbeKind::PathTool),
        ];
        let observations = vec![
            obs("ztool", true, Some("1.0.0"), "ztool 1.0.0", Some(0), ""),
            obs("atool", true, Some("1.0.0"), "atool 1.0.0", Some(0), ""),
        ];

        let probes = summarize_probes(&requirements, &observations);
        assert_eq!(probes[0].tool, "atool");
        assert_eq!(probes[1].tool, "ztool");
    }

    #[test]
    fn probe_result_serializes_to_schema_values() {
        let row = ProbeSummary {
            tool: "node".into(),
            cmd: vec!["node".into(), "--version".into()],
            result: ProbeResult::VersionMismatch,
            raw: "node v18.0.0".into(),
        };
        let json = serde_json::to_value(&row).expect("serialize");
        assert_eq!(json["result"].as_str(), Some("version_mismatch"));
    }

    #[test]
    fn dependency_graph_empty_for_no_requirements() {
        let graph = dependency_graph(&[]);
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn dependency_graph_node_ecosystem() {
        let requirements = vec![
            req("node", Some(">=20"), ProbeKind::PathTool),
            req("npm", Some(">=10"), ProbeKind::PathTool),
            req("pnpm", Some(">=9"), ProbeKind::PathTool),
        ];

        let graph = dependency_graph(&requirements);
        assert_eq!(graph.nodes, vec!["node", "npm", "pnpm"]);
        assert_eq!(graph.edges.len(), 2);
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "npm" && e.to == "node")
        );
        assert!(
            graph
                .edges
                .iter()
                .any(|e| e.from == "pnpm" && e.to == "node")
        );
    }

    #[test]
    fn dependency_graph_adds_implicit_runtime_nodes() {
        let requirements = vec![req("pipx", Some(">=1"), ProbeKind::PathTool)];
        let graph = dependency_graph(&requirements);
        assert!(graph.nodes.contains(&"pipx".to_string()));
        assert!(graph.nodes.contains(&"python".to_string()));
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].from, "pipx");
        assert_eq!(graph.edges[0].to, "python");
    }
}
