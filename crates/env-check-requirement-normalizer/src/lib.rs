//! Requirement normalization used by the application layer.

use env_check_config::AppConfig;
use env_check_types::Requirement;

pub fn normalize_requirements(mut reqs: Vec<Requirement>, cfg: &AppConfig) -> Vec<Requirement> {
    reqs.retain(|r| !cfg.ignore_tools.iter().any(|t| t == &r.tool));

    for req in &mut reqs {
        if cfg.force_required.iter().any(|t| t == &req.tool) {
            req.required = true;
        }
    }

    let mut out: Vec<Requirement> = Vec::new();
    for req in reqs {
        if out
            .iter()
            .any(|x| x.tool == req.tool && x.probe_kind == req.probe_kind)
        {
            continue;
        }
        out.push(req);
    }

    out
}
