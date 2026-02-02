//! Markdown renderer for env-check receipts.
//!
//! Rendering is pure and deterministic. Any truncation/caps must already be reflected
//! in the receipt (e.g., `data.truncated=true`).

use env_check_types::{ReceiptEnvelope, Severity, VerdictStatus};

pub fn render_markdown(report: &ReceiptEnvelope) -> String {
    let status = match report.verdict.status {
        VerdictStatus::Pass => "PASS",
        VerdictStatus::Warn => "WARN",
        VerdictStatus::Fail => "FAIL",
        VerdictStatus::Skip => "SKIP",
    };

    let mut out = String::new();
    out.push_str(&format!("## env-check: {}\n\n", status));
    out.push_str(&format!(
        "- Findings: {} error, {} warn, {} info\n",
        report.verdict.counts.error, report.verdict.counts.warn, report.verdict.counts.info
    ));

    if let Some(data) = report.data.as_ref().and_then(|d| d.as_object()) {
        if let Some(profile) = data.get("profile").and_then(|v| v.as_str()) {
            out.push_str(&format!("- Profile: `{}`\n", profile));
        }
        if let Some(fail_on) = data.get("fail_on").and_then(|v| v.as_str()) {
            out.push_str(&format!("- fail_on: `{}`\n", fail_on));
        }
        if let Some(srcs) = data.get("sources_used").and_then(|v| v.as_array()) {
            let list: Vec<String> = srcs.iter().filter_map(|x| x.as_str().map(|s| format!("`{}`", s))).collect();
            if !list.is_empty() {
                out.push_str(&format!("- Sources: {}\n", list.join(", ")));
            }
        }
        if data.get("truncated").and_then(|v| v.as_bool()) == Some(true) {
            out.push_str("- Note: output truncated; see `report.json` for full details.\n");
        }
    }

    out.push_str("\n");

    // Show up to 10 findings, prioritizing errors then warns.
    let mut items: Vec<_> = report.findings.iter().collect();
    items.sort_by(|a, b| a.severity.rank().cmp(&b.severity.rank()).reverse().then(a.code.cmp(&b.code)));

    let max = 10usize;
    if items.is_empty() {
        out.push_str("_No findings._\n");
        return out;
    }

    out.push_str("### Findings\n\n");
    for f in items.into_iter().take(max) {
        let sev = match f.severity {
            Severity::Error => "error",
            Severity::Warn => "warn",
            Severity::Info => "info",
        };

        let loc = f
            .location
            .as_ref()
            .map(|l| format!(" ({})", l.path))
            .unwrap_or_default();

        out.push_str(&format!("- **{}** `{}`{} — {}\n", sev, f.code, loc, f.message));
        if let Some(help) = &f.help {
            out.push_str(&format!("  - {}
", help));
        }
    }

    out
}
