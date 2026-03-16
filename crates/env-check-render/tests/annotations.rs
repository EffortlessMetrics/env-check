use chrono::Utc;
use env_check_render::render_github_annotations;
use env_check_types::{
    Counts, Finding, Location, ReceiptEnvelope, RunMeta, Severity, ToolMeta, Verdict, VerdictStatus,
};

fn receipt(findings: Vec<Finding>) -> ReceiptEnvelope {
    ReceiptEnvelope {
        schema: "sensor.report.v1".to_string(),
        tool: ToolMeta {
            name: "env-check".to_string(),
            version: "0.1.0".to_string(),
            commit: None,
        },
        run: RunMeta {
            started_at: Utc::now(),
            ended_at: None,
            duration_ms: None,
            host: None,
            ci: None,
            git: None,
            capabilities: None,
        },
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: Counts {
                info: 0,
                warn: findings.len() as u32,
                error: 0,
            },
            reasons: vec![],
        },
        findings,
        artifacts: vec![],
        data: None,
    }
}

fn finding(
    severity: Severity,
    code: &str,
    message: &str,
    path: Option<&str>,
    line: Option<u32>,
    col: Option<u32>,
) -> Finding {
    Finding {
        severity,
        check_id: Some("env.test".to_string()),
        code: code.to_string(),
        message: message.to_string(),
        location: path.map(|p| Location {
            path: p.to_string(),
            line,
            col,
        }),
        help: None,
        url: None,
        fingerprint: None,
        data: None,
    }
}

#[test]
fn annotations_are_sorted_and_include_location() {
    let report = receipt(vec![
        finding(
            Severity::Warn,
            "env.version_mismatch",
            "Node does not satisfy constraint",
            Some(".tool-versions"),
            Some(1),
            None,
        ),
        finding(
            Severity::Error,
            "env.missing_tool",
            "Missing tool on PATH: node",
            Some(".tool-versions"),
            Some(1),
            Some(1),
        ),
    ]);

    let out = render_github_annotations(&report, 10);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(
        lines[0].starts_with("::error "),
        "error finding should be first"
    );
    assert!(lines[0].contains("title=env.missing_tool"));
    assert!(lines[0].contains("file=.tool-versions"));
    assert!(lines[0].contains("line=1"));
    assert!(lines[0].contains("col=1"));
    assert!(lines[1].starts_with("::warning "));
}

#[test]
fn annotations_escape_message_and_property_values() {
    let report = receipt(vec![finding(
        Severity::Warn,
        "env.version_mismatch",
        "bad%message\nnext line",
        Some("foo:bar,baz.toml"),
        Some(2),
        None,
    )]);

    let out = render_github_annotations(&report, 10);
    assert!(out.contains("file=foo%3Abar%2Cbaz.toml"));
    assert!(out.contains("bad%25message%0Anext line"));
}

#[test]
fn annotations_respect_max_findings() {
    let report = receipt(vec![
        finding(Severity::Error, "a", "a", Some("a"), None, None),
        finding(Severity::Warn, "b", "b", Some("b"), None, None),
    ]);

    let out = render_github_annotations(&report, 1);
    assert_eq!(out.lines().count(), 1);
    assert!(out.contains("title=a"));
}

#[test]
fn annotations_with_zero_max_are_empty() {
    let report = receipt(vec![finding(
        Severity::Warn,
        "env.version_mismatch",
        "x",
        None,
        None,
        None,
    )]);

    assert!(render_github_annotations(&report, 0).is_empty());
}
