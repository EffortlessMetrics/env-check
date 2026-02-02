use env_check_render::render_markdown;
use env_check_types::*;

#[test]
fn renders_basic() {
    let receipt = ReceiptEnvelope {
        schema: SCHEMA_ID.to_string(),
        tool: ToolMeta { name: TOOL_NAME.to_string(), version: "0.1.0".into(), commit: None },
        run: RunMeta {
            started_at: chrono::Utc::now(),
            ended_at: None,
            duration_ms: None,
            host: None,
            ci: None,
            git: None,
        },
        verdict: Verdict {
            status: VerdictStatus::Warn,
            counts: Counts { info: 0, warn: 1, error: 0 },
            reasons: vec!["missing_tool".into()],
        },
        findings: vec![
            Finding {
                severity: Severity::Warn,
                check_id: Some(checks::PRESENCE.into()),
                code: codes::ENV_MISSING_TOOL.into(),
                message: "Missing tool on PATH: node".into(),
                location: Some(Location { path: ".tool-versions".into(), line: None, col: None }),
                help: Some("Install node".into()),
                url: None,
                fingerprint: None,
                data: None,
            }
        ],
        data: None,
    };

    let md = render_markdown(&receipt);
    assert!(md.contains("env-check: WARN"));
    assert!(md.contains("env.missing_tool"));
}
