use chrono::Utc;
use env_check_render::render_markdown;
use env_check_types::{
    CiMeta, Counts, Finding, GitMeta, HostMeta, Location, ReceiptEnvelope, RunMeta, Severity,
    ToolMeta, Verdict, VerdictStatus,
};
use serde_json::json;

fn make_receipt(
    status: VerdictStatus,
    counts: Counts,
    findings: Vec<Finding>,
    data: Option<serde_json::Value>,
) -> ReceiptEnvelope {
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
            duration_ms: Some(42),
            host: None,
            ci: None,
            git: None,
            capabilities: None,
        },
        verdict: Verdict {
            status,
            counts,
            reasons: vec![],
        },
        findings,
        artifacts: vec![],
        data,
    }
}

fn make_receipt_with_run_meta(
    status: VerdictStatus,
    counts: Counts,
    findings: Vec<Finding>,
    data: Option<serde_json::Value>,
    run: RunMeta,
) -> ReceiptEnvelope {
    ReceiptEnvelope {
        schema: "sensor.report.v1".to_string(),
        tool: ToolMeta {
            name: "env-check".to_string(),
            version: "0.1.0".to_string(),
            commit: Some("abc1234".to_string()),
        },
        run,
        verdict: Verdict {
            status,
            counts,
            reasons: vec![],
        },
        findings,
        artifacts: vec![],
        data,
    }
}

fn make_finding(
    severity: Severity,
    code: &str,
    message: &str,
    path: Option<&str>,
    help: Option<&str>,
) -> Finding {
    Finding {
        severity,
        check_id: Some("env.check".into()),
        code: code.into(),
        message: message.into(),
        location: path.map(|p| Location {
            path: p.into(),
            line: None,
            col: None,
        }),
        help: help.map(|h| h.into()),
        url: None,
        fingerprint: None,
        data: None,
    }
}

#[test]
fn render_pass_no_findings() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts {
            info: 0,
            warn: 0,
            error: 0,
        },
        vec![],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_skip_no_sources() {
    let receipt = make_receipt(
        VerdictStatus::Skip,
        Counts::default(),
        vec![],
        Some(json!({"profile": "oss", "sources_used": []})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_warn_with_findings() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 2,
            error: 0,
        },
        vec![
            Finding {
                severity: Severity::Warn,
                check_id: Some("env.version".into()),
                code: "env.version_mismatch".into(),
                message: "Version mismatch for node: have 18.0.0, want >=20".into(),
                location: Some(Location {
                    path: ".tool-versions".into(),
                    line: Some(1),
                    col: None,
                }),
                help: Some("Install node 20+".into()),
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Warn,
                check_id: Some("env.version".into()),
                code: "env.version_mismatch".into(),
                message: "Version mismatch for python: have 3.10, want 3.12".into(),
                location: Some(Location {
                    path: ".mise.toml".into(),
                    line: None,
                    col: None,
                }),
                help: Some("Install python 3.12".into()),
                url: None,
                fingerprint: None,
                data: None,
            },
        ],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions", ".mise.toml"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_fail_with_errors() {
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 1,
            error: 2,
        },
        vec![
            Finding {
                severity: Severity::Error,
                check_id: Some("env.presence".into()),
                code: "env.missing_tool".into(),
                message: "Missing tool on PATH: rustc".into(),
                location: Some(Location {
                    path: "rust-toolchain.toml".into(),
                    line: None,
                    col: None,
                }),
                help: Some("Install rustup".into()),
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Error,
                check_id: Some("env.presence".into()),
                code: "env.missing_tool".into(),
                message: "Missing tool on PATH: cargo".into(),
                location: Some(Location {
                    path: "rust-toolchain.toml".into(),
                    line: None,
                    col: None,
                }),
                help: Some("Install rustup".into()),
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Warn,
                check_id: Some("env.version".into()),
                code: "env.version_mismatch".into(),
                message: "Version mismatch for node".into(),
                location: Some(Location {
                    path: ".tool-versions".into(),
                    line: None,
                    col: None,
                }),
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
        ],
        Some(
            json!({"profile": "team", "fail_on": "error", "sources_used": ["rust-toolchain.toml", ".tool-versions"]}),
        ),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_truncated() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 5,
            error: 0,
        },
        vec![], // findings truncated
        Some(json!({"profile": "oss", "truncated": true, "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

// ============================================================================
// Verdict Status Tests - Each status should render correctly
// ============================================================================

#[test]
fn render_verdict_pass_simple() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts {
            info: 1,
            warn: 0,
            error: 0,
        },
        vec![make_finding(
            Severity::Info,
            "env.info",
            "All tools verified",
            Some(".tool-versions"),
            None,
        )],
        Some(json!({"profile": "strict", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_verdict_warn_simple() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 1,
            error: 0,
        },
        vec![make_finding(
            Severity::Warn,
            "env.version_mismatch",
            "node version differs from expected",
            Some(".tool-versions"),
            Some("Run `asdf install node 20.0.0`"),
        )],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_verdict_fail_simple() {
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 0,
            error: 1,
        },
        vec![make_finding(
            Severity::Error,
            "env.missing_tool",
            "python is not installed",
            Some(".mise.toml"),
            Some("Install python via mise or pyenv"),
        )],
        Some(json!({"profile": "team", "fail_on": "error", "sources_used": [".mise.toml"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_verdict_skip_simple() {
    let receipt = make_receipt(
        VerdictStatus::Skip,
        Counts::default(),
        vec![],
        Some(json!({"profile": "oss", "sources_used": [], "reason": "No tool config files found"})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

// ============================================================================
// Finding Combinations
// ============================================================================

#[test]
fn render_no_findings_empty() {
    let receipt = make_receipt(VerdictStatus::Pass, Counts::default(), vec![], None);
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_single_error_finding() {
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 0,
            error: 1,
        },
        vec![Finding {
            severity: Severity::Error,
            check_id: Some("env.presence".into()),
            code: "env.missing_tool".into(),
            message: "rust toolchain 1.75.0 is not installed".into(),
            location: Some(Location {
                path: "rust-toolchain.toml".into(),
                line: Some(2),
                col: Some(10),
            }),
            help: Some("Run `rustup toolchain install 1.75.0`".into()),
            url: Some("https://rustup.rs".into()),
            fingerprint: Some("abc123".into()),
            data: Some(json!({"expected": "1.75.0", "found": null})),
        }],
        Some(
            json!({"profile": "strict", "fail_on": "error", "sources_used": ["rust-toolchain.toml"]}),
        ),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_multiple_warnings() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 3,
            error: 0,
        },
        vec![
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "node: expected 20.x, found 18.17.0",
                Some(".tool-versions"),
                Some("Update node version"),
            ),
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "python: expected 3.12, found 3.11.4",
                Some(".tool-versions"),
                Some("Update python version"),
            ),
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "go: expected 1.21, found 1.20.5",
                Some(".mise.toml"),
                None,
            ),
        ],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions", ".mise.toml"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_mixed_severity_findings() {
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 2,
            warn: 2,
            error: 2,
        },
        vec![
            make_finding(
                Severity::Error,
                "env.missing_tool",
                "rustc is not on PATH",
                Some("rust-toolchain.toml"),
                Some("Install rustup"),
            ),
            make_finding(
                Severity::Error,
                "env.toolchain_missing",
                "Rust toolchain 1.75.0 not installed",
                Some("rust-toolchain.toml"),
                Some("Run: rustup toolchain install 1.75.0"),
            ),
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "node version mismatch: want 20.x, have 18.17.0",
                Some(".tool-versions"),
                None,
            ),
            make_finding(
                Severity::Warn,
                "env.hash_mismatch",
                "Config file hash does not match manifest",
                Some(".env.example"),
                Some("Regenerate config file"),
            ),
            make_finding(
                Severity::Info,
                "env.info",
                "python 3.12.1 verified",
                Some(".mise.toml"),
                None,
            ),
            make_finding(
                Severity::Info,
                "env.info",
                "go 1.21.5 verified",
                Some(".mise.toml"),
                None,
            ),
        ],
        Some(json!({
            "profile": "team",
            "fail_on": "error",
            "sources_used": ["rust-toolchain.toml", ".tool-versions", ".mise.toml"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_truncated_with_many_findings() {
    // Tests the truncation note with actual findings
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 5,
            warn: 10,
            error: 3,
        },
        vec![
            make_finding(
                Severity::Error,
                "env.missing_tool",
                "cargo not found",
                Some("rust-toolchain.toml"),
                None,
            ),
            make_finding(
                Severity::Error,
                "env.missing_tool",
                "rustc not found",
                Some("rust-toolchain.toml"),
                None,
            ),
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "node mismatch",
                Some(".tool-versions"),
                None,
            ),
        ],
        Some(json!({
            "profile": "team",
            "truncated": true,
            "sources_used": ["rust-toolchain.toml", ".tool-versions"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

// ============================================================================
// Source Metadata Tests
// ============================================================================

#[test]
fn render_with_multiple_sources() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts {
            info: 4,
            warn: 0,
            error: 0,
        },
        vec![],
        Some(json!({
            "profile": "oss",
            "sources_used": [".tool-versions", ".mise.toml", "rust-toolchain.toml", ".hashes.json"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_with_profile_and_fail_on() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts::default(),
        vec![],
        Some(json!({
            "profile": "strict",
            "fail_on": "warn",
            "sources_used": [".tool-versions"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_with_ci_metadata() {
    let run = RunMeta {
        started_at: Utc::now(),
        ended_at: Some(Utc::now()),
        duration_ms: Some(1234),
        host: Some(HostMeta {
            os: "linux".into(),
            arch: "x86_64".into(),
            hostname: Some("runner-123".into()),
        }),
        ci: Some(CiMeta {
            provider: "github-actions".into(),
            job: Some("build".into()),
            run_id: Some("12345678".into()),
            workflow: Some("CI".into()),
            repository: Some("example/repo".into()),
            git_ref: Some("refs/heads/feature/add-tests".into()),
            sha: Some("def456".into()),
        }),
        git: Some(GitMeta {
            repo: Some("example/repo".into()),
            base_ref: Some("main".into()),
            head_ref: Some("feature/add-tests".into()),
            base_sha: Some("abc123".into()),
            head_sha: Some("def456".into()),
            merge_base: None,
            pr_number: Some(42),
        }),
        capabilities: None,
    };
    let receipt = make_receipt_with_run_meta(
        VerdictStatus::Pass,
        Counts::default(),
        vec![],
        Some(json!({
            "profile": "team",
            "sources_used": [".tool-versions"],
            "ci": {
                "provider": "github-actions",
                "job": "build",
                "run_id": "12345678"
            }
        })),
        run,
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn render_empty_findings_with_sources() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts::default(),
        vec![],
        Some(json!({
            "profile": "oss",
            "sources_used": [".tool-versions", ".mise.toml", "rust-toolchain.toml"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_many_findings_truncation_display() {
    // Create 15 findings to test the 10-item limit in render
    let findings: Vec<Finding> = (1..=15)
        .map(|i| Finding {
            severity: if i <= 5 {
                Severity::Error
            } else if i <= 10 {
                Severity::Warn
            } else {
                Severity::Info
            },
            check_id: Some(format!("env.check.{}", i)),
            code: format!("env.test_{}", i),
            message: format!("Test finding number {}", i),
            location: Some(Location {
                path: format!("file{}.txt", i),
                line: Some(i as u32),
                col: None,
            }),
            help: if i % 2 == 0 {
                Some(format!("Help for finding {}", i))
            } else {
                None
            },
            url: None,
            fingerprint: None,
            data: None,
        })
        .collect();

    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 5,
            warn: 5,
            error: 5,
        },
        findings,
        Some(json!({"profile": "strict", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_long_messages() {
    let long_message = "This is a very long error message that spans multiple words and describes a complex issue with the environment configuration that might occur when multiple tools are misconfigured or when there are conflicts between different version managers like asdf, mise, and manual installations that can cause confusion for developers trying to set up their local environment";
    let long_help = "To fix this issue, you need to: 1) First check your PATH variable, 2) Verify that all version managers are configured correctly, 3) Ensure there are no conflicting installations, 4) Run the appropriate installation commands for each tool, 5) Restart your shell session to pick up the changes";

    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 0,
            error: 1,
        },
        vec![Finding {
            severity: Severity::Error,
            check_id: Some("env.complex".into()),
            code: "env.configuration_conflict".into(),
            message: long_message.into(),
            location: Some(Location {
                path: ".tool-versions".into(),
                line: Some(1),
                col: Some(1),
            }),
            help: Some(long_help.into()),
            url: Some("https://example.com/docs/troubleshooting/environment-setup".into()),
            fingerprint: None,
            data: None,
        }],
        Some(json!({"profile": "team", "fail_on": "error", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_no_data_object() {
    // Test when data is None
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts {
            info: 0,
            warn: 0,
            error: 0,
        },
        vec![],
        None,
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_empty_data_object() {
    // Test when data is an empty object
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts::default(),
        vec![],
        Some(json!({})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_findings_without_location() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 2,
            error: 0,
        },
        vec![
            Finding {
                severity: Severity::Warn,
                check_id: Some("env.global".into()),
                code: "env.version_mismatch".into(),
                message: "Global node version does not match project requirements".into(),
                location: None, // No location
                help: Some("Check your global node version".into()),
                url: None,
                fingerprint: None,
                data: None,
            },
            Finding {
                severity: Severity::Warn,
                check_id: Some("env.global".into()),
                code: "tool.runtime_error".into(),
                message: "Failed to determine python version".into(),
                location: None, // No location
                help: None,
                url: None,
                fingerprint: None,
                data: None,
            },
        ],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_findings_sorted_by_severity() {
    // Findings are intentionally out of order; renderer should sort by severity desc
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 1,
            warn: 1,
            error: 1,
        },
        vec![
            make_finding(
                Severity::Info,
                "env.info",
                "Info message",
                Some("a.txt"),
                None,
            ),
            make_finding(
                Severity::Error,
                "env.error",
                "Error message",
                Some("b.txt"),
                None,
            ),
            make_finding(
                Severity::Warn,
                "env.warn",
                "Warn message",
                Some("c.txt"),
                None,
            ),
        ],
        Some(json!({"profile": "team", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_special_characters_in_messages() {
    let receipt = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 1,
            error: 0,
        },
        vec![Finding {
            severity: Severity::Warn,
            check_id: Some("env.special".into()),
            code: "env.version_mismatch".into(),
            message: "Version constraint `>=3.10 && <4.0` not satisfied by `3.9.7`".into(),
            location: Some(Location {
                path: ".tool-versions".into(),
                line: Some(5),
                col: None,
            }),
            help: Some("Install python matching constraint: `>=3.10 && <4.0`".into()),
            url: None,
            fingerprint: None,
            data: None,
        }],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions"]})),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_all_stable_finding_codes() {
    // Test all stable finding codes from env-check-types::codes
    let receipt = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 2,
            error: 4,
        },
        vec![
            make_finding(
                Severity::Error,
                "env.missing_tool",
                "Tool 'rustc' not found in PATH",
                Some("rust-toolchain.toml"),
                Some("Install Rust via rustup"),
            ),
            make_finding(
                Severity::Error,
                "env.toolchain_missing",
                "Rust toolchain 1.75.0 not installed",
                Some("rust-toolchain.toml"),
                Some("Run: rustup toolchain install 1.75.0"),
            ),
            make_finding(
                Severity::Error,
                "env.source_parse_error",
                "Failed to parse .tool-versions: invalid syntax at line 3",
                Some(".tool-versions"),
                Some("Check file syntax"),
            ),
            make_finding(
                Severity::Error,
                "tool.runtime_error",
                "Command 'node --version' failed with exit code 1",
                None,
                None,
            ),
            make_finding(
                Severity::Warn,
                "env.version_mismatch",
                "node: expected 20.10.0, found 18.17.1",
                Some(".tool-versions"),
                Some("Run: asdf install nodejs 20.10.0"),
            ),
            make_finding(
                Severity::Warn,
                "env.hash_mismatch",
                "SHA256 hash mismatch for .env.example",
                Some(".hashes.json"),
                Some("Regenerate the file or update the hash manifest"),
            ),
        ],
        Some(json!({
            "profile": "strict",
            "fail_on": "error",
            "sources_used": ["rust-toolchain.toml", ".tool-versions", ".hashes.json"]
        })),
    );
    let md = render_markdown(&receipt);
    insta::assert_snapshot!(md);
}

#[test]
fn render_with_all_profiles() {
    // Test oss profile
    let receipt_oss = make_receipt(
        VerdictStatus::Warn,
        Counts {
            info: 0,
            warn: 1,
            error: 0,
        },
        vec![make_finding(
            Severity::Warn,
            "env.version_mismatch",
            "Version mismatch",
            Some(".tool-versions"),
            None,
        )],
        Some(json!({"profile": "oss", "sources_used": [".tool-versions"]})),
    );
    insta::assert_snapshot!("render_profile_oss", render_markdown(&receipt_oss));

    // Test team profile
    let receipt_team = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 0,
            error: 1,
        },
        vec![make_finding(
            Severity::Error,
            "env.missing_tool",
            "Missing tool",
            Some(".tool-versions"),
            None,
        )],
        Some(json!({"profile": "team", "fail_on": "error", "sources_used": [".tool-versions"]})),
    );
    insta::assert_snapshot!("render_profile_team", render_markdown(&receipt_team));

    // Test strict profile
    let receipt_strict = make_receipt(
        VerdictStatus::Fail,
        Counts {
            info: 0,
            warn: 1,
            error: 0,
        },
        vec![make_finding(
            Severity::Warn,
            "env.version_mismatch",
            "Version mismatch",
            Some(".tool-versions"),
            None,
        )],
        Some(json!({"profile": "strict", "fail_on": "warn", "sources_used": [".tool-versions"]})),
    );
    insta::assert_snapshot!("render_profile_strict", render_markdown(&receipt_strict));
}
