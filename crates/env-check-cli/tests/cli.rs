use assert_cmd::Command;
use jsonschema::JSONSchema;
use predicates::prelude::*;
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;

/// Helper to get the path to the fixtures directory
fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
}

fn envelope_schema() -> JSONSchema {
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("schemas")
        .join("receipt.envelope.v1.json");
    let schema_bytes = fs::read_to_string(&schema_path)
        .unwrap_or_else(|e| panic!("read schema {}: {}", schema_path.display(), e));
    let schema_json: Value = serde_json::from_str(&schema_bytes)
        .unwrap_or_else(|e| panic!("parse schema {}: {}", schema_path.display(), e));
    JSONSchema::compile(&schema_json)
        .unwrap_or_else(|e| panic!("compile schema {}: {}", schema_path.display(), e))
}

/// Create a Command for the env-check binary.
/// Uses CARGO_BIN_EXE_env-check which is set by cargo test automatically.
fn env_check_cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_env-check"))
}

// =============================================================================
// BASIC CLI FUNCTIONALITY
// =============================================================================

#[test]
fn help_works() {
    let mut cmd = env_check_cmd();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("env-check"));
}

#[test]
fn version_works() {
    let mut cmd = env_check_cmd();
    cmd.arg("--version");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("env-check"));
}

#[test]
fn check_subcommand_help() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--profile"))
        .stdout(predicate::str::contains("--root"))
        .stdout(predicate::str::contains("--out"));
}

#[test]
fn md_subcommand_help() {
    let mut cmd = env_check_cmd();
    cmd.arg("md").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--report"));
}

#[test]
fn explain_subcommand_help() {
    let mut cmd = env_check_cmd();
    cmd.arg("explain").arg("--help");
    cmd.assert().success();
}

#[test]
fn check_no_sources_exits_zero() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/no_sources")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().success();

    // Verify report was written
    assert!(out_path.exists());
    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "skip");
    let reasons = json["verdict"]["reasons"]
        .as_array()
        .expect("verdict.reasons should be an array");
    assert!(
        reasons.iter().any(|r| r.as_str() == Some("no_sources")),
        "expected verdict reasons to include no_sources"
    );
}

#[test]
fn check_missing_tool_team_profile_exits_two() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/missing_tool")
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    // Verify report contains error
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("\"status\": \"fail\""));
}

#[test]
fn check_missing_tool_oss_profile_exits_zero() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/missing_tool")
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().success();

    // Verify report contains warn (not error)
    let content = fs::read_to_string(&out_path).unwrap();
    assert!(content.contains("\"status\": \"warn\""));
}

#[test]
fn check_writes_markdown_when_requested() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("comment.md");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/no_sources")
        .arg("--out")
        .arg(&out_path)
        .arg("--md")
        .arg(&md_path);

    cmd.assert().success();

    assert!(md_path.exists());
    let md = fs::read_to_string(&md_path).unwrap();
    assert!(md.contains("## env-check:"));
}

#[test]
fn md_command_renders_from_report() {
    let tmp = tempdir().unwrap();
    let report_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("output.md");

    // First create a report
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/no_sources")
        .arg("--out")
        .arg(&report_path);
    cmd.assert().success();

    // Then render markdown from it
    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg("--report")
        .arg(&report_path)
        .arg("--out")
        .arg(&md_path);
    cmd.assert().success();

    assert!(md_path.exists());
}

#[test]
fn md_command_with_positional_argument() {
    let tmp = tempdir().unwrap();
    let report_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("output.md");

    // First create a report
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/no_sources")
        .arg("--out")
        .arg(&report_path);
    cmd.assert().success();

    // Then render markdown using positional argument (not --report flag)
    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg(&report_path) // positional argument
        .arg("--out")
        .arg(&md_path);
    cmd.assert().success();

    assert!(md_path.exists());
    let md = fs::read_to_string(&md_path).unwrap();
    assert!(md.contains("## env-check:"));
}

#[test]
fn md_command_positional_takes_precedence() {
    let tmp = tempdir().unwrap();
    let report_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("output.md");
    let fake_path = tmp.path().join("nonexistent.json");

    // First create a report
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/no_sources")
        .arg("--out")
        .arg(&report_path);
    cmd.assert().success();

    // Positional argument should take precedence over --report flag
    // Here we provide a valid positional and invalid --report; should succeed
    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg(&report_path) // valid positional argument
        .arg("--report")
        .arg(&fake_path) // invalid flag argument (would fail if used)
        .arg("--out")
        .arg(&md_path);
    cmd.assert().success();

    assert!(md_path.exists());
}

#[test]
fn md_command_requires_report_argument() {
    let tmp = tempdir().unwrap();
    let md_path = tmp.path().join("output.md");

    // md command without any report argument should fail
    let mut cmd = env_check_cmd();
    cmd.arg("md").arg("--out").arg(&md_path);
    cmd.assert().failure();
}

#[test]
fn explain_known_code() {
    let mut cmd = env_check_cmd();
    cmd.arg("explain").arg("env.missing_tool");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("PATH"));
}

#[test]
fn explain_unknown_code() {
    let mut cmd = env_check_cmd();
    cmd.arg("explain").arg("unknown.code.here");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Unknown code"));
}

#[test]
fn invalid_profile_fails() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--profile").arg("invalid");
    cmd.assert().failure();
}

#[test]
fn invalid_fail_on_fails() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--fail-on").arg("invalid");
    cmd.assert().failure();
}

#[test]
fn runtime_error_writes_receipt_and_exits_one() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let bad_config = tmp.path().join("bad.toml");

    fs::write(&bad_config, "not = [toml").unwrap();

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--config")
        .arg(&bad_config)
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(1);

    assert!(
        out_path.exists(),
        "Report should be written on runtime errors"
    );
    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "fail");
    let reasons = json["verdict"]["reasons"].as_array().unwrap();
    assert!(reasons.iter().any(|r| r.as_str() == Some("tool_error")));
    let finding = json["findings"]
        .as_array()
        .unwrap()
        .first()
        .expect("Missing finding");
    assert_eq!(finding["code"].as_str().unwrap(), "tool.runtime_error");

    let schema = envelope_schema();
    let validation = schema.validate(&json);
    if let Err(errors) = validation {
        let messages: Vec<String> = errors
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();
        panic!(
            "runtime error receipt failed envelope validation:\n{}",
            messages.join("\n")
        );
    }
}

// =============================================================================
// EXIT CODE TESTS
// =============================================================================

#[test]
fn exit_code_zero_for_pass_status() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(0);

    // Verify the status in the report
    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    let status = json["verdict"]["status"].as_str().unwrap();
    assert!(
        status == "pass" || status == "skip",
        "Expected pass or skip, got: {}",
        status
    );
}

#[test]
fn exit_code_zero_for_warn_status_oss_profile() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(0);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "warn");
}

#[test]
fn exit_code_two_for_fail_status_team_profile() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "fail");
}

#[test]
fn exit_code_two_for_strict_profile_missing_tool() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("strict")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "fail");
}

#[test]
fn exit_code_zero_for_skip_status() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(0);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "skip");
}

// =============================================================================
// OUTPUT FILE TESTS
// =============================================================================

#[test]
fn report_json_is_created_at_specified_path() {
    let tmp = tempdir().unwrap();
    let custom_path = tmp.path().join("custom").join("path").join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&custom_path);

    cmd.assert().success();

    assert!(
        custom_path.exists(),
        "Report should be created at custom path"
    );
}

#[test]
fn report_json_has_valid_structure() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path);

    cmd.assert().success();

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).expect("Report should be valid JSON");

    // Verify required top-level fields
    assert!(
        json.get("schema").is_some(),
        "Report should have 'schema' field"
    );
    assert!(
        json.get("tool").is_some(),
        "Report should have 'tool' field"
    );
    assert!(json.get("run").is_some(), "Report should have 'run' field");
    assert!(
        json.get("verdict").is_some(),
        "Report should have 'verdict' field"
    );

    // Verify schema value
    assert_eq!(
        json["schema"].as_str().unwrap(),
        "env-check.report.v1",
        "Schema should be 'env-check.report.v1'"
    );

    // Verify tool structure
    assert!(
        json["tool"].get("name").is_some(),
        "Tool should have 'name'"
    );
    assert!(
        json["tool"].get("version").is_some(),
        "Tool should have 'version'"
    );

    // Verify run structure
    assert!(
        json["run"].get("started_at").is_some(),
        "Run should have 'started_at'"
    );

    // Verify verdict structure
    assert!(
        json["verdict"].get("status").is_some(),
        "Verdict should have 'status'"
    );
    assert!(
        json["verdict"].get("counts").is_some(),
        "Verdict should have 'counts'"
    );
}

#[test]
fn report_json_matches_envelope_schema() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path);

    cmd.assert().success();

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).expect("Report should be valid JSON");

    let schema = envelope_schema();
    let validation = schema.validate(&json);
    if let Err(errors) = validation {
        let messages: Vec<String> = errors
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();
        panic!(
            "report.json failed envelope validation:\n{}",
            messages.join("\n")
        );
    }
}

#[test]
fn report_json_contains_findings_for_missing_tool() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();

    // Verify findings array exists and has content
    let findings = json["findings"]
        .as_array()
        .expect("Findings should be an array");
    assert!(
        !findings.is_empty(),
        "Findings should not be empty for missing tool"
    );

    // Verify finding structure
    let finding = &findings[0];
    assert!(
        finding.get("severity").is_some(),
        "Finding should have 'severity'"
    );
    assert!(finding.get("code").is_some(), "Finding should have 'code'");
    assert!(
        finding.get("message").is_some(),
        "Finding should have 'message'"
    );

    // Verify finding code for missing tool
    assert_eq!(
        finding["code"].as_str().unwrap(),
        "env.missing_tool",
        "Finding code should be 'env.missing_tool'"
    );
}

#[test]
fn markdown_file_is_created_when_md_flag_used() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("comment.md");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path)
        .arg("--md")
        .arg(&md_path);

    cmd.assert().success();

    assert!(md_path.exists(), "Markdown file should be created");
    let md_content = fs::read_to_string(&md_path).unwrap();
    assert!(
        md_content.contains("## env-check:"),
        "Markdown should contain env-check header"
    );
}

#[test]
fn markdown_not_created_without_md_flag() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("comment.md");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path);

    cmd.assert().success();

    assert!(
        !md_path.exists(),
        "Markdown file should not be created without --md flag"
    );
}

#[test]
fn md_command_creates_markdown_from_existing_report() {
    let tmp = tempdir().unwrap();
    let report_path = tmp.path().join("report.json");
    let md_path = tmp.path().join("output.md");

    // First create a report
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&report_path);
    cmd.assert().success();

    // Then render markdown from it
    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg("--report")
        .arg(&report_path)
        .arg("--out")
        .arg(&md_path);
    cmd.assert().success();

    assert!(
        md_path.exists(),
        "Markdown file should be created by md command"
    );
    let md_content = fs::read_to_string(&md_path).unwrap();
    assert!(
        md_content.contains("## env-check:"),
        "Markdown should contain env-check header"
    );
}

// =============================================================================
// PROFILE BEHAVIOR TESTS
// =============================================================================

#[test]
fn profile_oss_treats_missing_tool_as_warn() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(0);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "warn");
    assert!(json["verdict"]["counts"]["warn"].as_u64().unwrap() > 0);
}

#[test]
fn profile_team_treats_missing_tool_as_error() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "fail");
    assert!(json["verdict"]["counts"]["error"].as_u64().unwrap() > 0);
}

#[test]
fn profile_strict_treats_missing_tool_as_error() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("strict")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(2);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(json["verdict"]["status"].as_str().unwrap(), "fail");
    assert!(json["verdict"]["counts"]["error"].as_u64().unwrap() > 0);
}

#[test]
fn profile_default_is_oss() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    // Run without --profile flag
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--out")
        .arg(&out_path);

    // OSS profile should exit 0 for warnings
    cmd.assert().code(0);

    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).unwrap();
    assert_eq!(
        json["verdict"]["status"].as_str().unwrap(),
        "warn",
        "Default profile should be oss (warn for missing tools)"
    );
}

// =============================================================================
// FAIL-ON BEHAVIOR TESTS
// =============================================================================

#[test]
fn fail_on_warn_exits_two_for_warnings() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--fail-on")
        .arg("warn")
        .arg("--out")
        .arg(&out_path);

    // Even with OSS profile (which would normally exit 0), fail-on warn should cause exit 2
    cmd.assert().code(2);
}

#[test]
fn fail_on_never_exits_zero_even_for_errors() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("team")
        .arg("--fail-on")
        .arg("never")
        .arg("--out")
        .arg(&out_path);

    // Team profile would normally exit 2, but fail-on never should exit 0
    cmd.assert().code(0);
}

#[test]
fn fail_on_error_is_default() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    // OSS profile with warnings exits 0 (fail-on error is default)
    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path);

    cmd.assert().code(0);

    // Team profile with errors exits 2 (fail-on error is default)
    let tmp2 = tempdir().unwrap();
    let out_path2 = tmp2.path().join("report.json");

    let mut cmd2 = env_check_cmd();
    cmd2.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("team")
        .arg("--out")
        .arg(&out_path2);

    cmd2.assert().code(2);
}

// =============================================================================
// ERROR CONDITIONS TESTS
// =============================================================================

#[test]
fn invalid_profile_argument_fails_with_error() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--profile").arg("invalid_profile");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn invalid_fail_on_argument_fails_with_error() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--fail-on").arg("invalid_value");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn nonexistent_root_directory_skips() {
    // Note: When the root directory doesn't exist or is empty, the check skips
    // with exit 0 rather than failing, because there are no sources to check.
    // This is the expected behavior - "no sources" means "skip".
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let nonexistent = tmp.path().join("nonexistent_subdir_12345");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(&nonexistent)
        .arg("--out")
        .arg(&out_path);

    // The command succeeds but produces a skip verdict because no sources found
    cmd.assert().success();

    // Report should exist and show skip status
    if out_path.exists() {
        let content = fs::read_to_string(&out_path).unwrap();
        let json: Value = serde_json::from_str(&content).unwrap();
        assert_eq!(
            json["verdict"]["status"].as_str().unwrap(),
            "skip",
            "Should skip when root has no sources"
        );
    }
}

#[test]
fn malformed_tool_versions_handles_gracefully() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("malformed_tool_versions"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path);

    // Should not crash - may succeed with warnings or report parse errors
    let output = cmd.output().expect("Command should execute");

    // The command should complete (not crash)
    assert!(
        output.status.code().is_some(),
        "Command should complete without crashing"
    );

    // Report should still be created (if the command didn't fail early)
    if out_path.exists() {
        let content = fs::read_to_string(&out_path).unwrap();
        let json: Value = serde_json::from_str(&content).expect("Report should be valid JSON");
        assert!(json.get("verdict").is_some(), "Report should have verdict");
    }
}

#[test]
fn md_command_with_nonexistent_report_fails() {
    let tmp = tempdir().unwrap();
    let md_path = tmp.path().join("output.md");

    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg("--report")
        .arg("/nonexistent/report.json")
        .arg("--out")
        .arg(&md_path);

    cmd.assert().failure();
}

#[test]
fn md_command_with_invalid_json_report_fails() {
    let tmp = tempdir().unwrap();
    let report_path = tmp.path().join("invalid.json");
    let md_path = tmp.path().join("output.md");

    // Write invalid JSON
    fs::write(&report_path, "{ this is not valid json }").unwrap();

    let mut cmd = env_check_cmd();
    cmd.arg("md")
        .arg("--report")
        .arg(&report_path)
        .arg("--out")
        .arg(&md_path);

    cmd.assert().failure();
}

// =============================================================================
// EXPLAIN COMMAND TESTS
// =============================================================================

#[test]
fn explain_all_known_codes() {
    let known_codes = [
        ("env.missing_tool", "PATH"),
        ("env.version_mismatch", "version"),
        ("env.hash_mismatch", "hash"),
        ("env.toolchain_missing", "rustup"),
        ("env.source_parse_error", "parse"),
        ("tool.runtime_error", "execute"),
    ];

    for (code, expected_word) in known_codes {
        let mut cmd = env_check_cmd();
        cmd.arg("explain").arg(code);
        cmd.assert()
            .success()
            .stdout(predicate::str::contains(expected_word).from_utf8());
    }
}

#[test]
fn explain_unknown_code_returns_unknown_message() {
    let mut cmd = env_check_cmd();
    cmd.arg("explain").arg("completely.unknown.code.xyz");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Unknown code"));
}

// =============================================================================
// STDERR OUTPUT TESTS
// =============================================================================

#[test]
fn check_prints_summary_to_stderr() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("no_sources"))
        .arg("--out")
        .arg(&out_path);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("env-check:"));
}

// =============================================================================
// REPORT DETERMINISM TESTS
// =============================================================================

#[test]
fn report_is_deterministic_for_same_input() {
    let tmp1 = tempdir().unwrap();
    let tmp2 = tempdir().unwrap();
    let out_path1 = tmp1.path().join("report.json");
    let out_path2 = tmp2.path().join("report.json");

    // Run check twice with same inputs
    let mut cmd1 = env_check_cmd();
    cmd1.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path1);
    cmd1.assert().success();

    let mut cmd2 = env_check_cmd();
    cmd2.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path2);
    cmd2.assert().success();

    let content1 = fs::read_to_string(&out_path1).unwrap();
    let content2 = fs::read_to_string(&out_path2).unwrap();

    let json1: Value = serde_json::from_str(&content1).unwrap();
    let json2: Value = serde_json::from_str(&content2).unwrap();

    // Compare verdicts and findings (timestamps will differ)
    assert_eq!(
        json1["verdict"], json2["verdict"],
        "Verdicts should be deterministic"
    );
    assert_eq!(
        json1["findings"], json2["findings"],
        "Findings should be deterministic"
    );
    assert_eq!(
        json1["schema"], json2["schema"],
        "Schema should be deterministic"
    );
}

// =============================================================================
// VALID TOOLS FIXTURE TESTS
// =============================================================================

#[test]
fn valid_tools_fixture_produces_report() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path);

    // Should complete without crashing
    let output = cmd.output().expect("Command should execute");
    assert!(output.status.code().is_some(), "Command should complete");

    // Report should be created
    assert!(out_path.exists(), "Report should be created");
    let content = fs::read_to_string(&out_path).unwrap();
    let json: Value = serde_json::from_str(&content).expect("Report should be valid JSON");
    assert!(json.get("verdict").is_some(), "Report should have verdict");
}

// =============================================================================
// DEBUG LOGGING TESTS
// =============================================================================

#[test]
fn debug_flag_creates_raw_log() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let artifacts_dir = tmp.path().join("artifacts").join("env-check");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path)
        .arg("--debug")
        .current_dir(tmp.path());

    cmd.assert().success();

    // Verify raw.log was created at default location
    let log_path = artifacts_dir.join("raw.log");
    assert!(
        log_path.exists(),
        "raw.log should be created when --debug flag is used"
    );

    // Verify log has content
    let log_content = fs::read_to_string(&log_path).unwrap();
    assert!(
        log_content.contains("# env-check probe debug log"),
        "Log should have header"
    );
}

#[test]
fn log_file_flag_creates_custom_log() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let custom_log = tmp.path().join("custom").join("my_debug.log");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path)
        .arg("--log-file")
        .arg(&custom_log);

    cmd.assert().success();

    // Verify log was created at custom path
    assert!(
        custom_log.exists(),
        "Log should be created at custom path specified by --log-file"
    );

    // Verify log has content
    let log_content = fs::read_to_string(&custom_log).unwrap();
    assert!(
        log_content.contains("# env-check probe debug log"),
        "Log should have header"
    );
}

#[test]
fn no_debug_flag_does_not_create_log() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let artifacts_dir = tmp.path().join("artifacts").join("env-check");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path)
        .current_dir(tmp.path());

    cmd.assert().success();

    // Verify raw.log was NOT created
    let log_path = artifacts_dir.join("raw.log");
    assert!(
        !log_path.exists(),
        "raw.log should NOT be created when --debug flag is not used"
    );
}

#[test]
fn env_var_creates_log() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let env_log = tmp.path().join("env_debug.log");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path)
        .env("ENV_CHECK_DEBUG_LOG", &env_log);

    cmd.assert().success();

    // Verify log was created at path specified by env var
    assert!(
        env_log.exists(),
        "Log should be created at path specified by ENV_CHECK_DEBUG_LOG"
    );
}

#[test]
fn debug_log_contains_probe_info() {
    let tmp = tempdir().unwrap();
    let out_path = tmp.path().join("report.json");
    let log_path = tmp.path().join("debug.log");

    let mut cmd = env_check_cmd();
    cmd.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("valid_tools"))
        .arg("--out")
        .arg(&out_path)
        .arg("--log-file")
        .arg(&log_path);

    cmd.assert().success();

    // Verify log contains probe information
    let log_content = fs::read_to_string(&log_path).unwrap();

    // Should have header
    assert!(
        log_content.contains("# env-check probe debug log"),
        "Log should have header"
    );
    assert!(
        log_content.contains("# started:"),
        "Log should have timestamp"
    );
}

#[test]
fn debug_log_does_not_affect_report_determinism() {
    let tmp1 = tempdir().unwrap();
    let tmp2 = tempdir().unwrap();
    let out_path1 = tmp1.path().join("report.json");
    let out_path2 = tmp2.path().join("report.json");

    // Run with debug logging
    let mut cmd1 = env_check_cmd();
    cmd1.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path1)
        .arg("--debug")
        .current_dir(tmp1.path());
    cmd1.assert().success();

    // Run without debug logging
    let mut cmd2 = env_check_cmd();
    cmd2.arg("check")
        .arg("--root")
        .arg(fixtures_dir().join("missing_tool"))
        .arg("--profile")
        .arg("oss")
        .arg("--out")
        .arg(&out_path2);
    cmd2.assert().success();

    let content1 = fs::read_to_string(&out_path1).unwrap();
    let content2 = fs::read_to_string(&out_path2).unwrap();

    let json1: Value = serde_json::from_str(&content1).unwrap();
    let json2: Value = serde_json::from_str(&content2).unwrap();

    // Verdicts and findings should be identical regardless of debug logging
    assert_eq!(
        json1["verdict"], json2["verdict"],
        "Verdict should be the same with or without debug logging"
    );
    assert_eq!(
        json1["findings"], json2["findings"],
        "Findings should be the same with or without debug logging"
    );
}

#[test]
fn check_help_shows_debug_options() {
    let mut cmd = env_check_cmd();
    cmd.arg("check").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--debug"))
        .stdout(predicate::str::contains("--log-file"))
        .stdout(predicate::str::contains("ENV_CHECK_DEBUG_LOG"));
}
