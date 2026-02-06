//! Gherkin-style BDD tests for env-check CLI.
//!
//! We run these as a standalone test binary (harness = false) so cucumber can
//! own `main()` and exit codes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cucumber::{given, then, when, World};
use serde_json::Value;

#[derive(World, Debug, Default)]
struct EnvWorld {
    tmp: Option<tempfile::TempDir>,
    repo_root: Option<PathBuf>,
    exit_code: Option<i32>,
    report_json: Option<Value>,
    markdown: Option<String>,
    out_path: Option<PathBuf>,
    md_path: Option<PathBuf>,
    log_path: Option<PathBuf>,
    stdout: Option<String>,
}

#[given(expr = "a repo fixture {string}")]
async fn given_fixture(world: &mut EnvWorld, name: String) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);

    let tmp = tempfile::tempdir().expect("tempdir");
    let dst = tmp.path().join("repo");

    copy_dir_recursive(&src, &dst).expect("copy fixture");

    world.tmp = Some(tmp);
    world.repo_root = Some(dst);
    world.exit_code = None;
    world.report_json = None;
    world.markdown = None;
    world.out_path = None;
    world.md_path = None;
    world.log_path = None;
    world.stdout = None;
}

#[when(expr = "I run env-check with profile {string}")]
async fn when_run(world: &mut EnvWorld, profile: String) {
    run_env_check(world, &profile, None, false, false);
}

#[when(expr = "I run env-check with profile {string} and fail_on {string}")]
async fn when_run_with_fail_on(world: &mut EnvWorld, profile: String, fail_on: String) {
    run_env_check(world, &profile, Some(&fail_on), false, false);
}

#[when(expr = "I run env-check with profile {string} and markdown output")]
async fn when_run_with_markdown(world: &mut EnvWorld, profile: String) {
    run_env_check(world, &profile, None, true, false);
}

#[when(expr = "I run env-check with profile {string} and debug enabled")]
async fn when_run_with_debug(world: &mut EnvWorld, profile: String) {
    run_env_check(world, &profile, None, false, true);
}

#[when(expr = "I run env-check explain {string}")]
async fn when_run_explain(world: &mut EnvWorld, code: String) {
    // Ensure we have a temp dir for the explain command
    if world.tmp.is_none() {
        world.tmp = Some(tempfile::tempdir().expect("tempdir"));
    }

    let exe = env!("CARGO_BIN_EXE_env-check");

    let mut cmd = Command::new(exe);
    cmd.arg("explain").arg(&code);

    // Make the environment deterministic
    cmd.env("PATH", "");

    let out = cmd.output().expect("run env-check explain");
    world.exit_code = out.status.code();
    world.stdout = Some(String::from_utf8_lossy(&out.stdout).to_string());
}

fn run_env_check(
    world: &mut EnvWorld,
    profile: &str,
    fail_on: Option<&str>,
    with_markdown: bool,
    with_debug: bool,
) {
    let root = world.repo_root.as_ref().expect("fixture root");
    let tmp = world.tmp.as_ref().expect("temp dir");

    // Cargo exposes the built test binary paths via env vars, even for
    // harness=false tests.
    let exe = env!("CARGO_BIN_EXE_env-check");

    let out_path = tmp.path().join("artifacts/env-check/report.json");
    let md_path = tmp.path().join("artifacts/env-check/comment.md");
    let log_path = tmp.path().join("artifacts/env-check/raw.log");

    let mut cmd = Command::new(exe);
    cmd.arg("check")
        .arg("--root")
        .arg(root)
        .arg("--profile")
        .arg(profile)
        .arg("--out")
        .arg(&out_path);

    if let Some(fo) = fail_on {
        cmd.arg("--fail-on").arg(fo);
    }

    if with_markdown {
        cmd.arg("--md").arg(&md_path);
    }

    if with_debug {
        cmd.arg("--debug").arg("--log-file").arg(&log_path);
    }

    // Make the environment deterministic: don't leak tools from the host.
    cmd.env("PATH", "");

    let out = cmd.output().expect("run env-check");
    world.exit_code = out.status.code();
    world.out_path = Some(out_path.clone());
    world.md_path = Some(md_path.clone());
    world.log_path = Some(log_path.clone());
    world.stdout = Some(String::from_utf8_lossy(&out.stdout).to_string());

    // Try to load the report JSON if it was created
    if out_path.exists() {
        if let Ok(bytes) = fs::read(&out_path) {
            if let Ok(json) = serde_json::from_slice(&bytes) {
                world.report_json = Some(json);
            }
        }
    }

    // Try to load the markdown if it was created
    if md_path.exists() {
        if let Ok(content) = fs::read_to_string(&md_path) {
            world.markdown = Some(content);
        }
    }
}

#[then(expr = "the exit code is {int}")]
async fn then_exit_code(world: &mut EnvWorld, expected: i32) {
    assert_eq!(
        world.exit_code,
        Some(expected),
        "expected exit code {expected}, got {:?}",
        world.exit_code
    );
}

#[then(expr = "the verdict status is {string}")]
async fn then_verdict_status(world: &mut EnvWorld, expected: String) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let status = report
        .get("verdict")
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_str())
        .expect("verdict.status should exist");

    assert_eq!(
        status, expected,
        "expected verdict status '{}', got '{}'",
        expected, status
    );
}

#[then(expr = "the report contains sources {string} and {string}")]
async fn then_report_contains_two_sources(world: &mut EnvWorld, source1: String, source2: String) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let sources = report
        .get("data")
        .and_then(|d| d.get("sources_used"))
        .and_then(|s| s.as_array())
        .expect("data.sources_used should be an array");

    let sources_list: Vec<&str> = sources.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        sources_list.iter().any(|s| s.contains(&source1)),
        "expected sources to contain '{}', got: {:?}",
        source1,
        sources_list
    );
    assert!(
        sources_list.iter().any(|s| s.contains(&source2)),
        "expected sources to contain '{}', got: {:?}",
        source2,
        sources_list
    );
}

#[then(expr = "the report contains source {string}")]
async fn then_report_contains_source(world: &mut EnvWorld, source: String) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let sources = report
        .get("data")
        .and_then(|d| d.get("sources_used"))
        .and_then(|s| s.as_array())
        .expect("data.sources_used should be an array");

    let sources_list: Vec<&str> = sources.iter().filter_map(|v| v.as_str()).collect();

    assert!(
        sources_list.iter().any(|s| s.contains(&source)),
        "expected sources to contain '{}', got: {:?}",
        source,
        sources_list
    );
}

#[then(expr = "the report contains finding code {string}")]
async fn then_report_contains_finding_code(world: &mut EnvWorld, code: String) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let findings = report
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("findings should be an array");

    let codes: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.get("code").and_then(|c| c.as_str()))
        .collect();

    assert!(
        codes.contains(&code.as_str()),
        "expected findings to contain code '{}', got: {:?}",
        code,
        codes
    );
}

#[then(expr = "the report JSON is valid against the envelope schema")]
async fn then_report_valid_against_schema(world: &mut EnvWorld) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");

    // Load the schema from the project root
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/sensor.report.v1.schema.json");

    let schema_bytes = fs::read(&schema_path).expect("failed to read schema file");
    let schema_json: Value =
        serde_json::from_slice(&schema_bytes).expect("failed to parse schema JSON");

    let compiled =
        jsonschema::JSONSchema::compile(&schema_json).expect("failed to compile JSON schema");

    let result = compiled.validate(report);
    if let Err(errors) = result {
        let error_messages: Vec<String> = errors
            .map(|e| format!("  - {}: {}", e.instance_path, e))
            .collect();
        panic!(
            "report JSON does not match schema:\n{}",
            error_messages.join("\n")
        );
    }
}

#[then(expr = "the markdown contains {string}")]
async fn then_markdown_contains(world: &mut EnvWorld, expected: String) {
    let markdown = world
        .markdown
        .as_ref()
        .expect("markdown output should exist");
    assert!(
        markdown.contains(&expected),
        "expected markdown to contain '{}', got:\n{}",
        expected,
        markdown
    );
}

#[then(expr = "a debug log file exists")]
async fn then_debug_log_exists(world: &mut EnvWorld) {
    let log_path = world.log_path.as_ref().expect("log path should be set");
    assert!(
        log_path.exists(),
        "expected debug log file to exist at {:?}",
        log_path
    );
}

#[then(expr = "the stdout contains {string}")]
async fn then_stdout_contains(world: &mut EnvWorld, expected: String) {
    let stdout = world.stdout.as_ref().expect("stdout should exist");
    assert!(
        stdout.contains(&expected),
        "expected stdout to contain '{}', got:\n{}",
        expected,
        stdout
    );
}

#[then(expr = "the finding count is {int}")]
async fn then_finding_count(world: &mut EnvWorld, expected: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let findings = report
        .get("findings")
        .and_then(|f| f.as_array())
        .expect("findings should be an array");

    assert_eq!(
        findings.len() as i32,
        expected,
        "expected {} findings, got {}",
        expected,
        findings.len()
    );
}

#[then(expr = "the warning count is greater than {int}")]
async fn then_warning_count_gt(world: &mut EnvWorld, min: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let warn_count = report
        .get("verdict")
        .and_then(|v| v.get("counts"))
        .and_then(|c| c.get("warn"))
        .and_then(|w| w.as_i64())
        .expect("verdict.counts.warn should exist");

    assert!(
        warn_count > min as i64,
        "expected warning count > {}, got {}",
        min,
        warn_count
    );
}

#[then(expr = "the warning count is {int}")]
async fn then_warning_count(world: &mut EnvWorld, expected: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let warn_count = report
        .get("verdict")
        .and_then(|v| v.get("counts"))
        .and_then(|c| c.get("warn"))
        .and_then(|w| w.as_i64())
        .expect("verdict.counts.warn should exist");

    assert_eq!(
        warn_count, expected as i64,
        "expected warning count {}, got {}",
        expected, warn_count
    );
}

#[then(expr = "the error count is {int}")]
async fn then_error_count(world: &mut EnvWorld, expected: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let error_count = report
        .get("verdict")
        .and_then(|v| v.get("counts"))
        .and_then(|c| c.get("error"))
        .and_then(|e| e.as_i64())
        .expect("verdict.counts.error should exist");

    assert_eq!(
        error_count, expected as i64,
        "expected error count {}, got {}",
        expected, error_count
    );
}

#[then(expr = "the error count is greater than {int}")]
async fn then_error_count_gt(world: &mut EnvWorld, min: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let error_count = report
        .get("verdict")
        .and_then(|v| v.get("counts"))
        .and_then(|c| c.get("error"))
        .and_then(|e| e.as_i64())
        .expect("verdict.counts.error should exist");

    assert!(
        error_count > min as i64,
        "expected error count > {}, got {}",
        min,
        error_count
    );
}

#[then(expr = "the info count is {int}")]
async fn then_info_count(world: &mut EnvWorld, expected: i32) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let info_count = report
        .get("verdict")
        .and_then(|v| v.get("counts"))
        .and_then(|c| c.get("info"))
        .and_then(|i| i.as_i64())
        .expect("verdict.counts.info should exist");

    assert_eq!(
        info_count, expected as i64,
        "expected info count {}, got {}",
        expected, info_count
    );
}

#[then(expr = "the verdict reasons contain {string}")]
async fn then_verdict_reasons_contain(world: &mut EnvWorld, expected: String) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let reasons = report
        .get("verdict")
        .and_then(|v| v.get("reasons"))
        .and_then(|r| r.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>())
        .unwrap_or_default();

    assert!(
        reasons.iter().any(|r| r.contains(&expected)),
        "expected verdict reasons to contain '{}', got: {:?}",
        expected,
        reasons
    );
}

#[then(expr = "the report data contains sources_used")]
async fn then_report_data_contains_sources_used(world: &mut EnvWorld) {
    let report = world
        .report_json
        .as_ref()
        .expect("report JSON should exist");
    let sources = report
        .get("data")
        .and_then(|d| d.get("sources_used"))
        .and_then(|s| s.as_array());

    assert!(
        sources.is_some(),
        "expected report.data.sources_used to exist and be an array"
    );
    assert!(
        !sources.unwrap().is_empty(),
        "expected report.data.sources_used to be non-empty"
    );
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            fs::copy(&from, &to)?;
        }
        // Ignore other file types (symlinks, etc.) for fixtures.
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let features = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../features");

    EnvWorld::run(features).await;
}
