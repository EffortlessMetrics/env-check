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
}

#[when(expr = "I run env-check with profile {string}")]
async fn when_run(world: &mut EnvWorld, profile: String) {
    run_env_check(world, &profile, None, false);
}

#[when(expr = "I run env-check with profile {string} and fail_on {string}")]
async fn when_run_with_fail_on(world: &mut EnvWorld, profile: String, fail_on: String) {
    run_env_check(world, &profile, Some(&fail_on), false);
}

#[when(expr = "I run env-check with profile {string} and markdown output")]
async fn when_run_with_markdown(world: &mut EnvWorld, profile: String) {
    run_env_check(world, &profile, None, true);
}

fn run_env_check(world: &mut EnvWorld, profile: &str, fail_on: Option<&str>, with_markdown: bool) {
    let root = world.repo_root.as_ref().expect("fixture root");
    let tmp = world.tmp.as_ref().expect("temp dir");

    // Cargo exposes the built test binary paths via env vars, even for
    // harness=false tests.
    let exe = env!("CARGO_BIN_EXE_env-check");

    let out_path = tmp.path().join("artifacts/env-check/report.json");
    let md_path = tmp.path().join("artifacts/env-check/comment.md");

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

    // Make the environment deterministic: don't leak tools from the host.
    cmd.env("PATH", "");

    let out = cmd.output().expect("run env-check");
    world.exit_code = out.status.code();
    world.out_path = Some(out_path.clone());
    world.md_path = Some(md_path.clone());

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
    let report = world.report_json.as_ref().expect("report JSON should exist");
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
    let report = world.report_json.as_ref().expect("report JSON should exist");
    let sources = report
        .get("data")
        .and_then(|d| d.get("sources_used"))
        .and_then(|s| s.as_array())
        .expect("data.sources_used should be an array");

    let sources_list: Vec<&str> = sources
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

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
    let report = world.report_json.as_ref().expect("report JSON should exist");
    let sources = report
        .get("data")
        .and_then(|d| d.get("sources_used"))
        .and_then(|s| s.as_array())
        .expect("data.sources_used should be an array");

    let sources_list: Vec<&str> = sources
        .iter()
        .filter_map(|v| v.as_str())
        .collect();

    assert!(
        sources_list.iter().any(|s| s.contains(&source)),
        "expected sources to contain '{}', got: {:?}",
        source,
        sources_list
    );
}

#[then(expr = "the report contains finding code {string}")]
async fn then_report_contains_finding_code(world: &mut EnvWorld, code: String) {
    let report = world.report_json.as_ref().expect("report JSON should exist");
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
    let report = world.report_json.as_ref().expect("report JSON should exist");

    // Load the schema from the project root
    let schema_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../schemas/receipt.envelope.v1.json");

    let schema_bytes = fs::read(&schema_path)
        .expect("failed to read schema file");
    let schema_json: Value = serde_json::from_slice(&schema_bytes)
        .expect("failed to parse schema JSON");

    let compiled = jsonschema::JSONSchema::compile(&schema_json)
        .expect("failed to compile JSON schema");

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
    let markdown = world.markdown.as_ref().expect("markdown output should exist");
    assert!(
        markdown.contains(&expected),
        "expected markdown to contain '{}', got:\n{}",
        expected,
        markdown
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
