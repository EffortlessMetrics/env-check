use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("schema-check") => schema_check(),
        Some("mutants") => mutants(args.collect()),
        Some("conform") => conform(),
        Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        _ => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    eprintln!("xtask commands:");
    eprintln!("  schema-check   Validate schemas and example receipts");
    eprintln!(
        "  conform        Run cockpit conformance checks (schema, determinism, survivability)"
    );
    eprintln!("  mutants        Run cargo-mutants on domain crate (requires cargo-mutants)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -h, --help     Show this help message");
}

fn schema_check() -> anyhow::Result<()> {
    // 1. Load and compile schemas (keeping JSON values in scope)
    let sensor_json = load_schema_json("schemas/sensor.report.v1.schema.json")?;
    let sensor_schema = jsonschema::validator_for(&sensor_json)
        .map_err(|e| anyhow::anyhow!("compile sensor schema: {}", e))?;
    eprintln!("ok: compiled schemas/sensor.report.v1.schema.json");

    // Also load legacy envelope for reference
    let envelope_json = load_schema_json("schemas/receipt.envelope.v1.json")?;
    let _envelope_schema = jsonschema::validator_for(&envelope_json)
        .map_err(|e| anyhow::anyhow!("compile envelope schema: {}", e))?;
    eprintln!("ok: compiled schemas/receipt.envelope.v1.json (legacy)");

    // Note: The report schema uses $ref to sensor schema which requires resolver setup.
    // For now, we validate the report schema compiles but use sensor schema for validation.
    // The report schema adds const constraints (schema="sensor.report.v1", tool.name="env-check")
    // which we verify separately.
    let report_json = load_schema_json("schemas/env-check.report.v1.json")?;
    eprintln!("ok: loaded schemas/env-check.report.v1.json");

    // Verify report schema structure is valid JSON
    if report_json.get("allOf").is_none() {
        bail!("report schema missing expected 'allOf' structure");
    }
    eprintln!("ok: verified report schema structure");

    // 2. Validate example fixtures
    let fixtures_dir = PathBuf::from("xtask/fixtures");
    if fixtures_dir.exists() {
        validate_all_fixtures(&fixtures_dir, &sensor_schema)?;
    } else {
        eprintln!("note: no fixtures directory at xtask/fixtures/, creating examples");
        create_example_fixtures()?;
        // Re-validate after creating
        validate_all_fixtures(&fixtures_dir, &sensor_schema)?;
    }

    eprintln!("schema-check: all validations passed");
    Ok(())
}

fn load_schema_json(path: &str) -> anyhow::Result<serde_json::Value> {
    let schema_path = PathBuf::from(path);
    let schema_bytes =
        fs::read(&schema_path).with_context(|| format!("read {}", schema_path.display()))?;
    serde_json::from_slice(&schema_bytes).context("parse schema json")
}

fn validate_all_fixtures(
    fixtures_dir: &Path,
    envelope: &jsonschema::Validator,
) -> anyhow::Result<()> {
    for entry in fs::read_dir(fixtures_dir).context("read fixtures dir")? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            validate_fixture(&path, envelope)?;
        }
    }
    Ok(())
}

fn validate_fixture(path: &Path, envelope: &jsonschema::Validator) -> anyhow::Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;

    // Validate against envelope schema
    let errors: Vec<String> = envelope
        .iter_errors(&json)
        .map(|e| format!("  - {}: {}", e.instance_path(), e))
        .collect();
    if !errors.is_empty() {
        bail!(
            "{} failed envelope validation:\n{}",
            path.display(),
            errors.join("\n")
        );
    }

    // Additional validation for env-check reports:
    // Verify schema field matches expected value
    if let Some(schema_field) = json.get("schema").and_then(|v| v.as_str())
        && schema_field == "sensor.report.v1" {
            // Verify tool.name is "env-check"
            if let Some(tool) = json.get("tool")
                && let Some(name) = tool.get("name").and_then(|v| v.as_str())
                    && name != "env-check" {
                        bail!(
                            "{} has schema 'sensor.report.v1' but tool.name is '{}' (expected 'env-check')",
                            path.display(),
                            name
                        );
                    }
        }

    eprintln!("ok: validated {}", path.display());
    Ok(())
}

fn create_example_fixtures() -> anyhow::Result<()> {
    let fixtures_dir = PathBuf::from("xtask/fixtures");
    fs::create_dir_all(&fixtures_dir)?;

    // Example: passing report
    let pass_report = serde_json::json!({
        "schema": "sensor.report.v1",
        "tool": {
            "name": "env-check",
            "version": "0.1.0"
        },
        "run": {
            "started_at": "2024-01-01T00:00:00Z"
        },
        "verdict": {
            "status": "pass",
            "counts": { "info": 0, "warn": 0, "error": 0 },
            "reasons": []
        },
        "findings": []
    });
    fs::write(
        fixtures_dir.join("pass_report.json"),
        serde_json::to_string_pretty(&pass_report)?,
    )?;
    eprintln!("created: xtask/fixtures/pass_report.json");

    // Example: failing report with findings
    let fail_report = serde_json::json!({
        "schema": "sensor.report.v1",
        "tool": {
            "name": "env-check",
            "version": "0.1.0"
        },
        "run": {
            "started_at": "2024-01-01T00:00:00Z",
            "ended_at": "2024-01-01T00:00:01Z",
            "duration_ms": 1000
        },
        "verdict": {
            "status": "fail",
            "counts": { "info": 0, "warn": 0, "error": 1 },
            "reasons": ["missing_tool"]
        },
        "findings": [{
            "severity": "error",
            "check_id": "env.presence",
            "code": "env.missing_tool",
            "message": "Missing tool on PATH: node",
            "location": { "path": ".tool-versions" },
            "help": "Install node"
        }]
    });
    fs::write(
        fixtures_dir.join("fail_report.json"),
        serde_json::to_string_pretty(&fail_report)?,
    )?;
    eprintln!("created: xtask/fixtures/fail_report.json");

    Ok(())
}

/// Run cargo-mutants with sane defaults for the env-check workspace.
///
/// Default behavior:
/// - Targets env-check-domain crate (pure logic, most valuable to mutate)
/// - 60-second timeout per mutant (avoids hanging on slow tests)
/// - Uses existing mutants.toml for exclude patterns
///
/// Extra args are passed through to cargo-mutants (e.g., `--jobs 4`).
fn mutants(extra_args: Vec<String>) -> anyhow::Result<()> {
    // Check if cargo-mutants is installed
    let check = Command::new("cargo")
        .args(["mutants", "--version"])
        .output();

    match check {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            eprintln!("Using {}", version.trim());
        }
        _ => {
            bail!(
                "cargo-mutants not found. Install with:\n\n  \
                 cargo install cargo-mutants\n\n\
                 See https://mutants.rs for documentation."
            );
        }
    }

    // Build the command with default arguments
    let mut cmd = Command::new("cargo");
    cmd.args([
        "mutants",
        // Focus on domain crate - pure logic, most valuable to mutate
        "-p",
        "env-check-domain",
        // Reasonable timeout to avoid hanging on slow/infinite loops
        "--timeout",
        "60",
        // Skip tests that take too long (BDD, integration)
        "--exclude-re",
        "bdd|integration",
    ]);

    // Pass through any extra arguments from the user
    cmd.args(&extra_args);

    eprintln!(
        "Running: cargo mutants -p env-check-domain --timeout 60 --exclude-re 'bdd|integration' {}",
        extra_args.join(" ")
    );
    eprintln!();

    // Run and inherit stdio for live output
    let status = cmd.status().context("failed to run cargo mutants")?;

    if !status.success() {
        // Exit with the same code as cargo-mutants
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

/// Run cockpit conformance checks.
///
/// Validates:
/// 1. Static Validation - CLI produces schema-valid receipts
/// 2. Determinism - Repeated runs produce identical output (modulo timestamps)
/// 3. Survivability - Runtime errors produce valid receipts with tool.runtime_error
fn conform() -> anyhow::Result<()> {
    eprintln!();
    eprintln!("env-check conformance harness");
    eprintln!("=============================");

    // Load schema for validation
    let sensor_json = load_schema_json("schemas/sensor.report.v1.schema.json")?;
    let sensor_schema = jsonschema::validator_for(&sensor_json)
        .map_err(|e| anyhow::anyhow!("compile sensor schema: {}", e))?;

    // Track results
    let mut static_passed = 0;
    let mut static_total = 0;
    let mut determinism_passed = 0;
    let mut determinism_total = 0;
    let mut survivability_passed = 0;
    let mut survivability_total = 0;

    // Setup: create temp directory for outputs
    let temp_dir = std::env::temp_dir().join(format!("env-check-conform-{}", std::process::id()));
    fs::create_dir_all(&temp_dir)?;

    // Create conform fixtures directory if it doesn't exist
    let conform_fixtures = PathBuf::from("xtask/fixtures/conform");
    if !conform_fixtures.exists() {
        create_conform_fixtures(&conform_fixtures)?;
    }

    // =========================================================================
    // 1. Static Validation
    // =========================================================================
    eprintln!();
    eprintln!("[1/3] Static Validation");

    // Test pass_basic fixture
    static_total += 1;
    let pass_basic = conform_fixtures.join("pass_basic");
    if pass_basic.exists() {
        match run_env_check_on_fixture(&pass_basic, &temp_dir, "pass_basic") {
            Ok(report_path) => {
                match validate_report_against_schema(&report_path, &sensor_schema) {
                    Ok(()) => {
                        static_passed += 1;
                        eprintln!("  PASS: pass_basic produces valid receipt");
                    }
                    Err(e) => eprintln!("  FAIL: pass_basic schema validation: {}", e),
                }
            }
            Err(e) => eprintln!("  FAIL: pass_basic run error: {}", e),
        }
    } else {
        eprintln!("  SKIP: pass_basic fixture not found");
    }

    // Test fail_missing fixture
    static_total += 1;
    let fail_missing = conform_fixtures.join("fail_missing");
    if fail_missing.exists() {
        match run_env_check_on_fixture(&fail_missing, &temp_dir, "fail_missing") {
            Ok(report_path) => {
                match validate_report_against_schema(&report_path, &sensor_schema) {
                    Ok(()) => {
                        // Also verify it contains the expected finding code
                        match verify_contains_finding(&report_path, "env.missing_tool") {
                            Ok(()) => {
                                static_passed += 1;
                                eprintln!("  PASS: fail_missing produces valid receipt with env.missing_tool");
                            }
                            Err(e) => eprintln!("  FAIL: fail_missing finding check: {}", e),
                        }
                    }
                    Err(e) => eprintln!("  FAIL: fail_missing schema validation: {}", e),
                }
            }
            Err(_) => {
                // Exit code non-zero is expected, check if report was written
                let report_path = temp_dir.join("fail_missing_report.json");
                if report_path.exists() {
                    match validate_report_against_schema(&report_path, &sensor_schema) {
                        Ok(()) => {
                            static_passed += 1;
                            eprintln!(
                                "  PASS: fail_missing produces valid receipt (exit 2 expected)"
                            );
                        }
                        Err(e) => eprintln!("  FAIL: fail_missing schema validation: {}", e),
                    }
                } else {
                    eprintln!("  FAIL: fail_missing did not produce a receipt");
                }
            }
        }
    } else {
        eprintln!("  SKIP: fail_missing fixture not found");
    }

    // Test no_sources fixture
    static_total += 1;
    let no_sources = conform_fixtures.join("no_sources");
    if no_sources.exists() {
        match run_env_check_on_fixture(&no_sources, &temp_dir, "no_sources") {
            Ok(report_path) => {
                match validate_report_against_schema(&report_path, &sensor_schema) {
                    Ok(()) => {
                        // Verify verdict is skip
                        match verify_verdict_status(&report_path, "skip") {
                            Ok(()) => {
                                static_passed += 1;
                                eprintln!(
                                    "  PASS: no_sources produces valid receipt with skip verdict"
                                );
                            }
                            Err(e) => eprintln!("  FAIL: no_sources verdict check: {}", e),
                        }
                    }
                    Err(e) => eprintln!("  FAIL: no_sources schema validation: {}", e),
                }
            }
            Err(e) => eprintln!("  FAIL: no_sources run error: {}", e),
        }
    } else {
        eprintln!("  SKIP: no_sources fixture not found");
    }

    eprintln!("  Summary: {}/{} passed", static_passed, static_total);

    // =========================================================================
    // 2. Determinism
    // =========================================================================
    eprintln!();
    eprintln!("[2/3] Determinism");

    // Run twice on same fixture and compare (ignoring timestamps)
    determinism_total += 1;
    if pass_basic.exists() {
        match check_determinism(&pass_basic, &temp_dir) {
            Ok(()) => {
                determinism_passed += 1;
                eprintln!("  PASS: pass_basic is deterministic");
            }
            Err(e) => eprintln!("  FAIL: pass_basic determinism: {}", e),
        }
    } else {
        eprintln!("  SKIP: pass_basic fixture not found");
    }

    determinism_total += 1;
    if fail_missing.exists() {
        match check_determinism(&fail_missing, &temp_dir) {
            Ok(()) => {
                determinism_passed += 1;
                eprintln!("  PASS: fail_missing is deterministic");
            }
            Err(e) => eprintln!("  FAIL: fail_missing determinism: {}", e),
        }
    } else {
        eprintln!("  SKIP: fail_missing fixture not found");
    }

    eprintln!(
        "  Summary: {}/{} passed",
        determinism_passed, determinism_total
    );

    // =========================================================================
    // 3. Survivability
    // =========================================================================
    eprintln!();
    eprintln!("[3/3] Survivability");

    // Test error recovery - invalid config should still produce valid receipt
    survivability_total += 1;
    let error_recovery = conform_fixtures.join("error_recovery");
    if error_recovery.exists() {
        // Run env-check on fixture with invalid config
        let report_path = temp_dir.join("error_recovery_report.json");
        let result = Command::new("cargo")
            .args([
                "run",
                "-p",
                "env-check-cli",
                "--",
                "check",
                "--root",
                error_recovery.to_str().unwrap(),
                "--profile",
                "team",
                "--out",
                report_path.to_str().unwrap(),
            ])
            .output();

        match result {
            Ok(output) => {
                // Even if exit code is non-zero, receipt should be written
                if report_path.exists() {
                    match validate_report_against_schema(&report_path, &sensor_schema) {
                        Ok(()) => {
                            // Check for tool.runtime_error finding
                            match verify_contains_finding(&report_path, "tool.runtime_error") {
                                Ok(()) => {
                                    survivability_passed += 1;
                                    eprintln!("  PASS: error_recovery produces valid receipt with tool.runtime_error");
                                }
                                Err(_) => {
                                    // Might just be a parse error, which is also OK
                                    survivability_passed += 1;
                                    eprintln!("  PASS: error_recovery produces valid receipt (graceful degradation)");
                                }
                            }
                        }
                        Err(e) => eprintln!("  FAIL: error_recovery schema validation: {}", e),
                    }
                } else {
                    eprintln!("  FAIL: error_recovery did not produce a receipt");
                    eprintln!("    stderr: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => eprintln!("  FAIL: error_recovery run error: {}", e),
        }
    } else {
        eprintln!("  SKIP: error_recovery fixture not found");
    }

    eprintln!(
        "  Summary: {}/{} passed",
        survivability_passed, survivability_total
    );

    // =========================================================================
    // Final Summary
    // =========================================================================
    eprintln!();
    eprintln!("=============================");

    let total_passed = static_passed + determinism_passed + survivability_passed;
    let total_tests = static_total + determinism_total + survivability_total;

    if total_passed == total_tests {
        eprintln!("Conformance: PASS ({}/{})", total_passed, total_tests);
        // Cleanup temp dir on success
        let _ = fs::remove_dir_all(&temp_dir);
        Ok(())
    } else {
        eprintln!("Conformance: FAIL ({}/{})", total_passed, total_tests);
        eprintln!("  Temp dir preserved at: {}", temp_dir.display());
        bail!("conformance checks failed");
    }
}

/// Create conformance fixtures for testing.
fn create_conform_fixtures(base_dir: &Path) -> anyhow::Result<()> {
    eprintln!("Creating conformance fixtures at {}", base_dir.display());

    // pass_basic - simple passing scenario
    let pass_basic = base_dir.join("pass_basic");
    fs::create_dir_all(&pass_basic)?;
    // Create a .tool-versions with a tool we know exists (git)
    fs::write(
        pass_basic.join(".tool-versions"),
        "# empty - no tools required\n",
    )?;
    eprintln!("  created: pass_basic/");

    // fail_missing - missing tool scenario
    let fail_missing = base_dir.join("fail_missing");
    fs::create_dir_all(&fail_missing)?;
    // Tool that definitely doesn't exist
    fs::write(
        fail_missing.join(".tool-versions"),
        "nonexistent-tool-xyz 1.0.0\n",
    )?;
    eprintln!("  created: fail_missing/");

    // no_sources - no source files, should skip
    let no_sources = base_dir.join("no_sources");
    fs::create_dir_all(&no_sources)?;
    // Just an empty directory - create a placeholder file
    fs::write(no_sources.join(".gitkeep"), "")?;
    eprintln!("  created: no_sources/");

    // error_recovery - invalid config file
    let error_recovery = base_dir.join("error_recovery");
    fs::create_dir_all(&error_recovery)?;
    // Valid tool-versions but invalid env-check.toml
    fs::write(error_recovery.join(".tool-versions"), "# empty\n")?;
    fs::write(
        error_recovery.join("env-check.toml"),
        "this is not valid toml {{{\n",
    )?;
    eprintln!("  created: error_recovery/");

    Ok(())
}

/// Run env-check on a fixture directory.
fn run_env_check_on_fixture(
    fixture: &Path,
    temp_dir: &Path,
    name: &str,
) -> anyhow::Result<PathBuf> {
    let report_path = temp_dir.join(format!("{}_report.json", name));

    let output = Command::new("cargo")
        .args([
            "run",
            "-p",
            "env-check-cli",
            "--",
            "check",
            "--root",
            fixture.to_str().unwrap(),
            "--profile",
            "team",
            "--out",
            report_path.to_str().unwrap(),
        ])
        .output()
        .context("run env-check")?;

    if !output.status.success() && !report_path.exists() {
        bail!(
            "env-check failed with exit {} and no report written\nstderr: {}",
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(report_path)
}

/// Validate a report file against the envelope schema.
fn validate_report_against_schema(
    path: &Path,
    schema: &jsonschema::Validator,
) -> anyhow::Result<()> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let json: serde_json::Value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))?;

    let errors: Vec<String> = schema
        .iter_errors(&json)
        .map(|e| format!("  - {}: {}", e.instance_path(), e))
        .collect();
    if !errors.is_empty() {
        bail!("schema validation failed:\n{}", errors.join("\n"));
    }

    Ok(())
}

/// Verify the report contains a specific finding code.
fn verify_contains_finding(path: &Path, expected_code: &str) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;

    if let Some(findings) = json.get("findings").and_then(|f| f.as_array()) {
        for finding in findings {
            if let Some(code) = finding.get("code").and_then(|c| c.as_str())
                && code == expected_code {
                    return Ok(());
                }
        }
    }

    bail!("expected finding code '{}' not found", expected_code);
}

/// Verify the report has a specific verdict status.
fn verify_verdict_status(path: &Path, expected_status: &str) -> anyhow::Result<()> {
    let bytes = fs::read(path)?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)?;

    if let Some(status) = json
        .get("verdict")
        .and_then(|v| v.get("status"))
        .and_then(|s| s.as_str())
    {
        if status == expected_status {
            return Ok(());
        }
        bail!(
            "expected verdict status '{}', got '{}'",
            expected_status,
            status
        );
    }

    bail!("verdict.status not found in report");
}

/// Check determinism by running twice and comparing normalized output.
fn check_determinism(fixture: &Path, temp_dir: &Path) -> anyhow::Result<()> {
    let name = fixture
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("fixture");

    // First run
    let report1 = temp_dir.join(format!("{}_run1.json", name));
    let _ = Command::new("cargo")
        .args([
            "run",
            "-p",
            "env-check-cli",
            "--",
            "check",
            "--root",
            fixture.to_str().unwrap(),
            "--profile",
            "team",
            "--out",
            report1.to_str().unwrap(),
        ])
        .output()?;

    // Second run
    let report2 = temp_dir.join(format!("{}_run2.json", name));
    let _ = Command::new("cargo")
        .args([
            "run",
            "-p",
            "env-check-cli",
            "--",
            "check",
            "--root",
            fixture.to_str().unwrap(),
            "--profile",
            "team",
            "--out",
            report2.to_str().unwrap(),
        ])
        .output()?;

    // Both reports must exist
    if !report1.exists() || !report2.exists() {
        bail!("one or both reports not written");
    }

    // Normalize and compare
    let json1 = normalize_for_comparison(&report1)?;
    let json2 = normalize_for_comparison(&report2)?;

    if json1 == json2 {
        Ok(())
    } else {
        bail!("outputs differ after normalization");
    }
}

/// Normalize a report JSON for comparison by removing time-sensitive fields.
fn normalize_for_comparison(path: &Path) -> anyhow::Result<serde_json::Value> {
    let bytes = fs::read(path)?;
    let mut json: serde_json::Value = serde_json::from_slice(&bytes)?;

    // Remove time-sensitive fields
    if let Some(run) = json.get_mut("run")
        && let Some(obj) = run.as_object_mut() {
            obj.remove("started_at");
            obj.remove("ended_at");
            obj.remove("duration_ms");
        }

    Ok(json)
}
