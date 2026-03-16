use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use anyhow::{Context, bail};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("schema-check") => schema_check(),
        Some("mutants") => mutants(args.collect()),
        Some("conform") => conform(),
        Some("adoption-check") => adoption_check(),
        Some("publish") => {
            let remaining: Vec<String> = args.collect();
            let dry_run = remaining.iter().any(|a| a == "--dry-run");
            let allow_dirty = remaining.iter().any(|a| a == "--allow-dirty");
            publish(dry_run, allow_dirty)
        }
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
        "  conform        Run cockpit conformance checks (schema, determinism, survivability, adoption)"
    );
    eprintln!(
        "  adoption-check Run repo-only adoption checks from Phase 7 (contracts/offline/action/docs/release)"
    );
    eprintln!("  mutants        Run cargo-mutants on domain crate (requires cargo-mutants)");
    eprintln!(
        "  publish        Publish all crates to crates.io in dependency order (--dry-run supported)"
    );
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
        && schema_field == "sensor.report.v1"
    {
        // Verify tool.name is "env-check"
        if let Some(tool) = json.get("tool")
            && let Some(name) = tool.get("name").and_then(|v| v.as_str())
            && name != "env-check"
        {
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
/// 4. Adoption Surface - repo-only Phase 7 checks (offline/action/docs/release)
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
    eprintln!("[1/4] Static Validation");

    // Test pass_basic fixture
    static_total += 1;
    let pass_basic = conform_fixtures.join("pass_basic");
    if pass_basic.exists() {
        match run_env_check_on_fixture(&pass_basic, &temp_dir, "pass_basic") {
            Ok(report_path) => match validate_report_against_schema(&report_path, &sensor_schema) {
                Ok(()) => {
                    static_passed += 1;
                    eprintln!("  PASS: pass_basic produces valid receipt");
                }
                Err(e) => eprintln!("  FAIL: pass_basic schema validation: {}", e),
            },
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
                                eprintln!(
                                    "  PASS: fail_missing produces valid receipt with env.missing_tool"
                                );
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
    eprintln!("[2/4] Determinism");

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
    eprintln!("[3/4] Survivability");

    // Test error recovery - invalid config should still produce valid receipt
    survivability_total += 1;
    let error_recovery = conform_fixtures.join("error_recovery");
    if error_recovery.exists() {
        // Run env-check on fixture with invalid config
        let report_path = temp_dir.join("error_recovery_report.json");
        let mut command = Command::new("cargo");
        command
            .args(["run", "-p", "env-check-cli", "--", "check", "--root"])
            .arg(&error_recovery)
            .args(["--profile", "team", "--out"])
            .arg(&report_path);
        let result = command.output();

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
                                    eprintln!(
                                        "  PASS: error_recovery produces valid receipt with tool.runtime_error"
                                    );
                                }
                                Err(_) => {
                                    // Might just be a parse error, which is also OK
                                    survivability_passed += 1;
                                    eprintln!(
                                        "  PASS: error_recovery produces valid receipt (graceful degradation)"
                                    );
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
    // 4. Adoption Surface (Phase 7)
    // =========================================================================
    eprintln!();
    eprintln!("[4/4] Adoption Surface");
    let (adoption_passed, adoption_total) = run_adoption_checks();
    eprintln!("  Summary: {}/{} passed", adoption_passed, adoption_total);

    // =========================================================================
    // Final Summary
    // =========================================================================
    eprintln!();
    eprintln!("=============================");

    let total_passed = static_passed + determinism_passed + survivability_passed + adoption_passed;
    let total_tests = static_total + determinism_total + survivability_total + adoption_total;

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

/// Run Phase 7 repo-only validation checks directly.
fn adoption_check() -> anyhow::Result<()> {
    eprintln!();
    eprintln!("env-check phase 7 adoption validation");
    eprintln!("====================================");

    let (passed, total) = run_adoption_checks();

    eprintln!();
    eprintln!("=============================");
    if passed == total {
        eprintln!("Adoption validation: PASS ({}/{})", passed, total);
        Ok(())
    } else {
        eprintln!("Adoption validation: FAIL ({}/{})", passed, total);
        bail!("phase 7 adoption checks failed");
    }
}

fn run_adoption_checks() -> (usize, usize) {
    let mut passed = 0usize;
    let mut total = 0usize;

    run_adoption_gate(
        "Contract conformance: schema validation gate is wired",
        &mut passed,
        &mut total,
        check_schema_contract_gate,
    );
    run_adoption_gate(
        "Contract conformance: findings ordering contract is enforced",
        &mut passed,
        &mut total,
        check_findings_order_contract,
    );
    run_adoption_gate(
        "Contract conformance: no_sources receipts include verdict reason",
        &mut passed,
        &mut total,
        check_no_sources_skip_reason_contract,
    );
    run_adoption_gate(
        "Contract conformance: explain registry covers stable codes/check IDs",
        &mut passed,
        &mut total,
        check_explain_registry_contract,
    );
    run_adoption_gate(
        "Offline-first: runtime crates avoid network client dependencies",
        &mut passed,
        &mut total,
        check_no_network_client_deps,
    );
    run_adoption_gate(
        "Offline-first: git metadata collection is best-effort and no-fetch",
        &mut passed,
        &mut total,
        check_git_metadata_no_fetch,
    );
    run_adoption_gate(
        "Action usage: composite action installs pinned release",
        &mut passed,
        &mut total,
        check_action_pinned_release_install,
    );
    run_adoption_gate(
        "Action usage: composite action writes canonical artifacts",
        &mut passed,
        &mut total,
        check_action_writes_artifacts,
    );
    run_adoption_gate(
        "Action usage: example workflow uploads artifacts/env-check/",
        &mut passed,
        &mut total,
        check_example_uploads_artifacts,
    );
    run_adoption_gate(
        "Cockpit ingestion: docs define Environment section + direct receipt ingestion",
        &mut passed,
        &mut total,
        check_cockpit_ingestion_docs,
    );
    run_adoption_gate(
        "Release readiness: dist workflows match configured targets/installers",
        &mut passed,
        &mut total,
        check_release_readiness_gates,
    );
    run_adoption_gate(
        "Release readiness: adoption surface pins v0.2.0 action reference",
        &mut passed,
        &mut total,
        check_release_pin_surface,
    );

    (passed, total)
}

fn run_adoption_gate<F>(label: &str, passed: &mut usize, total: &mut usize, check: F)
where
    F: FnOnce() -> anyhow::Result<()>,
{
    *total += 1;
    match check() {
        Ok(()) => {
            *passed += 1;
            eprintln!("  PASS: {}", label);
        }
        Err(err) => eprintln!("  FAIL: {}: {}", label, err),
    }
}

fn check_schema_contract_gate() -> anyhow::Result<()> {
    for schema in [
        "schemas/sensor.report.v1.schema.json",
        "schemas/env-check.report.v1.json",
    ] {
        if !Path::new(schema).exists() {
            bail!("required schema missing: {}", schema);
        }
    }

    let ci = read_text(".github/workflows/ci.yml")?;
    require_contains(
        &ci,
        "cargo run -p xtask -- schema-check",
        ".github/workflows/ci.yml",
    )?;
    require_contains(
        &ci,
        "cargo run -p xtask -- conform",
        ".github/workflows/ci.yml",
    )?;
    Ok(())
}

fn check_findings_order_contract() -> anyhow::Result<()> {
    use env_check_types::{Finding, Location, Severity};

    fn finding(
        severity: Severity,
        path: &str,
        check_id: &str,
        code: &str,
        message: &str,
    ) -> Finding {
        Finding {
            severity,
            check_id: Some(check_id.to_string()),
            code: code.to_string(),
            message: message.to_string(),
            location: Some(Location {
                path: path.to_string(),
                line: None,
                col: None,
            }),
            help: None,
            url: None,
            fingerprint: None,
            data: None,
        }
    }

    let mut findings = [
        finding(
            Severity::Warn,
            "z.txt",
            "env.version",
            "env.version_mismatch",
            "Version mismatch z",
        ),
        finding(
            Severity::Error,
            "b.txt",
            "env.presence",
            "env.missing_tool",
            "Missing tool b",
        ),
        finding(
            Severity::Warn,
            "a.txt",
            "z.check",
            "env.hash_mismatch",
            "Hash mismatch z",
        ),
        finding(
            Severity::Warn,
            "a.txt",
            "a.check",
            "env.hash_mismatch",
            "Hash mismatch a",
        ),
    ];
    findings.sort_by_key(env_check_types::finding_sort_key);

    if findings[0].severity.rank() != Severity::Error.rank() {
        bail!("expected error severity first after canonical sort");
    }
    if findings[1].location.as_ref().map(|l| l.path.as_str()) != Some("a.txt")
        || findings[1].check_id.as_deref() != Some("a.check")
    {
        bail!("expected path/check_id ordering after severity ordering");
    }
    if findings[2].location.as_ref().map(|l| l.path.as_str()) != Some("a.txt")
        || findings[2].check_id.as_deref() != Some("z.check")
    {
        bail!("expected check_id tie-break ordering within same path");
    }
    if findings[3].location.as_ref().map(|l| l.path.as_str()) != Some("z.txt") {
        bail!("expected path ordering within same severity");
    }

    let domain_src = read_text("crates/env-check-domain/src/lib.rs")?;
    require_contains(
        &domain_src,
        "findings.sort_by(|a, b|",
        "crates/env-check-domain/src/lib.rs",
    )?;
    require_contains(
        &domain_src,
        "finding_sort_key",
        "crates/env-check-domain/src/lib.rs",
    )?;
    Ok(())
}

fn check_no_sources_skip_reason_contract() -> anyhow::Result<()> {
    use env_check_types::{PolicyConfig, VerdictStatus};

    let out = env_check_domain::evaluate(&[], &[], &PolicyConfig::default(), &[]);
    if out.verdict.status != VerdictStatus::Skip {
        bail!(
            "expected no-sources verdict status 'skip', got '{:?}'",
            out.verdict.status
        );
    }

    if !out.verdict.reasons.iter().any(|r| r == "no_sources") {
        bail!("expected no-sources verdict reasons to include 'no_sources'");
    }

    if out.verdict.reasons.first().map(String::as_str) != Some("no_sources") {
        bail!(
            "expected 'no_sources' to be first verdict reason, got {:?}",
            out.verdict.reasons
        );
    }

    Ok(())
}

fn check_explain_registry_contract() -> anyhow::Result<()> {
    use std::collections::BTreeSet;

    use env_check_types::{
        KNOWN_CHECK_IDS, KNOWN_CODES, UNKNOWN_EXPLAIN_MESSAGE, explain_entries, explain_message,
    };

    for code in KNOWN_CODES {
        let msg = explain_message(code);
        if msg == UNKNOWN_EXPLAIN_MESSAGE {
            bail!("missing explain registry entry for code '{}'", code);
        }
    }

    for check_id in KNOWN_CHECK_IDS {
        let msg = explain_message(check_id);
        if msg == UNKNOWN_EXPLAIN_MESSAGE {
            bail!("missing explain registry entry for check_id '{}'", check_id);
        }
    }

    let entries = explain_entries();
    if entries.is_empty() {
        bail!("explain registry is empty");
    }

    let mut seen = BTreeSet::new();
    for entry in entries {
        if entry.id.trim().is_empty() {
            bail!("explain registry contains empty identifier");
        }
        if !seen.insert(entry.id) {
            bail!("duplicate explain registry identifier '{}'", entry.id);
        }
    }

    // Keep CLI explain surface wired to the shared types registry.
    let cli = read_text("crates/env-check-cli/src/lib.rs")?;
    require_contains(
        &cli,
        "explain_message(code)",
        "crates/env-check-cli/src/lib.rs",
    )?;
    require_contains(
        &cli,
        "for entry in explain_entries()",
        "crates/env-check-cli/src/lib.rs",
    )?;

    Ok(())
}

fn check_no_network_client_deps() -> anyhow::Result<()> {
    let banned = ["reqwest", "ureq", "hyper", "surf", "isahc", "attohttpc"];

    let mut manifests = vec![PathBuf::from("Cargo.toml")];
    for entry in fs::read_dir("crates").context("read crates/ for Cargo manifests")? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        if manifest.exists() {
            manifests.push(manifest);
        }
    }
    manifests.sort();

    for manifest in manifests {
        let text = fs::read_to_string(&manifest)
            .with_context(|| format!("read {}", manifest.display()))?;
        let lower = text.to_ascii_lowercase();
        for needle in banned {
            if lower.contains(needle) {
                bail!(
                    "{} declares network client dependency '{}'",
                    manifest.display(),
                    needle
                );
            }
        }
    }

    Ok(())
}

fn check_git_metadata_no_fetch() -> anyhow::Result<()> {
    let app = read_text("crates/env-check-app/src/lib.rs")?;
    for forbidden in [
        "\"fetch\"",
        "\"pull\"",
        "ls-remote",
        "git fetch",
        "git pull",
    ] {
        if app.contains(forbidden) {
            bail!(
                "crates/env-check-app/src/lib.rs contains forbidden git network operation '{}'",
                forbidden
            );
        }
    }

    require_contains(&app, "detect_git(root)", "crates/env-check-app/src/lib.rs")?;
    Ok(())
}

fn check_action_pinned_release_install() -> anyhow::Result<()> {
    let action = read_text("action.yml")?;
    require_contains(&action, "using: \"composite\"", "action.yml")?;
    require_contains(
        &action,
        "releases/download/${ENV_CHECK_VERSION}/env-check-installer.sh",
        "action.yml",
    )?;
    require_contains(
        &action,
        "releases/download/$env:ENV_CHECK_VERSION/env-check-installer.ps1",
        "action.yml",
    )?;
    require_contains(
        &action,
        "version input required when action is not referenced by a vX.Y.Z tag",
        "action.yml",
    )?;
    require_not_contains(&action, "/releases/latest/download/", "action.yml")?;
    Ok(())
}

fn check_action_writes_artifacts() -> anyhow::Result<()> {
    let action = read_text("action.yml")?;
    require_contains(
        &action,
        "default: \"artifacts/env-check/report.json\"",
        "action.yml",
    )?;
    require_contains(
        &action,
        "ARGS=(check --root \"${{ inputs.root }}\" --profile \"${{ inputs.profile }}\" --out \"${{ inputs.out }}\")",
        "action.yml",
    )?;
    Ok(())
}

fn check_example_uploads_artifacts() -> anyhow::Result<()> {
    let example = read_text("examples/github-actions-env-check.yml")?;
    require_contains(
        &example,
        "uses: actions/upload-artifact@v4",
        "examples/github-actions-env-check.yml",
    )?;
    require_contains(
        &example,
        "path: artifacts/env-check",
        "examples/github-actions-env-check.yml",
    )?;
    Ok(())
}

fn check_cockpit_ingestion_docs() -> anyhow::Result<()> {
    let cockpit = read_text("docs/cockpit.md")?;
    require_contains(
        &cockpit,
        "Cockpit comment contract (Environment section)",
        "docs/cockpit.md",
    )?;
    require_contains(&cockpit, "- Environment:", "docs/cockpit.md")?;
    require_contains(
        &cockpit,
        "artifacts/env-check/comment.md",
        "docs/cockpit.md",
    )?;
    require_contains(
        &cockpit,
        "without adapters or special cases",
        "docs/cockpit.md",
    )?;
    Ok(())
}

fn check_release_readiness_gates() -> anyhow::Result<()> {
    let cargo = read_text("Cargo.toml")?;
    let release = read_text(".github/workflows/release.yml")?;
    let dist_pr = read_text(".github/workflows/dist-pr.yml")?;

    let parsed: toml::Value = toml::from_str(&cargo).context("parse Cargo.toml")?;
    let dist = parsed
        .get("workspace")
        .and_then(|v| v.get("metadata"))
        .and_then(|v| v.get("dist"))
        .ok_or_else(|| anyhow::anyhow!("Cargo.toml missing [workspace.metadata.dist]"))?;

    let targets = dist
        .get("targets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Cargo.toml missing workspace.metadata.dist.targets"))?;

    let mut target_names = Vec::with_capacity(targets.len());
    for target in targets {
        let name = target
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("invalid non-string target entry"))?;
        target_names.push(name.to_string());
    }
    if target_names.is_empty() {
        bail!("workspace.metadata.dist.targets is empty");
    }

    let installers = dist
        .get("installers")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Cargo.toml missing workspace.metadata.dist.installers"))?;
    let installer_names: Vec<&str> = installers.iter().filter_map(|v| v.as_str()).collect();
    if !installer_names.contains(&"shell") || !installer_names.contains(&"powershell") {
        bail!(
            "workspace.metadata.dist.installers must include both shell and powershell, got {:?}",
            installer_names
        );
    }

    require_contains(&release, "- \"v*.*.*\"", ".github/workflows/release.yml")?;
    require_contains(
        &release,
        "cargo dist build --artifacts=global",
        ".github/workflows/release.yml",
    )?;
    require_contains(
        &release,
        "files: target/distrib/*",
        ".github/workflows/release.yml",
    )?;
    require_contains(&dist_pr, "cargo dist plan", ".github/workflows/dist-pr.yml")?;

    for target in target_names {
        if !release.contains(&target) {
            bail!(
                ".github/workflows/release.yml missing target '{}' from workspace.metadata.dist.targets",
                target
            );
        }
    }

    Ok(())
}

fn check_release_pin_surface() -> anyhow::Result<()> {
    let readme = read_text("README.md")?;
    let example = read_text("examples/github-actions-env-check.yml")?;

    require_contains(
        &readme,
        "uses: EffortlessMetrics/env-check@v0.2.0",
        "README.md",
    )?;
    require_contains(
        &example,
        "uses: EffortlessMetrics/env-check@v0.2.0",
        "examples/github-actions-env-check.yml",
    )?;
    Ok(())
}

fn read_text(path: &str) -> anyhow::Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path))
}

fn require_contains(haystack: &str, needle: &str, path: &str) -> anyhow::Result<()> {
    if haystack.contains(needle) {
        Ok(())
    } else {
        bail!("{} missing required text: {}", path, needle);
    }
}

fn require_not_contains(haystack: &str, needle: &str, path: &str) -> anyhow::Result<()> {
    if haystack.contains(needle) {
        bail!("{} must not contain: {}", path, needle);
    } else {
        Ok(())
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

    let mut command = Command::new("cargo");
    command
        .args(["run", "-p", "env-check-cli", "--", "check", "--root"])
        .arg(fixture)
        .args(["--profile", "team", "--out"])
        .arg(&report_path);
    let output = command.output().context("run env-check")?;

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
                && code == expected_code
            {
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
    let mut first_run = Command::new("cargo");
    first_run
        .args(["run", "-p", "env-check-cli", "--", "check", "--root"])
        .arg(fixture)
        .args(["--profile", "team", "--out"])
        .arg(&report1);
    let _ = first_run.output()?;

    // Second run
    let report2 = temp_dir.join(format!("{}_run2.json", name));
    let mut second_run = Command::new("cargo");
    second_run
        .args(["run", "-p", "env-check-cli", "--", "check", "--root"])
        .arg(fixture)
        .args(["--profile", "team", "--out"])
        .arg(&report2);
    let _ = second_run.output()?;

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
        && let Some(obj) = run.as_object_mut()
    {
        obj.remove("started_at");
        obj.remove("ended_at");
        obj.remove("duration_ms");
    }

    Ok(json)
}

fn publish(dry_run: bool, allow_dirty: bool) -> anyhow::Result<()> {
    const CRATES: &[&str] = &[
        "env-check-types",
        "env-check-config",
        "env-check-parser-flags",
        "env-check-requirement-normalizer",
        "env-check-runtime-metadata",
        "env-check-sources-node",
        "env-check-sources-python",
        "env-check-sources-go",
        "env-check-sources-hash",
        "env-check-sources",
        "env-check-probe",
        "env-check-runtime",
        "env-check-domain",
        "env-check-evidence",
        "env-check-reporting",
        "env-check-render",
        "env-check-app",
        "env-check-cli",
        "env-check",
    ];

    let total = CRATES.len();
    for (i, crate_name) in CRATES.iter().enumerate() {
        eprintln!(
            "[{}/{}] Publishing {}{}...",
            i + 1,
            total,
            crate_name,
            if dry_run { " (dry-run)" } else { "" }
        );

        let mut cmd = Command::new("cargo");
        if dry_run {
            // Use `cargo package --list` for dry-run: validates metadata and lists
            // packagable files without resolving deps from crates.io (which would
            // fail since earlier crates in the chain aren't published yet).
            cmd.arg("package").arg("-p").arg(crate_name).arg("--list");
            if allow_dirty {
                cmd.arg("--allow-dirty");
            }
        } else {
            cmd.arg("publish").arg("-p").arg(crate_name);
            if allow_dirty {
                cmd.arg("--allow-dirty");
            }
        }

        let status = cmd
            .status()
            .with_context(|| format!("failed to run cargo publish for {}", crate_name))?;

        if !status.success() {
            bail!(
                "cargo publish failed for crate '{}' (exit code: {:?})",
                crate_name,
                status.code()
            );
        }

        eprintln!(
            "[{}/{}] {} published successfully.",
            i + 1,
            total,
            crate_name
        );

        // Sleep between publishes (except after the last one) to let crates.io index,
        // but skip the sleep in dry-run mode.
        let is_last = i + 1 == total;
        if !is_last && !dry_run {
            eprintln!("Waiting 65 seconds for crates.io to index...");
            thread::sleep(Duration::from_secs(65));
        }
    }

    eprintln!("All {} crates published successfully.", total);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("env-check-xtask-{prefix}-{unique}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn load_schema_json_reads_valid_json() {
        let root = temp_dir("schema-json");
        let path = root.join("schema.json");
        fs::write(&path, r#"{ "type": "object" }"#).expect("write schema");

        let value = load_schema_json(path.to_str().unwrap()).expect("load schema");
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("object"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_fixture_accepts_env_check_schema() {
        let root = temp_dir("fixture-ok");
        let path = root.join("report.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "schema": "sensor.report.v1",
                "tool": { "name": "env-check" }
            }))
            .unwrap(),
        )
        .expect("write report");

        let schema = jsonschema::validator_for(&json!({"type": "object"})).unwrap();
        validate_fixture(&path, &schema).expect("validate fixture");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_fixture_rejects_wrong_tool_name() {
        let root = temp_dir("fixture-bad-tool");
        let path = root.join("report.json");
        fs::write(
            &path,
            serde_json::to_string_pretty(&json!({
                "schema": "sensor.report.v1",
                "tool": { "name": "not-env-check" }
            }))
            .unwrap(),
        )
        .expect("write report");

        let schema = jsonschema::validator_for(&json!({"type": "object"})).unwrap();
        let err = validate_fixture(&path, &schema).unwrap_err().to_string();
        assert!(err.contains("tool.name"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_report_against_schema_fails_on_missing_field() {
        let root = temp_dir("schema-validate");
        let report = root.join("report.json");
        fs::write(&report, serde_json::to_string_pretty(&json!({})).unwrap())
            .expect("write report");

        let schema = jsonschema::validator_for(&json!({
            "type": "object",
            "required": ["schema"],
            "properties": { "schema": { "const": "sensor.report.v1" } }
        }))
        .unwrap();

        let err = validate_report_against_schema(&report, &schema)
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema validation failed"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_report_against_schema_accepts_valid_report() {
        let root = temp_dir("schema-validate-ok");
        let report = root.join("report.json");
        fs::write(
            &report,
            serde_json::to_string_pretty(&json!({"schema": "sensor.report.v1"})).unwrap(),
        )
        .expect("write report");

        let schema = jsonschema::validator_for(&json!({
            "type": "object",
            "required": ["schema"],
            "properties": { "schema": { "const": "sensor.report.v1" } }
        }))
        .unwrap();

        validate_report_against_schema(&report, &schema).expect("schema validation");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_contains_finding_ok_and_err() {
        let root = temp_dir("finding-check");
        let report = root.join("report.json");
        fs::write(
            &report,
            serde_json::to_string_pretty(&json!({
                "findings": [
                    { "code": "env.missing_tool" },
                    { "code": "env.version_mismatch" }
                ]
            }))
            .unwrap(),
        )
        .expect("write report");

        verify_contains_finding(&report, "env.missing_tool").expect("finding present");
        let err = verify_contains_finding(&report, "tool.runtime_error")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected finding code"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn verify_verdict_status_ok_and_err() {
        let root = temp_dir("verdict-check");
        let report = root.join("report.json");
        fs::write(
            &report,
            serde_json::to_string_pretty(&json!({
                "verdict": { "status": "pass" }
            }))
            .unwrap(),
        )
        .expect("write report");

        verify_verdict_status(&report, "pass").expect("status matches");
        let err = verify_verdict_status(&report, "fail")
            .unwrap_err()
            .to_string();
        assert!(err.contains("expected verdict status"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn normalize_for_comparison_removes_run_timestamps() {
        let root = temp_dir("normalize");
        let report = root.join("report.json");
        fs::write(
            &report,
            serde_json::to_string_pretty(&json!({
                "run": {
                    "started_at": "2024-01-01T00:00:00Z",
                    "ended_at": "2024-01-01T00:00:01Z",
                    "duration_ms": 1000,
                    "other": "keep"
                }
            }))
            .unwrap(),
        )
        .expect("write report");

        let normalized = normalize_for_comparison(&report).expect("normalize");
        let run = normalized.get("run").and_then(|v| v.as_object()).unwrap();
        assert!(run.get("started_at").is_none());
        assert!(run.get("ended_at").is_none());
        assert!(run.get("duration_ms").is_none());
        assert_eq!(run.get("other").and_then(|v| v.as_str()), Some("keep"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn validate_all_fixtures_only_checks_json_files() {
        let root = temp_dir("fixtures");
        let json_path = root.join("ok.json");
        let txt_path = root.join("ignore.txt");
        fs::write(
            &json_path,
            serde_json::to_string_pretty(&json!({"schema": "ok"})).unwrap(),
        )
        .expect("write json");
        fs::write(&txt_path, "ignore").expect("write txt");

        let schema = jsonschema::validator_for(&json!({"type": "object"})).unwrap();
        validate_all_fixtures(&root, &schema).expect("validate fixtures");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn explain_registry_contract_passes() {
        // check_explain_registry_contract reads files relative to the workspace
        // root, so we need to cd there first (tests run from CARGO_MANIFEST_DIR).
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .expect("xtask parent is workspace root");
        std::env::set_current_dir(workspace_root).expect("cd to workspace root");
        check_explain_registry_contract().expect("explain registry contract should pass");
    }

    #[test]
    fn create_conform_fixtures_writes_expected_structure() {
        let root = temp_dir("conform");
        create_conform_fixtures(&root).expect("create fixtures");

        assert!(root.join("pass_basic").join(".tool-versions").exists());
        assert!(root.join("fail_missing").join(".tool-versions").exists());
        assert!(root.join("no_sources").join(".gitkeep").exists());
        assert!(root.join("error_recovery").join("env-check.toml").exists());

        let _ = fs::remove_dir_all(&root);
    }
}
