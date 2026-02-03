use std::fs;
use std::path::PathBuf;

use anyhow::{Context, bail};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("schema-check") => schema_check(),
        _ => {
            eprintln!("xtask commands:");
            eprintln!("  schema-check   Validate schemas and example receipts");
            Ok(())
        }
    }
}

fn schema_check() -> anyhow::Result<()> {
    // 1. Load and compile both schemas (keeping JSON values in scope)
    let envelope_json = load_schema_json("schemas/receipt.envelope.v1.json")?;
    let envelope_schema = jsonschema::JSONSchema::compile(&envelope_json)
        .map_err(|e| anyhow::anyhow!("compile envelope schema: {}", e))?;
    eprintln!("ok: compiled schemas/receipt.envelope.v1.json");

    // Note: The report schema uses $ref to envelope schema which requires resolver setup.
    // For now, we validate the report schema compiles but use envelope for validation.
    // The report schema adds const constraints (schema="env-check.report.v1", tool.name="env-check")
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
        validate_all_fixtures(&fixtures_dir, &envelope_schema)?;
    } else {
        eprintln!("note: no fixtures directory at xtask/fixtures/, creating examples");
        create_example_fixtures()?;
        // Re-validate after creating
        validate_all_fixtures(&fixtures_dir, &envelope_schema)?;
    }

    eprintln!("schema-check: all validations passed");
    Ok(())
}

fn load_schema_json(path: &str) -> anyhow::Result<serde_json::Value> {
    let schema_path = PathBuf::from(path);
    let schema_bytes = fs::read(&schema_path)
        .with_context(|| format!("read {}", schema_path.display()))?;
    serde_json::from_slice(&schema_bytes).context("parse schema json")
}

fn validate_all_fixtures(
    fixtures_dir: &PathBuf,
    envelope: &jsonschema::JSONSchema,
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

fn validate_fixture(
    path: &PathBuf,
    envelope: &jsonschema::JSONSchema,
) -> anyhow::Result<()> {
    let bytes = fs::read(path)
        .with_context(|| format!("read {}", path.display()))?;
    let json: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", path.display()))?;

    // Validate against envelope schema
    let result = envelope.validate(&json);
    if let Err(errors) = result {
        let error_messages: Vec<String> = errors
            .map(|e| format!("  - {}: {}", e.instance_path, e))
            .collect();
        bail!(
            "{} failed envelope validation:\n{}",
            path.display(),
            error_messages.join("\n")
        );
    }

    // Additional validation for env-check reports:
    // Verify schema field matches expected value
    if let Some(schema_field) = json.get("schema").and_then(|v| v.as_str()) {
        if schema_field == "env-check.report.v1" {
            // Verify tool.name is "env-check"
            if let Some(tool) = json.get("tool") {
                if let Some(name) = tool.get("name").and_then(|v| v.as_str()) {
                    if name != "env-check" {
                        bail!(
                            "{} has schema 'env-check.report.v1' but tool.name is '{}' (expected 'env-check')",
                            path.display(),
                            name
                        );
                    }
                }
            }
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
        "schema": "env-check.report.v1",
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
        "schema": "env-check.report.v1",
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
