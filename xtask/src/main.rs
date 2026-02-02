use std::fs;
use std::path::PathBuf;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("schema-check") => schema_check(),
        _ => {
            eprintln!("xtask commands:");
            eprintln!("  schema-check   Validate example receipts against schemas");
            Ok(())
        }
    }
}

fn schema_check() -> anyhow::Result<()> {
    // Minimal scaffold: validate schemas compile.
    // Add example receipts under `tests/fixtures/` as they land.
    let schema_path = PathBuf::from("schemas/env-check.report.v1.json");
    let schema_bytes = fs::read(&schema_path).with_context(|| format!("read {}", schema_path.display()))?;
    let schema_json: serde_json::Value = serde_json::from_slice(&schema_bytes).context("parse schema json")?;

    let compiled = jsonschema::JSONSchema::compile(&schema_json).context("compile schema")?;
    let _ = compiled; // placeholder

    eprintln!("ok: compiled {}", schema_path.display());
    Ok(())
}
