# env-check Feature Implementation Guide

This guide documents the patterns and steps for implementing new features in env-check. Follow these instructions to maintain consistency with the existing architecture.

## Table of Contents

1. [Adding a New Source Parser](#adding-a-new-source-parser)
2. [Adding a New Probe Type](#adding-a-new-probe-type)
3. [Adding a New Output Format](#adding-a-new-output-format)
4. [Adding a New CLI Command](#adding-a-new-cli-command)
5. [Testing Requirements](#testing-requirements)

---

## Adding a New Source Parser

Source parsers extract tool requirements from configuration files. Each parser is implemented as a separate microcrate with feature-gated inclusion.

### Step 1: Create the Microcrate

Create a new crate in `crates/env-check-sources-<name>/`:

```toml
# crates/env-check-sources-<name>/Cargo.toml
[package]
name = "env-check-sources-<name>"
version = "0.1.0"
edition.workspace = true
license.workspace = true
rust-version.workspace = true
repository.workspace = true
homepage.workspace = true
authors.workspace = true
description = "Parser for <format> files."

[dependencies]
env-check-types.workspace = true
anyhow.workspace = true

[dev-dependencies]
proptest.workspace = true
```

### Step 2: Implement the Parser

Create [`src/lib.rs`](crates/env-check-sources-go/src/lib.rs:1) with parsing functions:

```rust
//! <format> parser microcrate.

use std::fs;
use std::path::Path;

use anyhow::Context;
use env_check_types::{ProbeKind, Requirement, SourceKind, SourceRef};

/// Parse a <format> file and extract requirements.
pub fn parse_<format>(root: &Path, path: &Path) -> anyhow::Result<Vec<Requirement>> {
    let text = fs::read_to_string(path).with_context(|| "read <format>")?;
    parse_<format>_str(root, path, &text)
}

/// Parse <format> content from a string.
pub fn parse_<format>_str(root: &Path, path: &Path, text: &str) -> anyhow::Result<Vec<Requirement>> {
    let mut requirements = Vec::new();
    
    // Parse the file format and extract tool requirements
    for line in text.lines() {
        // Extract tool name and version constraint
        // Create Requirement structs
    }
    
    Ok(requirements)
}
```

**Key Contract Points:**

- Return `Vec<Requirement>` with normalized tool IDs (e.g., `nodejs` → `node`, `golang` → `go`)
- Set [`SourceRef.path`](crates/env-check-types/src/lib.rs:1) relative to repo root with forward slashes
- Use [`ProbeKind::Version`](crates/env-check-types/src/lib.rs:1) for version requirements
- Never panic on malformed input; return `Err` instead

### Step 3: Add Feature Flag

Update [`crates/env-check-parser-flags/src/lib.rs`](crates/env-check-parser-flags/src/lib.rs:1):

```rust
// Add to Parser enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Parser {
    Node,
    Python,
    Go,
    <Name>,  // Add new variant
}

impl Parser {
    fn as_str(self) -> &'static str {
        match self {
            // ... existing arms
            Self::<Name> => "<name>",
        }
    }
}

fn parse_parser_name(value: &str) -> Option<Parser> {
    match value.trim().to_lowercase().as_str() {
        // ... existing arms
        "<name>" | "<alt-name>" => Some(Parser::<Name>),
        _ => None,
    }
}

fn available_parsers() -> Vec<Parser> {
    let mut parsers = Vec::new();
    // ... existing checks
    if cfg!(feature = "parser-<name>") {
        parsers.push(Parser::<Name>);
    }
    parsers
}
```

Update [`ParserFilters`](crates/env-check-parser-flags/src/lib.rs:68):

```rust
#[derive(Debug, Clone, Default)]
pub struct ParserFilters {
    node: bool,
    python: bool,
    go: bool,
    <name>: bool,  // Add field
}
```

### Step 4: Register in Workspace

Add to [`Cargo.toml`](Cargo.toml:1) workspace members:

```toml
[workspace]
members = [
  # ... existing members
  "crates/env-check-sources-<name>",
]

[workspace.dependencies]
env-check-sources-<name> = { version = "0.1.0", path = "crates/env-check-sources-<name>" }
```

### Step 5: Add to Sources Crate

Update [`crates/env-check-sources/Cargo.toml`](crates/env-check-sources/Cargo.toml:1):

```toml
[dependencies]
env-check-sources-<name> = { workspace = true, optional = true }

[features]
parser-<name> = ["dep:env-check-sources-<name>", "env-check-parser-flags/parser-<name>"]
```

Update [`crates/env-check-sources/src/lib.rs`](crates/env-check-sources/src/lib.rs:1) to re-export and call the parser.

### Step 6: Add Tests

Create test files following the pattern in [`crates/env-check-sources/tests/parse.rs`](crates/env-check-sources/tests/parse.rs:1):

```rust
#[test]
fn parses_<format>_basic() {
    let root = Path::new("tests/fixtures/<format>_basic");
    let path = root.join("<format-file>");
    let reqs = parse_<format>(root, &path).unwrap();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].tool, "expected-tool");
}
```

Create fixtures in `crates/env-check-sources/tests/fixtures/<format>_basic/`.

### Step 7: Add Fuzzing

Create [`fuzz/fuzz_targets/fuzz_<format>.rs`](fuzz/fuzz_targets/fuzz_go_mod.rs:1):

```rust
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let root = Path::new("/fuzz");
        let path = root.join("<format-file>");
        let _ = env_check_sources::parse_<format>_str(root, &path, text);
    }
});
```

Add corpus files in `fuzz/corpus/fuzz_<format>/`.

---

## Adding a New Probe Type

Probe types define how env-check verifies tools on the local machine.

### Step 1: Define the ProbeKind Variant

Update [`crates/env-check-types/src/lib.rs`](crates/env-check-types/src/lib.rs:1):

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    Version,
    Hash,
    <NewKind>,  // Add variant
}
```

### Step 2: Implement the Probe Logic

Update [`crates/env-check-probe/src/lib.rs`](crates/env-check-probe/src/lib.rs:1):

```rust
impl<R: CommandRunner, P: PathResolver, H: Hasher> Prober<R, P, H> {
    pub fn probe_<new_kind>(&self, req: &Requirement) -> Result<Observation, EnvCheckError> {
        // Implement probing logic
        // Return Observation with appropriate fields set
    }
}
```

The [`Prober`](crates/env-check-probe/src/lib.rs:98) struct provides access to:
- [`runner: R`](crates/env-check-probe/src/lib.rs:99) - Execute commands
- [`path: P`](crates/env-check-probe/src/lib.rs:100) - Resolve tool paths
- [`hasher: H`](crates/env-check-probe/src/lib.rs:101) - Compute hashes

### Step 3: Add Test Fakes

Create fake implementations for testing:

```rust
#[cfg(test)]
pub struct Fake<NewKind>Prober {
    // Configure behavior for tests
}

#[cfg(test)]
impl Fake<NewKind>Prober {
    pub fn new() -> Self { /* ... */ }
    
    pub fn with_<new_kind>(mut self, tool: &str, result: Result<...>) -> Self {
        // Configure expected behavior
        self
    }
}
```

### Step 4: Update Domain Evaluation

Update [`crates/env-check-domain/src/lib.rs`](crates/env-check-domain/src/lib.rs:1) to handle the new probe kind in [`eval_one()`](crates/env-check-domain/src/lib.rs:93).

---

## Adding a New Output Format

Output formats render the receipt for different consumers.

### Step 1: Implement the Render Function

Add to [`crates/env-check-render/src/lib.rs`](crates/env-check-render/src/lib.rs:1):

```rust
/// Render receipt as <format>.
///
/// Rendering is pure and deterministic.
pub fn render_<format>(report: &ReceiptEnvelope) -> String {
    let mut out = String::new();
    
    // Render header
    out.push_str(&format!("## env-check: {:?}\n", report.verdict.status));
    
    // Render findings (sorted deterministically)
    let mut items: Vec<_> = report.findings.iter().collect();
    items.sort_by(|a, b| {
        finding_sort_key(a).cmp(&finding_sort_key(b))
    });
    
    for finding in items {
        // Format each finding
    }
    
    out
}
```

**Key Requirements:**

- Rendering must be pure (no IO, no side effects)
- Output must be deterministic for the same input
- Use [`finding_sort_key()`](crates/env-check-types/src/lib.rs:1) for stable ordering
- Respect any truncation already applied to the receipt

### Step 2: Add Snapshot Tests

Create tests in [`crates/env-check-render/tests/render.rs`](crates/env-check-render/tests/render.rs:1):

```rust
#[test]
fn render_<format>_basic() {
    let receipt = make_receipt(
        VerdictStatus::Pass,
        Counts { info: 0, warn: 0, error: 0 },
        vec![],
        None,
    );
    
    let output = render_<format>(&receipt);
    insta::assert_snapshot!("render_<format>_basic", output);
}
```

Run `cargo insta test` to create snapshots in `tests/snapshots/`.

### Step 3: Add CLI Support

Update [`crates/env-check-cli/src/main.rs`](crates/env-check-cli/src/main.rs:1) to add output options:

```rust
#[derive(Subcommand, Debug)]
enum Command {
    Check {
        // ... existing options
        
        /// Output format: json|markdown|<format>
        #[arg(long, default_value = "json")]
        format: FormatArg,
    },
}
```

---

## Adding a New CLI Command

CLI commands are defined using clap's derive macros.

### Step 1: Define the Subcommand

Add to [`crates/env-check-cli/src/main.rs`](crates/env-check-cli/src/main.rs:22):

```rust
#[derive(Subcommand, Debug)]
enum Command {
    // ... existing commands
    
    /// <Brief description for clap help>
    #[command(
        after_help = "EXAMPLES:\n    env-check <name> <args>\n    env-check <name> --option value"
    )]
    <Name> {
        /// Positional argument description
        #[arg(value_name = "ARG")]
        arg: Option<PathBuf>,
        
        /// Flag option description
        #[arg(long)]
        option: Option<String>,
        
        /// Option with default
        #[arg(long, default_value = "default")]
        with_default: String,
    },
}
```

### Step 2: Implement Command Handler

Add a function to handle the command:

```rust
fn run_<name>(
    arg: Option<&PathBuf>,
    option: Option<&str>,
    with_default: &str,
) -> anyhow::Result<()> {
    // 1. Load configuration if needed
    // 2. Execute the operation
    // 3. Write outputs
    // 4. Return appropriate exit code
    Ok(())
}
```

### Step 3: Wire Up in Main

Update the [`main()`](crates/env-check-cli/src/main.rs:1) function:

```rust
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    
    match cli.cmd {
        Command::Check { .. } => { /* ... */ }
        Command::Md { .. } => { /* ... */ }
        Command::Explain { .. } => { /* ... */ }
        Command::<Name> { arg, option, with_default } => {
            run_<name>(arg.as_ref(), option.as_deref(), &with_default)
        }
    }
}
```

### Step 4: Add Integration Tests

Create tests in [`crates/env-check-cli/tests/cli.rs`](crates/env-check-cli/tests/cli.rs:1):

```rust
#[test]
fn <name>_command_basic() {
    let mut cmd = Command::cargo_bin("env-check").unwrap();
    cmd.arg("<name>")
        .arg("--option")
        .arg("value");
    
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("expected output"));
}
```

---

## Testing Requirements

All new features must include appropriate tests.

### Unit Tests

Location: `src/` directory with `#[cfg(test)]` module

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_<feature>_basic() {
        // Test normal operation
    }
    
    #[test]
    fn test_<feature>_edge_case() {
        // Test boundary conditions
    }
    
    #[test]
    fn test_<feature>_error_handling() {
        // Test error paths
    }
}
```

### Integration Tests

Location: `tests/` directory

```rust
// tests/<feature>.rs
use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn integration_<feature>() {
    let mut cmd = Command::cargo_bin("env-check").unwrap();
    cmd.arg("check")
        .arg("--root")
        .arg("tests/fixtures/<fixture>");
    
    cmd.assert()
        .code(0)
        .stdout(predicate::str::contains("PASS"));
}
```

### BDD Scenarios

Location: [`features/env_check.feature`](features/env_check.feature:1)

```gherkin
Feature: <Feature Name>

  Scenario: <Scenario Description>
    Given a repository with <setup>
    When I run env-check <command>
    Then the exit code should be <code>
    And the output should contain <expected>
```

Implement step definitions in [`crates/env-check-cli/tests/bdd.rs`](crates/env-check-cli/tests/bdd.rs:1).

### Property Tests

Location: `tests/proptest.rs`

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_<feature>_never_panics(input in ".*") {
        // Should never panic on any input
        let _ = parse_<feature>_str(Path::new("/"), Path::new("/file"), &input);
    }
    
    #[test]
    fn prop_<feature>_deterministic(input in ".*") {
        // Same input should produce same output
        let root = Path::new("/");
        let path = root.join("file");
        let a = parse_<feature>_str(root, &path, &input);
        let b = parse_<feature>_str(root, &path, &input);
        assert_eq!(a.is_ok(), b.is_ok());
    }
}
```

### Fuzzing

Location: [`fuzz/fuzz_targets/`](fuzz/fuzz_targets/)

Every parser must have a fuzz target:

```rust
// fuzz/fuzz_targets/fuzz_<parser>.rs
#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let root = Path::new("/fuzz");
        let path = root.join("<file>");
        // Must never panic
        let _ = env_check_sources::parse_<parser>_str(root, &path, text);
    }
});
```

Add corpus seeds in `fuzz/corpus/fuzz_<parser>/`.

### Snapshot Tests

Location: `tests/` with [`insta`](https://insta.rs/)

```rust
#[test]
fn snapshot_<feature>() {
    let result = render_<feature>(&input);
    insta::assert_snapshot!("snapshot_name", result);
}
```

### Test Running Commands

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p env-check-<crate>

# BDD tests
cargo test -p env-check-cli --test bdd

# Property tests
cargo test -p env-check-sources --test proptest

# Fuzzing (requires nightly)
cargo +nightly fuzz run fuzz_<target>
```

---

## Checklist for New Features

Before submitting a PR with new features:

- [ ] Code follows the dependency direction: `types ← (sources|probe|domain|evidence|render) ← app ← cli`
- [ ] All new types are in `env-check-types` crate
- [ ] Parsers are in microcrates with feature flags
- [ ] Probes use trait injection for testability
- [ ] Renderers are pure functions
- [ ] CLI commands use clap derive macros
- [ ] Unit tests cover normal and error paths
- [ ] Integration tests verify end-to-end behavior
- [ ] BDD scenarios cover user workflows
- [ ] Property tests validate invariants
- [ ] Fuzz targets exist for all parsers
- [ ] Output is deterministic (stable ordering, no host-dependent values)
- [ ] Documentation updated (CLAUDE.md, README.md as needed)
