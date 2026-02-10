# env-check

**Project Type:** Rust Workspace (CLI & GitHub Action)
**Purpose:** Machine-truth preflight tool to validate local environments against repository tool declarations.

## Project Overview

`env-check` answers the question: "Is this machine set up to work with the repo's declared tool requirements?"
It parses standard configuration files (like `.tool-versions`, `package.json`, `go.mod`, etc.) and verifies that the required tools are present and meet version constraints on the local machine.

**Key Characteristics:**
*   **Read-Only:** It does not install tools or modify the system.
*   **Machine-Truth:** Checks what is actually on the PATH or managed by toolchains.
*   **Optional:** Designed to be non-blocking by default.
*   **Output:** Generates machine-readable receipts (`report.json`) and human-readable summaries (`comment.md`).

## Architecture

The project is organized as a Cargo workspace with modular crates:

*   **`crates/env-check-cli`**: The binary entry point and CLI interface (using `clap`).
*   **`crates/env-check-app`**: Application wiring and high-level logic.
*   **`crates/env-check-domain`**: Core domain logic (evaluation, findings, verdicts).
*   **`crates/env-check-probe`**: Logic for detecting tools and versions on the host.
*   **`crates/env-check-sources`**: Parsers for various configuration files (`.tool-versions`, `package.json`, etc.).
*   **`crates/env-check-render`**: Rendering logic for JSON reports and Markdown summaries.
*   **`crates/env-check-types`**: Shared type definitions used across crates.
*   **`xtask`**: Internal automation tool for development tasks (schema validation, conformance testing).

## Development & Usage

### Building
Standard Cargo commands apply:
```bash
cargo build
cargo build --release
```

### Running the CLI
```bash
cargo run -p env-check-cli -- check --root . --profile oss
```

### Automation (`xtask`)
The `xtask` crate provides project-specific automation:
```bash
cargo run -p xtask -- schema-check  # Validate schemas and examples
cargo run -p xtask -- conform       # Run conformance checks (determinism, survivability)
cargo run -p xtask -- mutants       # Run mutation tests (requires cargo-mutants)
```

## Testing Strategy

The project employs a multi-layered testing strategy to ensure reliability and correctness.

1.  **Unit Tests:** Focus on parsers, domain evaluation, and rendering.
    ```bash
    cargo test
    ```
2.  **Integration Tests:** End-to-end CLI tests using `assert_cmd`, located in `tests/` directories.
3.  **BDD (Behavior Driven Development):** Cucumber tests in `crates/env-check-cli/tests/bdd.rs` and `features/`.
    ```bash
    cargo test -p env-check-cli --test bdd
    ```
4.  **Property Testing:** `proptest` used for robust parsing logic.
5.  **Fuzzing:** `cargo-fuzz` targets for all source parsers (e.g., `parse_tool_versions`, `fuzz_package_json`).
    ```bash
    cargo fuzz list
    # Example: cargo fuzz run parse_tool_versions
    ```
6.  **Mutation Testing:** `cargo-mutants` is used to verify test coverage quality, specifically targeting `env-check-domain`.
    ```bash
    cargo run -p xtask -- mutants
    ```
7.  **Snapshot Testing:** `insta` is used for output verification.
    ```bash
    cargo insta accept # Update snapshots
    ```

## Key Files & Directories

*   **`Cargo.toml`**: Workspace configuration.
*   **`.github/settings.yml`**: Repository metadata and settings (managed via "Settings" app).
*   **`.github/CODEOWNERS`**: Code ownership and protection rules.
*   **`action.yml`**: GitHub Action definition.
*   **`xtask/`**: helper scripts and automation.
*   **`schemas/`**: JSON schemas for the output reports (`sensor.report.v1.schema.json`).
*   **`docs/`**: Detailed documentation (architecture, testing, design).
*   **`fuzz/`**: Fuzzing targets and corpus.

## Conventions

*   **Rust Edition:** 2024.
*   **Code Style:** Standard `rustfmt` and `clippy` guidelines.
*   **Settings-as-Code:** Repository "About" metadata is managed via `.github/settings.yml`.
*   **Determinism:** Outputs must be deterministic (verified by `xtask conform`).
*   **Safety:** The tool is designed to be safe to run; it never modifies the repository or installs software.
