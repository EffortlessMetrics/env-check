# env-check-fuzz

`cargo-fuzz` harness for parser robustness in env-check.

## What This Package Covers

- `.tool-versions`
- `.mise.toml`
- `rust-toolchain.toml` / `rust-toolchain`
- hash manifest parsing
- Node sources (`.node-version`, `.nvmrc`, `package.json`)
- Python sources (`.python-version`, `pyproject.toml`)
- `go.mod`

## Purpose

- Ensure arbitrary/untrusted input never causes parser panics.
- Strengthen deterministic parser behavior on malformed input.

## Boundaries

- Fuzz harness only; not part of normal runtime path.
- Not published (`publish = false`).
