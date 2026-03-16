# env-check-evidence

Pure helpers for shaping receipt evidence data.

## Purpose

This crate keeps `env-check-app` orchestration-focused by handling deterministic
evidence formatting:

- Source/probe kind normalization for `data.observed`
- Probe transcript condensation for `data.probes`
- Dependency graph shaping for `data.dependencies`

## Working Agreements

- Keep logic pure and deterministic.
- Depend only on `env-check-types` + small parsing utilities.
- Do not perform any I/O.
- Keep output ordering stable across runs.
