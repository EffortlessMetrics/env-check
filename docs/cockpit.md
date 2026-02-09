# Cockpit integration

env-check emits a standard receipt and an optional human-friendly markdown summary. The cockpit
should treat env-check as a **machine-truth** sensor and keep it informational by default.

## Recommended policy (default)

```toml
[sensors.env-check]
blocking = false
missing = "skip"
```

## When to make it blocking

```toml
[sensors.env-check]
blocking = true
missing = "warn"
```

Use this only for controlled runners or lanes where reproducibility matters.

## Cockpit comment contract (Environment section)

Keep it short. Example layout:

- Environment: 1 error, 2 warnings (env-check)
- Missing tool: node (>=20)
- Version mismatch: python (3.12)
- Repro: `env-check check --root . --profile oss --out artifacts/env-check/report.json --md artifacts/env-check/comment.md`

The full detail should live in `artifacts/env-check/comment.md`.
