# env-check-render

Pure markdown renderer for receipts.

## Purpose

This crate transforms a `ReceiptEnvelope` into human-readable markdown, suitable for PR comments or terminal output. It has no I/O and produces fully deterministic output.

## Key Function

```rust
pub fn render_markdown(report: &ReceiptEnvelope) -> String
```

## Output Format

```markdown
# ✅ PASS (or ⚠️ WARN / ❌ FAIL / ⏭️ SKIP)

**Summary**: 0 errors, 0 warnings, 2 info
**Profile**: oss | **Fail on**: error
**Sources**: .tool-versions, rust-toolchain.toml

## Findings

### `env.version_mismatch`
📍 .tool-versions:3
Node version mismatch: expected 20.x, found 18.17.0

💡 Update Node.js to match the required version
```

## Rendering Rules

- Header shows verdict status with emoji
- Summary includes error/warn/info counts, profile, fail_on, sources used
- Truncation note if findings were capped
- Up to 10 findings displayed (prioritized by severity)
- Each finding shows code, location, message, and help text if available

## Working Agreements

- **No I/O** - pure transformation function
- Output must be deterministic (same input → same output)
- Limit findings to 10 to keep PR comments readable
- Use GitHub-flavored markdown
- Emoji usage is intentional for quick visual scanning

## Testing

```bash
# Run unit tests with snapshot testing
cargo test -p env-check-render

# Update snapshots after intentional changes
cargo insta accept
```

## Snapshot Testing

Uses `insta` for snapshot testing. When rendering logic changes:
1. Run tests to see diff
2. Review changes carefully
3. Run `cargo insta accept` to update snapshots
