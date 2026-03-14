# env-check-render

Deterministic renderers for env-check receipts.

## What This Crate Does

- Renders receipt summaries/findings as markdown.
- Renders findings as GitHub Actions workflow command annotations.
- Keeps output ordering and caps deterministic.

## Public API Highlights

- `render_markdown(report: &ReceiptEnvelope) -> String`
- `render_github_annotations(report: &ReceiptEnvelope, max_findings: usize) -> String`

## Boundaries

- No file writes or command execution.
- No policy decisions; renders whatever is present in the receipt.
- Any truncation policy is expected to be applied upstream (app/domain).
