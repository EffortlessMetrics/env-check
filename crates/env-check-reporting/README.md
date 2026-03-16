# env-check-reporting

Focused crate for shaping and serializing the `data` and `capabilities` sections
of an env-check receipt.

- `build_data`: policy + source + probe outcome summary and dependency graph.
- `build_capabilities`: observed capability status block for git/inputs/engine/baseline.

The crate is intentionally pure and deterministic, with no filesystem side effects,
so it is easy to extend without making the orchestration layer less predictable.
