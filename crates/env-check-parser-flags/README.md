# env-check-parser-flags

> **Note**: This is an internal implementation detail of [env-check](https://crates.io/crates/env-check).
> API not covered by semver guarantees. Use `cargo install env-check` instead.

Microcrate that owns parser feature flag semantics for env-check.

It centralizes:

- parser identifier parsing and normalization (`node`, `nodejs`, `node.js`, `python`, `py`)
- parser availability mapping through crate features (`parser-node`, `parser-python`, `parser-go`)
- stable `ParserFilters` configuration semantics for `enabled` and `disabled` lists

This allows source parsing, CLI wiring, and BDD scenarios to rely on one small,
stable API for parser feature resolution.
