# env-check-parser-flags

Microcrate that owns parser feature flag semantics for env-check.

It centralizes:

- parser identifier parsing and normalization (`node`, `nodejs`, `node.js`, `python`, `py`)
- parser availability mapping through crate features (`parser-node`, `parser-python`, `parser-go`)
- stable `ParserFilters` configuration semantics for `enabled` and `disabled` lists

This allows source parsing, CLI wiring, and BDD scenarios to rely on one small,
stable API for parser feature resolution.
