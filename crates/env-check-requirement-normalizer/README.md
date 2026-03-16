# env-check-requirement-normalizer

Pure helper crate for request normalization in env-check app orchestration.

It currently applies stable, deterministic transforms for:

- applying `ignore_tools`
- applying `force_required`
- deduplicating requirements by `(tool, probe_kind)`

The API intentionally contains no I/O so it can be consumed by orchestration and test code.
