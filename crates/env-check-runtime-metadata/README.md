# env-check-runtime-metadata

Runtime metadata helpers extracted from `env-check-runtime` so metadata behavior is isolated
into a dedicated microcrate:

- Host metadata (`os`, `arch`, `hostname`)
- CI environment detection (`GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TF_BUILD`, fallback `CI`)
- GitHub event parsing (`$GITHUB_EVENT_PATH` and pull request metadata)
- Repo metadata probing (`git`/`merge-base` helpers)

This crate remains small and deterministic so other layers can depend on it as a pure
runtime information service.
