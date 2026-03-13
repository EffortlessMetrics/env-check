# env-check Roadmap: Now / Next / Later

This document outlines the development roadmap for env-check, organized by time horizon and priority.

---

## NOW (v0.2.0) - Current Quarter

**Theme: Polish & UX**

Focus on documentation completeness, user experience improvements, and addressing edge cases reported by early adopters.

### Documentation

| Task | Description | Priority | Effort | Status |
|------|-------------|----------|--------|--------|
| CLI Reference Expansion | Document all CLI flags including `--mode cockpit`, exit codes, and environment variables | High | Small (1 day) | [ ] |
| Configuration Schema | Complete config file documentation with examples for all options | High | Small (1 day) | [ ] |
| CI Integration Guide | Multi-provider CI examples (GitHub Actions, GitLab CI, CircleCI, Azure Pipelines) | High | Medium (2 days) | [ ] |
| Contributing Guide | Extract contributor guidelines from AGENTS.md into standalone CONTRIBUTING.md | Medium | Small (1 day) | [ ] |
| Video Walkthrough | Create screencast demonstrating common workflows | Low | Medium (2 days) | [ ] |

### Enhancements

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| Probe Timeout Support | Add configurable timeout for tool probing (default 30s) | #TBD | High | Medium (2-3 days) | None |
| Shell Completions | Generate completions for bash, zsh, fish, powershell | #TBD | High | Small (1 day) | None |
| Progress Output | Show progress indicators during long-running checks | #TBD | Medium | Small (1 day) | None |
| Custom Probe Commands | Allow configuring custom version detection commands | #TBD | Medium | Medium (2-3 days) | None |
| Performance Benchmarking | Establish performance baselines and optimize hot paths | #TBD | Medium | Medium (2-3 days) | None |

### Bug Fixes

| Task | Description | Issue | Priority | Effort |
|------|-------------|-------|----------|--------|
| Version Parse Edge Cases | Handle tools with non-standard `--version` output (e.g., Windows tools, legacy versions) | #TBD | High | Small (1 day) |
| Path Normalization | Fix path handling edge cases on Windows | #TBD | Medium | Small (1 day) |
| Error Message Clarity | Improve error messages for common failure modes | #TBD | Medium | Small (1 day) |

---

## NEXT (v0.3.0) - Next Quarter

**Theme: Platform Expansion**

Extend source type support and platform coverage to serve a broader range of development environments.

### New Source Types

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| Terraform Version Constraints | Parse `.terraform-version` and module version constraints from `.tf` files | #TBD | High | Medium (2-3 days) | None |
| Dockerfile FROM Pins | Extract base image versions from Dockerfile `FROM` instructions | #TBD | High | Medium (2-3 days) | None |
| Containerfile Support | Parse Containerfile (Podman) image versions | #TBD | Medium | Small (1 day) | Dockerfile FROM Pins |
| Helm Chart Requirements | Parse `Chart.yaml` dependencies for Kubernetes tooling | #TBD | Low | Medium (2-3 days) | None |

### Platform Support

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| ARM64 Windows Support | Native Windows ARM64 probing and binary releases | #TBD | High | Medium (2-3 days) | None |
| FreeBSD Support | Add FreeBSD platform support with native probing | #TBD | Medium | Medium (2-3 days) | None |
| Container-Native Probing | Support running probes inside Docker/Podman containers | #TBD | Medium | Large (1-2 weeks) | None |

### Integration

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| VS Code Extension | Language server for `env-check.toml` with validation and autocomplete | #TBD | High | Large (1-2 weeks) | None |
| Pre-commit Hook | Pre-commit.com hook integration for automatic checking | #TBD | High | Small (1 day) | None |
| Git Hooks | Native git hooks for pre-commit and pre-push | #TBD | Medium | Small (1 day) | None |

---

## LATER (v0.4.0+) - Future Quarters

**Theme: Advanced Features & Ecosystem**

Build advanced capabilities and ecosystem integrations for enterprise adoption.

### Advanced Features

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| Diff-Scoped Behavior | Compare base/head requirements for PRs, only check changed tools | #TBD | High | Large (1-2 weeks) | Git metadata detection |
| Self-Update Mechanism | Binary self-update from GitHub releases with signature verification | #TBD | Medium | Medium (2-3 days) | Network access (opt-in) |
| Centralized Policy Server | Team/enterprise policy distribution via HTTP endpoint | #TBD | Medium | Large (2+ weeks) | Network access, authentication |
| Policy Caching | Local cache for remote policies with TTL | #TBD | Low | Medium (2-3 days) | Centralized Policy Server |
| Remediation Suggestions | Suggest installation commands for missing tools | #TBD | Low | Medium (2-3 days) | None |

### Ecosystem

| Task | Description | Issue | Priority | Effort | Dependencies |
|------|-------------|-------|----------|--------|--------------|
| Python SDK | Python bindings for programmatic access | #TBD | High | Medium (1 week) | PyO3 or Uniffi |
| JavaScript SDK | Node.js bindings for programmatic access | #TBD | High | Medium (1 week) | napi-rs |
| Go SDK | Go bindings for programmatic access | #TBD | Medium | Medium (1 week) | cgo |
| Terraform Provider | Infrastructure as Code integration | #TBD | Medium | Large (2+ weeks) | Terraform SDK |
| Kubernetes Admission Controller | Cluster-level enforcement via admission webhook | #TBD | Low | Large (2+ weeks) | Kubernetes client |

---

## Metrics & Success Criteria

### Quality Metrics

| Metric | Current | Target | Description |
|--------|---------|--------|-------------|
| Test Coverage | ~85% | >90% | Line coverage across all crates |
| Fuzz Corpus | ~50 inputs | >1000 executions | All parsers with comprehensive corpus |
| Property Tests | Basic | Comprehensive | All parsers with proptest cases |
| BDD Scenarios | 551 lines | 800+ lines | Feature coverage for all workflows |

### Performance Metrics

| Metric | Current | Target | Description |
|--------|---------|--------|-------------|
| Execution Time | ~50ms | <100ms | For typical repos (10-20 requirements) |
| Startup Time | ~5ms | <10ms | Cold start to first output |
| Binary Size | ~8MB | <10MB | Release build, stripped |
| Memory Peak | ~30MB | <50MB | Maximum RSS during execution |

### Adoption Metrics

| Metric | Current | Target | Description |
|--------|---------|--------|-------------|
| GitHub Stars | - | 500+ | Community interest indicator |
| Homebrew Installs | - | 1000+ | macOS user adoption |
| GitHub Actions Usage | - | 100+ repos | CI integration adoption |

---

## Release Schedule

| Version | Target Date | Theme | Key Deliverables |
|---------|-------------|-------|------------------|
| v0.2.0 | Q2 2024 | Polish & UX | Documentation, shell completions, probe timeout |
| v0.3.0 | Q3 2024 | Platform Expansion | New sources, ARM64 Windows, VS Code extension |
| v0.4.0 | Q4 2024 | Advanced Features | Diff-scoped behavior, self-update, SDKs |
| v0.5.0 | Q1 2025 | Ecosystem | Terraform provider, Kubernetes integration |
| v1.0.0 | Q2 2025 | Stable API | API stability guarantee, enterprise features |

### Release Cadence

- **Patch releases** (v0.x.Y): Bug fixes, documentation updates - as needed
- **Minor releases** (v0.X.0): New features, enhancements - quarterly
- **Major release** (v1.0.0): API stability commitment - when ready

---

## Completed Milestones

### v0.1.0 - Foundation ✅

The initial release established core functionality:

**Source Discovery & Parsing**
- ✅ `.tool-versions` (asdf format)
- ✅ `.mise.toml` (mise format)
- ✅ `.node-version` and `.nvmrc` (Node.js)
- ✅ `package.json` engines field (Node.js)
- ✅ `.python-version` (pyenv format)
- ✅ `pyproject.toml` requires-python (Python)
- ✅ `go.mod` toolchain directive (Go)
- ✅ `rust-toolchain.toml` (Rust)
- ✅ Hash manifests (SHA256 checksums)

**Runtime Probing**
- ✅ Tool presence detection
- ✅ Version detection via `--version` flags
- ✅ Hash verification (SHA256)
- ✅ OS adapters for Windows, macOS, Linux

**Evaluation & Output**
- ✅ Semver constraint matching
- ✅ Profile-based severity mapping (oss/team/strict)
- ✅ JSON receipt output
- ✅ Markdown summaries
- ✅ GitHub Actions annotations

**Quality & Testing**
- ✅ BDD test suite (551 lines of scenarios)
- ✅ Fuzz testing for all parsers
- ✅ Property-based testing
- ✅ Snapshot testing for renderers

---

## Contributing

See [AGENTS.md](../AGENTS.md) for contribution guidelines and [docs/testing.md](testing.md) for testing instructions.

## Changelog

See [CHANGELOG.md](../CHANGELOG.md) for release history.
