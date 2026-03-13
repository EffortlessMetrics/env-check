# CI Integration Guide

This guide covers integrating env-check with various CI/CD systems to validate that build runners satisfy your project's tool requirements.

## Table of Contents

- [Supported CI Providers](#supported-ci-providers)
- [GitHub Actions Integration](#github-actions-integration)
- [Example Workflows](#example-workflows)
- [Exit Code Handling](#exit-code-handling)
- [Artifact Upload Patterns](#artifact-upload-patterns)
- [Cockpit Mode for CI Orchestrators](#cockpit-mode-for-ci-orchestrators)

---

## Supported CI Providers

env-check automatically detects the CI environment and includes metadata in the receipt. The following providers are supported:

### Detection Methods

| Provider | Detection Environment Variable | Provider ID |
|----------|-------------------------------|-------------|
| GitHub Actions | `GITHUB_ACTIONS` | `github` |
| GitLab CI | `GITLAB_CI` | `gitlab` |
| CircleCI | `CIRCLECI` | `circleci` |
| Azure Pipelines | `TF_BUILD` | `azure` |
| Generic CI | `CI` | `unknown` |

### Captured Metadata

When running in a detected CI environment, env-check captures:

| Field | Description | GitHub Actions | GitLab CI | CircleCI | Azure Pipelines |
|-------|-------------|----------------|-----------|----------|-----------------|
| `job` | Current job name | `GITHUB_JOB` | `CI_JOB_NAME` | `CIRCLE_JOB` | `SYSTEM_JOBDISPLAYNAME` |
| `run_id` | Run/build identifier | `GITHUB_RUN_ID` | `CI_JOB_ID` | `CIRCLE_BUILD_NUM` | `BUILD_BUILDID` |
| `workflow` | Pipeline/workflow name | `GITHUB_WORKFLOW` | `CI_PIPELINE_NAME` | `CIRCLE_WORKFLOW_ID` | `BUILD_DEFINITIONNAME` |
| `repository` | Repository path | `GITHUB_REPOSITORY` | `CI_PROJECT_PATH` | `CIRCLE_PROJECT_REPONAME` | `BUILD_REPOSITORY_NAME` |
| `git_ref` | Branch or ref | `GITHUB_REF` | `CI_COMMIT_REF_NAME` | `CIRCLE_BRANCH` | `BUILD_SOURCEBRANCH` |
| `sha` | Commit SHA | `GITHUB_SHA` | `CI_COMMIT_SHA` | `CIRCLE_SHA1` | `BUILD_SOURCEVERSION` |

### CI Metadata in Receipts

The captured metadata appears in the `run.ci` object of the receipt:

```json
{
  "schema": "sensor.report.v1",
  "run": {
    "ci": {
      "provider": "github",
      "job": "build",
      "run_id": "1234567890",
      "workflow": "CI",
      "repository": "owner/repo",
      "git_ref": "refs/pull/42/merge",
      "sha": "abc123def456..."
    }
  }
}
```

---

## GitHub Actions Integration

env-check provides a first-class GitHub Actions integration via [`action.yml`](../action.yml).

### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `version` | No* | *(from action ref)* | Release tag to install (e.g., `v0.1.0`) |
| `profile` | No | `oss` | Policy profile: `oss`, `team`, or `strict` |
| `root` | No | `.` | Repository root directory to scan |
| `config` | No | `""` | Optional path to `env-check.toml` configuration |
| `out` | No | `artifacts/env-check/report.json` | JSON receipt output path |
| `md` | No | `""` | Optional markdown summary output path |
| `annotations` | No | `""` | GitHub Actions annotations output path |
| `annotations_max` | No | `20` | Maximum findings to include in annotations |
| `debug` | No | `false` | Enable debug transcript logging |
| `log_file` | No | `artifacts/env-check/extras/raw.log` | Debug log file path |

*The `version` input is required when the action is not referenced by a version tag (e.g., `@main`).

### Version Resolution

The action automatically resolves the version in this order:

1. Uses the `version` input if provided
2. Uses the action ref if it matches `vX.Y.Z*` pattern (e.g., `@v0.1.0`)
3. Fails with an error if neither is available

### Platform Support

The action supports both Unix (Linux, macOS) and Windows runners:

- **Unix**: Downloads and runs `env-check-installer.sh` via `curl`
- **Windows**: Downloads and runs `env-check-installer.ps1` via PowerShell

---

## Example Workflows

### Basic GitHub Actions Workflow

```yaml
name: env-check

on:
  pull_request:
  push:

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        continue-on-error: true
        with:
          profile: oss
          root: .
          md: artifacts/env-check/comment.md

      - name: Upload env-check artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: env-check
          path: artifacts/env-check
```

### Strict Profile with Annotations

```yaml
name: env-check

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: strict
          root: .
          out: artifacts/env-check/report.json
          md: artifacts/env-check/comment.md
          annotations: artifacts/env-check/annotations.txt
          annotations_max: 50

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: env-check
          path: artifacts/env-check
```

### Team Profile with Debug Logging

```yaml
name: env-check

on: [push, pull_request]

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
          debug: true
          log_file: artifacts/env-check/extras/debug.log

      - name: Upload artifacts (including debug logs)
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: env-check
          path: artifacts/env-check
```

### Using Custom Configuration

```yaml
name: env-check

on: [push]

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
          config: ./env-check.toml
```

### GitLab CI Example

```yaml
# .gitlab-ci.yml
stages:
  - validate

env-check:
  stage: validate
  image: rust:latest
  script:
    - curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
    - env-check check --profile oss --out artifacts/env-check/report.json --md artifacts/env-check/comment.md
  artifacts:
    when: always
    paths:
      - artifacts/env-check/
```

### CircleCI Example

```yaml
# .circleci/config.yml
version: 2.1

jobs:
  env-check:
    docker:
      - image: cimg/base:stable
    steps:
      - checkout
      - run:
          name: Install env-check
          command: curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
      - run:
          name: Run env-check
          command: env-check check --profile oss --out artifacts/env-check/report.json
      - store_artifacts:
          path: artifacts/env-check

workflows:
  validate:
    jobs:
      - env-check
```

### Azure Pipelines Example

```yaml
# azure-pipelines.yml
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
  - script: |
      curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
    displayName: 'Install env-check'
  
  - script: |
      env-check check --profile oss --out $(Build.ArtifactStagingDirectory)/env-check/report.json
    displayName: 'Run env-check'
  
  - task: PublishBuildArtifacts@1
    condition: always()
    inputs:
      pathToPublish: $(Build.ArtifactStagingDirectory)/env-check
      artifactName: env-check
```

---

## Exit Code Handling

env-check uses a three-tier exit code scheme designed for CI integration:

| Exit Code | Meaning | Condition |
|-----------|---------|-----------|
| `0` | OK | Pass, warn, or skip (unless `--fail_on warn`) |
| `1` | Tool/Runtime Error | Unexpected failure during execution |
| `2` | Policy Fail | Environment does not meet requirements |

### Exit Code 0: OK

The tool completed successfully and the environment is acceptable:
- All required tools present with correct versions
- Or warnings present but `--fail_on` is not set to `warn`

### Exit Code 1: Tool/Runtime Error

Something went wrong with the tool itself:
- Unrecoverable I/O error
- Parse failure in configuration
- Probe execution failure (unexpected)
- Any condition that prevents completing the check

This indicates "env-check failed to run" not "environment failed check".

### Exit Code 2: Policy Fail

The tool completed successfully but the environment fails policy:
- Missing required tools (in `team`/`strict` profiles)
- Version mismatches (in `strict` profile)
- Hash mismatches (in `team`/`strict` profiles)
- Warnings when `--fail_on warn`

### Fail-On Levels

The `--fail_on` flag controls when exit code 2 is returned:

| Level | Behavior |
|-------|----------|
| `error` | Exit `2` if any error-level findings exist (default) |
| `warn` | Exit `2` if any warning or error findings exist |
| `never` | Always exit `0` (unless a runtime error occurs) |

### Handling in CI

Most CI systems treat non-zero exit codes as failure:

```yaml
# Fail the build on policy violations
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  with:
    profile: strict
```

Use `continue-on-error` for informational runs:

```yaml
# Run for visibility without failing the build
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  continue-on-error: true
  with:
    profile: oss
```

---

## Artifact Upload Patterns

### Canonical Artifact Paths

env-check produces consistent artifact paths by default:

```
artifacts/env-check/
├── report.json           # Always written (receipt)
├── comment.md            # Optional (--md flag)
├── annotations.txt       # Optional (--annotations flag)
└── extras/
    └── raw.log           # Debug logs (--debug flag)
```

### Receipt Contract

The receipt at `artifacts/env-check/report.json` always conforms to `sensor.report.v1`:

```json
{
  "schema": "sensor.report.v1",
  "tool": {
    "name": "env-check",
    "version": "0.1.0"
  },
  "run": {
    "timestamp": "2024-01-15T10:30:00Z",
    "ci": { "...": "..." },
    "git": { "...": "..." }
  },
  "verdict": {
    "status": "pass|warn|fail|skip",
    "counts": { "error": 0, "warn": 2, "info": 1 },
    "reasons": []
  },
  "findings": [],
  "artifacts": [],
  "data": {}
}
```

### Upload Pattern for GitHub Actions

```yaml
- name: Upload env-check artifacts
  if: always()  # Upload even on failure
  uses: actions/upload-artifact@v4
  with:
    name: env-check
    path: artifacts/env-check
    retention-days: 30
```

### Upload Pattern for GitLab CI

```yaml
artifacts:
  when: always  # Upload even on failure
  paths:
    - artifacts/env-check/
  expire_in: 1 week
```

### Upload Pattern for CircleCI

```yaml
- store_artifacts:
    path: artifacts/env-check
```

### Consuming Artifacts

Downstream jobs or systems can:

1. **Parse the receipt**: Read `report.json` for structured verdict and findings
2. **Display markdown**: Post `comment.md` to PRs or chat notifications
3. **Create annotations**: Use `annotations.txt` for inline CI annotations
4. **Debug issues**: Review `extras/raw.log` for detailed execution traces

---

## Cockpit Mode for CI Orchestrators

Cockpit mode is designed for CI orchestrators that want to parse the receipt and handle the verdict themselves.

### Enabling Cockpit Mode

```bash
env-check check --mode cockpit
```

Or in GitHub Actions:

```yaml
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  with:
    profile: oss
    # Note: cockpit mode is set via CLI args in the action
```

### Cockpit Mode Behavior

| Mode | Exit Code Behavior |
|------|-------------------|
| `default` | Exit code reflects verdict: `0` for pass/warn/skip, `1` for runtime error, `2` for policy failure |
| `cockpit` | Always exit `0` if receipt was written successfully |

In cockpit mode:
- Exit code `0`: Receipt was written successfully (check the `verdict.status` field)
- Exit code `1`: Runtime error prevented receipt generation

### Cockpit Integration Pattern

```yaml
# .cockpit/cockpit.toml
[sensors.env-check]
blocking = false   # Non-blocking by default
missing = "skip"   # Skip if sensor not found
```

#### Recommended Policy (Default)

```toml
[sensors.env-check]
blocking = false
missing = "skip"
```

#### When to Make It Blocking

```toml
[sensors.env-check]
blocking = true
missing = "warn"
```

Use blocking mode only for controlled runners or lanes where reproducibility is critical.

### Parsing the Verdict

Cockpit orchestrators should parse `verdict.status` from the receipt:

| Status | Meaning |
|--------|---------|
| `pass` | All requirements satisfied |
| `warn` | Requirements met with warnings |
| `fail` | Requirements not met |
| `skip` | No sources found or check skipped |

Example parsing logic:

```python
import json

with open('artifacts/env-check/report.json') as f:
    receipt = json.load(f)

status = receipt['verdict']['status']
counts = receipt['verdict']['counts']

if status == 'fail':
    print(f"Environment check failed: {counts['error']} errors")
    # Take blocking action
elif status == 'warn':
    print(f"Environment check passed with warnings: {counts['warn']} warnings")
    # Optionally warn or block
else:
    print("Environment check passed")
```

### Cockpit Comment Contract

When generating CI comments from env-check output, keep it concise:

```markdown
- Environment: 1 error, 2 warnings (env-check)
- Missing tool: node (>=20)
- Version mismatch: python (3.12)
- Repro: `env-check check --root . --profile oss --out artifacts/env-check/report.json --md artifacts/env-check/comment.md`
```

The full detail should live in `artifacts/env-check/comment.md`.

---

## Best Practices

### 1. Use `continue-on-error` for Non-Blocking Checks

```yaml
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  continue-on-error: true
```

This allows the workflow to continue while still collecting artifacts.

### 2. Always Upload Artifacts

```yaml
- name: Upload artifacts
  if: always()  # Critical: ensures artifacts are uploaded on failure
  uses: actions/upload-artifact@v4
```

### 3. Pin to a Specific Version

```yaml
- uses: EffortlessMetrics/env-check@v0.1.0  # Pinned
```

Avoid `@main` or `@latest` for production workflows.

### 4. Match Profile to Your Risk Tolerance

| Profile | Use Case |
|---------|----------|
| `oss` | Open-source projects, informational |
| `team` | Team projects, enforced missing tools |
| `strict` | Production systems, full enforcement |

### 5. Enable Debug Logging for Troubleshooting

```yaml
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  with:
    debug: true
```

Debug logs are written to `artifacts/env-check/extras/raw.log`.

---

## Troubleshooting

### "version input required" Error

This error occurs when using `@main` or `@latest` without specifying a version:

```yaml
# This fails:
- uses: EffortlessMetrics/env-check@main

# Fix by pinning version:
- uses: EffortlessMetrics/env-check@v0.1.0

# Or specify version input:
- uses: EffortlessMetrics/env-check@main
  with:
    version: v0.1.0
```

### Empty Receipt or Missing Artifacts

Ensure the artifact directory is created and the `if: always()` condition is set:

```yaml
- name: Upload artifacts
  if: always()  # Required for failure cases
  uses: actions/upload-artifact@v4
```

### CI Not Detected

If CI metadata is missing from the receipt, verify:
1. The `CI` environment variable is set
2. Provider-specific variables are available (e.g., `GITHUB_ACTIONS`)

### Exit Code 1 vs Exit Code 2

- **Exit 1**: env-check itself failed (bug, config error, I/O issue)
- **Exit 2**: env-check ran successfully but found policy violations

Check `artifacts/env-check/extras/raw.log` for details on exit code 1.

---

---

## Cross-Platform Considerations

### Platform-Specific Behavior

env-check behaves consistently across platforms, but there are some considerations:

| Platform | Path Separator | Shell | Notes |
|----------|---------------|-------|-------|
| Linux | `/` | bash/zsh | Full support |
| macOS | `/` | bash/zsh | Full support |
| Windows | `\` | PowerShell/cmd | Full support, use PowerShell for best results |

### Windows-Specific Notes

```yaml
# GitHub Actions - Windows
jobs:
  env-check-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: oss
```

### macOS-Specific Notes

```yaml
# GitHub Actions - macOS
jobs:
  env-check-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: oss
```

---

## Matrix Builds

### Multi-Platform Matrix

Test across multiple platforms and tool versions:

```yaml
# GitHub Actions - Multi-platform matrix
name: env-check-matrix

on: [push, pull_request]

jobs:
  env-check:
    runs-on: ${{ matrix.os }}
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, macos-latest, windows-latest]
        profile: [oss, team]
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: ${{ matrix.profile }}

      - name: Upload artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: env-check-${{ matrix.os }}-${{ matrix.profile }}
          path: artifacts/env-check
```

### Tool Version Matrix

Test with multiple versions of a tool:

```yaml
# GitHub Actions - Node.js version matrix
name: env-check-node-matrix

on: [push, pull_request]

jobs:
  env-check:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [18, 20, 22]
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
```

---

## Advanced Workflow Patterns

### PR Validation with Required Status Checks

```yaml
# GitHub Actions - PR validation with required status checks
name: pr-validation

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        id: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
          fail_on: error

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = JSON.parse(fs.readFileSync('artifacts/env-check/report.json', 'utf8'));
            const verdict = report.verdict.status;
            const counts = report.verdict.counts;
            
            await github.rest.issues.createComment({
              owner: context.repo.owner,
              repo: context.repo.repo,
              issue_number: context.issue.number,
              body: `## env-check Results\n\n**Status:** ${verdict}\n\n**Counts:**\n- Errors: ${counts.error}\n- Warnings: ${counts.warn}\n- Info: ${counts.info}\n`
            });
```

### Scheduled Runs with Slack Notification

```yaml
# GitHub Actions - Scheduled validation with Slack notification
name: scheduled-env-check

on:
  schedule:
    - cron: '0 6 * * 1'  # Every Monday at 6 AM UTC
  workflow_dispatch:

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: strict
          debug: true

      - name: Notify Slack on failure
        if: failure()
        uses: slackapi/slack-github-action@v1
        with:
          payload: |
            {
              "text": "env-check failed in scheduled run",
              "attachments": [
                {
                  "color": "danger",
                  "fields": [
                    {
                      "title": "Repository",
                      "value": "${{ github.repository }}",
                      "short": true
                    },
                    {
                      "title": "Run ID",
                      "value": "${{ github.run_id }}",
                      "short": true
                    }
                  ]
                }
              ]
            }
```

### Conditional Tool Installation

```yaml
# GitHub Actions - Install tools conditionally
name: conditional-tools

on: [push, pull_request]

jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Read required Node.js version
        id: node-version
        run: |
          if [ -f ".node-version" ]; then
            echo "version=$(cat .node-version)" >> $GITHUB_OUTPUT
          else
            echo "version=20" >> $GITHUB_OUTPUT
          fi

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: ${{ steps.node-version.outputs.version }}

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
```

---

## Integration with Version Managers

### Using with asdf

```yaml
# GitHub Actions - with asdf
jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup asdf
        uses: asdf-vm/actions/setup@v3

      - name: Install tools from .tool-versions
        run: asdf install

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
```

### Using with mise

```yaml
# GitHub Actions - with mise
jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup mise
        uses: jdx/mise-action@v2

      - name: Install tools
        run: mise install

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: team
```

### Using with volta

```yaml
# GitHub Actions - with volta
jobs:
  env-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Volta
        uses: volta-cli/action@v4

      - name: env-check
        uses: EffortlessMetrics/env-check@v0.1.0
        with:
          profile: oss
```

---

## GitLab CI Advanced Patterns

### Multi-Stage Pipeline with Environment Validation

```yaml
# .gitlab-ci.yml - Multi-stage with env-check
stages:
  - validate
  - test
  - build

.env-check:
  stage: validate
  image: rust:latest
  script:
    - curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
    - env-check check --profile team --out artifacts/env-check/report.json --md artifacts/env-check/comment.md
  artifacts:
    when: always
    paths:
      - artifacts/env-check/
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
      allow_failure: false
    - allow_failure: true

test:
  stage: test
  needs: [.env-check]
  script:
    - echo "Running tests with validated environment"
```

### GitLab Matrix

```yaml
# .gitlab-ci.yml - Matrix builds
env-check:
  parallel:
    matrix:
      - PROFILE: [oss, team, strict]
        OS: [ubuntu, macos]
  stage: validate
  tags:
    - docker
  image: rust:latest
  script:
    - curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
    - env-check check --profile $PROFILE --out artifacts/env-check/report.json
  artifacts:
    when: always
    paths:
      - artifacts/env-check/
```

---

## CircleCI Advanced Patterns

### Multi-Platform with Orbs

```yaml
# .circleci/config.yml - Multi-platform with orbs
version: 2.1

orbs:
  node: circleci/node@5

jobs:
  env-check:
    parameters:
      os:
        type: executor
      profile:
        type: string
        default: "oss"
    executor: << parameters.os >>
    steps:
      - checkout
      - run:
          name: Install env-check
          command: curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
      - run:
          name: Run env-check
          command: env-check check --profile << parameters.profile >> --out artifacts/env-check/report.json
      - store_artifacts:
          path: artifacts/env-check

workflows:
  validate:
    jobs:
      - env-check:
          matrix:
            parameters:
              os: [linux, macos]
              profile: [oss, team]
```

---

## Azure Pipelines Advanced Patterns

### Multi-Stage Pipeline

```yaml
# azure-pipelines.yml - Multi-stage pipeline
trigger:
  branches:
    include:
      - main
      - feature/*

stages:
  - stage: Validate
    jobs:
      - job: env_check
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: |
              curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
            displayName: 'Install env-check'
          
          - script: |
              env-check check --profile team --out $(Build.ArtifactStagingDirectory)/env-check/report.json
            displayName: 'Run env-check'
          
          - task: PublishBuildArtifacts@1
            condition: always()
            inputs:
              pathToPublish: $(Build.ArtifactStagingDirectory)/env-check
              artifactName: env-check

  - stage: Build
    dependsOn: Validate
    jobs:
      - job: build
        pool:
          vmImage: 'ubuntu-latest'
        steps:
          - script: echo "Building with validated environment..."
```

### Azure Matrix Strategy

```yaml
# azure-pipelines.yml - Matrix strategy
jobs:
  - job: env_check
    strategy:
      matrix:
        linux_oss:
          os: ubuntu-latest
          profile: oss
        linux_strict:
          os: ubuntu-latest
          profile: strict
        windows_oss:
          os: windows-latest
          profile: oss
        macos_oss:
          os: macos-latest
          profile: oss
    pool:
      vmImage: $(os)
    steps:
      - script: |
          curl -sL https://github.com/EffortlessMetrics/env-check/releases/latest/download/env-check-installer.sh | sh
        displayName: 'Install env-check'
      
      - script: |
          env-check check --profile $(profile) --out $(Build.ArtifactStagingDirectory)/env-check/report.json
        displayName: 'Run env-check'
```

---

## Troubleshooting CI Issues

### Common Problems

| Problem | Cause | Solution |
|---------|-------|----------|
| Tool not found | Tool not installed on runner | Add setup step or use different runner |
| Version mismatch | Runner has different version | Pin versions in CI or use version manager |
| Permission denied | Script not executable | Add `chmod +x` or use proper shell |
| Timeout | Tool probing takes too long | Use `--probe-timeout` flag |
| Artifacts missing | Output path incorrect | Verify `artifacts/env-check/` path |

### Debug Mode in CI

```yaml
# Enable debug logging for troubleshooting
- name: env-check
  uses: EffortlessMetrics/env-check@v0.1.0
  with:
    profile: team
    debug: true

- name: Upload debug logs
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: env-check-debug
    path: artifacts/env-check/extras/raw.log
```

---

## See Also

- [CLI Reference](cli-reference.md) - Full command-line documentation
- [Configuration](configuration.md) - Configuration file options
- [Cockpit Integration](cockpit.md) - Cockpit orchestrator details
- [Contracts](contracts.md) - Receipt schema and finding codes
- [ADR-008: Exit Code Semantics](adr/ADR-008-exit-codes.md) - Exit code design decisions
