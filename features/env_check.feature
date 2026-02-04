Feature: Environment sanity

  # ===========================================================================
  # Profile scenarios
  # ===========================================================================

  Scenario: No sources yields skip
    Given a repo fixture "no_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0

  Scenario: Missing required tool fails under team
    Given a repo fixture "missing_tool"
    When I run env-check with profile "team"
    Then the exit code is 2

  Scenario: Missing required tool warns under oss
    Given a repo fixture "missing_tool"
    When I run env-check with profile "oss"
    Then the exit code is 0

  Scenario: Missing required tool fails under strict
    Given a repo fixture "missing_tool"
    When I run env-check with profile "strict"
    Then the exit code is 2

  Scenario: Valid tool-versions with present tools passes
    Given a repo fixture "valid_tools"
    When I run env-check with profile "team"
    Then the exit code is 0

  Scenario: Malformed tool-versions produces warning
    Given a repo fixture "malformed_tool_versions"
    When I run env-check with profile "oss"
    Then the exit code is 0

  Scenario: Version mismatch fails under strict profile
    Given a repo fixture "version_mismatch"
    When I run env-check with profile "strict"
    Then the exit code is 2

  Scenario: Version mismatch warns under oss profile
    Given a repo fixture "version_mismatch"
    When I run env-check with profile "oss"
    Then the exit code is 0

  # ===========================================================================
  # Source scenarios
  # ===========================================================================

  Scenario: Multiple source files are all discovered
    Given a repo fixture "multiple_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains sources ".tool-versions" and ".mise.toml"

  Scenario: Hash manifest file is discovered and validated
    Given a repo fixture "hash_manifest"
    When I run env-check with profile "team"
    Then the exit code is 0
    And the report contains source "scripts/tools.sha256"

  Scenario: Hash manifest with mismatch fails under team
    Given a repo fixture "hash_manifest_mismatch"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report contains finding code "env.hash_mismatch"

  # ===========================================================================
  # Verdict scenarios
  # ===========================================================================

  Scenario: All tools present and matching yields pass
    Given a repo fixture "all_tools_pass"
    When I run env-check with profile "team"
    Then the exit code is 0
    And the verdict status is "pass"

  Scenario: fail_on=warn escalates warnings to failure
    Given a repo fixture "missing_tool"
    When I run env-check with profile "oss" and fail_on "warn"
    Then the exit code is 2
    And the verdict status is "fail"

  Scenario: fail_on=never downgrades errors to warn status
    Given a repo fixture "missing_tool"
    When I run env-check with profile "team" and fail_on "never"
    Then the exit code is 0
    And the verdict status is "warn"

  # ===========================================================================
  # Output scenarios
  # ===========================================================================

  Scenario: Report JSON matches schema
    Given a repo fixture "valid_tools"
    When I run env-check with profile "team"
    Then the exit code is 0
    And the report JSON is valid against the envelope schema

  Scenario: Markdown output includes findings summary
    Given a repo fixture "missing_tool"
    When I run env-check with profile "oss" and markdown output
    Then the exit code is 0
    And the markdown contains "env-check:"
    And the markdown contains "Findings:"

  # ===========================================================================
  # Node.js source discovery scenarios
  # ===========================================================================

  Scenario: .node-version file is discovered
    Given a repo fixture "node_version_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source ".node-version"

  Scenario: .nvmrc file is discovered
    Given a repo fixture "nvmrc_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source ".nvmrc"

  Scenario: package.json engines and packageManager are discovered
    Given a repo fixture "package_json_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source "package.json"

  Scenario: Multiple Node.js sources are all discovered
    Given a repo fixture "multiple_node_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source ".node-version"
    And the report contains source ".nvmrc"
    And the report contains source "package.json"

  # ===========================================================================
  # Python source discovery scenarios
  # ===========================================================================

  Scenario: .python-version file is discovered
    Given a repo fixture "python_version_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source ".python-version"

  Scenario: pyproject.toml requires-python is discovered
    Given a repo fixture "pyproject_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source "pyproject.toml"

  # ===========================================================================
  # Go source discovery scenarios
  # ===========================================================================

  Scenario: go.mod file is discovered
    Given a repo fixture "go_mod_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source "go.mod"

  # ===========================================================================
  # Rust toolchain scenarios
  # ===========================================================================

  Scenario: rust-toolchain.toml file is discovered
    Given a repo fixture "rust_toolchain_source"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source "rust-toolchain.toml"

  # ===========================================================================
  # Polyglot project scenarios
  # ===========================================================================

  Scenario: Polyglot project discovers all source types
    Given a repo fixture "polyglot_project"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains source ".tool-versions"
    And the report contains source ".node-version"
    And the report contains source ".python-version"
    And the report contains source "go.mod"

  # ===========================================================================
  # Parse error scenarios
  # ===========================================================================

  Scenario: Malformed package.json produces parse error finding
    Given a repo fixture "malformed_package_json"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.source_parse_error"

  Scenario: Malformed go.mod produces parse error finding
    Given a repo fixture "malformed_go_mod"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.source_parse_error"

  Scenario: Malformed pyproject.toml produces parse error finding
    Given a repo fixture "malformed_pyproject"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.source_parse_error"

  Scenario: Parse error in .tool-versions produces finding
    Given a repo fixture "parse_error_finding"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.source_parse_error"

  # ===========================================================================
  # Finding code scenarios
  # ===========================================================================

  Scenario: Missing tool produces env.missing_tool finding
    Given a repo fixture "missing_tool_finding"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report contains finding code "env.missing_tool"

  # ===========================================================================
  # Debug output scenarios
  # ===========================================================================

  Scenario: Debug flag produces debug log file
    Given a repo fixture "debug_logging"
    When I run env-check with profile "oss" and debug enabled
    Then the exit code is 0
    And a debug log file exists

  # ===========================================================================
  # Explain command scenarios
  # ===========================================================================

  Scenario: Explain command shows help for env.missing_tool
    When I run env-check explain "env.missing_tool"
    Then the exit code is 0
    And the stdout contains "not on PATH"

  Scenario: Explain command shows help for env.source_parse_error
    When I run env-check explain "env.source_parse_error"
    Then the exit code is 0
    And the stdout contains "could not be parsed"

  # ===========================================================================
  # Verdict count scenarios
  # ===========================================================================

  Scenario: Skip verdict has zero findings
    Given a repo fixture "no_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the verdict status is "skip"
    And the finding count is 0

  Scenario: Warn verdict counts warnings correctly
    Given a repo fixture "missing_tool"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the verdict status is "warn"
    And the warning count is greater than 0

  # ===========================================================================
  # Extended explain command scenarios
  # ===========================================================================

  Scenario: Explain command shows help for env.version_mismatch
    When I run env-check explain "env.version_mismatch"
    Then the exit code is 0
    And the stdout contains "version"

  Scenario: Explain command shows help for env.hash_mismatch
    When I run env-check explain "env.hash_mismatch"
    Then the exit code is 0
    And the stdout contains "hash"

  Scenario: Explain command shows help for env.toolchain_missing
    When I run env-check explain "env.toolchain_missing"
    Then the exit code is 0
    And the stdout contains "toolchain"

  Scenario: Explain command shows help for tool.runtime_error
    When I run env-check explain "tool.runtime_error"
    Then the exit code is 0
    And the stdout contains "probe"

  Scenario: Explain command handles unknown code gracefully
    When I run env-check explain "unknown.code"
    Then the exit code is 0
    And the stdout contains "Unknown code"

  # ===========================================================================
  # Verdict reasons scenarios
  # ===========================================================================

  Scenario: Verdict reasons include missing_tool
    Given a repo fixture "missing_tool"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the verdict reasons contain "missing_tool"

  Scenario: Verdict reasons include source_parse_error
    Given a repo fixture "malformed_tool_versions"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the verdict reasons contain "source_parse_error"

  # ===========================================================================
  # Multiple findings scenarios
  # ===========================================================================

  Scenario: Multiple missing tools produce multiple findings
    Given a repo fixture "multiple_missing_tools"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the error count is 3
    And the finding count is 3

  Scenario: Multiple missing tools produce multiple warnings in oss
    Given a repo fixture "multiple_missing_tools"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the verdict status is "warn"
    And the warning count is 3

  # ===========================================================================
  # Error count scenarios
  # ===========================================================================

  Scenario: Error count is tracked correctly
    Given a repo fixture "missing_tool"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the error count is greater than 0

  Scenario: Pass verdict has zero errors and warnings
    Given a repo fixture "valid_tools"
    When I run env-check with profile "team"
    Then the exit code is 0
    And the verdict status is "pass"
    And the error count is 0
    And the warning count is 0

  # ===========================================================================
  # Info count scenarios
  # ===========================================================================

  Scenario: Info count is tracked in verdict
    Given a repo fixture "all_tools_pass"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the info count is 0

  # ===========================================================================
  # Semver constraint scenarios
  # ===========================================================================

  Scenario: Semver range constraint is parsed
    Given a repo fixture "version_constraint_semver"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.missing_tool"

  # ===========================================================================
  # Malformed source scenarios (extended)
  # ===========================================================================

  Scenario: Multiple malformed sources all produce findings
    Given a repo fixture "malformed_tool_versions"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report contains finding code "env.source_parse_error"

  # ===========================================================================
  # Pass edge cases
  # ===========================================================================

  Scenario: Empty tool-versions file is valid
    Given a repo fixture "valid_tools"
    When I run env-check with profile "strict"
    Then the exit code is 0
    And the verdict status is "pass"

  # ===========================================================================
  # Fail on modes
  # ===========================================================================

  Scenario: fail_on=warn with no warnings passes
    Given a repo fixture "valid_tools"
    When I run env-check with profile "team" and fail_on "warn"
    Then the exit code is 0
    And the verdict status is "pass"

  Scenario: fail_on=error with warnings is warn status
    Given a repo fixture "missing_tool"
    When I run env-check with profile "oss" and fail_on "error"
    Then the exit code is 0
    And the verdict status is "warn"

  # ===========================================================================
  # Determinism scenarios
  # ===========================================================================

  Scenario: Multiple runs produce identical results
    Given a repo fixture "missing_tool"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report JSON is valid against the envelope schema

  # ===========================================================================
  # Rust toolchain scenarios
  # ===========================================================================

  Scenario: Rust toolchain produces env.toolchain_missing finding
    Given a repo fixture "rust_toolchain_source"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report contains finding code "env.toolchain_missing"

  # ===========================================================================
  # Presence-only constraint scenarios
  # ===========================================================================

  Scenario: Latest constraint still requires tool presence
    Given a repo fixture "presence_constraint"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report contains finding code "env.missing_tool"

  # ===========================================================================
  # Scale scenarios
  # ===========================================================================

  Scenario: Many tools produce correct finding count
    Given a repo fixture "many_tools_truncation"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the finding count is 10
    And the warning count is 10

  Scenario: Many tools produce correct error count under team
    Given a repo fixture "many_tools_truncation"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the finding count is 10
    And the error count is 10

  # ===========================================================================
  # Report data structure scenarios
  # ===========================================================================

  Scenario: Report includes sources_used in data
    Given a repo fixture "multiple_sources"
    When I run env-check with profile "oss"
    Then the exit code is 0
    And the report data contains sources_used

  Scenario: Report schema is always valid
    Given a repo fixture "multiple_missing_tools"
    When I run env-check with profile "team"
    Then the exit code is 2
    And the report JSON is valid against the envelope schema