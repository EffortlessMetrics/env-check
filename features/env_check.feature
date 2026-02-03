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
