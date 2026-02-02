Feature: Environment sanity

  Scenario: No sources yields skip
    Given a repo fixture no_sources
    When I run env-check with profile oss
    Then the exit code is 0

  Scenario: Missing required tool fails under team
    Given a repo fixture missing_tool
    When I run env-check with profile team
    Then the exit code is 2
