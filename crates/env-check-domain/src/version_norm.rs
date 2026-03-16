//! Version normalization for common CLI output.
//!
//! This module provides lenient extraction and strict normalization of version strings
//! from typical CLI tool output (e.g., `git version 2.43.0`, `node v20.11.0`).
//!
//! # Design Principles
//!
//! - **Lenient at extraction**: Accept common CLI output formats without strict semver requirements
//! - **Strict at normalization**: Produce valid semver strings for comparison
//! - **Preserve metadata**: Keep prerelease and build metadata when present
//! - **Zero-fill unambiguous**: Convert `1` → `1.0.0`, `1.2` → `1.2.0`
//! - **No guessing**: Reject ambiguous or marketing-style version strings

use std::fmt;

use semver::{Version, VersionReq};

/// Error returned when version parsing fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionParseError {
    /// The input was empty or contained only whitespace.
    EmptyInput,
    /// No version-like pattern could be found in the input.
    NoVersionFound,
    /// The version string could not be parsed as valid semver.
    InvalidSemver(String),
}

impl fmt::Display for VersionParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VersionParseError::EmptyInput => write!(f, "empty version input"),
            VersionParseError::NoVersionFound => write!(f, "no version pattern found"),
            VersionParseError::InvalidSemver(s) => write!(f, "invalid semver: {}", s),
        }
    }
}

impl std::error::Error for VersionParseError {}

/// A normalized version ready for semver comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedVersion {
    /// The original raw input string.
    pub raw: String,
    /// The normalized semver string (e.g., "1.2.3" or "1.2.3-prerelease.1+build.5").
    pub normalized: String,
    /// The parsed semver Version for comparison.
    version: Version,
}

impl NormalizedVersion {
    /// Returns the parsed semver version for comparison.
    pub fn as_semver(&self) -> &Version {
        &self.version
    }

    /// Checks if this version satisfies the given constraint.
    pub fn satisfies(&self, constraint: &str) -> bool {
        match VersionReq::parse(constraint.trim()) {
            Ok(req) => req.matches(&self.version),
            Err(_) => {
                // Fallback: exact string match for non-semver constraints
                self.normalized.trim() == constraint.trim()
            }
        }
    }
}

impl fmt::Display for NormalizedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.normalized)
    }
}

impl PartialOrd for NormalizedVersion {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NormalizedVersion {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.version.cmp(&other.version)
    }
}

/// Normalize a version string from CLI output.
///
/// This function:
/// 1. Trims whitespace
/// 2. Strips common prefixes (e.g., "v", "version ", "go")
/// 3. Extracts the first semver-like pattern
/// 4. Zero-fills missing minor/patch components
/// 5. Preserves prerelease and build metadata
///
/// # Examples
///
/// ```
/// use env_check_domain::version_norm::{normalize_version, NormalizedVersion};
///
/// // Basic extraction
/// let v = normalize_version("git version 2.43.0").unwrap();
/// assert_eq!(v.normalized, "2.43.0");
///
/// // v-prefix handling
/// let v = normalize_version("v20.11.0").unwrap();
/// assert_eq!(v.normalized, "20.11.0");
///
/// // Zero-filling
/// let v = normalize_version("1").unwrap();
/// assert_eq!(v.normalized, "1.0.0");
///
/// let v = normalize_version("1.2").unwrap();
/// assert_eq!(v.normalized, "1.2.0");
///
/// // Prerelease preservation
/// let v = normalize_version("1.2.3-rc.1").unwrap();
/// assert_eq!(v.normalized, "1.2.3-rc.1");
///
/// // Build metadata preservation
/// let v = normalize_version("1.2.3+build.5").unwrap();
/// assert_eq!(v.normalized, "1.2.3+build.5");
/// ```
pub fn normalize_version(input: &str) -> Result<NormalizedVersion, VersionParseError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(VersionParseError::EmptyInput);
    }

    // Extract the version token from CLI output
    let extracted = extract_version_token(trimmed);
    if extracted.is_empty() {
        return Err(VersionParseError::NoVersionFound);
    }

    // Strip optional 'v' prefix (but not if followed by another letter, e.g., "version")
    let stripped = if extracted.starts_with('v') || extracted.starts_with('V') {
        let after_v = &extracted[1..];
        // Only strip if the next char is a digit (v1.2.3 → 1.2.3, but "version" stays)
        if after_v
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            after_v
        } else {
            extracted
        }
    } else {
        extracted
    };

    // Try to parse as-is first (handles full semver with prerelease/build)
    if let Ok(version) = Version::parse(stripped) {
        return Ok(NormalizedVersion {
            raw: input.to_string(),
            normalized: stripped.to_string(),
            version,
        });
    }

    // Try zero-filling for incomplete versions
    let filled = zero_fill_version(stripped);
    if let Ok(version) = Version::parse(&filled) {
        return Ok(NormalizedVersion {
            raw: input.to_string(),
            normalized: filled,
            version,
        });
    }

    // Try to extract just the numeric portion with optional prerelease/build
    let semver_pattern = extract_semver_pattern(stripped);
    if let Ok(version) = Version::parse(&semver_pattern) {
        return Ok(NormalizedVersion {
            raw: input.to_string(),
            normalized: semver_pattern.clone(),
            version,
        });
    }

    Err(VersionParseError::InvalidSemver(stripped.to_string()))
}

/// Extract a version token from common CLI output patterns.
///
/// Handles patterns like:
/// - "git version 2.43.0.windows.1" → "2.43.0"
/// - "node v20.11.0 (LTS)" → "20.11.0"
/// - "Python 3.12.0" → "3.12.0"
/// - "go1.22.1" → "1.22.1"
/// - "1.2.3" → "1.2.3"
fn extract_version_token(s: &str) -> &str {
    let s = s.trim();

    // Pattern: "version X.Y.Z" (git, svn, etc.)
    if let Some(after) = s.strip_prefix("version ") {
        return extract_numeric_start(after);
    }

    // Pattern: "Version X.Y.Z" (capitalized)
    if let Some(after) = s.strip_prefix("Version ") {
        return extract_numeric_start(after);
    }

    // Pattern: "tool X.Y.Z" (Python, Ruby, etc.)
    // Look for a word followed by space and version
    if let Some(pos) = s.find(' ') {
        let after = &s[pos + 1..];
        // Check if it starts with 'v' followed by digit or just digit
        let after = after.trim();
        if after.starts_with('v')
            || after.starts_with('V')
            || after
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            return extract_numeric_start(after);
        }
    }

    // Pattern: "go1.22.1" (Go-style, tool prefix without space)
    // Check for common tool prefixes (case-insensitive)
    let s_lower = s.to_ascii_lowercase();
    for prefix in &["go", "node", "python", "ruby", "rust", "git"] {
        if let Some(after_lower) = s_lower.strip_prefix(prefix)
            && after_lower
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        {
            // Get the corresponding slice from the original string
            let after = &s[prefix.len()..];
            return extract_numeric_start(after);
        }
    }

    // Default: extract from the start
    extract_numeric_start(s)
}

/// Extract from the start of a numeric version sequence, including prerelease/build.
fn extract_numeric_start(s: &str) -> &str {
    let s = s.trim();

    // Skip optional 'v' prefix (only if followed by a digit)
    let s = if s.starts_with('v') || s.starts_with('V') {
        let after_v = &s[1..];
        if after_v
            .chars()
            .next()
            .map(|c| c.is_ascii_digit())
            .unwrap_or(false)
        {
            after_v
        } else {
            s
        }
    } else {
        s
    };

    // Find the first digit - this is where the version starts
    let start_pos = s.find(|c: char| c.is_ascii_digit()).unwrap_or(0);
    let s = &s[start_pos..];

    if s.is_empty() {
        return "";
    }

    // Find the end of the version pattern (major.minor.patch[-prerelease][+build])
    let mut end = 0;
    let mut in_prerelease_or_build = false;
    let chars: Vec<char> = s.chars().collect();

    while end < chars.len() {
        let c = chars[end];

        if c.is_ascii_digit() || c == '.' {
            end += 1;
        } else if c == '-' || c == '+' {
            // Start of prerelease or build metadata
            in_prerelease_or_build = true;
            end += 1;
        } else if in_prerelease_or_build
            && (c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
        {
            // Allow alphanumeric and certain chars in prerelease/build
            end += 1;
        } else if c == ' ' && end > 0 {
            // Space terminates the version
            break;
        } else if c == '(' || c == '[' {
            // Parentheses typically start trailing info like "(LTS)"
            break;
        } else {
            break;
        }
    }

    if end == 0 {
        return "";
    }

    let result = &s[..end];

    // Trim trailing non-version artifacts like ".windows.1" from "2.43.0.windows.1"
    // But preserve valid prerelease/build like "-rc.1" or "+build.5"
    trim_version_artifacts(result)
}

/// Trim trailing non-standard version artifacts.
///
/// Handles cases like "2.43.0.windows.1" → "2.43.0"
/// while preserving "2.43.0-rc.1" and "2.43.0+build.5".
fn trim_version_artifacts(s: &str) -> &str {
    // If there's a '-' or '+', we have prerelease/build metadata - preserve it
    if let Some(pos) = s.find(['-', '+']) {
        // Keep the version part and the prerelease/build marker with content
        let _version_part = &s[..pos];
        let prerelease_part = &s[pos..];

        // Find where the prerelease/build identifier ends
        // Prerelease identifiers are alphanumeric + hyphen (e.g., "rc.1", "alpha-beta.2")
        let prerelease_end = prerelease_part
            .find([' ', '(', ')', '[', ']'])
            .unwrap_or(prerelease_part.len());

        // Only return if we have actual prerelease content after the marker
        let trimmed = &s[..pos + prerelease_end];
        // Ensure we don't return just "X.Y.Z-" or "X.Y.Z+" without content
        if trimmed.ends_with('-') || trimmed.ends_with('+') || trimmed.ends_with('.') {
            // Fall through to check for non-standard suffixes
        } else {
            return trimmed;
        }
    }

    // No prerelease/build - check for trailing non-standard suffixes
    // Pattern: X.Y.Z.something where "something" isn't a valid semver continuation
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() > 3 {
        // Check if the 4th part looks like a prerelease identifier or garbage
        if let Some(fourth) = parts.get(3) {
            // Common garbage patterns: "windows", "linux", etc.
            if !fourth.chars().all(|c| c.is_ascii_digit()) {
                // Non-numeric 4th component - likely not part of version
                return &s[..parts[0].len() + 1 + parts[1].len() + 1 + parts[2].len()];
            }
        }
    }

    s
}

/// Zero-fill a version string to have major.minor.patch format.
///
/// Examples:
/// - "1" → "1.0.0"
/// - "1.2" → "1.2.0"
/// - "1.2.3" → "1.2.3"
/// - "1.2.3-rc.1" → "1.2.3-rc.1"
/// - "1-rc.1" → "1.0.0-rc.1"
fn zero_fill_version(s: &str) -> String {
    let s = s.trim();

    // Split into version and prerelease/build parts
    let (version_part, prerelease_part) = if let Some(pos) = s.find(['-', '+']) {
        (&s[..pos], Some(&s[pos..]))
    } else {
        (s, None)
    };

    let parts: Vec<&str> = version_part.split('.').collect();
    let filled = match parts.len() {
        1 => format!("{}.0.0", parts[0]),
        2 => format!("{}.{}.0", parts[0], parts[1]),
        _ => version_part.to_string(),
    };

    if let Some(pre) = prerelease_part {
        format!("{}{}", filled, pre)
    } else {
        filled
    }
}

/// Extract a semver pattern from a string, handling edge cases.
///
/// This handles cases where the string has extra characters that prevent direct parsing.
fn extract_semver_pattern(s: &str) -> String {
    let s = s.trim();

    // Try to extract major.minor.patch[-prerelease][+build]
    // Pattern: digit(s) . digit(s) . digit(s) [- prerelease] [+ build]

    let mut result = String::new();
    let mut state = ParseState::Major;
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        match state {
            ParseState::Major => {
                if c.is_ascii_digit() {
                    result.push(c);
                } else if c == '.' && !result.is_empty() {
                    result.push(c);
                    state = ParseState::Minor;
                } else if !result.is_empty() {
                    break;
                }
            }
            ParseState::Minor => {
                if c.is_ascii_digit() {
                    result.push(c);
                } else if c == '.' && !result.ends_with('.') {
                    result.push(c);
                    state = ParseState::Patch;
                } else if c == '-' || c == '+' {
                    result.push(c);
                    state = ParseState::Prerelease;
                } else if !result.ends_with('.') {
                    break;
                }
            }
            ParseState::Patch => {
                if c.is_ascii_digit() {
                    result.push(c);
                } else if c == '-' || c == '+' {
                    result.push(c);
                    state = ParseState::Prerelease;
                } else {
                    break;
                }
            }
            ParseState::Prerelease => {
                if c.is_alphanumeric() || c == '.' || c == '-' || c == '_' || c == '+' {
                    result.push(c);
                } else {
                    break;
                }
            }
        }
        i += 1;
    }

    // Zero-fill if needed
    let dot_count = result.matches('.').count();
    if dot_count < 2 && !result.contains('-') && !result.contains('+') {
        // Need to zero-fill before any prerelease
        return zero_fill_version(&result);
    }

    result
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum ParseState {
    Major,
    Minor,
    Patch,
    Prerelease,
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== normalize_version tests ====================

    #[test]
    fn normalize_empty_input() {
        assert_eq!(normalize_version(""), Err(VersionParseError::EmptyInput));
        assert_eq!(normalize_version("   "), Err(VersionParseError::EmptyInput));
        assert_eq!(
            normalize_version("\t\n"),
            Err(VersionParseError::EmptyInput)
        );
    }

    #[test]
    fn normalize_no_version_found() {
        assert_eq!(
            normalize_version("no digits here"),
            Err(VersionParseError::NoVersionFound)
        );
        assert_eq!(
            normalize_version("latest"),
            Err(VersionParseError::NoVersionFound)
        );
    }

    #[test]
    fn normalize_basic_semver() {
        let v = normalize_version("1.2.3").unwrap();
        assert_eq!(v.normalized, "1.2.3");
        assert_eq!(v.raw, "1.2.3");
    }

    #[test]
    fn normalize_with_v_prefix() {
        let v = normalize_version("v1.2.3").unwrap();
        assert_eq!(v.normalized, "1.2.3");

        let v = normalize_version("V1.2.3").unwrap();
        assert_eq!(v.normalized, "1.2.3");
    }

    #[test]
    fn normalize_git_style() {
        let v = normalize_version("git version 2.43.0").unwrap();
        assert_eq!(v.normalized, "2.43.0");

        let v = normalize_version("git version 2.43.0.windows.1").unwrap();
        assert_eq!(v.normalized, "2.43.0");
    }

    #[test]
    fn normalize_node_style() {
        let v = normalize_version("node v20.11.0 (LTS)").unwrap();
        assert_eq!(v.normalized, "20.11.0");

        let v = normalize_version("v20.11.0").unwrap();
        assert_eq!(v.normalized, "20.11.0");
    }

    #[test]
    fn normalize_python_style() {
        let v = normalize_version("Python 3.12.0").unwrap();
        assert_eq!(v.normalized, "3.12.0");

        let v = normalize_version("python 3.12.0").unwrap();
        assert_eq!(v.normalized, "3.12.0");
    }

    #[test]
    fn normalize_go_style() {
        let v = normalize_version("go1.22.1").unwrap();
        assert_eq!(v.normalized, "1.22.1");
    }

    #[test]
    fn normalize_zero_fill_single() {
        let v = normalize_version("1").unwrap();
        assert_eq!(v.normalized, "1.0.0");
    }

    #[test]
    fn normalize_zero_fill_double() {
        let v = normalize_version("1.2").unwrap();
        assert_eq!(v.normalized, "1.2.0");
    }

    #[test]
    fn normalize_preserves_prerelease() {
        let v = normalize_version("1.2.3-rc.1").unwrap();
        assert_eq!(v.normalized, "1.2.3-rc.1");
        assert!(v.satisfies(">=1.2.3-rc.1"));
    }

    #[test]
    fn normalize_preserves_build_metadata() {
        let v = normalize_version("1.2.3+build.5").unwrap();
        assert_eq!(v.normalized, "1.2.3+build.5");
    }

    #[test]
    fn normalize_prerelease_with_zero_fill() {
        let v = normalize_version("1-rc.1").unwrap();
        assert_eq!(v.normalized, "1.0.0-rc.1");
    }

    #[test]
    fn normalize_full_prerelease() {
        let v = normalize_version("1.2.3-alpha.1.beta.2").unwrap();
        assert_eq!(v.normalized, "1.2.3-alpha.1.beta.2");
    }

    #[test]
    fn normalize_comparison_ordering() {
        let v1 = normalize_version("1.0.0").unwrap();
        let v2 = normalize_version("2.0.0").unwrap();
        let v3 = normalize_version("1.1.0").unwrap();
        let v4 = normalize_version("1.0.1").unwrap();

        assert!(v2 > v1);
        assert!(v3 > v1);
        assert!(v4 > v1);
        assert!(v2 > v3);
    }

    #[test]
    fn normalize_satisfies_constraint() {
        let v = normalize_version("20.11.0").unwrap();
        assert!(v.satisfies(">=20.0.0"));
        assert!(v.satisfies("^20.0.0"));
        assert!(!v.satisfies(">=21.0.0"));
    }

    // ==================== extract_version_token tests ====================

    #[test]
    fn extract_version_basic() {
        assert_eq!(extract_version_token("1.2.3"), "1.2.3");
    }

    #[test]
    fn extract_version_with_prefix() {
        assert_eq!(extract_version_token("version 2.43.0"), "2.43.0");
        assert_eq!(extract_version_token("Version 2.43.0"), "2.43.0");
    }

    #[test]
    fn extract_version_with_v_prefix() {
        assert_eq!(extract_version_token("v1.2.3"), "1.2.3");
        assert_eq!(extract_version_token("V1.2.3"), "1.2.3");
    }

    // ==================== zero_fill_version tests ====================

    #[test]
    fn zero_fill_single_digit() {
        assert_eq!(zero_fill_version("1"), "1.0.0");
    }

    #[test]
    fn zero_fill_double_digit() {
        assert_eq!(zero_fill_version("1.2"), "1.2.0");
    }

    #[test]
    fn zero_fill_full_version() {
        assert_eq!(zero_fill_version("1.2.3"), "1.2.3");
    }

    #[test]
    fn zero_fill_with_prerelease() {
        assert_eq!(zero_fill_version("1-rc.1"), "1.0.0-rc.1");
        assert_eq!(zero_fill_version("1.2-rc.1"), "1.2.0-rc.1");
    }

    // ==================== trim_version_artifacts tests ====================

    #[test]
    fn trim_artifacts_basic() {
        assert_eq!(trim_version_artifacts("2.43.0"), "2.43.0");
    }

    #[test]
    fn trim_artifacts_windows_suffix() {
        assert_eq!(trim_version_artifacts("2.43.0.windows.1"), "2.43.0");
    }

    #[test]
    fn trim_artifacts_preserves_prerelease() {
        assert_eq!(trim_version_artifacts("1.2.3-rc.1"), "1.2.3-rc.1");
    }

    #[test]
    fn trim_artifacts_preserves_build() {
        assert_eq!(trim_version_artifacts("1.2.3+build.5"), "1.2.3+build.5");
    }

    // ==================== Property tests ====================

    #[test]
    fn normalize_is_idempotent() {
        // Normalizing an already normalized version should produce the same result
        let v1 = normalize_version("1.2.3").unwrap();
        let v2 = normalize_version(&v1.normalized).unwrap();
        assert_eq!(v1.normalized, v2.normalized);
    }

    #[test]
    fn normalize_handles_whitespace() {
        let v = normalize_version("  1.2.3  ").unwrap();
        assert_eq!(v.normalized, "1.2.3");
    }

    #[test]
    fn normalize_rejects_latest() {
        // "latest" is not a version - should fail
        assert!(normalize_version("latest").is_err());
    }

    #[test]
    fn normalize_rejects_system() {
        // "system" is not a version - should fail
        assert!(normalize_version("system").is_err());
    }

    // ==================== Fixture-Based Behavioral Contract ====================
    //
    // This test suite defines the canonical version parsing behavior.
    // Each case documents expected input → output mappings.
    // Regressions are detected when these assertions fail.
    //
    // See docs/parsers.md for the version normalization reference.

    /// Test case for version parsing fixtures
    #[derive(Debug, Clone)]
    struct VersionFixture {
        /// Category name for grouping
        category: &'static str,
        /// Description of what this case tests
        description: &'static str,
        /// Raw input string
        input: &'static str,
        /// Expected result: Ok(normalized_string) or Err(expected_error)
        expected: Result<&'static str, VersionParseError>,
    }

    /// Canonical version parsing fixtures - the behavioral contract.
    ///
    /// When adding new cases:
    /// 1. Add the fixture here
    /// 2. Update docs/parsers.md to document the pattern
    /// 3. Ensure the test passes
    ///
    /// Categories:
    /// - `plain`: Plain semver versions
    /// - `prefixed`: Versions with 'v' prefix
    /// - `wrapped`: Versions embedded in CLI output
    /// - `partial`: Incomplete versions requiring zero-fill
    /// - `prerelease`: Versions with prerelease identifiers
    /// - `build`: Versions with build metadata
    /// - `failure`: Inputs that must be rejected
    const VERSION_FIXTURES: &[VersionFixture] = &[
        // ==================== Plain Semver ====================
        VersionFixture {
            category: "plain",
            description: "standard semver",
            input: "1.2.3",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "plain",
            description: "large major version",
            input: "20.11.0",
            expected: Ok("20.11.0"),
        },
        VersionFixture {
            category: "plain",
            description: "large patch version",
            input: "1.2.345",
            expected: Ok("1.2.345"),
        },
        VersionFixture {
            category: "plain",
            description: "zero versions",
            input: "0.0.0",
            expected: Ok("0.0.0"),
        },
        VersionFixture {
            category: "plain",
            description: "zero major with non-zero minor",
            input: "0.1.0",
            expected: Ok("0.1.0"),
        },
        // ==================== Prefixed Semver ====================
        VersionFixture {
            category: "prefixed",
            description: "lowercase v prefix",
            input: "v1.2.3",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "prefixed",
            description: "uppercase V prefix",
            input: "V1.2.3",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "prefixed",
            description: "v prefix with large version",
            input: "v20.11.0",
            expected: Ok("20.11.0"),
        },
        VersionFixture {
            category: "prefixed",
            description: "V prefix with large version",
            input: "V20.11.0",
            expected: Ok("20.11.0"),
        },
        // ==================== Text-Wrapped Versions ====================
        VersionFixture {
            category: "wrapped",
            description: "git version output",
            input: "git version 2.43.0",
            expected: Ok("2.43.0"),
        },
        VersionFixture {
            category: "wrapped",
            description: "git version with windows suffix",
            input: "git version 2.43.0.windows.1",
            expected: Ok("2.43.0"),
        },
        VersionFixture {
            category: "wrapped",
            description: "Python version output",
            input: "Python 3.11.8",
            expected: Ok("3.11.8"),
        },
        VersionFixture {
            category: "wrapped",
            description: "python lowercase",
            input: "python 3.12.0",
            expected: Ok("3.12.0"),
        },
        VersionFixture {
            category: "wrapped",
            description: "Terraform version output",
            input: "Terraform v1.7.5",
            expected: Ok("1.7.5"),
        },
        VersionFixture {
            category: "wrapped",
            description: "Go version output",
            input: "go1.22.1",
            expected: Ok("1.22.1"),
        },
        VersionFixture {
            category: "wrapped",
            description: "node version with LTS marker",
            input: "node v20.11.0 (LTS)",
            expected: Ok("20.11.0"),
        },
        VersionFixture {
            category: "wrapped",
            description: "version prefix with capital V",
            input: "Version 2.43.0",
            expected: Ok("2.43.0"),
        },
        VersionFixture {
            category: "wrapped",
            description: "version prefix lowercase",
            input: "version 2.43.0",
            expected: Ok("2.43.0"),
        },
        // ==================== Partial Versions (Zero-Fill) ====================
        VersionFixture {
            category: "partial",
            description: "major only",
            input: "1",
            expected: Ok("1.0.0"),
        },
        VersionFixture {
            category: "partial",
            description: "major.minor only",
            input: "1.2",
            expected: Ok("1.2.0"),
        },
        VersionFixture {
            category: "partial",
            description: "large major only",
            input: "20",
            expected: Ok("20.0.0"),
        },
        VersionFixture {
            category: "partial",
            description: "large major.minor",
            input: "20.11",
            expected: Ok("20.11.0"),
        },
        VersionFixture {
            category: "partial",
            description: "zero major",
            input: "0",
            expected: Ok("0.0.0"),
        },
        VersionFixture {
            category: "partial",
            description: "zero major with minor",
            input: "0.1",
            expected: Ok("0.1.0"),
        },
        // ==================== Prerelease Versions ====================
        VersionFixture {
            category: "prerelease",
            description: "rc prerelease",
            input: "1.2.3-rc.1",
            expected: Ok("1.2.3-rc.1"),
        },
        VersionFixture {
            category: "prerelease",
            description: "alpha prerelease",
            input: "1.2.3-alpha.1",
            expected: Ok("1.2.3-alpha.1"),
        },
        VersionFixture {
            category: "prerelease",
            description: "beta prerelease",
            input: "1.2.3-beta.2",
            expected: Ok("1.2.3-beta.2"),
        },
        VersionFixture {
            category: "prerelease",
            description: "complex prerelease",
            input: "1.2.3-alpha.1.beta.2",
            expected: Ok("1.2.3-alpha.1.beta.2"),
        },
        VersionFixture {
            category: "prerelease",
            description: "prerelease with zero-fill",
            input: "1-rc.1",
            expected: Ok("1.0.0-rc.1"),
        },
        VersionFixture {
            category: "prerelease",
            description: "major.minor prerelease with zero-fill",
            input: "1.2-rc.1",
            expected: Ok("1.2.0-rc.1"),
        },
        VersionFixture {
            category: "prerelease",
            description: "v-prefixed prerelease",
            input: "v1.2.3-rc.1",
            expected: Ok("1.2.3-rc.1"),
        },
        // ==================== Build Metadata ====================
        VersionFixture {
            category: "build",
            description: "build metadata only",
            input: "1.2.3+build.5",
            expected: Ok("1.2.3+build.5"),
        },
        VersionFixture {
            category: "build",
            description: "prerelease and build",
            input: "1.2.3-rc.1+build.5",
            expected: Ok("1.2.3-rc.1+build.5"),
        },
        VersionFixture {
            category: "build",
            description: "complex build metadata",
            input: "1.2.3+build.abc.123",
            expected: Ok("1.2.3+build.abc.123"),
        },
        // ==================== Whitespace Handling ====================
        VersionFixture {
            category: "whitespace",
            description: "leading whitespace",
            input: "  1.2.3",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "whitespace",
            description: "trailing whitespace",
            input: "1.2.3  ",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "whitespace",
            description: "surrounding whitespace",
            input: "  1.2.3  ",
            expected: Ok("1.2.3"),
        },
        VersionFixture {
            category: "whitespace",
            description: "tab and newline",
            input: "\t1.2.3\n",
            expected: Ok("1.2.3"),
        },
        // ==================== Explicit Failure Cases ====================
        VersionFixture {
            category: "failure",
            description: "empty string",
            input: "",
            expected: Err(VersionParseError::EmptyInput),
        },
        VersionFixture {
            category: "failure",
            description: "whitespace only",
            input: "   ",
            expected: Err(VersionParseError::EmptyInput),
        },
        VersionFixture {
            category: "failure",
            description: "tab and newline only",
            input: "\t\n",
            expected: Err(VersionParseError::EmptyInput),
        },
        VersionFixture {
            category: "failure",
            description: "latest keyword",
            input: "latest",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "system keyword",
            input: "system",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "default keyword",
            input: "default",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "wildcard",
            input: "*",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "text without version",
            input: "no digits here",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "LTS alias",
            input: "lts/*",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "node alias",
            input: "node",
            expected: Err(VersionParseError::NoVersionFound),
        },
        VersionFixture {
            category: "failure",
            description: "stable alias",
            input: "stable",
            expected: Err(VersionParseError::NoVersionFound),
        },
    ];

    /// Run all version fixtures as a single comprehensive test.
    /// This makes regressions immediately visible with clear failure messages.
    #[test]
    fn version_parsing_behavioral_contract() {
        let mut failures = Vec::new();

        for fixture in VERSION_FIXTURES {
            let result = normalize_version(fixture.input);

            let passed = match (&fixture.expected, &result) {
                (Ok(expected), Ok(actual)) => actual.normalized == *expected,
                (Err(expected_err), Err(actual_err)) => {
                    // Compare error types (not exact messages for InvalidSemver)
                    matches!(
                        (expected_err, actual_err),
                        (VersionParseError::EmptyInput, VersionParseError::EmptyInput)
                            | (
                                VersionParseError::NoVersionFound,
                                VersionParseError::NoVersionFound
                            )
                            | (
                                VersionParseError::InvalidSemver(_),
                                VersionParseError::InvalidSemver(_)
                            )
                    )
                }
                _ => false,
            };

            if !passed {
                let expected_str = match &fixture.expected {
                    Ok(s) => format!("Ok(\"{}\")", s),
                    Err(e) => format!("Err({:?})", e),
                };
                let actual_str = match &result {
                    Ok(v) => format!("Ok(\"{}\")", v.normalized),
                    Err(e) => format!("Err({:?})", e),
                };
                failures.push(format!(
                    "[{}/{}] input: {:?}\n  expected: {}\n  actual:   {}",
                    fixture.category, fixture.description, fixture.input, expected_str, actual_str
                ));
            }
        }

        if !failures.is_empty() {
            panic!(
                "Version parsing behavioral contract violations:\n\n{}\n\n{} fixtures failed out of {}",
                failures.join("\n\n"),
                failures.len(),
                VERSION_FIXTURES.len()
            );
        }
    }

    /// Generate a summary of all fixtures by category for documentation.
    /// Run with `cargo test -- --nocapture` to see output.
    #[test]
    fn print_fixture_summary() {
        let mut categories: std::collections::HashMap<&str, Vec<&VersionFixture>> =
            std::collections::HashMap::new();

        for fixture in VERSION_FIXTURES {
            categories
                .entry(fixture.category)
                .or_default()
                .push(fixture);
        }

        println!("\n=== Version Parsing Fixture Summary ===\n");
        println!("Total fixtures: {}\n", VERSION_FIXTURES.len());

        let mut cat_names: Vec<&str> = categories.keys().copied().collect();
        cat_names.sort();

        for cat in cat_names {
            let fixtures = &categories[cat];
            println!("## {} ({} cases)", cat, fixtures.len());
            for f in fixtures {
                let expected_str = match &f.expected {
                    Ok(s) => format!("→ {}", s),
                    Err(e) => format!("→ ERR: {:?}", e),
                };
                println!("  - {:30} {:?} {}", f.description, f.input, expected_str);
            }
            println!();
        }
    }

    /// Test that each fixture category has at least one case.
    /// Ensures the fixture matrix stays comprehensive.
    #[test]
    fn fixture_categories_are_populated() {
        let required_categories = [
            "plain",
            "prefixed",
            "wrapped",
            "partial",
            "prerelease",
            "build",
            "whitespace",
            "failure",
        ];

        let mut found_categories: std::collections::HashSet<&str> =
            std::collections::HashSet::new();

        for fixture in VERSION_FIXTURES {
            found_categories.insert(fixture.category);
        }

        for required in &required_categories {
            assert!(
                found_categories.contains(required),
                "Missing required fixture category: {}",
                required
            );
        }
    }

    /// Verify that all documented success cases in docs/parsers.md are covered.
    #[test]
    fn documented_patterns_have_fixtures() {
        // These patterns must have corresponding fixtures
        let documented_patterns = [
            ("1.2.3", "plain semver"),
            ("v1.2.3", "v-prefix"),
            ("git version 2.43.0", "git output"),
            ("Python 3.11.8", "python output"),
            ("Terraform v1.7.5", "terraform output"),
            ("go1.22.1", "go output"),
            ("1.2", "partial version"),
            ("1", "single component"),
            ("1.2.3-rc.1", "prerelease"),
            ("1.2.3+build.5", "build metadata"),
        ];

        let fixture_inputs: std::collections::HashSet<&str> =
            VERSION_FIXTURES.iter().map(|f| f.input).collect();

        for (pattern, description) in &documented_patterns {
            assert!(
                fixture_inputs.contains(pattern),
                "Documented pattern missing from fixtures: {} ({})",
                pattern,
                description
            );
        }
    }

    /// Verify that all documented failure cases are covered.
    #[test]
    fn documented_failures_have_fixtures() {
        let documented_failures = [
            ("", "empty string"),
            ("latest", "marketing label"),
            ("system", "presence-only constraint"),
            ("*", "wildcard"),
            ("default", "presence-only constraint"),
        ];

        let failure_fixtures: Vec<&VersionFixture> = VERSION_FIXTURES
            .iter()
            .filter(|f| f.category == "failure")
            .collect();

        let failure_inputs: std::collections::HashSet<&str> =
            failure_fixtures.iter().map(|f| f.input).collect();

        for (pattern, description) in &documented_failures {
            assert!(
                failure_inputs.contains(pattern),
                "Documented failure case missing from fixtures: {} ({})",
                pattern,
                description
            );
        }
    }
}
