use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};
use env_check_app::{CheckOptions, run_check_with_options, write_atomic};
use env_check_types::{
    ArtifactRef, FailOn, Profile, ReceiptEnvelope, explain_entries, explain_message,
};

#[derive(Parser, Debug)]
#[command(
    name = "env-check",
    version,
    about = "Machine-truth preflight for repo tool requirements"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover sources, probe tools, evaluate policy, write a receipt (and optional markdown).
    ///
    /// Reads .tool-versions, .mise.toml, rust-toolchain.toml and other source files
    /// to determine required tools, then probes the local machine to verify they are installed.
    #[command(
        after_help = "EXAMPLES:\n    env-check check\n    env-check check --profile team --root ./my-repo\n    env-check check --profile strict --md comment.md\n    env-check check --annotations artifacts/env-check/extras/annotations.txt"
    )]
    Check {
        /// Repo root
        #[arg(long, default_value = ".")]
        root: PathBuf,

        /// Optional env-check.toml path
        #[arg(long)]
        config: Option<PathBuf>,

        /// Profile: oss|team|strict
        #[arg(long, default_value = "oss")]
        profile: ProfileArg,

        /// fail_on: error|warn|never
        #[arg(long, default_value = "error")]
        fail_on: FailOnArg,

        /// Receipt output path
        #[arg(long, default_value = "artifacts/env-check/report.json")]
        out: PathBuf,

        /// Optional markdown output path
        #[arg(long)]
        md: Option<PathBuf>,

        /// Enable debug logging (writes to artifacts/env-check/extras/raw.log by default).
        /// This is a side artifact that does NOT affect receipt determinism.
        #[arg(long)]
        debug: bool,

        /// Custom debug log file path (implies --debug).
        /// Can also be set via ENV_CHECK_DEBUG_LOG environment variable.
        #[arg(long, env = "ENV_CHECK_DEBUG_LOG")]
        log_file: Option<PathBuf>,

        /// Timeout in seconds for individual tool probing operations.
        /// Defaults to 30 seconds if not specified.
        #[arg(long, default_value_t = 30)]
        probe_timeout: u64,

        /// Optional GitHub annotations output path.
        /// Writes workflow command annotations for top findings.
        #[arg(long)]
        annotations: Option<PathBuf>,

        /// Max findings to emit to GitHub annotations output.
        #[arg(long, default_value_t = 20)]
        annotations_max: usize,

        /// Output mode: default (exit 2 on fail) or cockpit (exit 0 if receipt written).
        ///
        /// In cockpit mode, the exit code is 0 as long as the receipt was successfully written,
        /// regardless of the verdict. This is useful for CI integrations where the cockpit
        /// orchestrator reads the receipt and handles the verdict separately.
        #[arg(long, default_value = "default", value_parser = parse_mode)]
        mode: OutputMode,
    },

    /// Render markdown from an existing report.json.
    ///
    /// Examples:
    ///   env-check md artifacts/env-check/report.json
    ///   env-check md --report artifacts/env-check/report.json --out comment.md
    #[command(
        after_help = "EXAMPLES:\n    env-check md path/to/report.json\n    env-check md --report path/to/report.json --out comment.md"
    )]
    Md {
        /// Path to the report.json file (positional or via --report)
        #[arg(value_name = "REPORT")]
        report_positional: Option<PathBuf>,

        /// Path to the report.json file (alternative to positional argument)
        #[arg(long = "report", value_name = "FILE")]
        report_flag: Option<PathBuf>,

        /// Output markdown file path
        #[arg(long, default_value = "artifacts/env-check/comment.md")]
        out: PathBuf,
    },

    /// Explain a stable finding code or check_id (e.g., env.missing_tool, env.version).
    ///
    /// Finding codes are stable identifiers that can be used in CI integrations
    /// to filter or handle specific types of findings.
    #[command(
        after_help = "EXAMPLES:\n    env-check explain env.missing_tool\n    env-check explain env.version\n    env-check explain --list"
    )]
    Explain {
        /// List all known explainable codes and check IDs.
        #[arg(long, conflicts_with = "code")]
        list: bool,

        /// The finding code or check_id to explain
        #[arg(value_name = "CODE", required_unless_present = "list")]
        code: Option<String>,
    },

    /// Generate shell completion scripts for env-check.
    ///
    /// Supports bash, zsh, fish, and PowerShell. The completion script is
    /// printed to stdout and can be redirected to the appropriate location
    /// for your shell.
    #[command(
        after_help = "EXAMPLES:\n    env-check completions bash > /usr/share/bash-completion/completions/env-check\n    env-check completions zsh > ~/.zfunc/_env-check\n    env-check completions fish > ~/.config/fish/completions/env-check.fish\n    env-check completions powershell > env-check.ps1"
    )]
    Completions {
        /// The shell to generate completions for (bash, zsh, fish, powershell)
        #[arg(value_name = "SHELL")]
        shell: String,
    },
}

#[derive(Clone, Debug)]
enum ProfileArg {
    Oss,
    Team,
    Strict,
}

impl std::str::FromStr for ProfileArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "oss" => Ok(ProfileArg::Oss),
            "team" => Ok(ProfileArg::Team),
            "strict" => Ok(ProfileArg::Strict),
            other => Err(format!("invalid profile: {}", other)),
        }
    }
}

impl From<ProfileArg> for Profile {
    fn from(p: ProfileArg) -> Self {
        match p {
            ProfileArg::Oss => Profile::Oss,
            ProfileArg::Team => Profile::Team,
            ProfileArg::Strict => Profile::Strict,
        }
    }
}

#[derive(Clone, Debug)]
enum FailOnArg {
    Error,
    Warn,
    Never,
}

impl std::str::FromStr for FailOnArg {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(FailOnArg::Error),
            "warn" => Ok(FailOnArg::Warn),
            "never" => Ok(FailOnArg::Never),
            other => Err(format!("invalid fail_on: {}", other)),
        }
    }
}

impl From<FailOnArg> for FailOn {
    fn from(f: FailOnArg) -> Self {
        match f {
            FailOnArg::Error => FailOn::Error,
            FailOnArg::Warn => FailOn::Warn,
            FailOnArg::Never => FailOn::Never,
        }
    }
}

/// Output mode for CI integrations.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum OutputMode {
    /// Default mode: exit code reflects verdict (0 for pass/warn, 2 for fail).
    #[default]
    Default,
    /// Cockpit mode: exit 0 if receipt was written successfully, regardless of verdict.
    /// The cockpit orchestrator reads the receipt and handles the verdict separately.
    Cockpit,
}

fn parse_mode(s: &str) -> Result<OutputMode, String> {
    match s {
        "default" => Ok(OutputMode::Default),
        "cockpit" => Ok(OutputMode::Cockpit),
        other => Err(format!(
            "invalid mode '{}': expected 'default' or 'cockpit'",
            other
        )),
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Command::Check {
            root,
            config,
            profile,
            fail_on,
            out,
            md,
            debug,
            log_file,
            annotations,
            annotations_max,
            mode,
        } => {
            // Determine debug log path:
            // 1. Explicit --log-file takes precedence
            // 2. --debug flag uses default path
            // 3. Otherwise, no debug logging
            let debug_log_path = if let Some(path) = log_file {
                Some(path)
            } else if debug {
                let receipt_parent = out.parent().unwrap_or(Path::new("."));
                Some(receipt_parent.join("extras").join("raw.log"))
            } else {
                None
            };

            let options = CheckOptions {
                debug_log_path: debug_log_path.clone(),
                probe_timeout_secs: probe_timeout,
            };

            match run_check_with_options(
                &root,
                config.as_deref(),
                profile.into(),
                fail_on.into(),
                options,
            )
            .with_context(|| "run env-check")
            {
                Ok(mut output) => {
                    // If a debug log was written, add an artifact pointer to the receipt.
                    if let Some(ref log_path) = debug_log_path {
                        maybe_add_artifact(
                            &mut output.receipt,
                            &out,
                            log_path,
                            "debug_log",
                            "Probe debug transcript",
                        );
                    }

                    // Optional GitHub annotations side artifact.
                    if let Some(ref annotations_path) = annotations {
                        let annotations_text = env_check_render::render_github_annotations(
                            &output.receipt,
                            annotations_max,
                        );
                        write_atomic(annotations_path, annotations_text.as_bytes())?;
                        maybe_add_artifact(
                            &mut output.receipt,
                            &out,
                            annotations_path,
                            "github_annotations",
                            "GitHub workflow command annotations",
                        );
                    }

                    let json = serde_json::to_vec_pretty(&output.receipt)?;
                    write_atomic(&out, &json)?;

                    if let Some(md_path) = md {
                        write_atomic(&md_path, output.markdown.as_bytes())?;
                    }

                    // Print a one-line summary (useful for local runs).
                    eprintln!("env-check: {:?}", output.receipt.verdict.status);

                    // In cockpit mode, exit 0 if receipt was written successfully.
                    // The orchestrator reads the receipt and handles the verdict.
                    let exit_code = match mode {
                        OutputMode::Cockpit => 0,
                        OutputMode::Default => output.exit_code,
                    };
                    std::process::exit(exit_code);
                }
                Err(err) => {
                    let mut receipt = env_check_app::runtime_error_receipt(&err.to_string());

                    if let Some(ref annotations_path) = annotations {
                        let annotations_text =
                            env_check_render::render_github_annotations(&receipt, annotations_max);
                        write_atomic(annotations_path, annotations_text.as_bytes())?;
                        maybe_add_artifact(
                            &mut receipt,
                            &out,
                            annotations_path,
                            "github_annotations",
                            "GitHub workflow command annotations",
                        );
                    }

                    let json = serde_json::to_vec_pretty(&receipt)?;
                    write_atomic(&out, &json)?;

                    if let Some(md_path) = md {
                        let markdown = env_check_render::render_markdown(&receipt);
                        write_atomic(&md_path, markdown.as_bytes())?;
                    }

                    eprintln!("env-check: {}", err);
                    // In cockpit mode, exit 0 even for runtime errors if receipt was written.
                    // The receipt contains the error finding.
                    let exit_code = match mode {
                        OutputMode::Cockpit => 0,
                        OutputMode::Default => 1,
                    };
                    std::process::exit(exit_code);
                }
            }
        }
        Command::Md {
            report_positional,
            report_flag,
            out,
        } => {
            // Positional argument takes precedence over --report flag
            let report = report_positional
                .or(report_flag)
                .ok_or_else(|| anyhow::anyhow!("missing required argument: REPORT or --report"))?;

            let bytes = fs::read(&report).with_context(|| format!("read {}", report.display()))?;
            let receipt: ReceiptEnvelope =
                serde_json::from_slice(&bytes).with_context(|| "parse report.json")?;
            let md = env_check_render::render_markdown(&receipt);
            write_atomic(&out, md.as_bytes())?;
        }
        Command::Explain { list, code } => {
            if list {
                print_explain_registry();
            } else if let Some(code) = code {
                println!("{}", explain(&code));
            }
        }
        Command::Completions { shell } => {
            let shell_type = match shell.to_lowercase().as_str() {
                "bash" => Shell::Bash,
                "zsh" => Shell::Zsh,
                "fish" => Shell::Fish,
                "powershell" => Shell::PowerShell,
                _ => {
                    eprintln!(
                        "error: invalid shell '{}'. Supported shells: bash, zsh, fish, powershell",
                        shell
                    );
                    std::process::exit(1);
                }
            };
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(shell_type, &mut cmd, name, &mut io::stdout());
        }
    }

    Ok(())
}

fn explain(code: &str) -> &'static str {
    explain_message(code)
}

fn print_explain_registry() {
    for entry in explain_entries() {
        println!("{}: {}", entry.id, entry.message);
    }
}

fn maybe_add_artifact(
    receipt: &mut ReceiptEnvelope,
    receipt_path: &Path,
    artifact_path: &Path,
    kind: &str,
    description: &str,
) {
    if !artifact_path.exists() {
        return;
    }
    if let Some(receipt_parent) = receipt_path.parent() {
        if let Ok(rel) = artifact_path.strip_prefix(receipt_parent) {
            let artifact = ArtifactRef {
                path: rel.to_string_lossy().replace('\\', "/"),
                kind: kind.to_string(),
                description: Some(description.to_string()),
            };
            if artifact.is_safe() {
                receipt.artifacts.push(artifact);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_mode_accepts_valid_values() {
        assert_eq!(parse_mode("default").unwrap(), OutputMode::Default);
        assert_eq!(parse_mode("cockpit").unwrap(), OutputMode::Cockpit);
    }

    #[test]
    fn parse_mode_rejects_invalid_value() {
        let err = parse_mode("nope").unwrap_err();
        assert!(err.contains("invalid mode"));
    }

    #[test]
    fn profile_arg_parses_valid_values() {
        assert!(matches!("oss".parse::<ProfileArg>(), Ok(ProfileArg::Oss)));
        assert!(matches!("team".parse::<ProfileArg>(), Ok(ProfileArg::Team)));
        assert!(matches!(
            "strict".parse::<ProfileArg>(),
            Ok(ProfileArg::Strict)
        ));
    }

    #[test]
    fn profile_arg_rejects_invalid_value() {
        let err = "invalid".parse::<ProfileArg>().unwrap_err();
        assert!(err.contains("invalid profile"));
    }

    #[test]
    fn fail_on_arg_parses_valid_values() {
        assert!(matches!("error".parse::<FailOnArg>(), Ok(FailOnArg::Error)));
        assert!(matches!("warn".parse::<FailOnArg>(), Ok(FailOnArg::Warn)));
        assert!(matches!("never".parse::<FailOnArg>(), Ok(FailOnArg::Never)));
    }

    #[test]
    fn fail_on_arg_rejects_invalid_value() {
        let err = "invalid".parse::<FailOnArg>().unwrap_err();
        assert!(err.contains("invalid fail_on"));
    }

    #[test]
    fn explain_returns_known_and_unknown_messages() {
        assert!(explain("env.missing_tool").contains("PATH"));
        assert!(explain("env.presence").contains("PATH"));
        assert!(explain("tool.runtime_error").contains("execute"));
        assert!(explain("tool.runtime").contains("execute"));
        assert!(explain("unknown.code").contains("Unknown code"));
    }

    #[test]
    fn explain_covers_all_known_codes_and_checks() {
        for code in env_check_types::KNOWN_CODES {
            let msg = explain(code);
            assert_ne!(msg, env_check_types::UNKNOWN_EXPLAIN_MESSAGE);
        }
        for check in env_check_types::KNOWN_CHECK_IDS {
            let msg = explain(check);
            assert_ne!(msg, env_check_types::UNKNOWN_EXPLAIN_MESSAGE);
        }
    }

    #[test]
    fn print_explain_registry_includes_codes_and_checks() {
        let entries = explain_entries();
        assert!(entries.iter().any(|e| e.id == "env.missing_tool"));
        assert!(entries.iter().any(|e| e.id == "env.presence"));
        assert!(entries.iter().any(|e| e.id == "tool.runtime_error"));
        assert!(entries.iter().any(|e| e.id == "tool.runtime"));
    }
}
