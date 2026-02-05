use std::fs;
use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use env_check_app::{run_check_with_options, write_atomic, CheckOptions};
use env_check_types::{FailOn, Profile, ReceiptEnvelope};

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
        after_help = "EXAMPLES:\n    env-check check\n    env-check check --profile team --root ./my-repo\n    env-check check --profile strict --md comment.md"
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

        /// Enable debug logging (writes to artifacts/env-check/raw.log by default).
        /// This is a side artifact that does NOT affect receipt determinism.
        #[arg(long)]
        debug: bool,

        /// Custom debug log file path (implies --debug).
        /// Can also be set via ENV_CHECK_DEBUG_LOG environment variable.
        #[arg(long, env = "ENV_CHECK_DEBUG_LOG")]
        log_file: Option<PathBuf>,
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

    /// Explain a stable finding code (e.g., env.missing_tool).
    ///
    /// Finding codes are stable identifiers that can be used in CI integrations
    /// to filter or handle specific types of findings.
    #[command(
        after_help = "EXAMPLES:\n    env-check explain env.missing_tool\n    env-check explain env.version_mismatch\n\nAVAILABLE CODES:\n    env.missing_tool      - Tool not found on PATH\n    env.version_mismatch  - Version constraint not satisfied\n    env.hash_mismatch     - Binary hash doesn't match manifest\n    env.toolchain_missing - Rust toolchain not installed\n    env.source_parse_error - Source file parse error\n    tool.runtime_error    - Probe command execution failed"
    )]
    Explain {
        /// The finding code to explain
        #[arg(value_name = "CODE")]
        code: String,
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
        } => {
            // Determine debug log path:
            // 1. Explicit --log-file takes precedence
            // 2. --debug flag uses default path
            // 3. Otherwise, no debug logging
            let debug_log_path = if let Some(path) = log_file {
                Some(path)
            } else if debug {
                Some(PathBuf::from("artifacts/env-check/raw.log"))
            } else {
                None
            };

            let options = CheckOptions { debug_log_path };

            match run_check_with_options(
                &root,
                config.as_deref(),
                profile.into(),
                fail_on.into(),
                options,
            )
            .with_context(|| "run env-check")
            {
                Ok(output) => {
                    let json = serde_json::to_vec_pretty(&output.receipt)?;
                    write_atomic(&out, &json)?;

                    if let Some(md_path) = md {
                        write_atomic(&md_path, output.markdown.as_bytes())?;
                    }

                    // Print a one-line summary (useful for local runs).
                    eprintln!("env-check: {:?}", output.receipt.verdict.status);

                    std::process::exit(output.exit_code);
                }
                Err(err) => {
                    let receipt = env_check_app::runtime_error_receipt(&err.to_string());
                    let json = serde_json::to_vec_pretty(&receipt)?;
                    write_atomic(&out, &json)?;

                    if let Some(md_path) = md {
                        let markdown = env_check_render::render_markdown(&receipt);
                        write_atomic(&md_path, markdown.as_bytes())?;
                    }

                    eprintln!("env-check: {}", err);
                    std::process::exit(1);
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
        Command::Explain { code } => {
            println!("{}", explain(&code));
        }
    }

    Ok(())
}

fn explain(code: &str) -> &'static str {
    match code {
        "env.missing_tool" => "The tool is not on PATH. Install it and ensure the runner PATH includes its bin directory.",
        "env.version_mismatch" => "The tool is present but its version does not satisfy the repo constraint. Install a compatible version or adjust the repo constraint.",
        "env.hash_mismatch" => "A repo-local binary does not match the hash manifest. Re-fetch/restore the binary so it matches repo truth.",
        "env.toolchain_missing" => "The repo requires a rust toolchain (rust-toolchain.toml), but rustup or the requested toolchain is missing. Install rustup and the requested toolchain.",
        "env.source_parse_error" => "A supported source file exists but could not be parsed. Fix its syntax or remove it temporarily.",
        "tool.runtime_error" => "env-check could not execute a probe command. Ensure the tool is executable and the runner allows process execution.",
        _ => "Unknown code. If this code was emitted, the explain registry is missing an entry (bug).",
    }
}
