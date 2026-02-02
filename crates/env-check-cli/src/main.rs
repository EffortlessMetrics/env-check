use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use clap::{Parser, Subcommand};
use env_check_app::{run_check, write_atomic};
use env_check_types::{FailOn, Profile, ReceiptEnvelope};

#[derive(Parser, Debug)]
#[command(name = "env-check", version, about = "Machine-truth preflight for repo tool requirements")]
struct Cli {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Discover sources, probe tools, evaluate policy, write a receipt (and optional markdown).
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
    },

    /// Render markdown from an existing report.json.
    Md {
        #[arg(long)]
        report: PathBuf,

        #[arg(long, default_value = "artifacts/env-check/comment.md")]
        out: PathBuf,
    },

    /// Explain a stable finding code (e.g., env.missing_tool).
    Explain {
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
        Command::Check { root, config, profile, fail_on, out, md } => {
            let output = run_check(&root, config.as_deref(), profile.into(), fail_on.into())
                .with_context(|| "run env-check")?;

            let json = serde_json::to_vec_pretty(&output.receipt)?;
            write_atomic(&out, &json)?;

            if let Some(md_path) = md {
                write_atomic(&md_path, output.markdown.as_bytes())?;
            }

            // Print a one-line summary (useful for local runs).
            eprintln!("env-check: {:?}", output.receipt.verdict.status);

            std::process::exit(output.exit_code);
        }
        Command::Md { report, out } => {
            let bytes = fs::read(&report).with_context(|| format!("read {}", report.display()))?;
            let receipt: ReceiptEnvelope = serde_json::from_slice(&bytes).with_context(|| "parse report.json")?;
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
