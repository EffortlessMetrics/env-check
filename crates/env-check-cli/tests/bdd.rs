//! Gherkin-style BDD tests for env-check CLI.
//!
//! We run these as a standalone test binary (harness = false) so cucumber can
//! own `main()` and exit codes.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cucumber::{given, then, when, World};

#[derive(World, Debug, Default)]
struct EnvWorld {
    tmp: Option<tempfile::TempDir>,
    repo_root: Option<PathBuf>,
    exit_code: Option<i32>,
}

#[given(expr = "a repo fixture {string}")]
async fn given_fixture(world: &mut EnvWorld, name: String) {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name);

    let tmp = tempfile::tempdir().expect("tempdir");
    let dst = tmp.path().join("repo");

    copy_dir_recursive(&src, &dst).expect("copy fixture");

    world.tmp = Some(tmp);
    world.repo_root = Some(dst);
    world.exit_code = None;
}

#[when(expr = "I run env-check with profile {string}")]
async fn when_run(world: &mut EnvWorld, profile: String) {
    let root = world.repo_root.as_ref().expect("fixture root");

    // Cargo exposes the built test binary paths via env vars, even for
    // harness=false tests.
    let exe = env!("CARGO_BIN_EXE_env-check");

    let mut cmd = Command::new(exe);
    cmd.arg("check")
        .arg("--root")
        .arg(root)
        .arg("--profile")
        .arg(profile);

    // Make the environment deterministic: don't leak tools from the host.
    cmd.env("PATH", "");

    let out = cmd.output().expect("run env-check");
    world.exit_code = out.status.code();
}

#[then(expr = "the exit code is {int}")]
async fn then_exit_code(world: &mut EnvWorld, expected: i32) {
    assert_eq!(
        world.exit_code,
        Some(expected),
        "expected exit code {expected}, got {:?}",
        world.exit_code
    );
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dst)?;

    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let from = entry.path();
        let to = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if file_type.is_file() {
            fs::copy(&from, &to)?;
        }
        // Ignore other file types (symlinks, etc.) for fixtures.
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let features = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../features");
    let features = features
        .to_str()
        .expect("features path is valid UTF-8");

    EnvWorld::cucumber()
        .features(&[features])
        .run_and_exit()
        .await;
}
