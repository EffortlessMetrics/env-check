use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn facade_binary_explain_smoke() {
    let mut cmd = Command::cargo_bin("env-check").unwrap();
    cmd.arg("explain")
        .arg("env.missing_tool")
        .assert()
        .success()
        .stdout(predicate::str::contains("not on PATH"));
}
