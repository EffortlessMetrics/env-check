use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn help_works() {
    let mut cmd = Command::cargo_bin("env-check").unwrap();
    cmd.arg("--help");
    cmd.assert().success().stdout(predicate::str::contains("env-check"));
}
