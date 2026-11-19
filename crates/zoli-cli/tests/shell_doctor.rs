//! Shell-integration and doctor process checks.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use support::*;

fn run_in(home: &Path, cwd: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zoli"))
        .current_dir(cwd)
        .env_clear()
        .env("HOME", home)
        .env("ZOLI_HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn interactive_shims_install_once_and_uninstall_cleanly() {
    let home = home(vec![]);
    std::fs::write(home.path().join(".bashrc"), "export ORIGINAL=1\n").unwrap();
    let output = run_in(
        home.path(),
        home.path(),
        &["--json", "shims", "install", "--shell", "bash"],
    );
    let value = result(output, 0);
    assert_eq!(value["changed"], true);
    let rc = std::fs::read_to_string(home.path().join(".bashrc")).unwrap();
    assert_eq!(rc.matches(zoli_shell::BEGIN).count(), 1);
    assert_eq!(rc.matches(zoli_shell::END).count(), 1);
    assert!(rc.starts_with("export ORIGINAL=1\n"));
    assert!(home.path().join("shims/zoli.bash").is_file());
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bashrc.zoli-backup")).unwrap(),
        "export ORIGINAL=1\n"
    );
    let output = run_in(
        home.path(),
        home.path(),
        &["--json", "shims", "install", "--shell", "bash"],
    );
    let value = result(output, 0);
    assert_eq!(value["changed"], false);
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bashrc")).unwrap(),
        rc
    );
    let output = run_in(
        home.path(),
        home.path(),
        &["--json", "shims", "uninstall", "--shell", "bash"],
    );
    let value = result(output, 0);
    assert_eq!(value["changed"], true);
    assert_eq!(
        std::fs::read_to_string(home.path().join(".bashrc")).unwrap(),
        "export ORIGINAL=1\n"
    );
    assert!(!home.path().join("shims/zoli.bash").exists());
}

#[test]
fn ci_shims_are_reported_and_removed() {
    let home = home(vec![]);
    let output = run_in(
        home.path(),
        home.path(),
        &["--json", "shims", "install", "--ci"],
    );
    let value = result(output, 0);
    assert_eq!(value["mode"], "ci");
    assert_eq!(value["changed"], true);
    let directory = home.path().join("shims/bin");
    assert!(directory.join("npm").is_file());
    assert!(directory.join("npx").is_file());
    let output = run_in(
        home.path(),
        home.path(),
        &["--json", "shims", "uninstall", "--ci"],
    );
    let value = result(output, 0);
    assert_eq!(value["changed"], true);
    assert!(!directory.exists());
}

#[test]
fn doctor_reports_a_healthy_local_prerequisite_set() {
    let home = home(vec![]);
    let output = run_in(home.path(), home.path(), &["--json", "doctor"]);
    let value = result(output, 0);
    assert_eq!(value["scope"], "doctor");
    assert_eq!(value["status"], "warn"); // shims are not installed in this fixture
    let checks = value["checks"].as_array().unwrap();
    let feed = checks.iter().find(|check| check["name"] == "feed").unwrap();
    assert_eq!(feed["status"], "ok");
    let config = checks
        .iter()
        .find(|check| check["name"] == "config")
        .unwrap();
    assert_eq!(config["status"], "ok");
    let npm = checks.iter().find(|check| check["name"] == "npm").unwrap();
    assert_eq!(npm["status"], "ok");
}

#[test]
fn doctor_blocks_a_stale_feed_and_reports_shims() {
    let home = home(vec![]);
    publish_with_sequence(home.path(), vec![], 7_200, None, 2);
    run_in(
        home.path(),
        home.path(),
        &["shims", "install", "--shell", "bash"],
    );
    let output = run_in(home.path(), home.path(), &["--json", "doctor"]);
    let value = result(output, 10);
    assert_eq!(value["status"], "fail");
    let checks = value["checks"].as_array().unwrap();
    let feed = checks.iter().find(|check| check["name"] == "feed").unwrap();
    assert_eq!(feed["status"], "fail");
    assert!(
        feed["detail"]
            .as_str()
            .unwrap()
            .contains("guard would block")
    );
    let shims = checks
        .iter()
        .find(|check| check["name"] == "shims")
        .unwrap();
    assert_eq!(shims["status"], "ok");
}

#[test]
fn doctor_fails_closed_without_configuration() {
    let empty = tempfile::tempdir().unwrap();
    let output = run_in(empty.path(), empty.path(), &["--json", "doctor"]);
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(10));
    assert!(
        value["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["name"] == "config" && check["status"] == "fail")
    );
}
