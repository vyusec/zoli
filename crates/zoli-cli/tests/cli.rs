//! Phase 0 contract: the command surface exists and every command fails closed.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::process::{Command, Output};

fn zoli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_zoli"))
        .args(args)
        .output()
        .expect("run zoli")
}

#[test]
fn help_lists_every_command() {
    let out = zoli(&["--help"]);
    assert!(out.status.success());
    let help = String::from_utf8(out.stdout).unwrap();
    for command in [
        "wrap", "serve", "check", "update", "status", "shims", "doctor",
    ] {
        assert!(help.contains(command), "help is missing {command}");
    }
}

#[test]
fn version_is_reported() {
    let out = zoli(&["--version"]);
    assert!(out.status.success());
    assert!(String::from_utf8(out.stdout).unwrap().starts_with("zoli "));
}

#[test]
fn unimplemented_commands_fail_closed() {
    let cases: &[&[&str]] = &[
        &["wrap", "npm", "--", "install", "left-pad"],
        &["serve"],
        &[
            "check", "--eco", "npm", "--name", "left-pad", "--ver", "1.3.0",
        ],
        &[
            "check",
            "--eco",
            "npm",
            "--name",
            "left-pad",
            "--ver",
            "1.3.0",
            "--suspicious",
            "block",
        ],
        &["update"],
        &["status"],
        &["shims", "install", "--shell", "bash"],
        &["shims", "uninstall", "--shell", "fish"],
        &["shims", "install", "--ci"],
        &["doctor"],
    ];
    for args in cases {
        let out = zoli(args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        assert!(out.stdout.is_empty(), "{args:?} wrote to stdout");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("not implemented"), "{args:?}: {stderr}");
    }
}

#[test]
fn usage_errors_exit_2() {
    let cases: &[&[&str]] = &[
        &[],
        &["wrap", "curl", "--", "https://example.com"],
        &["check", "--eco", "npm", "--name", "left-pad"],
        &[
            "check",
            "--eco",
            "npm",
            "--name",
            "x",
            "--ver",
            "1",
            "--suspicious",
            "allow",
        ],
        &["shims", "install"],
        &["shims", "install", "--shell", "bash", "--ci"],
        &["shims", "install", "--shell", "powershell"],
    ];
    for args in cases {
        assert_eq!(zoli(args).status.code(), Some(2), "{args:?}");
    }
}

/// `zoli wrap` must not start the real package manager before Phase 2 can
/// guard it. A fake `npm` on PATH records whether it was ever executed.
#[cfg(unix)]
#[test]
fn wrap_never_starts_the_package_manager() {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("wrap-never-runs");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("npm-ran");
    let fake = dir.join("npm");
    std::fs::write(&fake, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_zoli"))
        .args(["wrap", "npm", "--", "install", "left-pad"])
        .env("PATH", &dir)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(3));
    assert!(!marker.exists(), "zoli wrap started the package manager");
}
