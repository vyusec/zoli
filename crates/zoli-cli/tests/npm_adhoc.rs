//! Guarded ad-hoc npm install and npx checks against an isolated registry.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Output},
};
use support::*;

fn package_archive(name: &str, version: &str, extra: &[(&str, &[u8])]) -> Vec<u8> {
    let manifest = format!(r#"{{"name":"{name}","version":"{version}"}}"#);
    let mut files: Vec<(&str, &[u8])> = vec![("package/package.json", manifest.as_bytes())];
    files.extend_from_slice(extra);
    archive(&files)
}

fn tool_archive() -> Vec<u8> {
    let manifest = br#"{"name":"tool","version":"1.0.0","bin":{"tool":"cli.js"}}"#;
    let source = br#"#!/usr/bin/env node
const fs = require('fs');
fs.writeFileSync(process.cwd() + '/npx-ran', process.argv.slice(2).join(' '));
console.log('tool ran ' + process.argv.slice(2).join(' '));
process.exit(Number(process.env.TOOL_EXIT || 0));
"#;
    archive(&[
        ("package/package.json", manifest),
        ("package/cli.js", source),
    ])
}

struct Registry {
    server: Server,
    archives: BTreeMap<String, Vec<u8>>,
}

fn registry(age_hours: i64) -> Registry {
    let fixture = package_archive(
        "fixture",
        "1.0.0",
        &[("package/index.js", b"console.log('fixture loaded')")],
    );
    let child = archive(&[
        (
            "package/package.json",
            br#"{"name":"child","version":"1.0.0","scripts":{"postinstall":"node hook.js"}}"#,
        ),
        (
            "package/hook.js",
            b"require('fs').writeFileSync('hook-ran','approved'); console.log('child hook');",
        ),
    ]);
    let tool = tool_archive();
    let archives = BTreeMap::from([
        ("/npm/fixture.tgz".to_owned(), fixture.clone()),
        ("/npm/child.tgz".to_owned(), child.clone()),
        ("/npm/tool.tgz".to_owned(), tool.clone()),
    ]);
    let responses = archives.clone();
    let stamp = (time::OffsetDateTime::now_utc() - time::Duration::hours(age_hours))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let fixture_meta = serde_json::to_vec(&json!({
        "name":"fixture","versions":{"1.0.0":{"name":"fixture","version":"1.0.0","dependencies":{"child":"1.0.0"},"dist":{"tarball":"__ORIGIN__/npm/fixture.tgz","integrity":integrity(&fixture)}}},"time":{"1.0.0":stamp}
    }))
    .unwrap();
    let child_meta = serde_json::to_vec(&json!({
        "name":"child","versions":{"1.0.0":{"name":"child","version":"1.0.0","dist":{"tarball":"__ORIGIN__/npm/child.tgz","integrity":integrity(&child)}}},"time":{"1.0.0":stamp}
    }))
    .unwrap();
    let tool_meta = serde_json::to_vec(&json!({
        "name":"tool","versions":{"1.0.0":{"name":"tool","version":"1.0.0","bin":{"tool":"cli.js"},"dist":{"tarball":"__ORIGIN__/npm/tool.tgz","integrity":integrity(&tool)}}},"time":{"1.0.0":stamp}
    }))
    .unwrap();
    let origin = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let server = {
        let origin = origin.clone();
        Server::new(move |request| {
            let path = request.split_whitespace().nth(1).unwrap();
            if let Some(bytes) = responses.get(path) {
                return (
                    200,
                    vec![("Content-Type".into(), "application/octet-stream".into())],
                    bytes.clone(),
                );
            }
            let name = path.trim_start_matches("/npm/");
            let meta = match name {
                "fixture" => &fixture_meta,
                "child" => &child_meta,
                "tool" => &tool_meta,
                _ => return (404, vec![], vec![]),
            };
            let origin = origin.lock().unwrap().clone();
            (
                200,
                vec![("Content-Type".into(), "application/json".into())],
                String::from_utf8(meta.clone())
                    .unwrap()
                    .replace("__ORIGIN__", &origin)
                    .into_bytes(),
            )
        })
    };
    *origin.lock().unwrap() = server.origin.clone();
    Registry { server, archives }
}

fn setup(home: &Path, server: &Server, name: &str) {
    configure(home, |config| {
        config["registries"] = json!({"npm":[server.registry()]})
    });
    std::fs::write(
        home.join(".npmrc"),
        format!("registry={}/npm\n", server.origin),
    )
    .unwrap();
    let _ = name;
}

fn project(dir: &Path, manifest: Value) {
    std::fs::write(
        dir.join("package.json"),
        serde_json::to_vec(&manifest).unwrap(),
    )
    .unwrap();
}

fn command(home: &Path, project: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_zoli"));
    command
        .current_dir(project)
        .env_clear()
        .env("HOME", home)
        .env("ZOLI_HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("NODE_EXTRA_CA_CERTS", ca());
    command
}

fn assert_code(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn audit(home: &Path) -> Vec<Value> {
    std::fs::read_to_string(home.join("log/audit.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn guarded_install_resolves_inspects_and_installs_from_the_private_cache() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "fixture");
    let project_dir = tempfile::tempdir().unwrap();
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{"fixture":"^1.0.0"}}),
    );
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npm", "--", "install", "--foreground-scripts"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    assert!(project_dir.path().join("package-lock.json").is_file());
    assert_eq!(
        std::fs::read_to_string(project_dir.path().join("node_modules/child/hook-ran")).unwrap(),
        "approved"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("child hook"));
    let events = audit(home.path());
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npm_install_release"
                && event["decision"]["complete"] == true)
    );
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npm_install_authorization")
    );
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npm_install_exit" && event["exit_code"] == 0)
    );
}

#[test]
fn guarded_install_adds_a_direct_exact_spec_and_rewrites_both_inputs() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "fixture");
    let project_dir = tempfile::tempdir().unwrap();
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{}}),
    );
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npm", "--", "install", "fixture@1.0.0"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(project_dir.path().join("package.json")).unwrap())
            .unwrap();
    assert_eq!(manifest["dependencies"]["fixture"], "^1.0.0");
    let lock: Value = serde_json::from_slice(
        &std::fs::read(project_dir.path().join("package-lock.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(lock["packages"][""]["dependencies"]["fixture"], "^1.0.0");
    assert!(
        project_dir
            .path()
            .join("node_modules/fixture/package.json")
            .is_file()
    );
}

#[test]
fn blocked_install_never_changes_project_files_or_writes_tarballs_to_disk() {
    for scenario in ["malicious", "young"] {
        let registry = registry(if scenario == "young" { 1 } else { 48 });
        let records = if scenario == "malicious" {
            let mut record = record("malicious", &format!("{}/npm", registry.server.origin));
            record.affected.as_mut().unwrap()[0].package.name = "child".into();
            vec![record]
        } else {
            vec![]
        };
        let home = home(records);
        setup(home.path(), &registry.server, "fixture");
        let project_dir = tempfile::tempdir().unwrap();
        let manifest = json!({"name":"app","version":"1.0.0","dependencies":{"fixture":"1.0.0"}});
        project(project_dir.path(), manifest.clone());
        let output = command(home.path(), project_dir.path())
            .args(["wrap", "npm", "--", "install"])
            .output()
            .unwrap();
        assert_code(&output, 10);
        assert!(!project_dir.path().join("package-lock.json").exists());
        assert!(!project_dir.path().join("node_modules").exists());
        let current: Value = serde_json::from_slice(
            &std::fs::read(project_dir.path().join("package.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(current, manifest);
        assert!(
            !audit(home.path())
                .iter()
                .any(|event| event["scope"] == "npm_install_authorization")
        );
        let requests = registry.server.requests.lock().unwrap();
        if scenario == "young" {
            assert!(!requests.iter().any(|request| request.contains(".tgz")));
        }
    }
}

#[test]
fn guarded_npx_installs_and_runs_only_the_declared_executable() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "tool");
    let project_dir = tempfile::tempdir().unwrap();
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npx", "--", "tool@1.0.0", "hello", "world"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("tool ran hello world"));
    assert_eq!(
        std::fs::read_to_string(project_dir.path().join("npx-ran")).unwrap(),
        "hello world"
    );
    let events = audit(home.path());
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npx_assessment")
    );
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npx_authorization")
    );
    assert!(
        events
            .iter()
            .any(|event| event["scope"] == "npx_exit" && event["exit_code"] == 0)
    );
}

#[test]
fn npx_exit_status_is_preserved_and_malicious_packages_never_run() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "tool");
    let project_dir = tempfile::tempdir().unwrap();
    let output = command(home.path(), project_dir.path())
        .env("TOOL_EXIT", "7")
        .args(["wrap", "npx", "--", "tool@1.0.0"])
        .output()
        .unwrap();
    assert_code(&output, 7);
    assert!(project_dir.path().join("npx-ran").is_file());
    std::fs::remove_file(project_dir.path().join("npx-ran")).unwrap();

    let mut record = record("malicious", &format!("{}/npm", registry.server.origin));
    record.affected.as_mut().unwrap()[0].package.name = "tool".into();
    let home = support::home(vec![record]);
    setup(home.path(), &registry.server, "tool");
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npx", "--", "tool@1.0.0"])
        .output()
        .unwrap();
    assert_code(&output, 10);
    assert!(!project_dir.path().join("npx-ran").exists());
    assert!(
        !audit(home.path())
            .iter()
            .any(|event| event["scope"] == "npx_authorization")
    );
}

#[test]
fn nested_shim_invocations_passthrough_without_reassessing() {
    let home = support::home(vec![]);
    let project_dir = tempfile::tempdir().unwrap();
    let output = command(home.path(), project_dir.path())
        .env("ZOLI_WRAPPED", "1")
        .args(["wrap", "npx", "--", "--version"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("10."));
}

#[test]
fn unapproved_scoped_registry_routes_refuse_before_resolution() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "fixture");
    std::fs::write(
        home.path().join(".npmrc"),
        format!(
            "registry={}/npm\n@evil:registry=https://evil.example.invalid/npm\n",
            registry.server.origin
        ),
    )
    .unwrap();
    let project_dir = tempfile::tempdir().unwrap();
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{}}),
    );
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npm", "--", "install"])
        .output()
        .unwrap();
    assert_code(&output, 1);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not approved"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!project_dir.path().join("package-lock.json").exists());
}

#[test]
fn unsupported_sources_and_options_are_refused_before_resolution() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "fixture");
    let project_dir = tempfile::tempdir().unwrap();
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{}}),
    );
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npm", "--", "install", "--cache=/tmp/untrusted"])
        .output()
        .unwrap();
    assert_code(&output, 2);
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{"fixture":"file:../fixture"}}),
    );
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npm", "--", "install"])
        .output()
        .unwrap();
    assert_code(&output, 1);
    assert!(!project_dir.path().join("package-lock.json").exists());
    let output = command(home.path(), project_dir.path())
        .args(["wrap", "npx", "--", "--package=tool@1.0.0"])
        .output()
        .unwrap();
    assert_code(&output, 2);
}

#[test]
fn tarball_cache_is_not_shared_with_resolution_metadata() {
    let registry = registry(48);
    let home = home(vec![]);
    setup(home.path(), &registry.server, "fixture");
    let project_dir = tempfile::tempdir().unwrap();
    project(
        project_dir.path(),
        json!({"name":"app","version":"1.0.0","dependencies":{"fixture":"1.0.0"}}),
    );
    // Seed the user's normal npm cache with the fixture tarball. The guard must
    // not treat it as approved and must still fetch and inspect its own copy.
    let cache = home.path().join("untrusted-cache");
    let tarball = home.path().join("fixture.tgz");
    std::fs::write(&tarball, &registry.archives["/npm/fixture.tgz"]).unwrap();
    let seeded = Command::new("npm")
        .args([
            "cache",
            "add",
            "--ignore-scripts",
            "--offline",
            "--audit=false",
            "--fund=false",
        ])
        .arg(&tarball)
        .arg("--cache")
        .arg(&cache)
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap())
        .output()
        .unwrap();
    assert!(seeded.status.success());
    let before = registry.server.requests.lock().unwrap().len();
    let output = command(home.path(), project_dir.path())
        .env("npm_config_cache", &cache)
        .args(["wrap", "npm", "--", "install"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    let after = registry.server.requests.lock().unwrap().len();
    assert!(
        after > before,
        "the guard must fetch its own approved artifacts"
    );
    assert!(
        project_dir
            .path()
            .join("node_modules/fixture/package.json")
            .is_file()
    );
}
