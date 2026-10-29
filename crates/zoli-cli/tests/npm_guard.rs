//! Real npm guard checks against an isolated signed feed and HTTPS registry.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::Path,
    process::{Command, Output},
};
use support::*;

fn artifacts(exit: bool) -> BTreeMap<String, Vec<u8>> {
    let parent = br#"{"name":"fixture","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#;
    let child = br#"{"name":"child","version":"1.0.0","scripts":{"postinstall":"node hook.js"}}"#;
    let source = if exit {
        b"console.log('fixture child stdout'); console.error('fixture child stderr'); process.exit(7);".as_slice()
    } else {
        b"require('fs').writeFileSync('hook-ran','approved'); console.log('fixture child stdout');"
            .as_slice()
    };
    BTreeMap::from([
        (
            "/npm/fixture.tgz".into(),
            archive(&[("package/package.json", parent)]),
        ),
        (
            "/npm/child.tgz".into(),
            archive(&[("package/package.json", child), ("package/hook.js", source)]),
        ),
    ])
}
fn registry(data: BTreeMap<String, Vec<u8>>, age_hours: i64) -> Server {
    Server::new(move |request| {
        let path = request.split_whitespace().nth(1).unwrap();
        if let Some(bytes) = data.get(path) {
            return (200, vec![], bytes.clone());
        }
        let name = path.trim_start_matches("/npm/");
        if !["fixture", "child"].contains(&name) {
            return (404, vec![], vec![]);
        }
        let stamp = (time::OffsetDateTime::now_utc() - time::Duration::hours(age_hours))
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap();
        (200,vec![],serde_json::to_vec(&json!({"name":name,"versions":{"1.0.0":{"name":name,"version":"1.0.0","dist":{"integrity":integrity(&data[&format!("/npm/{name}.tgz")])}}},"time":{"1.0.0":stamp}})).unwrap())
    })
}
fn setup(project: &Path, home: &Path, server: &Server, data: &BTreeMap<String, Vec<u8>>) {
    configure(home, |c| {
        c["registries"] = json!({"npm":[server.registry()]})
    });
    std::fs::write(
        home.join(".npmrc"),
        format!(
            "registry={}/npm\ncache={}\n",
            server.origin,
            home.join("untrusted-cache").display()
        ),
    )
    .unwrap();
    let root = json!({"name":"guard-fixture-project","version":"1.0.0","dependencies":{"fixture":"1.0.0"}});
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), root.clone());
    for name in ["fixture", "child"] {
        let path = format!("/npm/{name}.tgz");
        let mut entry = json!({"version":"1.0.0","resolved":format!("{}{path}",server.origin),"integrity":integrity(&data[&path])});
        if name == "fixture" {
            entry["dependencies"] = json!({"child":"1.0.0"});
        } else {
            entry["hasInstallScript"] = json!(true);
        }
        packages.insert(format!("node_modules/{name}"), entry);
    }
    std::fs::write(
        project.join("package.json"),
        serde_json::to_vec(&root).unwrap(),
    )
    .unwrap();
    std::fs::write(
        project.join("package-lock.json"),
        serde_json::to_vec(&json!({"lockfileVersion":3,"packages":packages})).unwrap(),
    )
    .unwrap();
}
fn command_for(home: &Path, project: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_zoli"));
    c.current_dir(project)
        .env_clear()
        .env("HOME", home)
        .env("ZOLI_HOME", home)
        .env("PATH", std::env::var_os("PATH").unwrap());
    c
}
fn run(home: &Path, project: &Path, extra: &[&str]) -> Output {
    command_for(home, project)
        .args(["wrap", "npm", "--", "ci"])
        .args(extra)
        .output()
        .unwrap()
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
        .map(|s| serde_json::from_str(s).unwrap())
        .collect()
}

#[test]
fn real_npm_ci_uses_only_approved_cache_and_preserves_lifecycle_output() {
    let data = artifacts(false);
    let server = registry(data.clone(), 48);
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    let before = std::fs::read(project.path().join("package-lock.json")).unwrap();
    // A warm user cache and NODE_OPTIONS injection must not select another execution path.
    std::fs::create_dir(home.path().join("untrusted-cache")).unwrap();
    std::fs::write(home.path().join("untrusted-cache/sentinel"), b"retain").unwrap();
    let output = command_for(home.path(), project.path())
        .env("npm_config_cache", home.path().join("untrusted-cache"))
        .env("NODE_OPTIONS", "--require=/does/not/exist.js")
        .args(["wrap", "npm", "--", "ci", "--foreground-scripts"])
        .output()
        .unwrap();
    assert_code(&output, 0);
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture child stdout"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("Zoli"));
    assert_eq!(
        std::fs::read_to_string(project.path().join("node_modules/child/hook-ran")).unwrap(),
        "approved"
    );
    assert_eq!(
        std::fs::read(project.path().join("package-lock.json")).unwrap(),
        before
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join("untrusted-cache/sentinel")).unwrap(),
        "retain"
    );
    let events = audit(home.path());
    assert!(
        events
            .iter()
            .any(|v| v["scope"] == "npm_ci_release" && v["decision"]["complete"] == true)
    );
    assert!(
        events
            .iter()
            .any(|v| v["scope"] == "npm_ci_authorization" && v["min_publish_age_hours"] == 24)
    );
    assert_eq!(events.last().unwrap()["exit_code"], 0);
    // Only Zoli's two metadata reads and two artifact reads reached the registry.
    assert_eq!(server.requests.lock().unwrap().len(), 4);
}

#[test]
fn known_malicious_transitive_and_too_young_packages_never_install() {
    for scenario in ["malicious", "young"] {
        let data = artifacts(false);
        let server = registry(data.clone(), if scenario == "young" { 1 } else { 48 });
        let records = if scenario == "malicious" {
            let mut r = record("malicious", &format!("{}/npm", server.origin));
            r.affected.as_mut().unwrap()[0].package.name = "child".into();
            vec![r]
        } else {
            vec![]
        };
        let home = home(records);
        let project = tempfile::tempdir().unwrap();
        setup(project.path(), home.path(), &server, &data);
        let output = run(home.path(), project.path(), &[]);
        assert_code(&output, 10);
        assert!(!project.path().join("node_modules").exists());
        assert!(
            !audit(home.path())
                .iter()
                .any(|v| v["scope"] == "npm_ci_authorization")
        );
        let requests = server.requests.lock().unwrap();
        assert!(
            !requests
                .iter()
                .any(|s| s.starts_with("GET /npm/child.tgz "))
        );
        if scenario == "young" {
            assert!(!requests.iter().any(|s| s.contains(".tgz")));
        }
    }
}

#[test]
fn npm_exit_status_and_ignore_scripts_are_preserved() {
    let data = artifacts(true);
    let server = registry(data.clone(), 48);
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    let output = run(home.path(), project.path(), &["--foreground-scripts"]);
    assert_code(&output, 7);
    assert!(String::from_utf8_lossy(&output.stdout).contains("fixture child stdout"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("fixture child stderr"));
    assert_eq!(audit(home.path()).last().unwrap()["exit_code"], 7);
    let output = run(home.path(), project.path(), &["--ignore-scripts"]);
    assert_code(&output, 0);
}

#[test]
fn cache_overrides_audit_failure_and_changed_project_fail_before_installation() {
    let data = artifacts(false);
    let server = registry(data.clone(), 48);
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    assert_code(
        &run(home.path(), project.path(), &["--cache=/tmp/untrusted"]),
        2,
    );
    std::fs::write(project.path().join(".npmrc"), "cache=/tmp/untrusted\n").unwrap();
    assert_code(&run(home.path(), project.path(), &[]), 1);
    std::fs::remove_file(project.path().join(".npmrc")).unwrap();
    std::fs::create_dir_all(home.path().join("log")).unwrap();
    std::fs::write(home.path().join("log/audit.jsonl"), "partial").unwrap();
    assert_code(&run(home.path(), project.path(), &[]), 1);
    assert!(!project.path().join("node_modules").exists());
}

#[test]
fn project_mutation_during_acquisition_cannot_reuse_an_approval() {
    let data = artifacts(false);
    let project = tempfile::tempdir().unwrap();
    let root = project.path().to_owned();
    let responses = data.clone();
    let server = Server::new(move |request| {
        let path = request.split_whitespace().nth(1).unwrap();
        if let Some(bytes) = responses.get(path) {
            std::fs::write(root.join("package.json"), br#"{"name":"changed-project"}"#).unwrap();
            return (200, vec![], bytes.clone());
        }
        let name = path.trim_start_matches("/npm/");
        (200,vec![],serde_json::to_vec(&json!({"name":name,"versions":{"1.0.0":{"version":"1.0.0","dist":{"integrity":integrity(&responses[&format!("/npm/{name}.tgz")])}}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}})).unwrap())
    });
    let home = home(vec![]);
    setup(project.path(), home.path(), &server, &data);
    let output = run(home.path(), project.path(), &[]);
    assert_code(&output, 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("changed during assessment"));
    assert!(!project.path().join("node_modules").exists());
}

#[test]
fn a_populated_user_cache_cannot_bypass_a_new_malicious_verdict() {
    let data = artifacts(false);
    let server = registry(data.clone(), 48);
    let home = home(vec![record("malicious", &format!("{}/npm", server.origin))]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    let archive = home.path().join("cached-fixture.tgz");
    std::fs::write(&archive, &data["/npm/fixture.tgz"]).unwrap();
    let cache = home.path().join("untrusted-cache");
    let output = Command::new("npm")
        .current_dir(home.path())
        .env_clear()
        .env("HOME", home.path())
        .env("PATH", std::env::var_os("PATH").unwrap())
        .args([
            "cache",
            "add",
            "--ignore-scripts",
            "--offline",
            "--audit=false",
            "--fund=false",
        ])
        .arg(&archive)
        .arg("--cache")
        .arg(&cache)
        .output()
        .unwrap();
    assert_code(&output, 0);
    assert!(cache.join("_cacache").is_dir());
    let output = run(home.path(), project.path(), &[]);
    assert_code(&output, 10);
    assert!(!project.path().join("node_modules").exists());
    assert!(
        !audit(home.path())
            .iter()
            .any(|v| v["scope"] == "npm_ci_authorization")
    );
}

#[test]
fn scoped_aliases_use_authenticated_publish_metadata_and_approved_bytes() {
    let bytes = archive(&[(
        "package/package.json",
        br#"{"name":"@scope/tool","version":"1.0.0"}"#,
    )]);
    let response = bytes.clone();
    let server = Server::new(move |request| {
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer scoped-fixture")
        );
        let path = request.split_whitespace().nth(1).unwrap();
        if path == "/npm/tool.tgz" {
            return (200, vec![], response.clone());
        }
        assert_eq!(path, "/npm/@scope%2Ftool");
        (200,vec![],serde_json::to_vec(&json!({"name":"@scope/tool","versions":{"1.0.0":{"version":"1.0.0","dist":{"integrity":integrity(&response)}}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}})).unwrap())
    });
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    configure(home.path(), |c| {
        c["registries"] = json!({"npm":[server.registry()]})
    });
    std::fs::write(
        home.path().join(".npmrc"),
        format!(
            "registry={}/npm\n{}/npm/:_authToken=scoped-fixture\n",
            server.origin,
            server.origin.trim_start_matches("https:")
        ),
    )
    .unwrap();
    let root = json!({"name":"alias-project","dependencies":{"alias":"npm:@scope/tool@1.0.0"}});
    std::fs::write(
        project.path().join("package.json"),
        serde_json::to_vec(&root).unwrap(),
    )
    .unwrap();
    std::fs::write(project.path().join("npm-shrinkwrap.json"),serde_json::to_vec(&json!({"lockfileVersion":3,"packages":{"":root,"node_modules/alias":{"name":"@scope/tool","version":"1.0.0","resolved":format!("{}/npm/tool.tgz",server.origin),"integrity":integrity(&bytes)}}})).unwrap()).unwrap();
    let output = run(home.path(), project.path(), &[]);
    assert_code(&output, 0);
    let installed: Value = serde_json::from_slice(
        &std::fs::read(project.path().join("node_modules/alias/package.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(installed["name"], "@scope/tool");
    assert_eq!(server.requests.lock().unwrap().len(), 2);
}

#[test]
fn publish_age_cannot_be_borrowed_for_different_registry_artifact_bytes() {
    let data = artifacts(false);
    let responses = data.clone();
    let server = Server::new(move |request| {
        let path = request.split_whitespace().nth(1).unwrap();
        if let Some(bytes) = responses.get(path) {
            return (200, vec![], bytes.clone());
        }
        let name = path.trim_start_matches("/npm/");
        (200,vec![],serde_json::to_vec(&json!({"name":name,"versions":{"1.0.0":{"version":"1.0.0","dist":{"integrity":integrity(b"different registry bytes")}}},"time":{"1.0.0":"2026-01-01T00:00:00Z"}})).unwrap())
    });
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    let output = run(home.path(), project.path(), &[]);
    assert_code(&output, 1);
    assert!(!project.path().join("node_modules").exists());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("archive differs from the registry version")
    );
}

#[cfg(unix)]
#[test]
fn changed_feed_after_cache_population_is_rechecked_before_execution() {
    use std::os::unix::fs::PermissionsExt;
    let data = artifacts(false);
    let server = registry(data.clone(), 48);
    let home = home(vec![]);
    let project = tempfile::tempdir().unwrap();
    setup(project.path(), home.path(), &server, &data);
    let degraded = tempfile::tempdir().unwrap();
    publish_with_sequence(
        degraded.path(),
        vec![],
        0,
        Some("upstream failed after preflight"),
        2,
    );
    let wrappers = tempfile::tempdir().unwrap();
    let original = std::env::var_os("PATH").unwrap();
    let actual = std::env::split_paths(&original)
        .map(|p| p.join("npm"))
        .find(|p| p.is_file())
        .unwrap()
        .canonicalize()
        .unwrap();
    let wrapper = wrappers.path().join("npm");
    std::fs::write(&wrapper,format!("#!/bin/sh\n'{}' \"$@\"\nresult=$?\nif [ \"$1\" = cache ]; then\ncp '{}' '{}'\ncp '{}' '{}'\nfi\nexit $result\n",actual.display(),degraded.path().join("cache/feed.json").display(),home.path().join("cache/feed.json").display(),degraded.path().join("state.json").display(),home.path().join("state.json").display())).unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    let path = std::env::join_paths(
        std::iter::once(wrappers.path().to_owned()).chain(std::env::split_paths(&original)),
    )
    .unwrap();
    let output = command_for(home.path(), project.path())
        .env("PATH", path)
        .args(["wrap", "npm", "--", "ci"])
        .output()
        .unwrap();
    assert_code(&output, 10);
    assert!(!project.path().join("node_modules").exists());
    let release = audit(home.path())
        .into_iter()
        .find(|v| v["scope"] == "npm_ci_release")
        .unwrap();
    assert_eq!(release["sequence"], 2);
    assert_eq!(release["decision"]["action"], "block");
}
