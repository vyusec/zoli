//! Fail-closed CLI boundaries, using only synthetic feeds and loopback HTTPS.
#![allow(clippy::unwrap_used)]
mod support;
use serde_json::json;
use support::*;

#[test]
fn stale_or_failed_feed_prevents_any_registry_request() {
    let bytes = package("module.exports = 1;");
    let response = bytes.clone();
    let server = Server::new(move |_| (200, vec![], response.clone()));
    let project_dir = tempfile::tempdir().unwrap();
    let lock = project(
        project_dir.path(),
        &format!("{}/npm/fixture.tgz", server.origin),
        &bytes,
    );
    for (age, error) in [(3601, None), (0, Some("upstream unavailable"))] {
        let home = tempfile::tempdir().unwrap();
        publish(home.path(), vec![], age, error);
        let template = support::home(vec![]);
        std::fs::copy(
            template.path().join("config.json"),
            home.path().join("config.json"),
        )
        .unwrap();
        configure(home.path(), |c| {
            c["registries"] = json!({"npm":[server.registry()]})
        });
        let npmrc = home.path().join("npmrc");
        std::fs::write(&npmrc, format!("registry={}/npm", server.origin)).unwrap();
        let report = result(
            command(
                home.path(),
                &[
                    "--json",
                    "scan",
                    "--lockfile",
                    lock.to_str().unwrap(),
                    "--npmrc",
                    npmrc.to_str().unwrap(),
                ],
            ),
            10,
        );
        assert_eq!(report["decision"]["complete"], false);
        assert!(server.requests.lock().unwrap().is_empty());
    }
}

#[test]
fn invalid_configuration_never_releases_a_success_report() {
    let base = home(vec![]);
    let path = base.path().join("config.json");
    let original: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let changes = [
        ("/config_version", json!(2)),
        ("/feed/public_key", json!("invalid-base64")),
        ("/feed/public_key", json!("YQ==")),
        ("/feed/url", json!("http://example.invalid/feed")),
        ("/feed/url", json!("https://example.invalid:8443/feed")),
        ("/feed/url", json!("https://example.invalid/not-a-feed")),
        (
            "/feed/url",
            json!("https://example.invalid/feed?token=invalid"),
        ),
        (
            "/feed/url",
            json!("https://user:password@example.invalid/feed"),
        ),
    ];
    let mut configs = vec![];
    for (pointer, value) in changes {
        let mut config = original.clone();
        *config.pointer_mut(pointer).unwrap() = value;
        configs.push(config);
    }
    for (key, value) in [
        ("unknown", json!(true)),
        ("policy", json!({"max_staleness_hours":2})),
        ("policy", json!({"min_publish_age_hours":0})),
        ("policy", json!({"suspicious":"allow"})),
        ("analysis", json!({"worker_seconds":0})),
        ("analysis", json!({"worker_memory_bytes":0})),
        ("analysis", json!({"max_files":0})),
    ] {
        let mut config = original.clone();
        config[key] = value;
        configs.push(config);
    }
    for (index, config) in configs.iter().enumerate() {
        std::fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
        let report = result(command(base.path(), &["--json", "status"]), 1);
        assert_eq!(report["scope"], "error", "case {index}");
        assert!(report["decision"].is_null(), "case {index}");
    }
}

#[test]
fn ci_environment_enforces_suspicion_even_with_explicit_warn() {
    let home = home(vec![record("suspicious", "https://registry.npmjs.org")]);
    for (ci, expected) in [
        ("", 0),
        ("0", 0),
        ("false", 0),
        ("1", 10),
        ("true", 10),
        ("TRUE", 10),
        ("yes", 10),
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_zoli"))
            .env_clear()
            .env("HOME", home.path())
            .env("ZOLI_HOME", home.path())
            .env("CI", ci)
            .args([
                "--json",
                "--suspicious=warn",
                "check",
                "--eco",
                "npm",
                "--name",
                "fixture",
                "--ver",
                "1.0.0",
            ])
            .output()
            .unwrap();
        let report = result(output, expected);
        assert_eq!(report["decision"]["complete"], true);
        assert_eq!(
            report["decision"]["action"],
            if expected == 10 { "block" } else { "warn" }
        );
    }
}
